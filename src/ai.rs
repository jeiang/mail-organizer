//! The local language model stage. Mail no other stage could place goes to an
//! OpenAI-compatible server (llama-server), which picks one of the account's
//! folders, each shown with a few recent examples, or none, and may propose a
//! new folder. Verdicts are stored per message and folder set, so each message
//! is asked about once until the folders change.

use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::config::LlmConfig;
use crate::db::{self, Db, json_list};
use crate::rules::{self, MESSAGE_COLUMNS, Message};

/// Most messages asked about per pass, so a backlog cannot stall syncing.
const PER_PASS: usize = 20;
const EXAMPLES: usize = 3;
const BODY_CHARS: usize = 1500;
const TIMEOUT: Duration = Duration::from_secs(120);
const NONE: &str = "(none)";
const KINDS: [&str; 8] = [
    "personal",
    "receipt, order or bill",
    "account or security notice",
    "service update",
    "newsletter",
    "promotion",
    "social notification",
    "other",
];

/// The account's folders and the system prompt describing them.
pub struct Folders {
    pub names: Vec<String>,
    /// Identifies the folder set; a verdict for another set is asked again.
    pub key: String,
    prompt: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub folder: Option<String>,
    pub confident: bool,
    pub suggestion: Option<String>,
    pub reason: String,
}

fn prefix(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// The filing folders of `account` with their newest training examples,
/// older than `before` when given.
pub fn folders(c: &Connection, account: &str, before: Option<f64>) -> Result<Folders> {
    let names = rules::destinations(c, account)?;
    let mut stmt = c.prepare(
        "SELECT from_name, from_addr, subject FROM training_messages \
         WHERE account = ?1 AND folder = ?2 AND date_ts < ?3 ORDER BY date_ts DESC LIMIT ?4",
    )?;
    let mut lines = Vec::new();
    for name in &names {
        lines.push(format!("- {name}"));
        let examples = stmt.query_map(
            params![account, name, before.unwrap_or(f64::MAX), EXAMPLES as i64],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        )?;
        for e in examples {
            let (from_name, from_addr, subject) = e?;
            let sender = if from_name.is_empty() { from_addr } else { from_name };
            lines.push(format!("    {} — {}", prefix(&sender, 60), prefix(&subject, 100)));
        }
    }
    let prompt = format!(
        "You file the owner's email into their folders. Their folders, each with up to {EXAMPLES} recent examples (sender — subject):\n\
         {}\n\n\
         First name the kind of message. Then choose the folder it belongs in and grade the fit:\n\
         - strong: the folder holds mail of this kind for this purpose, for example from the same sender, or it is named for exactly this kind of mail.\n\
         - weak: the folder is only related by topic or by the sender's industry. A sale offer from a company whose receipts or release notes \
         are in a folder is a weak fit for that folder.\n\
         - none: no folder fits; answer \"{NONE}\".\n\
         Marketing, promotions and social network notifications fit strongly only in folders that hold such mail. \
         Unless the fit is strong, set new_folder to a short name for a folder the owner could create for this kind of mail \
         (for example Promotions or Social), in the style of the existing names, using / for subfolders; otherwise leave it empty. \
         Keep reason to one short sentence.",
        lines.join("\n")
    );
    let key = hex::encode(Sha256::digest(names.join("\n")))[..16].to_owned();
    Ok(Folders { names, key, prompt })
}

fn describe(m: &Message, body: &str) -> String {
    let mut out = format!("From: {} <{}>\nSender domain: {}\n", m.from_name, m.from_addr, m.from_domain);
    for (label, value) in [
        ("List-Id", &m.list_id),
        ("Precedence", &m.precedence),
        ("Gmail category", &m.category),
    ] {
        if !value.is_empty() {
            out.push_str(&format!("{label}: {value}\n"));
        }
    }
    let attachments = json_list(&m.att_types);
    if !attachments.is_empty() {
        out.push_str(&format!("Attachments: {}\n", attachments.join(", ")));
    }
    out.push_str(&format!("Subject: {}\n\n{}", m.subject, prefix(body, BODY_CHARS)));
    out
}

/// One request to the server.
pub async fn ask(
    client: &reqwest::Client,
    llm: &LlmConfig,
    folders: &Folders,
    m: &Message,
    body: &str,
) -> Result<Verdict> {
    let mut choices: Vec<&str> = folders.names.iter().map(String::as_str).collect();
    choices.push(NONE);
    // Written by hand because serde_json sorts keys, and the grammar follows
    // property order: the model must state kind and reason before choosing.
    let schema = format!(
        r#"{{"type":"object","properties":{{"kind":{{"enum":{}}},"reason":{{"type":"string","maxLength":200}},"folder":{{"enum":{}}},"fit":{{"enum":["strong","weak","none"]}},"new_folder":{{"type":"string","maxLength":60}}}},"required":["kind","reason","folder","fit","new_folder"],"additionalProperties":false}}"#,
        json!(KINDS),
        json!(choices),
    );
    let messages = json!([
        {"role": "system", "content": folders.prompt},
        {"role": "user", "content": describe(m, body)},
    ]);
    // reasoning_format none: llama-server otherwise lets a model write free
    // text before the constrained answer.
    let request = format!(
        r#"{{"model":{},"temperature":0,"max_tokens":300,"reasoning_format":"none","messages":{messages},"response_format":{{"type":"json_schema","json_schema":{{"name":"verdict","strict":true,"schema":{schema}}}}}}}"#,
        json!(llm.model),
    );
    let url = format!("{}/v1/chat/completions", llm.url.trim_end_matches('/'));
    let response: Value = client
        .post(&url)
        .timeout(TIMEOUT)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(request)
        .send()
        .await
        .with_context(|| format!("asking {url}"))?
        .error_for_status()?
        .json()
        .await?;
    let content = response
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no message content in the model's response"))?;
    parse(content, &folders.names).with_context(|| {
        format!(
            "finish reason {}, answer {content:?}",
            response.pointer("/choices/0/finish_reason").unwrap_or(&Value::Null)
        )
    })
}

/// The model's answer, checked against the folders it was offered.
fn parse(content: &str, names: &[String]) -> Result<Verdict> {
    let answer: Value = serde_json::from_str(content).context("the model's answer is not JSON")?;
    let text = |k: &str| answer.get(k).and_then(Value::as_str).unwrap_or_default().trim();
    let folder = names.iter().find(|n| n.as_str() == text("folder")).cloned();
    let suggestion = Some(text("new_folder"))
        .filter(|s| rules::filing_destination(s) && !names.iter().any(|n| n.eq_ignore_ascii_case(s)))
        .map(String::from);
    Ok(Verdict {
        confident: folder.is_some() && text("fit") == "strong",
        folder,
        suggestion,
        reason: text("reason").to_owned(),
    })
}

/// The newest stored verdict for a message.
pub fn latest(c: &Connection, message_id: i64) -> Result<Option<Verdict>> {
    Ok(c.query_row(
        "SELECT folder, confident, suggestion, reason FROM ai_verdicts WHERE message_id = ?1 ORDER BY id DESC LIMIT 1",
        [message_id],
        |r| {
            Ok(Verdict {
                folder: r.get(0)?,
                confident: r.get(1)?,
                suggestion: r.get(2)?,
                reason: r.get(3)?,
            })
        },
    )
    .optional()?)
}

pub fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().build()?)
}

/// Asks about eligible mail that routing left in the inbox and that has no
/// verdict for the current folders. Returns how many verdicts were stored.
pub async fn consult(db: &Db, account: &str, llm: &LlmConfig) -> Result<usize> {
    let (name, model) = (account.to_owned(), llm.model.clone());
    let (folders, pending) = db
        .read(move |c| {
            let folders = folders(c, &name, None)?;
            let mut pending = Vec::new();
            for m in crate::router::eligible(c, &name)? {
                let unplaced: bool = c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM decisions WHERE message_id = ?1 AND stage = 'none' \
                     AND id = (SELECT MAX(id) FROM decisions WHERE message_id = ?1)) \
                     AND NOT EXISTS(SELECT 1 FROM ai_verdicts WHERE message_id = ?1 AND folders = ?2 AND model = ?3)",
                    params![m.id, folders.key, model],
                    |r| r.get(0),
                )?;
                if unplaced {
                    let body = crate::classify::body(c, m.id)?;
                    pending.push((m, body));
                    if pending.len() == PER_PASS {
                        break;
                    }
                }
            }
            Ok((folders, pending))
        })
        .await?;
    if pending.is_empty() || folders.names.is_empty() {
        return Ok(0);
    }
    let client = client()?;
    let mut verdicts = Vec::new();
    for (m, body) in &pending {
        match ask(&client, llm, &folders, m, body).await {
            Ok(v) => verdicts.push((m.id, v)),
            // The server may be loading or down; what was answered is kept
            // and the rest is asked next pass.
            Err(e) => {
                warn!(account, message.id = m.id, "language model unavailable: {e:#}");
                break;
            }
        }
    }
    let (n, key, model) = (verdicts.len(), folders.key.clone(), llm.model.clone());
    db.write(move |c| {
        let tx = c.transaction()?;
        let now = db::now();
        for (id, v) in &verdicts {
            tx.execute(
                "INSERT INTO ai_verdicts (message_id, ts, model, folders, folder, confident, suggestion, reason) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![id, now, model, key, v.folder, v.confident, v.suggestion, v.reason],
            )?;
        }
        tx.commit()?;
        Ok(())
    })
    .await?;
    if n > 0 {
        info!(account, verdicts = n, "language model consulted");
    }
    Ok(n)
}

#[derive(Debug, Default)]
pub struct Report {
    pub total: usize,
    pub answered: usize,
    pub agree: usize,
    pub confident: usize,
    pub confident_agree: usize,
    pub suggested: usize,
}

/// Asks about the newest `limit` training messages, describing the folders
/// with examples older than all of them, and compares with where they are.
pub async fn evaluate(db: &Db, account: &str, limit: usize, llm: &LlmConfig) -> Result<Report> {
    let name = account.to_owned();
    let (folders, sample) = db
        .read(move |c| {
            let sql = format!(
                "SELECT {MESSAGE_COLUMNS} FROM training_messages m WHERE m.account = ?1 AND m.date_ts > 0 \
                 ORDER BY m.date_ts DESC LIMIT ?2"
            );
            let messages: Vec<Message> = c
                .prepare(&sql)?
                .query_map(params![name, limit as i64], Message::from_row)?
                .collect::<rusqlite::Result<_>>()?;
            let cutoff = messages.iter().map(|m| m.date_ts).fold(f64::MAX, f64::min);
            let folders = folders(c, &name, Some(cutoff))?;
            let mut sample = Vec::new();
            for m in messages {
                let body = crate::classify::body(c, m.id)?;
                sample.push((m, body));
            }
            Ok((folders, sample))
        })
        .await?;
    let client = client()?;
    let mut report = Report::default();
    for (m, body) in &sample {
        let v = ask(&client, llm, &folders, m, body).await?;
        report.total += 1;
        let agree = v.folder.is_some() && v.folder == m.folder;
        report.answered += usize::from(v.folder.is_some());
        report.agree += usize::from(agree);
        report.confident += usize::from(v.confident);
        report.confident_agree += usize::from(v.confident && agree);
        report.suggested += usize::from(v.suggestion.is_some());
    }
    Ok(report)
}

pub fn print(account: &str, r: &Report) {
    let share = |n: usize, d: usize| 100.0 * n as f64 / d.max(1) as f64;
    println!(
        "{account} (language model): {} newest training examples, folders described by older mail",
        r.total
    );
    println!(
        "  answered: {}/{} ({:.1}%), agreement {}/{} ({:.1}%)",
        r.answered,
        r.total,
        share(r.answered, r.total),
        r.agree,
        r.answered,
        share(r.agree, r.answered)
    );
    println!(
        "  confident (would file): {}/{} ({:.1}% coverage), precision {}/{} ({:.1}%)",
        r.confident,
        r.total,
        share(r.confident, r.total),
        r.confident_agree,
        r.confident,
        share(r.confident_agree, r.confident)
    );
    println!("  proposed a new folder: {}", r.suggested);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_checked_against_the_offered_folders() {
        let names = vec!["News".to_owned(), "Purchases".to_owned()];
        let v = parse(
            r#"{"reason":"shop","folder":"Purchases","fit":"strong","new_folder":""}"#,
            &names,
        )
        .unwrap();
        assert_eq!(v.folder.as_deref(), Some("Purchases"));
        assert!(v.confident);
        assert!(v.suggestion.is_none());
        let v = parse(
            r#"{"reason":"x","folder":"Trash","fit":"strong","new_folder":"Promotions"}"#,
            &names,
        )
        .unwrap();
        assert!(v.folder.is_none() && !v.confident);
        assert_eq!(v.suggestion.as_deref(), Some("Promotions"));
        let v = parse(
            r#"{"reason":"sale","folder":"Purchases","fit":"weak","new_folder":""}"#,
            &names,
        )
        .unwrap();
        assert!(v.folder.is_some() && !v.confident);
        for bad in ["INBOX", "news", "Misc/Old", "Trash"] {
            let v = parse(
                &format!(r#"{{"reason":"","folder":"(none)","fit":"none","new_folder":"{bad}"}}"#),
                &names,
            )
            .unwrap();
            assert!(v.suggestion.is_none(), "{bad}");
        }
        assert!(parse("not json", &names).is_err());
    }
}
