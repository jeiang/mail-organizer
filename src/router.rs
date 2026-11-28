//! Routing: operator rules, then learned sender patterns, then the per-account
//! classifier, then the BM25 neighbour vote, then a stored language model
//! verdict. Anything else stays in the inbox for the owner to move.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tracing::{Span, info, info_span};

use crate::classify;
use crate::db::{self, Db, Mode};
use crate::rules::{self, MESSAGE_COLUMNS, Message, Rule};
use crate::similar;

pub const SIMILAR_K: usize = 7;
pub const SIMILAR_MIN_HITS: usize = 3;
pub const SIMILAR_MIN_SHARE: f64 = 0.9;
pub const MODEL_MIN: f64 = 0.95;

#[derive(Debug, Clone)]
pub struct Decision {
    pub stage: &'static str,
    pub action: &'static str,
    pub dest: Option<String>,
    pub key: Option<String>,
    pub confidence: Option<f64>,
    pub detail: Value,
}

pub fn decide(
    c: &Connection,
    m: &Message,
    rules: &[Rule],
    now: f64,
    use_similar: bool,
    model: Option<&classify::Model>,
) -> Result<Decision> {
    if let Some(rule) = rules::first_match(m, rules, now) {
        return Ok(Decision {
            stage: "operator",
            action: rule.action.as_str(),
            dest: rule.dest.clone(),
            key: Some(rule.id.clone()),
            confidence: None,
            detail: json!({"rule": rule}),
        });
    }
    if let Some(l) = rules::learned_match(c, m)? {
        return Ok(Decision {
            stage: "learned",
            action: "file",
            dest: Some(l.dest),
            key: Some(l.level.to_owned()),
            confidence: Some(l.purity),
            detail: json!({"n": l.n, "pattern": l.key, "counts": l.counts}),
        });
    }
    let mut detail = json!({});
    if let Some(model) = model {
        let (dest, p, top) = model.predict(m, &classify::body(c, m.id)?);
        if p >= MODEL_MIN {
            return Ok(Decision {
                stage: "model",
                action: "file",
                dest: Some(dest),
                key: Some("logreg".into()),
                confidence: Some(p),
                detail: json!({"p": p, "top": top}),
            });
        }
        // Keep the near miss visible on the inbox page.
        detail = json!({"model": {"p": p, "top": top}});
    }
    if use_similar {
        let near = similar::neighbours(c, m, SIMILAR_K)?;
        if let Some((folder, share)) = similar::vote(&near) {
            detail["neighbours"] = json!(near);
            detail["share"] = json!(share);
            detail["vote"] = json!(folder);
            if near.len() >= SIMILAR_MIN_HITS && share >= SIMILAR_MIN_SHARE {
                return Ok(Decision {
                    stage: "similar",
                    action: "file",
                    dest: Some(folder),
                    key: Some("bm25".into()),
                    confidence: Some(share),
                    detail,
                });
            }
        }
    }
    if let Some(v) = crate::ai::latest(c, m.id)? {
        if let (true, Some(dest)) = (v.confident, v.folder.clone()) {
            return Ok(Decision {
                stage: "ai",
                action: "file",
                dest: Some(dest),
                key: None,
                confidence: None,
                detail: json!({"ai": v}),
            });
        }
        detail["ai"] = json!(v);
    }
    Ok(Decision {
        stage: "none",
        action: "none",
        dest: None,
        key: None,
        confidence: None,
        detail,
    })
}

/// Read, unflagged inbox mail that has not been successfully filed or queued.
pub fn eligible(c: &Connection, account: &str) -> Result<Vec<Message>> {
    let sql = format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages m LEFT JOIN decisions latest \
         ON latest.id = (SELECT MAX(d.id) FROM decisions d WHERE d.message_id = m.id) \
         WHERE m.account = ?1 AND m.in_inbox = 1 AND m.seen = 1 \
         AND m.flagged = 0 AND m.sent = 0 AND m.gone_at IS NULL \
         AND NOT EXISTS (SELECT 1 FROM decisions d WHERE d.message_id = m.id AND d.apply_state IN ('done', 'imported')) \
         AND (latest.id IS NULL OR latest.apply_state IS NULL OR (latest.apply_state = 'skipped' \
         AND latest.apply_error IN ('unseen', 'flagged', 'destination', 'rule_changed'))) ORDER BY m.id"
    );
    let mut stmt = c.prepare(&sql)?;
    let rows = stmt.query_map([account], Message::from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Stores a decision, tagged with the current span's trace ids.
pub fn record(
    c: &Connection,
    m: &Message,
    d: &Decision,
    ts: f64,
    apply_state: Option<&str>,
) -> Result<i64> {
    let ids = crate::telemetry::current_ids();
    c.execute(
        "INSERT INTO decisions (message_id, account, ts, stage, key, action, dest, confidence, detail, apply_state, trace_id, span_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            m.id,
            m.account,
            ts,
            d.stage,
            d.key,
            d.action,
            d.dest,
            d.confidence,
            d.detail.to_string(),
            apply_state,
            ids.as_ref().map(|i| &i.0),
            ids.as_ref().map(|i| &i.1),
        ],
    )?;
    Ok(c.last_insert_rowid())
}

#[derive(Debug, Default)]
pub struct Routed {
    pub eligible: usize,
    pub by_stage: std::collections::BTreeMap<&'static str, usize>,
}

pub async fn route_account(db: &Db, account: &str) -> Result<Routed> {
    let span = info_span!(
        "mail.route",
        account,
        eligible = tracing::field::Empty,
        decided = tracing::field::Empty
    );
    let account = account.to_owned();
    let parent = span.clone();
    let routed = db
        .write(move |c| {
            let _entered = parent.enter();
            let mode = db::mode(c)?;
            let pending = eligible(c, &account)?;
            let rules = rules::load(c, Some(&account))?;
            let destinations = rules::destinations(c, &account)?;
            let now = db::now();
            let model = classify::Model::train(c, &account, None)?;
            let tx = c.transaction()?;
            let mut routed = Routed {
                eligible: pending.len(),
                ..Routed::default()
            };
            for m in &pending {
                let span = info_span!(
                    "mail.decide",
                    message.id = m.id,
                    decision.id = tracing::field::Empty,
                    mail.from_domain = %m.from_domain,
                    mail.stage = tracing::field::Empty,
                    mail.action = tracing::field::Empty,
                    mail.dest = tracing::field::Empty,
                    mail.confidence = tracing::field::Empty,
                );
                let _e = span.enter();
                let mut d = decide(&tx, m, &rules, now, true, model.as_ref())?;
                if d.action == "file" && !d.dest.as_ref().is_some_and(|dest| destinations.contains(dest)) {
                    d.detail = json!({"reason": "Destination is unavailable", "proposed": d.dest, "evidence": d.detail});
                    d.stage = "none";
                    d.action = "none";
                    d.dest = None;
                }
                let state = (mode == Mode::Live && d.action != "none").then_some("pending");
                let unchanged: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM decisions WHERE message_id = ?1
                     AND id = (SELECT MAX(id) FROM decisions WHERE message_id = ?1)
                     AND stage = ?2 AND action = ?3 AND dest IS ?4 AND key IS ?5 AND detail = ?6 AND apply_state IS ?7)",
                    params![m.id, d.stage, d.action, d.dest, d.key, d.detail.to_string(), state], |r| r.get(0),
                )?;
                if unchanged {
                    continue;
                }
                let id = record(&tx, m, &d, now, state)?;
                let s = Span::current();
                s.record("decision.id", id);
                s.record("mail.stage", d.stage);
                s.record("mail.action", d.action);
                if let Some(dest) = &d.dest {
                    s.record("mail.dest", dest.as_str());
                }
                if let Some(conf) = d.confidence {
                    s.record("mail.confidence", conf);
                }
                info!(
                    message.id = m.id,
                    decision.id = id,
                    mail.from_domain = %m.from_domain,
                    mail.stage = d.stage,
                    mail.action = d.action,
                    mail.dest = d.dest.as_deref().unwrap_or(""),
                    "decided"
                );
                crate::metrics::decided(&account, d.stage, d.action, d.dest.as_deref());
                *routed.by_stage.entry(d.stage).or_default() += 1;
            }
            tx.commit()?;
            Ok(routed)
        })
        .await?;
    span.record("eligible", routed.eligible);
    span.record("decided", routed.by_stage.values().sum::<usize>());
    Ok(routed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Connection {
        let mut c = Connection::open_in_memory().unwrap();
        db::migrate(&mut c).unwrap();
        c.execute_batch("INSERT INTO accounts(name,preset) VALUES ('test','icloud');
            INSERT INTO mailboxes(id,account,name,imap_name,role) VALUES
            (1,'test','INBOX','INBOX','inbox'),(2,'test','News','News','filed'),(3,'test','Misc','Misc','misc');
            INSERT INTO messages(id,account,mailbox_id,uidvalidity,uid,digest,seen,in_inbox,location,from_addr,first_seen)
            VALUES (1,'test',1,1,1,'inbox',1,1,'INBOX','news@example.com',1);").unwrap();
        c
    }

    fn examples(c: &Connection, folder: &str, mailbox: i64) {
        for id in 2..=4 {
            c.execute("INSERT INTO messages(id,account,mailbox_id,uidvalidity,uid,digest,location,folder,from_addr,first_seen)
                VALUES (?1,'test',?2,1,?1,?3,?4,?4,'news@example.com',1)",
                params![id,mailbox,format!("example-{id}"),folder]).unwrap();
        }
    }

    #[test]
    fn unmatched_mail_is_reconsidered_after_new_examples() {
        let c = fixture();
        let m = eligible(&c, "test").unwrap().remove(0);
        let d = decide(&c, &m, &[], 1.0, false, None).unwrap();
        record(&c, &m, &d, 1.0, None).unwrap();
        examples(&c, "News", 2);
        let pending = eligible(&c, "test").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            decide(&c, &pending[0], &[], 2.0, false, None)
                .unwrap()
                .dest
                .as_deref(),
            Some("News")
        );
    }

    #[test]
    fn misc_is_not_training_data() {
        let c = fixture();
        examples(&c, "Misc", 3);
        let m = eligible(&c, "test").unwrap().remove(0);
        assert!(rules::learned_match(&c, &m).unwrap().is_none());
    }

    #[test]
    fn automatic_filing_does_not_confirm_itself() {
        let c = fixture();
        examples(&c, "News", 2);
        let m = c
            .query_row(
                &format!("SELECT {MESSAGE_COLUMNS} FROM messages m WHERE id = 2"),
                [],
                Message::from_row,
            )
            .unwrap();
        let d = Decision {
            stage: "learned",
            action: "file",
            dest: Some("News".into()),
            key: None,
            confidence: None,
            detail: json!({}),
        };
        record(&c, &m, &d, 2.0, Some("done")).unwrap();
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM training_messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        c.execute(
            "UPDATE messages SET folder = 'Personal', location = 'Personal' WHERE id = 2",
            [],
        )
        .unwrap();
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM training_messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn specific_pattern_wins_over_dominant_sender() {
        let c = fixture();
        c.execute_batch("WITH RECURSIVE ids(i) AS (SELECT 2 UNION ALL SELECT i+1 FROM ids WHERE i < 101)
            INSERT INTO messages(id,account,mailbox_id,uidvalidity,uid,digest,folder,from_addr,subject_tmpl,first_seen)
            SELECT i,'test',2,1,i,'example-' || i,CASE WHEN i < 97 THEN 'News' ELSE 'Purchases' END,
            'news@example.com',CASE WHEN i < 97 THEN 'newsletter' ELSE 'receipt' END,1 FROM ids;
            UPDATE messages SET subject_tmpl = 'receipt' WHERE id = 1;").unwrap();
        let m = eligible(&c, "test").unwrap().remove(0);
        assert_eq!(
            rules::learned_match(&c, &m).unwrap().unwrap().dest,
            "Purchases"
        );
    }
}
