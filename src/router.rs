//! Routing: operator rules, then learned sender patterns, then the BM25
//! neighbour vote. Anything else stays in the inbox for the owner to move.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tracing::{Span, info, info_span};

use crate::db::{self, Db, Mode};
use crate::rules::{self, MESSAGE_COLUMNS, Message, Rule};
use crate::similar;

pub const SIMILAR_K: usize = 7;
pub const SIMILAR_MIN_HITS: usize = 3;
pub const SIMILAR_MIN_SHARE: f64 = 0.9;

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
) -> Result<Decision> {
    if let Some(rule) = rules::first_match(m, rules, now) {
        return Ok(Decision {
            stage: "operator",
            action: rule.action.as_str(),
            dest: rule.dest.clone(),
            key: Some(rule.id.clone()),
            confidence: None,
            detail: json!({}),
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
    if use_similar {
        let near = similar::neighbours(c, m, SIMILAR_K)?;
        if let Some((folder, share)) = similar::vote(&near) {
            detail = json!({"neighbours": near, "share": share, "vote": folder});
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
    Ok(Decision {
        stage: "none",
        action: "none",
        dest: None,
        key: None,
        confidence: None,
        detail,
    })
}

/// Read, unflagged, received inbox mail with no decision yet.
pub fn eligible(c: &Connection, account: &str) -> Result<Vec<Message>> {
    let sql = format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages m WHERE m.account = ?1 AND m.in_inbox = 1 AND m.seen = 1 \
         AND m.flagged = 0 AND m.sent = 0 AND m.gone_at IS NULL \
         AND NOT EXISTS (SELECT 1 FROM decisions d WHERE d.message_id = m.id) ORDER BY m.id"
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
            let now = db::now();
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
                let d = decide(&tx, m, &rules, now, true)?;
                let state = (mode == Mode::Live && d.action != "none").then_some("pending");
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
