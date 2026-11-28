//! Guarded mailbox operations and daily retention processing.

use std::collections::{BTreeMap, HashSet};

use anyhow::{Result, anyhow};
use rusqlite::{Connection, params};
use tracing::{Instrument, info, info_span, warn};

use crate::classify;
use crate::config::{Account, Preset};
use crate::db::{self, Db, Mode};
use crate::features;
use crate::imap::{Imap, MailboxInfo};
use crate::router::{self, Decision};
use crate::rules::{self, MESSAGE_COLUMNS, Message};
use crate::sync::is_system_name;

const MOVE_BATCH: usize = 100;
const MAX_FAILURES: i64 = 3;
const DELETION_INTERVAL: f64 = 86400.0;
pub const RETENTION: &str = "retention";
/// The owner's own choice from the web UI: applied in any mode, without
/// re-deciding, and counted as training data once done.
pub const MANUAL: &str = "manual";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Gone,
    UidValidity,
    Missing,
    MsgId,
    LeftInbox,
    Flagged,
    Unseen,
    UnsafeLabel,
    Destination,
    RuleChanged,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Gone => "gone",
            Reason::UidValidity => "uidvalidity",
            Reason::Missing => "missing",
            Reason::MsgId => "msgid",
            Reason::LeftInbox => "left_inbox",
            Reason::Flagged => "flagged",
            Reason::Unseen => "unseen",
            Reason::UnsafeLabel => "unsafe_label",
            Reason::Destination => "destination",
            Reason::RuleChanged => "rule_changed",
        }
    }
}

/// What the database says about the message when the decision was made.
#[derive(Debug, Clone)]
pub struct Stored {
    pub gone: bool,
    pub uidvalidity: i64,
    pub msgid: String,
    /// Filing needs the message still in the inbox; retention does not.
    pub require_inbox: bool,
    pub require_seen: bool,
}

/// What the server says now.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub uidvalidity: u32,
    pub present: bool,
    pub msgid: Option<String>,
    pub flags: Vec<String>,
    pub labels: Vec<String>,
    /// iCloud: the message is in the INBOX mailbox.
    pub in_inbox_mailbox: bool,
}

/// Whether the server's copy is still the message that was decided on, in the
/// state the decision assumed. Moving the wrong message is the data-loss risk.
pub fn guard(preset: Preset, stored: &Stored, observed: &Observed) -> Result<(), Reason> {
    if stored.gone {
        return Err(Reason::Gone);
    }
    if i64::from(observed.uidvalidity) != stored.uidvalidity {
        return Err(Reason::UidValidity);
    }
    if !observed.present {
        return Err(Reason::Missing);
    }
    if !stored.msgid.is_empty() && observed.msgid.as_deref() != Some(stored.msgid.as_str()) {
        return Err(Reason::MsgId);
    }
    let has = |list: &[String], x: &str| list.iter().any(|f| f == x);
    if stored.require_inbox {
        let in_inbox = match preset {
            Preset::Gmail => has(&observed.labels, "\\Inbox"),
            Preset::Icloud => observed.in_inbox_mailbox,
        };
        if !in_inbox {
            return Err(Reason::LeftInbox);
        }
    }
    if has(&observed.flags, "\\Flagged") {
        return Err(Reason::Flagged);
    }
    if stored.require_seen && !has(&observed.flags, "\\Seen") {
        return Err(Reason::Unseen);
    }
    Ok(())
}

/// A Gmail label the applier may add.
pub fn safe_label(name: &str) -> bool {
    rules::filing_destination(name)
}

#[derive(Debug, Clone)]
struct Pending {
    decision_id: i64,
    message_id: i64,
    stage: String,
    action: String,
    dest: Option<String>,
    trace_id: Option<String>,
    span_id: Option<String>,
    uid: u32,
    stored: Stored,
    imap_name: String,
    role: String,
    from_domain: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Outcome {
    pub applied: usize,
    pub skipped: usize,
    pub failed: usize,
}

fn load_pending(
    c: &Connection,
    account: &str,
    cap: usize,
    manual_only: bool,
) -> Result<Vec<Pending>> {
    let age_rules: HashSet<String> = rules::load(c, Some(account))?
        .into_iter()
        .filter(|r| r.has_age())
        .map(|r| r.id)
        .collect();
    let mut stmt = c.prepare(
        "SELECT d.id, d.message_id, d.stage, d.action, d.dest, d.trace_id, d.span_id, d.key, \
         m.uid, m.uidvalidity, m.msgid, m.gone_at IS NOT NULL, mb.imap_name, mb.role, m.from_domain \
         FROM decisions d JOIN messages m ON m.id = d.message_id JOIN mailboxes mb ON mb.id = m.mailbox_id \
         WHERE d.account = ?1 AND d.apply_state = 'pending' AND (NOT ?3 OR d.stage = ?4) ORDER BY d.id LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![account, cap as i64, manual_only, MANUAL], |r| {
        let stage: String = r.get(2)?;
        let key: Option<String> = r.get(7)?;
        let retention = stage == RETENTION;
        let manual = stage == MANUAL;
        Ok(Pending {
            decision_id: r.get(0)?,
            message_id: r.get(1)?,
            action: r.get(3)?,
            dest: r.get(4)?,
            trace_id: r.get(5)?,
            span_id: r.get(6)?,
            uid: r.get(8)?,
            stored: Stored {
                uidvalidity: r.get(9)?,
                msgid: r.get(10)?,
                gone: r.get(11)?,
                require_inbox: !retention,
                require_seen: !manual
                    && (!retention || !key.is_some_and(|k| age_rules.contains(&k))),
            },
            imap_name: r.get(12)?,
            role: r.get(13)?,
            from_domain: r.get(14)?,
            stage,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn server_msgid(header: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(header);
    let mut value: Option<String> = None;
    for line in text.split("\r\n").flat_map(|l| l.split('\n')) {
        if let Some(v) = value.as_mut() {
            if line.starts_with([' ', '\t']) {
                v.push_str(line);
                continue;
            }
            break;
        }
        if line.len() >= 11
            && line.is_char_boundary(11)
            && line[..11].eq_ignore_ascii_case("message-id:")
        {
            value = Some(line[11..].to_owned());
        }
    }
    value.map(|v| features::normalize_msgid(&v))
}

/// The result of one decision, recorded in the database and metrics.
enum Result1 {
    Done,
    Skipped(Reason),
    Failed(String),
}

fn is_server_refusal(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        matches!(
            c.downcast_ref::<async_imap::error::Error>(),
            Some(async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_))
        )
    })
}

pub async fn apply_account(
    db: &Db,
    imap: &mut Imap,
    account: &Account,
    cap: usize,
    use_ai: bool,
) -> Result<Outcome> {
    let span = info_span!(
        "mail.apply",
        account = %account.name,
        applied = tracing::field::Empty,
        skipped = tracing::field::Empty,
        failed = tracing::field::Empty,
    );
    let _mutation = db.mutations.lock().await;
    let out = apply_inner(db, imap, account, cap, use_ai)
        .instrument(span.clone())
        .await?;
    span.record("applied", out.applied);
    span.record("skipped", out.skipped);
    span.record("failed", out.failed);
    Ok(out)
}

async fn apply_inner(
    db: &Db,
    imap: &mut Imap,
    account: &Account,
    cap: usize,
    use_ai: bool,
) -> Result<Outcome> {
    let name = account.name.clone();
    let pending = db
        .read(move |c| {
            let manual_only = db::mode(c)? != Mode::Live;
            load_pending(c, &name, cap, manual_only)
        })
        .await?;
    let mut out = Outcome::default();
    if pending.is_empty() {
        return Ok(out);
    }
    let model = if pending.iter().any(|p| p.stage != MANUAL) {
        db.read({
            let name = account.name.clone();
            move |c| Ok(classify::Model::train(c, &name, None)?.map(std::sync::Arc::new))
        })
        .await?
    } else {
        None
    };
    let listed = imap.list().await?;
    let mut groups: BTreeMap<(String, i64), Vec<Pending>> = BTreeMap::new();
    let mut early = Vec::new();
    for p in pending {
        // Settled without touching the server: a mailbox command on a
        // deleted folder would fail every pass and never drain the queue.
        if p.stored.gone {
            early.push((p, Result1::Skipped(Reason::Gone)));
        } else if !listed.iter().any(|m| m.imap_name == p.imap_name) {
            early.push((p, Result1::Skipped(Reason::Missing)));
        } else if p.action == "file"
            && !p.dest.as_deref().is_some_and(|dest| {
                rules::filing_destination(dest) && listed.iter().any(|m| m.name == dest)
            })
        {
            early.push((p, Result1::Skipped(Reason::Destination)));
        } else if p.stage == MANUAL {
            groups
                .entry((p.imap_name.clone(), p.stored.uidvalidity))
                .or_default()
                .push(p);
        } else {
            let candidate = p.clone();
            let name = account.name.clone();
            let model = model.clone();
            let current = db
                .read(move |c| {
                    let m = c.query_row(
                        &format!("SELECT {MESSAGE_COLUMNS} FROM messages m WHERE id = ?1"),
                        [candidate.message_id],
                        Message::from_row,
                    )?;
                    let rules = rules::load(c, Some(&name))?;
                    let rule = rules::first_match(&m, &rules, db::now());
                    let fresh = if candidate.stage == RETENTION {
                        rule.is_some_and(|r| {
                            r.action == rules::Action::Delete && (m.seen || r.has_age())
                        })
                    } else {
                        let d = router::decide(
                            c,
                            &m,
                            &rules,
                            db::now(),
                            true,
                            model.as_deref(),
                            use_ai,
                        )?;
                        d.action == candidate.action && d.dest == candidate.dest
                    };
                    let detail: String = c.query_row(
                        "SELECT detail FROM decisions WHERE id = ?1",
                        [candidate.decision_id],
                        |r| r.get(0),
                    )?;
                    let snapshot = serde_json::from_str::<serde_json::Value>(&detail)?
                        .get("rule")
                        .cloned();
                    Ok(fresh
                        && snapshot.is_none_or(|s| {
                            rule.is_some_and(|r| serde_json::to_value(r).ok().as_ref() == Some(&s))
                        }))
                })
                .await?;
            if !current {
                early.push((p, Result1::Skipped(Reason::RuleChanged)));
                continue;
            }
            groups
                .entry((p.imap_name.clone(), p.stored.uidvalidity))
                .or_default()
                .push(p);
        }
    }
    record(db, &account.name, early, &mut out).await?;
    for ((imap_name, _), items) in groups {
        let status = imap.status(&imap_name).await?;
        let validity = imap.select(&imap_name).await?.max(status.uidvalidity);
        let uids: Vec<u32> = items.iter().map(|p| p.uid).collect();
        let present: HashSet<u32> = imap
            .uid_search(&format!("UID {}", crate::imap::uid_set(&uids)))
            .await?
            .into_iter()
            .collect();
        let headers = imap.fetch_headers(&uids).await?;
        let mut ok = Vec::new();
        let mut results: Vec<(Pending, Result1)> = Vec::new();
        for p in items {
            let fetched = headers.iter().find(|f| f.uid == p.uid);
            let observed = Observed {
                uidvalidity: validity,
                present: present.contains(&p.uid) && fetched.is_some(),
                msgid: fetched.and_then(|f| server_msgid(&f.header)),
                flags: fetched.map(|f| f.flags.clone()).unwrap_or_default(),
                labels: fetched.and_then(|f| f.labels.clone()).unwrap_or_default(),
                in_inbox_mailbox: p.role == "inbox",
            };
            let mut verdict = guard(account.preset, &p.stored, &observed);
            if verdict.is_ok()
                && account.preset == Preset::Gmail
                && p.action == "file"
                && !p.dest.as_deref().is_some_and(safe_label)
            {
                verdict = Err(Reason::UnsafeLabel);
            }
            match verdict {
                Ok(()) => ok.push(p),
                Err(reason) => results.push((p, Result1::Skipped(reason))),
            }
        }
        let mut by_target: BTreeMap<(String, Option<String>), Vec<Pending>> = BTreeMap::new();
        for p in ok {
            by_target
                .entry((p.action.clone(), p.dest.clone()))
                .or_default()
                .push(p);
        }
        for ((action, dest), batch) in by_target {
            for chunk in batch.chunks(MOVE_BATCH) {
                let uids: Vec<u32> = chunk.iter().map(|p| p.uid).collect();
                let r = execute(imap, &listed, &action, dest.as_deref(), &uids).await;
                let result = |r: &Result<()>| match r {
                    Ok(()) => Ok(()),
                    Err(e) if is_server_refusal(e) => Err(format!("{e:#}")),
                    Err(_) => Err(String::new()),
                };
                match result(&r) {
                    Ok(()) => results.extend(chunk.iter().cloned().map(|p| (p, Result1::Done))),
                    Err(msg) if !msg.is_empty() => results.extend(
                        chunk
                            .iter()
                            .cloned()
                            .map(|p| (p, Result1::Failed(msg.clone()))),
                    ),
                    // Connection trouble: the outcome is unknown, so the batch
                    // stays pending and the guard re-checks it next pass.
                    Err(_) => {
                        record(db, &account.name, results, &mut out).await?;
                        return Err(r.unwrap_err());
                    }
                }
            }
        }
        record(db, &account.name, results, &mut out).await?;
    }
    Ok(out)
}

async fn execute(
    imap: &mut Imap,
    listed: &[MailboxInfo],
    action: &str,
    dest: Option<&str>,
    uids: &[u32],
) -> Result<()> {
    match (action, imap.preset) {
        ("delete", _) => {
            let trash = listed
                .iter()
                .find(|m| m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Trash")))
                .or_else(|| {
                    listed.iter().find(|m| {
                        is_system_name(&m.name) && m.name.to_lowercase().contains("trash")
                    })
                })
                .ok_or_else(|| anyhow!("no Trash mailbox"))?;
            imap.uid_move(uids, &trash.imap_name).await
        }
        ("file", Preset::Gmail) => {
            let dest = dest.ok_or_else(|| anyhow!("file decision without dest"))?;
            imap.store_labels(uids, true, &[dest]).await?;
            imap.store_labels(uids, false, &["\\Inbox"]).await
        }
        ("file", Preset::Icloud) => {
            let dest = dest.ok_or_else(|| anyhow!("file decision without dest"))?;
            let imap_name = listed
                .iter()
                .find(|m| m.name == dest)
                .ok_or_else(|| anyhow!("destination no longer exists: {dest}"))?
                .imap_name
                .clone();
            imap.uid_move(uids, &imap_name).await
        }
        (other, _) => Err(anyhow!("unknown action {other}")),
    }
}

async fn record(
    db: &Db,
    account: &str,
    results: Vec<(Pending, Result1)>,
    out: &mut Outcome,
) -> Result<()> {
    if results.is_empty() {
        return Ok(());
    }
    let now = db::now();
    let mut rows = Vec::new();
    for (p, r) in results {
        let span = info_span!(
            "mail.move",
            message.id = p.message_id,
            decision.id = p.decision_id,
            mail.from_domain = %p.from_domain,
            mail.stage = %p.stage,
            mail.dest = p.dest.as_deref().unwrap_or(""),
            mail.result = tracing::field::Empty,
        );
        let _e = span.enter();
        if let (Some(t), Some(s)) = (&p.trace_id, &p.span_id) {
            crate::telemetry::link_to(t, s);
        }
        let (state, error, label) = match &r {
            Result1::Done => {
                out.applied += 1;
                crate::metrics::applied(account, "done", "");
                ("done", None, "done".to_owned())
            }
            Result1::Skipped(reason) => {
                out.skipped += 1;
                crate::metrics::applied(account, "skipped", reason.as_str());
                (
                    "skipped",
                    Some(reason.as_str().to_owned()),
                    format!("skipped:{}", reason.as_str()),
                )
            }
            Result1::Failed(msg) => {
                out.failed += 1;
                crate::metrics::applied(account, "failed", "imap");
                ("failed", Some(msg.clone()), "failed".to_owned())
            }
        };
        span.record("mail.result", label.as_str());
        match &r {
            Result1::Failed(msg) => {
                warn!(message.id = p.message_id, decision.id = p.decision_id, mail.result = %label, error = %msg, "move failed")
            }
            _ => {
                info!(message.id = p.message_id, decision.id = p.decision_id, mail.dest = p.dest.as_deref().unwrap_or(""), mail.result = %label, "applied")
            }
        }
        rows.push((p.decision_id, state, error));
    }
    db.write(move |c| {
        let tx = c.transaction()?;
        for (id, state, error) in rows {
            tx.execute(
                "UPDATE decisions SET apply_state = ?1, applied_at = ?2, apply_error = ?3 WHERE id = ?4",
                params![state, (state == "done").then_some(now), error, id],
            )?;
        }
        tx.commit()?;
        Ok(())
    })
    .await
}

/// Queues delete-rule matches anywhere outside the system mailboxes, at most
/// once a day per account, so rules with `age_days` fire as mail ages.
pub async fn deletion_pass(db: &Db, account: &Account, force: bool) -> Result<usize> {
    let span = info_span!(
        "mail.deletion_pass",
        account = %account.name,
        candidates = tracing::field::Empty,
        queued = tracing::field::Empty,
    );
    let parent = span.clone();
    let name = account.name.clone();
    db.write(move |c| {
        let _e = parent.enter();
        if db::mode(c)? != Mode::Live {
            return Ok(0);
        }
        let key = format!("deletion:{name}");
        let now = db::now();
        let last = db::get_state(c, &key)?.and_then(|v| v.parse::<f64>().ok());
        if !force && last.is_some_and(|t| now - t < DELETION_INTERVAL) {
            return Ok(0);
        }
        let rules = rules::load(c, Some(&name))?;
        let tx = c.transaction()?;
        db::set_state(&tx, &key, &now.to_string())?;
        if !rules.iter().any(|r| r.action == rules::Action::Delete) {
            tx.commit()?;
            return Ok(0);
        }
        let sql = format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id \
             WHERE m.account = ?1 AND m.gone_at IS NULL AND m.sent = 0 AND m.flagged = 0 \
             AND mb.role NOT IN ('drafts', 'junk', 'sent', 'system', 'trash') \
             AND NOT EXISTS (SELECT 1 FROM deletion_exclusions x WHERE x.account = m.account AND x.digest = m.digest) \
             AND NOT EXISTS (SELECT 1 FROM decisions d JOIN messages o ON o.id = d.message_id \
                 WHERE o.account = m.account AND o.digest = m.digest AND d.stage = 'retention' \
                 AND d.apply_state IN ('done', 'pending')) \
             AND (SELECT COUNT(*) FROM decisions d JOIN messages o ON o.id = d.message_id \
                 WHERE o.account = m.account AND o.digest = m.digest AND d.stage = 'retention' \
                 AND d.apply_state = 'failed') < ?2 \
             ORDER BY m.id"
        );
        let candidates: Vec<Message> = tx
            .prepare(&sql)?
            .query_map(params![name, MAX_FAILURES], Message::from_row)?
            .collect::<rusqlite::Result<_>>()?;
        let mut queued = 0;
        for m in &candidates {
            let Some(rule) = rules::first_match(m, &rules, now) else {
                continue;
            };
            if rule.action != rules::Action::Delete || !(m.seen || rule.has_age()) {
                continue;
            }
            let d = Decision {
                stage: RETENTION,
                action: "delete",
                dest: None,
                key: Some(rule.id.clone()),
                confidence: None,
                detail: serde_json::json!({"rule": rule}),
            };
            router::record(&tx, m, &d, now, Some("pending"))?;
            queued += 1;
        }
        tx.commit()?;
        parent.record("candidates", candidates.len());
        parent.record("queued", queued);
        if queued > 0 {
            info!(account = %name, queued, "retention deletions queued");
        }
        Ok(queued)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> Stored {
        Stored {
            gone: false,
            uidvalidity: 7,
            msgid: "a@b".into(),
            require_inbox: true,
            require_seen: false,
        }
    }

    fn observed() -> Observed {
        Observed {
            uidvalidity: 7,
            present: true,
            msgid: Some("a@b".into()),
            flags: vec!["\\Seen".into()],
            labels: vec!["\\Inbox".into()],
            in_inbox_mailbox: true,
        }
    }

    #[test]
    fn guard_reasons() {
        let p = Preset::Icloud;
        assert_eq!(guard(p, &stored(), &observed()), Ok(()));
        assert_eq!(
            guard(
                p,
                &Stored {
                    gone: true,
                    ..stored()
                },
                &observed()
            ),
            Err(Reason::Gone)
        );
        assert_eq!(
            guard(
                p,
                &stored(),
                &Observed {
                    uidvalidity: 8,
                    ..observed()
                }
            ),
            Err(Reason::UidValidity)
        );
        assert_eq!(
            guard(
                p,
                &stored(),
                &Observed {
                    present: false,
                    ..observed()
                }
            ),
            Err(Reason::Missing)
        );
        assert_eq!(
            guard(
                p,
                &stored(),
                &Observed {
                    msgid: Some("x@y".into()),
                    ..observed()
                }
            ),
            Err(Reason::MsgId)
        );
        assert_eq!(
            guard(
                p,
                &stored(),
                &Observed {
                    msgid: None,
                    ..observed()
                }
            ),
            Err(Reason::MsgId)
        );
        assert_eq!(
            guard(
                p,
                &stored(),
                &Observed {
                    in_inbox_mailbox: false,
                    ..observed()
                }
            ),
            Err(Reason::LeftInbox)
        );
        assert_eq!(
            guard(
                Preset::Gmail,
                &stored(),
                &Observed {
                    labels: vec![],
                    ..observed()
                }
            ),
            Err(Reason::LeftInbox)
        );
        assert_eq!(
            guard(
                p,
                &stored(),
                &Observed {
                    flags: vec!["\\Seen".into(), "\\Flagged".into()],
                    ..observed()
                }
            ),
            Err(Reason::Flagged)
        );
        let retention = Stored {
            require_inbox: false,
            require_seen: true,
            ..stored()
        };
        assert_eq!(
            guard(
                p,
                &retention,
                &Observed {
                    in_inbox_mailbox: false,
                    ..observed()
                }
            ),
            Ok(())
        );
        assert_eq!(
            guard(
                p,
                &retention,
                &Observed {
                    flags: vec![],
                    ..observed()
                }
            ),
            Err(Reason::Unseen)
        );
        assert_eq!(
            guard(
                p,
                &Stored {
                    msgid: String::new(),
                    ..stored()
                },
                &Observed {
                    msgid: None,
                    ..observed()
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn labels_and_msgids() {
        assert!(safe_label("Dev/GitHub"));
        assert!(!safe_label("\\Inbox"));
        assert!(!safe_label("[Gmail]/Spam"));
        assert!(!safe_label("Trash"));
        assert_eq!(
            server_msgid(b"Subject: x\r\nMessage-ID:\r\n <a.b@c>\r\n\r\n").as_deref(),
            Some("a.b@c")
        );
        assert_eq!(server_msgid(b"Subject: x\r\n\r\n"), None);
    }

    #[test]
    fn queued_filing_requires_read_status() {
        let mut c = Connection::open_in_memory().unwrap();
        db::migrate(&mut c).unwrap();
        c.execute_batch("INSERT INTO accounts(name,preset) VALUES ('test','icloud');
            INSERT INTO mailboxes(id,account,name,imap_name,role) VALUES (1,'test','INBOX','INBOX','inbox');
            INSERT INTO messages(id,account,mailbox_id,uidvalidity,uid,digest,seen,in_inbox,first_seen)
            VALUES (1,'test',1,1,1,'message',1,1,1);
            INSERT INTO decisions(message_id,account,ts,stage,action,dest,apply_state)
            VALUES (1,'test',1,'learned','file','News','pending');").unwrap();
        let pending = load_pending(&c, "test", 1, false).unwrap().remove(0);
        assert_eq!(
            guard(
                Preset::Icloud,
                &pending.stored,
                &Observed {
                    uidvalidity: 1,
                    flags: vec![],
                    ..observed()
                }
            ),
            Err(Reason::Unseen)
        );
    }
}
