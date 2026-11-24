//! Mailbox roles, message state, and synchronization.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use tracing::{Instrument, info, info_span};

use crate::config::{Account, Preset};
use crate::db::{self, Db};
use crate::features::{self, Features};
use crate::imap::{Fetched, Imap};
use crate::rules::{self, Message};
use crate::similar;
use crate::utf7;

const FETCH_BATCH: usize = 40;
const FLAG_BATCH: usize = 500;
const SENT_BACKFILL_DAYS: f64 = 90.0;
const GMAIL_CATEGORIES: [&str; 4] = ["social", "promotions", "updates", "forums"];

pub const INBOX: &str = "INBOX";
pub const GMAIL_ALL_MAIL: &str = "[Gmail]/All Mail";

const SYSTEM_FLAGS: &[(&str, &str)] = &[
    ("\\trash", "trash"),
    ("\\sent", "sent"),
    ("\\drafts", "drafts"),
    ("\\junk", "junk"),
];

const SYSTEM_NAMES: &[(&str, &str)] = &[
    ("trash", "trash"),
    ("deleted messages", "trash"),
    ("deleted items", "trash"),
    ("bin", "trash"),
    ("sent", "sent"),
    ("sent messages", "sent"),
    ("sent items", "sent"),
    ("drafts", "drafts"),
    ("junk", "junk"),
    ("spam", "junk"),
];

pub fn is_system_name(name: &str) -> bool {
    let folded = name.to_lowercase();
    SYSTEM_NAMES.iter().any(|(n, _)| *n == folded)
}

pub fn mailbox_role(name: &str, flags: &[String], preset: Preset) -> &'static str {
    if preset == Preset::Gmail {
        return if name == GMAIL_ALL_MAIL {
            "allmail"
        } else {
            "system"
        };
    }
    for flag in flags {
        let flag = flag.to_lowercase();
        if let Some((_, role)) = SYSTEM_FLAGS.iter().find(|(f, _)| *f == flag) {
            return role;
        }
    }
    let folded = name.to_lowercase();
    if folded == "inbox" {
        return "inbox";
    }
    if folded == "misc" {
        return "misc";
    }
    SYSTEM_NAMES
        .iter()
        .find(|(n, _)| *n == folded)
        .map_or("filed", |(_, role)| role)
}

/// Mailboxes the sync indexes: everything but Gmail's label views and the
/// system boxes other than Sent.
pub fn indexed_role(role: &str) -> bool {
    !matches!(role, "trash" | "drafts" | "junk" | "system")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub seen: bool,
    pub flagged: bool,
    pub in_inbox: bool,
    pub sent: bool,
    pub location: String,
    pub folder: Option<String>,
    pub flags: String,
    pub labels: String,
}

pub fn message_state(
    preset: Preset,
    role: &str,
    mailbox_name: &str,
    flags: &[String],
    labels: &[String],
) -> State {
    let has = |list: &[String], x: &str| list.iter().any(|f| f == x);
    let mut sorted = flags.to_vec();
    sorted.sort();
    let (in_inbox, sent, location, folder, labels) = if preset == Preset::Gmail {
        let leaves = utf7::collapse_labels(labels);
        let in_inbox = has(labels, "\\Inbox");
        let sent = has(labels, "\\Sent") || has(labels, "\\Draft") || has(flags, "\\Draft");
        let mut location = leaves.join("|");
        if location.is_empty() {
            location = if in_inbox { INBOX } else { "(none)" }.to_owned();
        }
        let folder = (leaves.len() == 1).then(|| leaves[0].clone());
        (in_inbox, sent, location, folder, labels.to_vec())
    } else {
        let folder = (role == "filed").then(|| mailbox_name.to_owned());
        (
            role == "inbox",
            role == "sent",
            mailbox_name.to_owned(),
            folder,
            Vec::new(),
        )
    };
    State {
        seen: has(flags, "\\Seen"),
        flagged: has(flags, "\\Flagged"),
        in_inbox,
        sent,
        location,
        folder,
        flags: serde_json::to_string(&sorted).unwrap_or_default(),
        labels: serde_json::to_string(&labels).unwrap_or_default(),
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    pub new: u64,
    pub gone: Vec<i64>,
    pub flag_changes: u64,
    pub mailboxes: u64,
}

#[derive(Debug, Clone)]
struct Mailbox {
    id: i64,
    name: String,
    imap_name: String,
    role: String,
    checkpoint: Option<Checkpoint>,
}

#[derive(Debug, Clone, Copy)]
struct Checkpoint {
    validity: i64,
    highest_uid: i64,
    modseq: Option<u64>,
}

struct Stored {
    id: i64,
    uid: u32,
    gone: bool,
    flags: String,
    labels: String,
    location: String,
    in_inbox: bool,
}

/// One sync of an account: mailboxes, new mail, flag and label changes,
/// vanished mail and the move/delete events that explain it.
pub async fn sync_account(db: &Db, imap: &mut Imap, account: &Account) -> Result<Stats> {
    let span = info_span!(
        "mail.sync",
        account = %account.name,
        new = tracing::field::Empty,
        gone = tracing::field::Empty,
        flag_changes = tracing::field::Empty,
        mailboxes = tracing::field::Empty,
    );
    let stats = sync_inner(db, imap, account)
        .instrument(span.clone())
        .await?;
    span.record("new", stats.new);
    span.record("gone", stats.gone.len());
    span.record("flag_changes", stats.flag_changes);
    span.record("mailboxes", stats.mailboxes);
    crate::metrics::synced(&account.name, "new", stats.new);
    crate::metrics::synced(&account.name, "gone", stats.gone.len() as u64);
    crate::metrics::synced(&account.name, "flags", stats.flag_changes);
    Ok(stats)
}

async fn sync_inner(db: &Db, imap: &mut Imap, account: &Account) -> Result<Stats> {
    let mut stats = Stats::default();
    let run = db::now();
    let (name, preset) = (account.name.clone(), account.preset);
    db.write(move |c| {
        c.execute(
            "INSERT OR IGNORE INTO accounts (name, preset) VALUES (?1, ?2)",
            params![name, preset.as_str()],
        )?;
        Ok(())
    })
    .await?;
    let listed = imap.list().await?;
    let names: HashSet<String> = listed.iter().map(|m| m.name.clone()).collect();
    let (folder_key, folder_names) = (
        format!("folders:{}", account.name),
        serde_json::to_string(
            &listed
                .iter()
                .filter(|m| rules::filing_destination(&m.name))
                .map(|m| &m.name)
                .collect::<Vec<_>>(),
        )?,
    );
    db.write(move |c| db::set_state(c, &folder_key, &folder_names))
        .await?;
    let name = account.name.clone();
    stats.gone.extend(
        db.write(move |c| retire_mailboxes(c, &name, &names, run))
            .await?,
    );
    let picked: Vec<(String, String, &'static str)> = listed
        .iter()
        .filter(|m| !m.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Noselect")))
        .map(|m| {
            (
                m.name.clone(),
                m.imap_name.clone(),
                mailbox_role(&m.name, &m.flags, preset),
            )
        })
        .filter(|(_, _, role)| indexed_role(role))
        .collect();
    let name = account.name.clone();
    let mailboxes = db
        .write(move |c| upsert_mailboxes(c, &name, &picked))
        .await?;
    for mbx in mailboxes {
        sync_mailbox(db, imap, account, &mbx, run, &mut stats)
            .instrument(info_span!("mail.sync.mailbox", mailbox = %mbx.name, fetched = tracing::field::Empty))
            .await?;
        stats.mailboxes += 1;
    }
    let (name, gone) = (account.name.clone(), stats.gone.clone());
    let inbox = db
        .write(move |c| {
            reconcile(c, &name, &gone, run)?;
            c.execute("UPDATE accounts SET last_sync_at = ?1 WHERE name = ?2", params![run, name])?;
            Ok(c.query_row(
                "SELECT COUNT(*) FROM messages WHERE account = ?1 AND in_inbox = 1 AND gone_at IS NULL AND sent = 0",
                [&name],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await?;
    crate::metrics::inbox(&account.name, inbox);
    Ok(stats)
}

fn retire_mailboxes(
    c: &mut Connection,
    account: &str,
    listed: &HashSet<String>,
    run: f64,
) -> Result<Vec<i64>> {
    let existing: Vec<(i64, String)> = c
        .prepare("SELECT id, name FROM mailboxes WHERE account = ?1")?
        .query_map([account], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut gone = Vec::new();
    let tx = c.transaction()?;
    for (id, name) in existing.into_iter().filter(|(_, n)| !listed.contains(n)) {
        gone.extend(mark_gone_in_mailbox(&tx, id, run)?);
        let remaining: i64 = tx.query_row(
            "SELECT COUNT(*) FROM messages WHERE mailbox_id = ?1",
            [id],
            |r| r.get(0),
        )?;
        if remaining == 0 {
            tx.execute("DELETE FROM mailboxes WHERE id = ?1", [id])?;
        }
        info!(account, mailbox = %name, "mailbox no longer listed");
    }
    tx.commit()?;
    Ok(gone)
}

fn mark_gone_in_mailbox(c: &Connection, mailbox_id: i64, run: f64) -> Result<Vec<i64>> {
    let ids: Vec<i64> = c
        .prepare("SELECT id FROM messages WHERE mailbox_id = ?1 AND gone_at IS NULL")?
        .query_map([mailbox_id], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    c.execute(
        "UPDATE messages SET gone_at = ?1 WHERE mailbox_id = ?2 AND gone_at IS NULL",
        params![run, mailbox_id],
    )?;
    Ok(ids)
}

fn upsert_mailboxes(
    c: &mut Connection,
    account: &str,
    picked: &[(String, String, &'static str)],
) -> Result<Vec<Mailbox>> {
    let tx = c.transaction()?;
    let mut out = Vec::new();
    for (name, imap_name, role) in picked {
        tx.execute(
            "INSERT INTO mailboxes (account, name, imap_name, role) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (account, name) DO UPDATE SET imap_name = excluded.imap_name, role = excluded.role",
            params![account, name, imap_name, role],
        )?;
        let mbx = tx.query_row(
            "SELECT id, name, imap_name, role, uidvalidity, highest_uid, highestmodseq FROM mailboxes WHERE account = ?1 AND name = ?2",
            params![account, name],
            |r| {
                let validity: Option<i64> = r.get(4)?;
                let modseq: Option<i64> = r.get(6)?;
                let highest_uid: i64 = r.get(5)?;
                Ok(Mailbox {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    imap_name: r.get(2)?,
                    role: r.get(3)?,
                    checkpoint: validity.map(|validity| Checkpoint {
                        validity,
                        highest_uid,
                        modseq: modseq.map(|m| m as u64),
                    }),
                })
            },
        )?;
        out.push(mbx);
    }
    tx.commit()?;
    out.sort_by(|a, b| (a.role != "inbox", &a.name).cmp(&(b.role != "inbox", &b.name)));
    Ok(out)
}

fn imap_date(ts: f64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let days = (ts / 86400.0).floor() as i64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{d}-{}-{y}", MONTHS[(m - 1) as usize])
}

async fn sync_mailbox(
    db: &Db,
    imap: &mut Imap,
    account: &Account,
    mbx: &Mailbox,
    run: f64,
    stats: &mut Stats,
) -> Result<()> {
    let preset = account.preset;
    let status = imap.status(&mbx.imap_name).await?;
    let validity = i64::from(status.uidvalidity);
    let mut prev = mbx.checkpoint;
    if let Some(p) = prev
        && p.validity != validity
    {
        let id = mbx.id;
        stats.gone.extend(
            db.write(move |c| {
                let tx = c.transaction()?;
                let gone = mark_gone_in_mailbox(&tx, id, run)?;
                tx.execute(
                    "UPDATE mailboxes SET uidvalidity = NULL, highest_uid = 0, highestmodseq = NULL WHERE id = ?1",
                    [id],
                )?;
                tx.commit()?;
                Ok(gone)
            })
            .await?,
        );
        info!(account = %account.name, mailbox = %mbx.name, "UIDVALIDITY changed; mailbox re-indexed");
        prev = None;
    }
    imap.select(&mbx.imap_name).await?;
    let server_uids = if mbx.role == "sent" {
        let id = mbx.id;
        let since = db
            .read(move |c| {
                let oldest: Option<f64> = c.query_row(
                    "SELECT MIN(date_ts) FROM messages WHERE mailbox_id = ?1 AND uidvalidity = ?2 AND gone_at IS NULL AND date_ts > 0",
                    params![id, validity],
                    |r| r.get(0),
                )?;
                let cutoff = run - SENT_BACKFILL_DAYS * 86400.0;
                Ok(oldest.map_or(cutoff, |o| cutoff.min(o - 2.0 * 86400.0)))
            })
            .await?;
        imap.uid_search(&format!("SINCE {}", imap_date(since)))
            .await?
    } else {
        imap.uid_search("ALL").await?
    };
    let id = mbx.id;
    let rows: Vec<Stored> = db
        .read(move |c| {
            Ok(c.prepare(
                "SELECT id, uid, gone_at IS NOT NULL, flags, labels, location, in_inbox FROM messages WHERE mailbox_id = ?1 AND uidvalidity = ?2",
            )?
            .query_map(params![id, validity], |r| {
                Ok(Stored {
                    id: r.get(0)?,
                    uid: r.get(1)?,
                    gone: r.get(2)?,
                    flags: r.get(3)?,
                    labels: r.get(4)?,
                    location: r.get(5)?,
                    in_inbox: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
        })
        .await?;
    let present: HashSet<u32> = server_uids.iter().copied().collect();
    let known: HashSet<u32> = rows.iter().map(|r| r.uid).collect();
    let (live, _): (Vec<Stored>, Vec<Stored>) = rows.into_iter().partition(|r| !r.gone);
    let mut survivors: HashMap<u32, Stored> = HashMap::new();
    let mut vanished = Vec::new();
    for r in live {
        if present.contains(&r.uid) {
            survivors.insert(r.uid, r);
        } else if mbx.role != "sent" {
            vanished.push(r.id);
        }
    }
    if !vanished.is_empty() {
        let ids = vanished.clone();
        db.write(move |c| {
            let tx = c.transaction()?;
            for id in &ids {
                tx.execute(
                    "UPDATE messages SET gone_at = ?1 WHERE id = ?2",
                    params![run, id],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
        stats.gone.extend(vanished);
    }
    let current_modseq = status.highestmodseq;
    stats.flag_changes +=
        refresh_flags(db, imap, account, mbx, survivors, prev, current_modseq, run).await?;
    let mut fresh: Vec<u32> = present.difference(&known).copied().collect();
    fresh.sort_unstable();
    let mut fetched_total = 0;
    for batch in fresh.chunks(FETCH_BATCH) {
        let fetched = imap.fetch_full(batch).await?;
        let (name, mbx2, n) = (account.name.clone(), mbx.clone(), fetched.len());
        db.write(move |c| {
            let tx = c.transaction()?;
            for item in &fetched {
                ingest(&tx, &name, preset, &mbx2, validity, run, item)?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
        stats.new += n as u64;
        fetched_total += n;
        info!(account = %account.name, mailbox = %mbx.name, "fetched {fetched_total}/{}", fresh.len());
    }
    tracing::Span::current().record("fetched", fetched_total);
    if preset == Preset::Gmail {
        refresh_categories(db, imap, mbx.id).await?;
    }
    let top = server_uids.iter().copied().max().map_or(0, i64::from);
    let top = match prev {
        Some(p) if p.validity == validity => top.max(p.highest_uid),
        _ => top,
    };
    let id = mbx.id;
    db.write(move |c| {
        c.execute(
            "UPDATE mailboxes SET uidvalidity = ?1, highest_uid = ?2, highestmodseq = ?3, synced_at = ?4 WHERE id = ?5",
            params![validity, top, current_modseq.map(|m| m as i64), run, id],
        )?;
        Ok(())
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn refresh_flags(
    db: &Db,
    imap: &mut Imap,
    account: &Account,
    mbx: &Mailbox,
    survivors: HashMap<u32, Stored>,
    prev: Option<Checkpoint>,
    current_modseq: Option<u64>,
    run: f64,
) -> Result<u64> {
    if survivors.is_empty() {
        return Ok(0);
    }
    let prev_modseq = prev.and_then(|p| p.modseq);
    let updates = match (imap.has("CONDSTORE"), current_modseq, prev_modseq) {
        (true, Some(cur), Some(old)) if cur != 0 && old != 0 => {
            if cur == old {
                return Ok(0);
            }
            imap.fetch_flags_changed_since(old).await?
        }
        _ => {
            let mut uids: Vec<u32> = survivors.keys().copied().collect();
            uids.sort_unstable();
            let mut all = Vec::new();
            for chunk in uids.chunks(FLAG_BATCH) {
                all.extend(imap.fetch_flags(chunk).await?);
            }
            all
        }
    };
    let (preset, role, name, acc) = (
        account.preset,
        mbx.role.clone(),
        mbx.name.clone(),
        account.name.clone(),
    );
    db.write(move |c| {
        let tx = c.transaction()?;
        let mut changes = 0;
        for item in updates {
            let Some(row) = survivors.get(&item.uid) else {
                continue;
            };
            let labels = item.labels.unwrap_or_else(|| db::json_list(&row.labels));
            let state = message_state(preset, &role, &name, &item.flags, &labels);
            if state.flags == row.flags && state.labels == row.labels {
                continue;
            }
            tx.execute(
                "UPDATE messages SET seen = ?1, flagged = ?2, in_inbox = ?3, sent = ?4, location = ?5, folder = ?6, flags = ?7, labels = ?8 WHERE id = ?9",
                params![state.seen, state.flagged, state.in_inbox, state.sent, state.location, state.folder, state.flags, state.labels, row.id],
            )?;
            let detail = json!({
                "flags": [db::json_list(&row.flags), db::json_list(&state.flags)],
                "location": [row.location, state.location],
                "in_inbox": [row.in_inbox as i64, state.in_inbox as i64],
            });
            let kind = if state.labels != row.labels { "labels" } else { "flags" };
            tx.execute(
                "INSERT INTO events (ts, account, kind, message_id, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![run, acc, kind, row.id, detail.to_string()],
            )?;
            changes += 1;
        }
        tx.commit()?;
        Ok(changes)
    })
    .await
}

fn json_text(list: &[String]) -> String {
    serde_json::to_string(list).unwrap_or_else(|_| "[]".into())
}

/// The routing view of a freshly extracted message, before it has an id.
pub fn message_from_features(
    account: &str,
    f: &Features,
    state: &State,
    category: &str,
) -> Message {
    Message {
        account: account.to_owned(),
        msgid: f.msgid.clone(),
        from_addr: f.from_addr.clone(),
        from_domain: f.from_domain.clone(),
        from_name: f.from_name.clone(),
        reply_to: f.reply_to.clone(),
        rpath_domain: f.rpath_domain.clone(),
        list_id: f.list_id.clone(),
        subject: f.subject.clone(),
        subject_tmpl: f.subject_tmpl.clone(),
        msgid_domain: f.msgid_domain.clone(),
        precedence: f.precedence.clone(),
        category: category.to_owned(),
        to_addrs: json_text(&f.to_addrs),
        dkim_d: json_text(&f.dkim_d),
        esp: json_text(&f.esp),
        att_types: json_text(&f.att_types),
        att_names: json_text(&f.att_names),
        date_ts: f.date_ts,
        folder: state.folder.clone(),
        seen: state.seen,
        ..Message::default()
    }
}

fn ingest(
    c: &Connection,
    account: &str,
    preset: Preset,
    mbx: &Mailbox,
    validity: i64,
    run: f64,
    item: &Fetched,
) -> Result<()> {
    let f = features::extract(&item.header, &item.text, item.internal_ts.unwrap_or(run));
    let digest = features::content_digest(&item.header, &item.text);
    let labels = item.labels.clone().unwrap_or_default();
    let state = message_state(preset, &mbx.role, &mbx.name, &item.flags, &labels);
    let m = message_from_features(account, &f, &state, "");
    c.execute(
        "INSERT INTO messages (account, mailbox_id, uidvalidity, uid, msgid, digest, gm_msgid, date_ts, flags, seen, flagged, \
         labels, in_inbox, sent, location, folder, from_addr, from_domain, from_name, to_addrs, reply_to, rpath_domain, \
         list_id, precedence, subject, subject_tmpl, msgid_domain, dkim_d, esp, att_types, att_names, first_seen) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, \
         ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32)",
        params![
            account, mbx.id, validity, item.uid, m.msgid, digest, item.gm_msgid.map(|g| g.to_string()), m.date_ts,
            state.flags, state.seen, state.flagged, state.labels, state.in_inbox, state.sent, state.location, state.folder,
            m.from_addr, m.from_domain, m.from_name, m.to_addrs, m.reply_to, m.rpath_domain, m.list_id, m.precedence,
            m.subject, m.subject_tmpl, m.msgid_domain, m.dkim_d, m.esp, m.att_types, m.att_names, run,
        ],
    )?;
    let id = c.last_insert_rowid();
    c.execute(
        "INSERT INTO message_fts (rowid, meta, subject, body) VALUES (?1, ?2, ?3, ?4)",
        params![id, similar::meta_tokens(&m), m.subject, f.body],
    )?;
    Ok(())
}

async fn refresh_categories(db: &Db, imap: &mut Imap, mailbox_id: i64) -> Result<()> {
    let mut assigned: HashMap<u32, &'static str> = HashMap::new();
    for category in GMAIL_CATEGORIES {
        for uid in imap
            .uid_search(&format!("X-GM-RAW \"category:{category}\""))
            .await?
        {
            assigned.insert(uid, category);
        }
    }
    db.write(move |c| {
        let tx = c.transaction()?;
        let rows: Vec<(i64, u32, String)> = tx
            .prepare(
                "SELECT id, uid, category FROM messages WHERE mailbox_id = ?1 AND gone_at IS NULL",
            )?
            .query_map([mailbox_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, uid, category) in rows {
            let wanted = assigned.get(&uid).copied().unwrap_or("primary");
            if category != wanted {
                tx.execute(
                    "UPDATE messages SET category = ?1 WHERE id = ?2",
                    params![wanted, id],
                )?;
                reindex_one(&tx, id)?;
            }
        }
        tx.commit()?;
        Ok(())
    })
    .await
}

/// Recomputes one message's metadata tokens.
pub fn reindex_one(c: &Connection, id: i64) -> Result<()> {
    let m = c
        .query_row(
            &format!(
                "SELECT {} FROM messages m WHERE m.id = ?1",
                crate::rules::MESSAGE_COLUMNS
            ),
            [id],
            Message::from_row,
        )
        .optional()?;
    if let Some(m) = m {
        c.execute(
            "UPDATE message_fts SET meta = ?1 WHERE rowid = ?2",
            params![similar::meta_tokens(&m), id],
        )?;
    }
    Ok(())
}

/// For each message that disappeared, a `move` event when a live copy with the
/// same content exists in another mailbox, else a `delete` event.
fn reconcile(c: &mut Connection, account: &str, gone: &[i64], run: f64) -> Result<()> {
    let tx = c.transaction()?;
    for id in gone {
        let (digest, location, mailbox_id): (String, String, i64) = tx.query_row(
            "SELECT digest, location, mailbox_id FROM messages WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let dest: Option<(i64, String)> = tx
            .query_row(
                "SELECT id, location FROM messages WHERE account = ?1 AND digest = ?2 AND gone_at IS NULL AND mailbox_id != ?3 ORDER BY id DESC LIMIT 1",
                params![account, digest, mailbox_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (kind, detail) = match dest {
            Some((to_id, to)) => ("move", json!({"from": location, "to": to, "to_id": to_id})),
            None => ("delete", json!({"from": location})),
        };
        tx.execute(
            "INSERT INTO events (ts, account, kind, message_id, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![run, account, kind, id, detail.to_string()],
        )?;
    }
    tx.commit()?;
    Ok(())
}
