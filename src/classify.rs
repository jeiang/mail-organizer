//! Per-account multinomial logistic regression over sender and text features.
//!
//! The model is trained in-process from the current filed mail and rebuilt per
//! routing pass, so a new example takes effect on the next pass. Features are
//! hashed into a fixed table: sender keys (address, domain, list-id, dkim, esp,
//! category, attachments) and words from the subject template and body.

use std::collections::BTreeMap;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};

use crate::db::json_list;
use crate::rules::{MESSAGE_COLUMNS, Message};

const BUCKETS: usize = 1 << 17;
const EPOCHS: usize = 8;
const RATE: f32 = 0.35;
const L2: f32 = 1e-6;
const SUBJECT_WORDS: usize = 24;
const BODY_WORDS: usize = 48;
const MIN_SAMPLES: usize = 20;

pub struct Model {
    labels: Vec<String>,
    weights: Vec<f32>,
}

fn hash(key: &str) -> u32 {
    let mut h = 0x811c_9dc5u32;
    for b in key.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h % BUCKETS as u32
}

fn words(out: &mut Vec<u32>, prefix: char, text: &str, min_len: usize, limit: usize) {
    let mut n = 0;
    for w in text.split(|c: char| !c.is_alphanumeric()) {
        let w = w.to_lowercase();
        if w.chars().count() >= min_len {
            out.push(hash(&format!("{prefix}:{w}")));
            n += 1;
            if n == limit {
                break;
            }
        }
    }
}

/// Bucket indices for a message; index 0 is the bias.
fn features(m: &Message, body: &str) -> Vec<u32> {
    let mut out = vec![0];
    for (prefix, value) in [
        ('a', &m.from_addr),
        ('d', &m.from_domain),
        ('l', &m.list_id),
        ('r', &m.reply_to),
        ('p', &m.rpath_domain),
        ('i', &m.msgid_domain),
        ('c', &m.category),
        ('e', &m.precedence),
    ] {
        let value = value.trim().to_lowercase();
        if value.len() > 2 {
            out.push(hash(&format!("{prefix}:{value}")));
        }
    }
    for (prefix, list) in [
        ('k', &m.dkim_d),
        ('s', &m.esp),
        ('t', &m.att_types),
        ('n', &m.att_names),
    ] {
        for value in json_list(list) {
            let value = value.trim().to_lowercase();
            if value.len() > 2 {
                out.push(hash(&format!("{prefix}:{value}")));
            }
        }
    }
    words(&mut out, 'j', &m.subject_tmpl, 3, SUBJECT_WORDS);
    words(&mut out, 'b', body, 4, BODY_WORDS);
    out.sort_unstable();
    out.dedup();
    out
}

impl Model {
    /// Trains on filed mail for `account`, restricted to messages older than
    /// `before` when given. Returns None until there is enough mail.
    pub fn train(c: &Connection, account: &str, before: Option<f64>) -> Result<Option<Self>> {
        let sql = format!(
            "SELECT {MESSAGE_COLUMNS}, f.body FROM main.training_messages m \
             JOIN message_fts f ON f.rowid = m.id \
             WHERE m.account = ?1 AND m.folder IS NOT NULL AND m.folder != ''{}",
            if before.is_some() {
                " AND m.date_ts < ?2"
            } else {
                ""
            }
        );
        let mut stmt = c.prepare(&sql)?;
        let mut rows = match before {
            Some(cut) => stmt.query(rusqlite::params![account, cut])?,
            None => stmt.query([account])?,
        };
        let mut samples: Vec<(Vec<u32>, String)> = Vec::new();
        while let Some(row) = rows.next()? {
            let m = Message::from_row(row)?;
            let Some(folder) = m.folder.clone().filter(|f| !f.is_empty()) else {
                continue;
            };
            let body: String = row.get(row.as_ref().column_count() - 1)?;
            samples.push((features(&m, &body), folder));
        }
        if samples.len() < MIN_SAMPLES {
            return Ok(None);
        }
        let mut labels: BTreeMap<String, usize> = BTreeMap::new();
        for (_, folder) in &samples {
            labels.insert(folder.clone(), 0);
        }
        // Class indices must match `names`, so assign them in sorted order.
        for (i, index) in labels.values_mut().enumerate() {
            *index = i;
        }
        if labels.len() < 2 {
            return Ok(None);
        }
        let names: Vec<String> = labels.keys().cloned().collect();
        let targets: Vec<usize> = samples.iter().map(|(_, folder)| labels[folder]).collect();
        let inputs: Vec<Vec<u32>> = samples.into_iter().map(|(f, _)| f).collect();

        let mut model = Self {
            labels: names,
            weights: vec![0.0; labels.len() * BUCKETS],
        };
        let k = model.labels.len();
        let mut logits = vec![0.0f32; k];
        let mut order: Vec<usize> = (0..inputs.len()).collect();
        let mut seed = 0x9e37_79b9u32;
        for _ in 0..EPOCHS {
            for i in (1..order.len()).rev() {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let j = (seed as usize) % (i + 1);
                order.swap(i, j);
            }
            for idx in &order {
                let feats = &inputs[*idx];
                let label = targets[*idx];
                for (class, logit) in logits.iter_mut().enumerate() {
                    let base = class * BUCKETS;
                    *logit = feats
                        .iter()
                        .map(|f| model.weights[base + *f as usize])
                        .sum();
                }
                let max = logits.iter().copied().fold(f32::MIN, f32::max);
                let mut total = 0.0f32;
                for logit in logits.iter_mut() {
                    *logit = (*logit - max).exp();
                    total += *logit;
                }
                for (class, p) in logits.iter_mut().enumerate() {
                    let g = *p / total - if class == label { 1.0 } else { 0.0 };
                    if g.abs() < 1e-9 {
                        continue;
                    }
                    let base = class * BUCKETS;
                    for f in feats {
                        let w = &mut model.weights[base + *f as usize];
                        *w -= RATE * (g + L2 * *w);
                    }
                }
            }
        }
        Ok(Some(model))
    }

    fn scores(&self, m: &Message, body: &str) -> Vec<f32> {
        let feats = features(m, body);
        let k = self.labels.len();
        let mut logits = vec![0.0f32; k];
        for (class, logit) in logits.iter_mut().enumerate() {
            let base = class * BUCKETS;
            *logit = feats.iter().map(|f| self.weights[base + *f as usize]).sum();
        }
        let max = logits.iter().copied().fold(f32::MIN, f32::max);
        let mut total = 0.0f32;
        for logit in logits.iter_mut() {
            *logit = (*logit - max).exp();
            total += *logit;
        }
        for logit in logits.iter_mut() {
            *logit /= total;
        }
        logits
    }

    /// The most likely folder, its probability, and the runner-ups.
    pub fn predict(&self, m: &Message, body: &str) -> (String, f64, Vec<(String, f64)>) {
        let probs = self.scores(m, body);
        let mut ranked: Vec<(usize, f32)> = probs.iter().copied().enumerate().collect();
        ranked.sort_unstable_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        let top: Vec<(String, f64)> = ranked
            .iter()
            .take(3)
            .map(|(i, p)| (self.labels[*i].clone(), f64::from(*p)))
            .collect();
        let (best, p) = ranked[0];
        (self.labels[best].clone(), f64::from(p), top)
    }
}

/// The stored text of a message, empty when it was never indexed.
pub fn body(c: &Connection, id: i64) -> Result<String> {
    Ok(
        c.query_row("SELECT body FROM message_fts WHERE rowid = ?1", [id], |r| {
            r.get(0)
        })
        .optional()?
        .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: i64, from: &str, folder: &str, subject: &str) -> Message {
        Message {
            id,
            account: "test".into(),
            from_addr: from.into(),
            from_domain: from.rsplit('@').next().unwrap_or_default().into(),
            subject: subject.into(),
            subject_tmpl: subject.into(),
            folder: Some(folder.into()),
            ..Message::default()
        }
    }

    #[test]
    fn learns_senders_and_words() {
        let mut c = Connection::open_in_memory().unwrap();
        crate::db::migrate(&mut c).unwrap();
        c.execute_batch(
            "INSERT INTO accounts(name,preset) VALUES ('test','icloud');
            INSERT INTO mailboxes(id,account,name,imap_name,role) VALUES
            (1,'test','News','News','filed'),(2,'test','Purchases','Purchases','filed'),
            (3,'test','Alerts','Alerts','filed');",
        )
        .unwrap();
        for i in 0..24 {
            let id = 10 + i;
            let (from, folder, subject, mailbox) = match i % 3 {
                0 => ("news@example.com", "News", "weekly digest", 1),
                1 => ("shop@example.com", "Purchases", "your receipt", 2),
                _ => ("alert@example.com", "Alerts", "security alert", 3),
            };
            c.execute(
                "INSERT INTO messages(id,account,mailbox_id,uidvalidity,uid,digest,from_addr,folder,in_inbox,date_ts,first_seen)
                 VALUES (?1,'test',?2,1,?1,?3,?4,?5,0,?1,1)",
                rusqlite::params![id, mailbox, format!("d{id}"), from, folder],
            )
            .unwrap();
            c.execute(
                "INSERT INTO message_fts(rowid,meta,subject,body) VALUES (?1,'',?2,?3)",
                rusqlite::params![id, subject, format!("{subject} from {from}")],
            )
            .unwrap();
        }
        let model = Model::train(&c, "test", None).unwrap().unwrap();
        let news = message(99, "news@example.com", "", "weekly digest");
        let (folder, p, top) = model.predict(&news, "weekly digest from news@example.com");
        assert_eq!(folder, "News");
        assert!(p > 0.8, "probability {p}, top {top:?}");
        let shop = message(98, "shop@example.com", "", "your receipt");
        assert_eq!(
            model.predict(&shop, "your receipt from shop@example.com").0,
            "Purchases"
        );
        let alert = message(97, "alert@example.com", "", "security alert");
        assert_eq!(
            model
                .predict(&alert, "security alert from alert@example.com")
                .0,
            "Alerts"
        );
    }
}
