//! FTS5 BM25 retrieval over metadata, subject, and body.

use std::collections::{BTreeMap, HashSet};

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::db::json_list;
use crate::rules::Message;

const MAX_TERMS: usize = 64;
const SUBJECT_WORDS: usize = 16;
const BODY_WORDS: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub struct Neighbour {
    pub id: i64,
    pub folder: String,
    pub score: f64,
}

fn words(text: &str, min_len: usize, limit: usize, seen: &mut HashSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for w in text.split(|c: char| !c.is_alphanumeric()) {
        let w = w.to_lowercase();
        if w.chars().count() >= min_len && seen.insert(w.clone()) {
            out.push(w);
            if out.len() == limit {
                break;
            }
        }
    }
    out
}

/// The FTS5 query for a message: its metadata tokens, then subject and body
/// words, ORed.
pub fn query(meta: &str, subject: &str, body: &str) -> Option<String> {
    let mut seen = HashSet::new();
    let mut terms: Vec<String> = meta
        .split_whitespace()
        .filter(|t| seen.insert((*t).to_owned()))
        .map(String::from)
        .collect();
    terms.extend(words(subject, 3, SUBJECT_WORDS, &mut seen));
    terms.extend(words(body, 4, BODY_WORDS, &mut seen));
    terms.truncate(MAX_TERMS);
    let quoted: Vec<String> = terms
        .iter()
        .map(|t| t.replace('"', ""))
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{t}\""))
        .collect();
    (!quoted.is_empty()).then(|| quoted.join(" OR "))
}

/// The `k` filed messages of the same account that best match `m` by BM25,
/// best first.
pub fn neighbours(c: &Connection, m: &Message, k: usize) -> Result<Vec<Neighbour>> {
    let body: String = c
        .query_row(
            "SELECT body FROM message_fts WHERE rowid = ?1",
            [m.id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default();
    let Some(q) = query(&meta_tokens(m), &m.subject, &body) else {
        return Ok(Vec::new());
    };
    let mut stmt = c.prepare_cached(
        "SELECT f.rowid, fm.folder, -bm25(message_fts, 5.0, 2.0, 1.0) AS s FROM message_fts f \
         JOIN training_messages fm ON fm.id = f.rowid \
         WHERE message_fts MATCH ?1 AND fm.account = ?2 AND fm.id != ?3 ORDER BY s DESC LIMIT ?4",
    )?;
    let rows = stmt.query_map(params![q, m.account, m.id, k as i64], |r| {
        Ok(Neighbour {
            id: r.get(0)?,
            folder: r.get(1)?,
            score: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The folder with the most score, and its share of the total. Ties go to the
/// larger folder name.
pub fn vote(neighbours: &[Neighbour]) -> Option<(String, f64)> {
    let mut scores: BTreeMap<&str, f64> = BTreeMap::new();
    for n in neighbours {
        *scores.entry(&n.folder).or_default() += n.score;
    }
    let total: f64 = scores.values().sum();
    if total <= 0.0 {
        return None;
    }
    let (folder, top) = scores
        .iter()
        .max_by(|a, b| a.1.total_cmp(b.1).then(a.0.cmp(b.0)))?;
    Some(((*folder).to_owned(), top / total))
}

fn token(prefix: &str, value: &str) -> Option<String> {
    let v: String = value
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '_'
            }
        })
        .collect();
    let v = v.trim_matches('_');
    (!v.is_empty()).then(|| format!("{prefix}_{v}"))
}

/// Space-separated synthetic tokens for the `meta` FTS column.
pub fn meta_tokens(m: &Message) -> String {
    let mut out: Vec<String> = Vec::new();
    for (prefix, value) in [
        ("fa", &m.from_addr),
        ("fd", &m.from_domain),
        ("li", &m.list_id),
        ("rp", &m.rpath_domain),
        ("rt", &m.reply_to),
        ("md", &m.msgid_domain),
        ("ca", &m.category),
        ("st", &m.subject_tmpl),
    ] {
        out.extend(token(prefix, value));
    }
    for (prefix, list) in [("dk", &m.dkim_d), ("es", &m.esp), ("at", &m.att_types)] {
        for v in json_list(list) {
            out.extend(token(prefix, &v));
        }
    }
    for word in m.subject_tmpl.split_whitespace() {
        out.extend(token("sw", word));
    }
    out.dedup();
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(folder: &str, score: f64) -> Neighbour {
        Neighbour {
            id: 0,
            folder: folder.into(),
            score,
        }
    }

    #[test]
    fn votes() {
        let (f, share) = vote(&[n("A", 3.0), n("B", 1.0), n("A", 4.0)]).unwrap();
        assert_eq!(f, "A");
        assert!((share - 0.875).abs() < 1e-9);
        assert_eq!(vote(&[n("A", 1.0), n("B", 1.0)]).unwrap().0, "B");
        assert!(vote(&[]).is_none());
    }

    #[test]
    fn queries() {
        let q = query(
            "fa_x_y_com st_hello",
            "Hello \"there\" world",
            "body text here",
        )
        .unwrap();
        assert_eq!(
            q,
            r#""fa_x_y_com" OR "st_hello" OR "hello" OR "there" OR "world" OR "body" OR "text" OR "here""#
        );
    }
}
