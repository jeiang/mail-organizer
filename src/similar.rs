//! The similarity stage: FTS5 BM25 over metadata tokens, subject and body,
//! replacing atrium's embedding kNN.

use crate::db::json_list;
use crate::rules::Message;

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
