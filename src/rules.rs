//! Operator rules and learned sender patterns, ported from atrium's
//! `rules/rules.go`.

use rusqlite::Row;

#[derive(Debug, Clone, Default)]
pub struct Message {
    pub id: i64,
    pub account: String,
    pub mailbox_id: i64,
    pub uidvalidity: i64,
    pub uid: i64,
    pub msgid: String,
    pub digest: String,
    pub from_addr: String,
    pub from_domain: String,
    pub from_name: String,
    pub reply_to: String,
    pub rpath_domain: String,
    pub list_id: String,
    pub subject: String,
    pub subject_tmpl: String,
    pub msgid_domain: String,
    pub precedence: String,
    pub category: String,
    /// JSON lists, as stored.
    pub to_addrs: String,
    pub dkim_d: String,
    pub esp: String,
    pub att_types: String,
    pub att_names: String,
    pub date_ts: f64,
    pub in_inbox: bool,
    pub folder: Option<String>,
    pub location: String,
    pub seen: bool,
    pub flagged: bool,
    pub gone: bool,
}

pub const MESSAGE_COLUMNS: &str = "m.id, m.account, m.mailbox_id, m.uidvalidity, m.uid, m.msgid, m.digest, \
m.from_addr, m.from_domain, m.from_name, m.reply_to, m.rpath_domain, m.list_id, m.subject, m.subject_tmpl, \
m.msgid_domain, m.precedence, m.category, m.to_addrs, m.dkim_d, m.esp, m.att_types, m.att_names, m.date_ts, \
m.in_inbox, m.folder, m.location, m.seen, m.flagged, m.gone_at IS NOT NULL";

impl Message {
    pub fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            account: r.get(1)?,
            mailbox_id: r.get(2)?,
            uidvalidity: r.get(3)?,
            uid: r.get(4)?,
            msgid: r.get(5)?,
            digest: r.get(6)?,
            from_addr: r.get(7)?,
            from_domain: r.get(8)?,
            from_name: r.get(9)?,
            reply_to: r.get(10)?,
            rpath_domain: r.get(11)?,
            list_id: r.get(12)?,
            subject: r.get(13)?,
            subject_tmpl: r.get(14)?,
            msgid_domain: r.get(15)?,
            precedence: r.get(16)?,
            category: r.get(17)?,
            to_addrs: r.get(18)?,
            dkim_d: r.get(19)?,
            esp: r.get(20)?,
            att_types: r.get(21)?,
            att_names: r.get(22)?,
            date_ts: r.get(23)?,
            in_inbox: r.get(24)?,
            folder: r.get(25)?,
            location: r.get(26)?,
            seen: r.get(27)?,
            flagged: r.get(28)?,
            gone: r.get(29)?,
        })
    }
}
