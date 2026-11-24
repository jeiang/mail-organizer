//! Mailbox roles, message state and the sync pass, ported from atrium's
//! `role.go`, `sync/state.go` and `sync/sync.go`.

use crate::config::Preset;
use crate::utf7;

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
