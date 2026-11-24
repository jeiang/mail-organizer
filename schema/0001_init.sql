CREATE TABLE accounts (
    name TEXT PRIMARY KEY,
    preset TEXT NOT NULL,
    last_sync_at REAL
);

CREATE TABLE mailboxes (
    id INTEGER PRIMARY KEY,
    account TEXT NOT NULL REFERENCES accounts(name),
    name TEXT NOT NULL,
    imap_name TEXT NOT NULL,
    role TEXT NOT NULL,
    uidvalidity INTEGER,
    highest_uid INTEGER NOT NULL DEFAULT 0,
    highestmodseq INTEGER,
    synced_at REAL,
    UNIQUE (account, name)
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    account TEXT NOT NULL,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id),
    uidvalidity INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    msgid TEXT NOT NULL DEFAULT '',
    digest TEXT NOT NULL,
    gm_msgid TEXT,
    date_ts REAL NOT NULL DEFAULT 0,
    flags TEXT NOT NULL DEFAULT '[]',
    seen INTEGER NOT NULL DEFAULT 0,
    flagged INTEGER NOT NULL DEFAULT 0,
    labels TEXT NOT NULL DEFAULT '[]',
    in_inbox INTEGER NOT NULL DEFAULT 0,
    sent INTEGER NOT NULL DEFAULT 0,
    location TEXT NOT NULL DEFAULT '',
    folder TEXT,
    category TEXT NOT NULL DEFAULT '',
    from_addr TEXT NOT NULL DEFAULT '',
    from_domain TEXT NOT NULL DEFAULT '',
    from_name TEXT NOT NULL DEFAULT '',
    to_addrs TEXT NOT NULL DEFAULT '[]',
    reply_to TEXT NOT NULL DEFAULT '',
    rpath_domain TEXT NOT NULL DEFAULT '',
    list_id TEXT NOT NULL DEFAULT '',
    precedence TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    subject_tmpl TEXT NOT NULL DEFAULT '',
    msgid_domain TEXT NOT NULL DEFAULT '',
    dkim_d TEXT NOT NULL DEFAULT '[]',
    esp TEXT NOT NULL DEFAULT '[]',
    att_types TEXT NOT NULL DEFAULT '[]',
    att_names TEXT NOT NULL DEFAULT '[]',
    first_seen REAL NOT NULL,
    gone_at REAL,
    UNIQUE (account, mailbox_id, uidvalidity, uid)
);
CREATE INDEX messages_addr ON messages (account, from_addr);
CREATE INDEX messages_domain ON messages (account, from_domain);
CREATE INDEX messages_digest ON messages (account, digest);
CREATE INDEX messages_mailbox ON messages (mailbox_id, gone_at);
CREATE INDEX messages_inbox ON messages (account, in_inbox, gone_at);

CREATE VIRTUAL TABLE message_fts USING fts5(meta, subject, body, tokenize = "unicode61 tokenchars '_'");

CREATE TABLE rules (
    position INTEGER NOT NULL,
    id TEXT PRIMARY KEY,
    account TEXT,
    action TEXT NOT NULL,
    dest TEXT,
    conditions TEXT NOT NULL
);

CREATE TABLE decisions (
    id INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES messages(id),
    account TEXT NOT NULL,
    ts REAL NOT NULL,
    stage TEXT NOT NULL,
    key TEXT,
    action TEXT NOT NULL,
    dest TEXT,
    confidence REAL,
    detail TEXT NOT NULL DEFAULT '{}',
    apply_state TEXT CHECK (apply_state IN ('pending', 'done', 'skipped', 'failed', 'imported')),
    applied_at REAL,
    apply_error TEXT,
    trace_id TEXT,
    span_id TEXT
);
CREATE INDEX decisions_message ON decisions (message_id);
CREATE INDEX decisions_pending ON decisions (account, apply_state);

CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    account TEXT NOT NULL,
    kind TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX events_message ON events (message_id);

CREATE TABLE state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE deletion_exclusions (
    account TEXT NOT NULL,
    digest TEXT NOT NULL,
    reason TEXT NOT NULL,
    PRIMARY KEY (account, digest)
);

CREATE VIEW filed_messages AS
SELECT * FROM messages
WHERE gone_at IS NULL AND sent = 0 AND in_inbox = 0 AND folder IS NOT NULL AND folder != '';
