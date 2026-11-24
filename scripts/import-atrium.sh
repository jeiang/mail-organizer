#!/usr/bin/env bash
# One-off: copy atrium's mail history and rules into a new mail-organizer database.
# Usage (as root, atrium stopped, mail-organizer never started):
#   import-atrium.sh /var/lib/atrium/atrium.db /run/secrets/atrium/db-key /var/lib/mail-organizer/mail.db
# Needs mail-organizer and sqlcipher on PATH.
set -euo pipefail

src=$1 key_file=$2 target=$3

if [ -e "$target" ] && [ "$(sqlcipher "$target" 'SELECT COUNT(*) FROM messages' 2>/dev/null || echo 0)" != 0 ]; then
  echo "refusing: $target already has messages" >&2
  exit 1
fi

config=$(mktemp)
trap 'rm -f "$config"' EXIT
printf 'db = "%s"\n' "$target" >"$config"
mail-organizer --config "$config" migrate

key=$(tr -d '[:space:]' <"$key_file")
if ! [[ $key =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "refusing: $key_file is not 64 hex digits" >&2
  exit 1
fi

# The key goes through stdin, never argv.
sqlcipher -bail "$target" <<SQL
ATTACH 'file:$src?mode=ro' AS src KEY "x'$key'";
BEGIN;
INSERT INTO accounts (name, preset, last_sync_at) SELECT name, kind, last_sync_at FROM src.accounts;
INSERT INTO mailboxes (id, account, name, imap_name, role, uidvalidity, highest_uid, highestmodseq, synced_at)
  SELECT id, account, name, imap_name, role, uidvalidity, highest_uid, highestmodseq, synced_at FROM src.mailboxes;
INSERT INTO messages (id, account, mailbox_id, uidvalidity, uid, msgid, digest, gm_msgid, date_ts, flags, seen, flagged,
    labels, in_inbox, sent, location, folder, category, from_addr, from_domain, from_name, to_addrs, reply_to,
    rpath_domain, list_id, precedence, subject, subject_tmpl, msgid_domain, dkim_d, esp, att_types, att_names,
    first_seen, gone_at)
  SELECT id, account, mailbox_id, uidvalidity, uid, msgid, digest, gm_msgid, date_ts, flags, seen, flagged,
    labels, in_inbox, sent, location, folder, category, from_addr, from_domain, from_name, to_addrs, reply_to,
    rpath_domain, list_id, precedence, subject, subject_tmpl, msgid_domain, dkim_d, esp, att_types, att_names,
    first_seen, gone_at FROM src.messages;
INSERT INTO message_fts (rowid, meta, subject, body)
  SELECT f.rowid, '', f.subject, substr(f.body, 1, 4000) FROM src.message_fts f
  WHERE f.rowid IN (SELECT id FROM main.messages);
INSERT INTO rules (position, id, account, action, dest, conditions)
  SELECT position, id, account, action, dest, conditions FROM src.rules;
INSERT INTO decisions (id, message_id, account, ts, stage, key, action, dest, confidence, detail, apply_state)
  SELECT id, message_id, account, ts, stage, key, action, dest, confidence, detail, 'imported' FROM src.decisions;
INSERT INTO events (id, ts, account, kind, message_id, detail)
  SELECT id, ts, account, kind, message_id, detail FROM src.events;
INSERT OR IGNORE INTO deletion_exclusions (account, digest, reason)
  SELECT m.account, m.digest, 'corrected' FROM src.corrections c JOIN src.messages m ON m.id = c.message_id
  UNION
  SELECT e.account, e.digest, 'trash_undone' FROM src.effects e
  WHERE e.origin = 'mail_auto' AND e.operation = 'trash' AND e.direction = 'forward' AND e.digest != ''
    AND (e.undone_by IS NOT NULL
      OR EXISTS (SELECT 1 FROM src.effect_resources er WHERE er.effect_id = e.id AND er.holding = 1));
COMMIT;
SELECT 'table', 'atrium', 'mail-organizer';
SELECT 'accounts', (SELECT COUNT(*) FROM src.accounts), (SELECT COUNT(*) FROM main.accounts);
SELECT 'mailboxes', (SELECT COUNT(*) FROM src.mailboxes), (SELECT COUNT(*) FROM main.mailboxes);
SELECT 'messages', (SELECT COUNT(*) FROM src.messages), (SELECT COUNT(*) FROM main.messages);
SELECT 'message_fts', (SELECT COUNT(*) FROM src.message_fts), (SELECT COUNT(*) FROM main.message_fts);
SELECT 'rules', (SELECT COUNT(*) FROM src.rules), (SELECT COUNT(*) FROM main.rules);
SELECT 'decisions', (SELECT COUNT(*) FROM src.decisions), (SELECT COUNT(*) FROM main.decisions);
SELECT 'events', (SELECT COUNT(*) FROM src.events), (SELECT COUNT(*) FROM main.events);
SELECT 'deletion_exclusions', '-', (SELECT COUNT(*) FROM main.deletion_exclusions);
SQL

mail-organizer --config "$config" reindex
