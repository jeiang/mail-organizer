CREATE VIEW training_messages AS
SELECT m.* FROM filed_messages m
WHERE lower(m.folder) != 'misc' AND lower(m.folder) NOT LIKE 'misc/%'
AND NOT EXISTS (
    SELECT 1 FROM decisions d JOIN messages source ON source.id = d.message_id
    WHERE source.account = m.account AND source.digest = m.digest
    AND d.apply_state = 'done' AND d.action = 'file' AND d.dest = m.folder
)
AND NOT EXISTS (
    SELECT 1 FROM filed_messages other
    WHERE other.account = m.account AND other.digest = m.digest AND other.folder != m.folder
)
AND m.id = (
    SELECT MAX(copy.id) FROM filed_messages copy
    WHERE copy.account = m.account AND copy.digest = m.digest
);
