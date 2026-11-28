//! Explicit rules and learned sender patterns.

use std::collections::{BTreeMap, HashSet};

use anyhow::Result;
use regex::Regex;
use rusqlite::{Connection, Row, params};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const AGE_FIELD: &str = "age_days";
const AGE_OP: &str = "gte";
const SECONDS_PER_DAY: f64 = 86400.0;
pub const LIST_FIELDS: [&str; 5] = ["to", "dkim_d", "esp", "att_type", "att_name"];
pub const SCALAR_FIELDS: [&str; 11] = [
    "from_addr",
    "from_domain",
    "from_name",
    "reply_to",
    "rpath_domain",
    "list_id",
    "subject",
    "subject_tmpl",
    "msgid_domain",
    "precedence",
    "category",
];
pub const OPS: [&str; 6] = ["eq", "in", "suffix", "re", "present", "absent"];

pub fn filing_destination(name: &str) -> bool {
    let folded = name.to_lowercase();
    !name.is_empty()
        && name.trim() == name
        && !name.chars().any(char::is_control)
        && !name.starts_with('\\')
        && !folded.starts_with("[gmail]")
        && !folded.starts_with("misc/")
        && folded != "inbox"
        && !crate::sync::is_system_name(name)
}

pub fn destinations(c: &Connection, account: &str) -> Result<Vec<String>> {
    if let Some(value) = crate::db::get_state(c, &format!("folders:{account}"))? {
        return Ok(serde_json::from_str::<Vec<String>>(&value)?
            .into_iter()
            .filter(|f| filing_destination(f))
            .collect());
    }
    Ok(c.prepare(
        "SELECT name FROM mailboxes WHERE account = ?1 AND role IN ('filed', 'misc') ORDER BY name",
    )?
    .query_map([account], |r| r.get::<_, String>(0))?
    .collect::<rusqlite::Result<Vec<_>>>()?
    .into_iter()
    .filter(|f| filing_destination(f))
    .collect())
}

pub const MIN_N: usize = 3;
pub const MIN_PURITY: f64 = 0.9;

/// Learned levels, most specific first: (name, columns).
pub const LEARNED_LEVELS: [(&str, &[&str]); 4] = [
    ("addr+tmpl", &["from_addr", "subject_tmpl"]),
    ("list", &["list_id"]),
    ("addr", &["from_addr"]),
    ("domain", &["from_domain"]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    File,
    Delete,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::File => "file",
            Action::Delete => "delete",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct RuleError(pub String);

fn rule_err<T>(msg: impl Into<String>) -> Result<T, RuleError> {
    Err(RuleError(msg.into()))
}

#[derive(Debug, Clone)]
pub struct Condition {
    pub field: String,
    pub op: String,
    pub value: Option<Value>,
    matcher: Option<Regex>,
}

impl Serialize for Condition {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = Map::new();
        m.insert("field".into(), Value::String(self.field.clone()));
        m.insert("op".into(), Value::String(self.op.clone()));
        if let Some(v) = &self.value {
            m.insert("value".into(), v.clone());
        }
        Value::Object(m).serialize(s)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    #[serde(rename = "when")]
    pub conditions: Vec<Condition>,
}

fn non_blank_list(v: &Value) -> Option<Vec<String>> {
    let items = v.as_array()?;
    if items.is_empty() {
        return None;
    }
    items
        .iter()
        .map(|i| {
            i.as_str()
                .filter(|s| !s.trim().is_empty())
                .map(String::from)
        })
        .collect()
}

fn positive_days(v: &Value) -> Option<f64> {
    v.as_f64().filter(|d| *d > 0.0)
}

pub fn validate_condition(raw: &Value) -> Result<Condition, RuleError> {
    let Some(obj) = raw.as_object() else {
        return rule_err(format!("condition must be an object: {raw}"));
    };
    let field = obj.get("field").and_then(Value::as_str);
    let op = obj.get("op").and_then(Value::as_str);
    let value = obj.get("value").filter(|v| !v.is_null()).cloned();
    if field == Some(AGE_FIELD) {
        if op != Some(AGE_OP) || value.as_ref().and_then(positive_days).is_none() {
            return rule_err(format!(
                "{AGE_FIELD} needs op {AGE_OP} and a positive number of days"
            ));
        }
        return Ok(Condition {
            field: AGE_FIELD.into(),
            op: AGE_OP.into(),
            value,
            matcher: None,
        });
    }
    let Some(field) = field.filter(|f| LIST_FIELDS.contains(f) || SCALAR_FIELDS.contains(f)) else {
        return rule_err(format!(
            "unknown field {}",
            obj.get("field").unwrap_or(&Value::Null)
        ));
    };
    let Some(op) = op.filter(|o| OPS.contains(o)) else {
        return rule_err(format!(
            "unknown op {}",
            obj.get("op").unwrap_or(&Value::Null)
        ));
    };
    let base = |value: Option<Value>, matcher: Option<Regex>| Condition {
        field: field.into(),
        op: op.into(),
        value,
        matcher,
    };
    if op == "present" || op == "absent" {
        if value.is_some() {
            return rule_err(format!("op {op} takes no value"));
        }
        return Ok(base(None, None));
    }
    let Some(value) = value else {
        return rule_err(format!("op {op} needs a value"));
    };
    let text = value.as_str();
    if (op == "eq" || op == "re") && text.is_none() {
        return rule_err(format!("op {op} needs a string value"));
    }
    if text.is_some_and(|t| t.trim().is_empty()) {
        return rule_err(format!("op {op} needs a value"));
    }
    let list = non_blank_list(&value);
    if op == "in" && list.is_none() {
        return rule_err("op in needs a non-empty list of strings");
    }
    if op == "suffix" && text.is_none() && list.is_none() {
        return rule_err("op suffix needs a string or list of strings");
    }
    if op == "re" {
        let pattern = text.unwrap_or_default();
        let re = Regex::new(&format!("(?i){pattern}"))
            .map_err(|e| RuleError(format!("invalid regex {pattern:?}: {e}")))?;
        return Ok(base(Some(value), Some(re)));
    }
    Ok(base(Some(value), None))
}

pub fn validate_rule(raw: &Value) -> Result<Rule, RuleError> {
    let Some(obj) = raw.as_object() else {
        return rule_err("rule must be an object");
    };
    let Some(id) = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return rule_err("rule needs a string id");
    };
    let action = match obj.get("action") {
        None => Action::File,
        Some(Value::String(s)) if s == "file" => Action::File,
        Some(Value::String(s)) if s == "delete" => Action::Delete,
        Some(other) => return rule_err(format!("{id}: unknown action {other}")),
    };
    let dest = obj.get("dest").filter(|v| !v.is_null());
    let dest = match (action, dest) {
        (Action::File, Some(Value::String(d))) if !d.is_empty() => Some(d.clone()),
        (Action::File, _) => return rule_err(format!("{id}: file rule needs dest")),
        (Action::Delete, Some(_)) => return rule_err(format!("{id}: delete rule takes no dest")),
        (Action::Delete, None) => None,
    };
    if dest.as_deref().is_some_and(|d| !filing_destination(d)) {
        return rule_err(format!(
            "{id}: destination must be a folder the sorter can file into"
        ));
    }
    let account = match obj.get("account").filter(|v| !v.is_null()) {
        None => None,
        Some(Value::String(a)) => Some(a.clone()),
        Some(_) => return rule_err(format!("{id}: account must be a string")),
    };
    let when = obj
        .get("when")
        .and_then(Value::as_array)
        .filter(|w| !w.is_empty());
    let Some(when) = when else {
        return rule_err(format!("{id}: when must be a non-empty list"));
    };
    let conditions = when
        .iter()
        .map(validate_condition)
        .collect::<Result<_, _>>()?;
    Ok(Rule {
        id: id.into(),
        account,
        action,
        dest,
        conditions,
    })
}

pub fn parse_ruleset(document: &Value) -> Result<Vec<Rule>, RuleError> {
    let list = document.get("rules").unwrap_or(document);
    let Some(items) = list.as_array() else {
        return rule_err(r#"expected a list of rules or {"rules": [...]}"#);
    };
    let rules: Vec<Rule> = items.iter().map(validate_rule).collect::<Result<_, _>>()?;
    let ids: HashSet<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    if ids.len() != rules.len() {
        return rule_err("duplicate rule ids");
    }
    Ok(rules)
}

impl Message {
    fn scalar(&self, field: &str) -> &str {
        match field {
            "from_addr" => &self.from_addr,
            "from_domain" => &self.from_domain,
            "from_name" => &self.from_name,
            "reply_to" => &self.reply_to,
            "rpath_domain" => &self.rpath_domain,
            "list_id" => &self.list_id,
            "subject" => &self.subject,
            "subject_tmpl" => &self.subject_tmpl,
            "msgid_domain" => &self.msgid_domain,
            "precedence" => &self.precedence,
            _ => &self.category,
        }
    }

    fn values(&self, field: &str) -> Vec<String> {
        let list = match field {
            "to" => &self.to_addrs,
            "dkim_d" => &self.dkim_d,
            "esp" => &self.esp,
            "att_type" => &self.att_types,
            "att_name" => &self.att_names,
            _ => return vec![self.scalar(field).to_owned()],
        };
        crate::db::json_list(list)
    }
}

fn fold(s: &str) -> String {
    s.to_lowercase()
}

fn members(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

fn domain_suffix(value: &str, suffix: &str) -> bool {
    value == suffix || value.ends_with(&format!(".{suffix}"))
}

impl Condition {
    pub fn matches(&self, m: &Message, now: f64) -> bool {
        if self.field == AGE_FIELD {
            let days = self
                .value
                .as_ref()
                .and_then(Value::as_f64)
                .unwrap_or(f64::MAX);
            return m.date_ts != 0.0 && (now - m.date_ts) / SECONDS_PER_DAY >= days;
        }
        let values = m.values(&self.field);
        let value = self.value.as_ref().unwrap_or(&Value::Null);
        match self.op.as_str() {
            "present" => values.iter().any(|v| !v.is_empty()),
            "absent" => !values.iter().any(|v| !v.is_empty()),
            "eq" => {
                let target = fold(value.as_str().unwrap_or_default());
                values.iter().any(|v| fold(v) == target)
            }
            "in" => {
                let targets: HashSet<String> = members(value).iter().map(|t| fold(t)).collect();
                values.iter().any(|v| targets.contains(&fold(v)))
            }
            "suffix" => {
                let targets: Vec<String> = members(value).iter().map(|t| fold(t)).collect();
                values
                    .iter()
                    .filter(|v| !v.is_empty())
                    .any(|v| targets.iter().any(|t| domain_suffix(&fold(v), t)))
            }
            "re" => self.matcher.as_ref().is_some_and(|re| {
                values
                    .iter()
                    .filter(|v| !v.is_empty())
                    .any(|v| re.is_match(v))
            }),
            _ => false,
        }
    }
}

impl Rule {
    pub fn matches(&self, m: &Message, now: f64) -> bool {
        self.conditions.iter().all(|c| c.matches(m, now))
    }

    pub fn has_age(&self) -> bool {
        self.conditions.iter().any(|c| c.field == AGE_FIELD)
    }
}

pub fn first_match<'a>(m: &Message, rules: &'a [Rule], now: f64) -> Option<&'a Rule> {
    rules.iter().find(|r| r.matches(m, now))
}

/// Stored rules for an account (or all, with `None`), in order. A rule whose
/// stored conditions no longer validate is skipped with a warning.
pub fn load(c: &Connection, account: Option<&str>) -> Result<Vec<Rule>> {
    let mut stmt =
        c.prepare("SELECT id, account, action, dest, conditions FROM rules ORDER BY position")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, rule_account, action, dest, conditions) = row?;
        if let (Some(want), Some(have)) = (account, &rule_account)
            && want != have
        {
            continue;
        }
        let raw = json!({
            "id": id, "account": rule_account, "action": action, "dest": dest,
            "when": serde_json::from_str::<Value>(&conditions).unwrap_or(Value::Null),
        });
        match validate_rule(&raw) {
            Ok(rule) => out.push(rule),
            Err(e) => {
                tracing::warn!(rule = %id, error = %e, "skipping rule with invalid conditions")
            }
        }
    }
    Ok(out)
}

/// Replaces every rule with the document's, in one transaction.
pub fn import(c: &mut Connection, document: &Value) -> Result<usize> {
    let rules = parse_ruleset(document)?;
    let tx = c.transaction()?;
    store(&tx, &rules)?;
    tx.commit()?;
    Ok(rules.len())
}

fn store(c: &Connection, rules: &[Rule]) -> Result<()> {
    c.execute(
        "UPDATE decisions SET apply_state = 'skipped', apply_error = 'rule_changed'
        WHERE apply_state = 'pending' AND stage != 'manual'",
        [],
    )?;
    c.execute("DELETE FROM state WHERE key LIKE 'deletion:%'", [])?;
    c.execute("DELETE FROM rules", [])?;
    for (i, r) in rules.iter().enumerate() {
        c.execute(
            "INSERT INTO rules (position, id, account, action, dest, conditions) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![i as i64, r.id, r.account, r.action.as_str(), r.dest, serde_json::to_string(&r.conditions)?],
        )?;
    }
    Ok(())
}

pub fn export(c: &Connection) -> Result<Value> {
    Ok(json!({ "rules": load(c, None)? }))
}

pub fn revision(c: &Connection) -> Result<String> {
    Ok(hex::encode(Sha256::digest(export(c)?.to_string())))
}

pub fn save(
    c: &mut Connection,
    rule: Rule,
    original: &str,
    position: usize,
    expected: &str,
) -> Result<()> {
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if revision(&tx)? != expected {
        return Err(RuleError(
            "Rules changed while you were editing. Reload and preview again.".into(),
        )
        .into());
    }
    let mut all = load(&tx, None)?;
    let stored: usize = tx.query_row("SELECT COUNT(*) FROM rules", [], |r| r.get(0))?;
    anyhow::ensure!(
        stored == all.len(),
        "Invalid stored rules must be repaired with CLI import before editing."
    );
    if original.is_empty() {
        if all.iter().any(|r| r.id == rule.id) {
            return Err(RuleError("A rule with that id already exists.".into()).into());
        }
    } else {
        if rule.id != original {
            return Err(RuleError("An existing rule's id cannot be changed.".into()).into());
        }
        let index = all
            .iter()
            .position(|r| r.id == original)
            .ok_or_else(|| RuleError("This rule no longer exists.".into()))?;
        all.remove(index);
    }
    all.insert(position.min(all.len()), rule);
    store(&tx, &all)?;
    tx.commit()?;
    Ok(())
}

pub struct Picked {
    pub folder: String,
    pub purity: f64,
    pub total: usize,
}

/// The dominant folder when there are enough messages and it holds
/// `MIN_PURITY` of them; ties go to the larger folder name.
pub fn pick_pure(counts: &BTreeMap<String, usize>) -> Option<Picked> {
    let total: usize = counts.values().sum();
    if total < MIN_N {
        return None;
    }
    let (folder, top) = counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(b.0)))?;
    let purity = *top as f64 / total as f64;
    (purity >= MIN_PURITY).then(|| Picked {
        folder: folder.clone(),
        purity,
        total,
    })
}

pub struct Learned {
    pub level: &'static str,
    pub key: String,
    pub values: Vec<String>,
    pub dest: String,
    pub purity: f64,
    pub n: usize,
    pub counts: BTreeMap<String, usize>,
}

pub fn learned_counts(
    c: &Connection,
    account: &str,
    columns: &[&str],
    values: &[&str],
    exclude: i64,
) -> Result<BTreeMap<String, usize>> {
    let filter: Vec<String> = columns.iter().map(|col| format!("{col} = ?")).collect();
    let sql = format!(
        "SELECT folder, COUNT(*) FROM training_messages WHERE account = ? AND {} AND id != ? GROUP BY folder",
        filter.join(" AND ")
    );
    let mut args: Vec<&dyn rusqlite::ToSql> = vec![&account];
    for v in values {
        args.push(v);
    }
    args.push(&exclude);
    let mut stmt = c.prepare_cached(&sql)?;
    let rows = stmt.query_map(args.as_slice(), |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (folder, n) = row?;
        out.insert(folder, n as usize);
    }
    Ok(out)
}

/// The first learned level whose sender pattern files purely to one folder.
pub fn learned_match(c: &Connection, m: &Message) -> Result<Option<Learned>> {
    for (level, columns) in LEARNED_LEVELS {
        let values: Vec<&str> = columns.iter().map(|col| m.scalar(col)).collect();
        if values.iter().any(|v| v.is_empty()) {
            continue;
        }
        let counts = learned_counts(c, &m.account, columns, &values, m.id)?;
        if let Some(p) = pick_pure(&counts) {
            return Ok(Some(Learned {
                level,
                key: values.join(" | "),
                values: values.iter().map(|v| (*v).to_owned()).collect(),
                dest: p.folder,
                purity: p.purity,
                n: p.total,
                counts,
            }));
        }
    }
    Ok(None)
}

/// Every sender pattern that currently passes the thresholds, for the UI.
pub fn learned_patterns(c: &Connection, account: &str) -> Result<Vec<Learned>> {
    let mut out = Vec::new();
    for (level, columns) in LEARNED_LEVELS {
        let cols = columns.join(", ");
        let nonblank: Vec<String> = columns.iter().map(|col| format!("{col} != ''")).collect();
        let sql = format!(
            "SELECT {cols}, folder, COUNT(*) FROM training_messages WHERE account = ?1 AND {} GROUP BY {cols}, folder",
            nonblank.join(" AND ")
        );
        let mut groups: BTreeMap<Vec<String>, BTreeMap<String, usize>> = BTreeMap::new();
        let mut stmt = c.prepare(&sql)?;
        let mut rows = stmt.query([account])?;
        while let Some(r) = rows.next()? {
            let key: Vec<String> = (0..columns.len())
                .map(|i| r.get(i))
                .collect::<rusqlite::Result<_>>()?;
            let folder: String = r.get(columns.len())?;
            let n: i64 = r.get(columns.len() + 1)?;
            groups.entry(key).or_default().insert(folder, n as usize);
        }
        for (key, counts) in groups {
            if let Some(p) = pick_pure(&counts) {
                out.push(Learned {
                    level,
                    key: key.join(" | "),
                    values: key,
                    dest: p.folder,
                    purity: p.purity,
                    n: p.total,
                    counts,
                });
            }
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.n));
    Ok(out)
}

pub struct MoveSuggestion {
    pub from_addr: String,
    pub dest: String,
    pub moved: usize,
}

/// Senders the owner moved out of the inbox, all of whose filed mail is in
/// one folder, that no rule or learned pattern covers yet.
pub fn move_suggestions(c: &Connection, account: &str) -> Result<Vec<MoveSuggestion>> {
    let moved: Vec<(String, String, i64, i64)> = c
        .prepare(
            "SELECT m.from_addr, m.folder, COUNT(*), MAX(m.id) FROM training_messages m \
             WHERE m.account = ?1 AND m.from_addr != '' \
             AND (EXISTS (SELECT 1 FROM messages o WHERE o.account = m.account AND o.digest = m.digest \
                  AND o.id != m.id AND o.in_inbox = 1) \
               OR EXISTS (SELECT 1 FROM events e WHERE e.message_id = m.id AND e.kind = 'labels' \
                  AND json_extract(e.detail, '$.in_inbox[0]') = 1 AND json_extract(e.detail, '$.in_inbox[1]') = 0)) \
             AND NOT EXISTS (SELECT 1 FROM decisions d JOIN messages s ON s.id = d.message_id \
                  WHERE s.account = m.account AND s.digest = m.digest AND d.apply_state = 'imported') \
             AND (SELECT COUNT(DISTINCT t.folder) FROM training_messages t \
                  WHERE t.account = m.account AND t.from_addr = m.from_addr) = 1 \
             GROUP BY m.from_addr, m.folder ORDER BY COUNT(*) DESC",
        )?
        .query_map([account], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let rules = load(c, Some(account))?;
    let now = crate::db::now();
    let mut out = Vec::new();
    for (from_addr, dest, n, id) in moved {
        let m = c.query_row(
            &format!("SELECT {MESSAGE_COLUMNS} FROM messages m WHERE m.id = ?1"),
            [id],
            Message::from_row,
        )?;
        if first_match(&m, &rules, now).is_none() && learned_match(c, &m)?.is_none() {
            out.push(MoveSuggestion {
                from_addr,
                dest,
                moved: n as usize,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cond(raw: Value) -> Condition {
        validate_condition(&raw).unwrap()
    }

    fn msg() -> Message {
        Message {
            from_addr: "News@A.Example.com".into(),
            from_domain: "a.example.com".into(),
            subject: "Your Weekly Digest".into(),
            to_addrs: r#"["me@x.com"]"#.into(),
            esp: "[]".into(),
            date_ts: 1000.0,
            ..Message::default()
        }
    }

    #[test]
    fn eq_folds_case() {
        assert!(
            cond(json!({"field":"from_addr","op":"eq","value":"news@a.example.COM"}))
                .matches(&msg(), 0.0)
        );
        assert!(
            !cond(json!({"field":"from_addr","op":"eq","value":"news@b.example.com"}))
                .matches(&msg(), 0.0)
        );
    }

    #[test]
    fn in_list() {
        assert!(
            cond(json!({"field":"to","op":"in","value":["ME@x.com","y@z"]})).matches(&msg(), 0.0)
        );
        assert!(!cond(json!({"field":"to","op":"in","value":["y@z"]})).matches(&msg(), 0.0));
    }

    #[test]
    fn suffix_respects_domain_boundary() {
        let c = cond(json!({"field":"from_domain","op":"suffix","value":"example.com"}));
        assert!(c.matches(&msg(), 0.0));
        let mut bad = msg();
        bad.from_domain = "badexample.com".into();
        assert!(!c.matches(&bad, 0.0));
    }

    #[test]
    fn re_is_case_insensitive() {
        assert!(
            cond(json!({"field":"subject","op":"re","value":"weekly\\s+digest"}))
                .matches(&msg(), 0.0)
        );
    }

    #[test]
    fn present_and_absent_on_empty_list() {
        assert!(cond(json!({"field":"esp","op":"absent"})).matches(&msg(), 0.0));
        assert!(!cond(json!({"field":"esp","op":"present"})).matches(&msg(), 0.0));
        assert!(cond(json!({"field":"to","op":"present"})).matches(&msg(), 0.0));
    }

    #[test]
    fn age_days() {
        let c = cond(json!({"field":"age_days","op":"gte","value":2}));
        assert!(c.matches(&msg(), 1000.0 + 2.0 * 86400.0));
        assert!(!c.matches(&msg(), 1000.0 + 86400.0));
        let mut undated = msg();
        undated.date_ts = 0.0;
        assert!(!c.matches(&undated, 1e12));
    }

    #[test]
    fn stale_edits_cannot_replace_newer_rules() {
        let mut c = Connection::open_in_memory().unwrap();
        crate::db::migrate(&mut c).unwrap();
        let initial = revision(&c).unwrap();
        let first = validate_rule(&json!({"id":"first","dest":"News","when":[{"field":"from_addr","op":"eq","value":"news@example.com"}]})).unwrap();
        save(&mut c, first.clone(), "", 0, &initial).unwrap();
        let saved = export(&c).unwrap();
        assert!(save(&mut c, first, "first", 0, &initial).is_err());
        assert_eq!(export(&c).unwrap(), saved);
    }

    #[test]
    fn rejections() {
        let when = json!([{"field":"subject","op":"eq","value":"x"}]);
        assert!(
            validate_rule(&json!({"id":"a","when":when})).is_err(),
            "file without dest"
        );
        assert!(
            validate_rule(&json!({"id":"a","action":"delete","dest":"X","when":when})).is_err()
        );
        assert!(validate_rule(&json!({"id":"a","dest":"X","when":[]})).is_err());
        assert!(
            validate_rule(
                &json!({"id":"a","dest":"X","when":[{"field":"nope","op":"eq","value":"x"}]})
            )
            .is_err()
        );
        assert!(validate_condition(&json!({"field":"esp","op":"present","value":"x"})).is_err());
        assert!(validate_condition(&json!({"field":"age_days","op":"gte","value":true})).is_err());
        assert!(
            parse_ruleset(&json!({"rules":[
                {"id":"a","dest":"X","when":when},{"id":"a","dest":"Y","when":when}
            ]}))
            .is_err()
        );
        assert!(parse_ruleset(&json!([{"id":"a","action":"delete","when":when}])).is_ok());
        for dest in ["misc/News", "INBOX", "Trash", "News\nInjected"] {
            assert!(validate_rule(&json!({"id":"a","dest":dest,"when":when})).is_err());
        }
        assert!(validate_rule(&json!({"id":"a","dest":"Misc","when":when})).is_ok());
    }

    #[test]
    fn purity() {
        let counts: BTreeMap<String, usize> = [("A".to_string(), 9), ("B".to_string(), 1)].into();
        assert_eq!(pick_pure(&counts).unwrap().folder, "A");
        let counts: BTreeMap<String, usize> = [("A".to_string(), 8), ("B".to_string(), 2)].into();
        assert!(pick_pure(&counts).is_none());
        let counts: BTreeMap<String, usize> = [("A".to_string(), 2)].into();
        assert!(pick_pure(&counts).is_none());
    }
}

#[derive(Debug, Clone, Default)]
pub struct Message {
    pub id: i64,
    pub account: String,
    pub msgid: String,
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
    pub folder: Option<String>,
    pub seen: bool,
}

pub const MESSAGE_COLUMNS: &str = "m.id, m.account, m.msgid, m.from_addr, m.from_domain, m.from_name, m.reply_to, m.rpath_domain, m.list_id, m.subject, m.subject_tmpl, m.msgid_domain, m.precedence, m.category, m.to_addrs, m.dkim_d, m.esp, m.att_types, m.att_names, m.date_ts, m.folder, m.seen";

impl Message {
    pub fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            account: r.get(1)?,
            msgid: r.get(2)?,
            from_addr: r.get(3)?,
            from_domain: r.get(4)?,
            from_name: r.get(5)?,
            reply_to: r.get(6)?,
            rpath_domain: r.get(7)?,
            list_id: r.get(8)?,
            subject: r.get(9)?,
            subject_tmpl: r.get(10)?,
            msgid_domain: r.get(11)?,
            precedence: r.get(12)?,
            category: r.get(13)?,
            to_addrs: r.get(14)?,
            dkim_d: r.get(15)?,
            esp: r.get(16)?,
            att_types: r.get(17)?,
            att_names: r.get(18)?,
            date_ts: r.get(19)?,
            folder: r.get(20)?,
            seen: r.get(21)?,
        })
    }
}
