use super::*;
use axum::Form;
use axum::response::Redirect;
use serde_json::json;
use sha2::Digest;

pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/rules/edit", get(edit))
        .route("/rules/preview", axum::routing::post(preview))
        .route("/rules/save", axum::routing::post(save))
        .route("/rules/accept", axum::routing::post(accept))
}

#[derive(Deserialize, Default)]
struct EditQuery {
    id: Option<String>,
    account: Option<String>,
    level: Option<String>,
    pattern: Option<String>,
}

fn value<'a>(form: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    form.get(key).map(String::as_str).unwrap_or_default()
}

fn fields(rule: &rules::Rule) -> anyhow::Result<BTreeMap<String, String>> {
    let mut form = BTreeMap::from([
        ("id".into(), rule.id.clone()),
        ("account".into(), rule.account.clone().unwrap_or_default()),
        ("action".into(), rule.action.as_str().into()),
        ("dest".into(), rule.dest.clone().unwrap_or_default()),
    ]);
    for (i, condition) in rule.conditions.iter().enumerate() {
        form.insert(format!("field_{i}"), condition.field.clone());
        form.insert(format!("op_{i}"), condition.op.clone());
        let text = match &condition.value {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
            Some(Value::String(text)) => text.clone(),
            Some(v) => v.to_string(),
            None => String::new(),
        };
        form.insert(format!("value_{i}"), text);
    }
    Ok(form)
}

fn parse(form: &BTreeMap<String, String>) -> anyhow::Result<rules::Rule> {
    let mut conditions = Vec::new();
    for (key, field) in form.iter().filter(|(k, _)| k.starts_with("field_")) {
        let i: usize = key[6..].parse()?;
        anyhow::ensure!(
            i < form.len() && i.to_string() == key[6..],
            "Invalid condition index."
        );
        let text = value(form, &format!("value_{i}"));
        if field.is_empty() && text.is_empty() {
            continue;
        }
        let op = value(form, &format!("op_{i}"));
        let v = if matches!(op, "present" | "absent") {
            anyhow::ensure!(text.is_empty(), "Present/absent conditions take no value.");
            Value::Null
        } else if field == rules::AGE_FIELD {
            json!(text.parse::<f64>()?)
        } else if op == "in" || (op == "suffix" && text.lines().count() > 1) {
            json!(text.lines().map(str::to_owned).collect::<Vec<_>>())
        } else {
            json!(text)
        };
        conditions.push(json!({"field":field,"op":op,"value":v}));
    }
    let account = value(form, "account");
    let action = value(form, "action");
    let dest = value(form, "dest");
    Ok(rules::validate_rule(&json!({
        "id":value(form,"id"), "account":(!account.is_empty()).then_some(account),
        "action":action, "dest":(!dest.is_empty()).then_some(dest), "when":conditions
    }))?)
}

fn validate_scope(c: &Connection, rule: &rules::Rule) -> anyhow::Result<()> {
    let accounts = rows(c, "SELECT name FROM accounts ORDER BY name", &[])?;
    anyhow::ensure!(!accounts.is_empty(), "No synced accounts are available.");
    if let Some(account) = &rule.account {
        anyhow::ensure!(
            accounts.iter().any(|a| &a[0] == account),
            "Unknown account."
        );
    }
    if let Some(dest) = &rule.dest {
        for a in accounts
            .iter()
            .filter(|a| rule.account.as_ref().is_none_or(|name| name == &a[0]))
        {
            anyhow::ensure!(
                rules::destinations(c, &a[0])?.contains(dest),
                "Destination does not exist for {}. Choose an existing folder.",
                a[0]
            );
        }
    }
    Ok(())
}

async fn form_content(app: &App, form: &BTreeMap<String, String>, error: Option<&str>) -> Page {
    let (accounts, folders, revision) = app
        .db
        .read(|c| {
            let accounts = rows(c, "SELECT name FROM accounts ORDER BY name", &[])?;
            let mut folders = std::collections::BTreeSet::new();
            for a in &accounts {
                folders.extend(rules::destinations(c, &a[0])?);
            }
            Ok((accounts, folders, rules::revision(c)?))
        })
        .await?;
    let count = form
        .keys()
        .filter_map(|k| k.strip_prefix("field_")?.parse::<usize>().ok())
        .filter(|i| *i < form.len())
        .max()
        .map_or(1, |i| i + 2);
    let original = value(form, "original");
    let body = html! {
        p { "Rules are optional overrides. All conditions must match; the first matching rule wins. Misc is for leftovers and is excluded from learning." }
        @if let Some(error) = error { p class="error" role="alert" { (error) } }
        form method="post" action="/rules/preview" {
            input type="hidden" name="csrf" value=(app.csrf.as_ref());
            input type="hidden" name="original" value=(original);
            input type="hidden" name="revision" value=(if form.contains_key("revision") { value(form,"revision") } else { &revision });
            label for="rule-id" { "Rule name" }
            input id="rule-id" name="id" required maxlength="128" readonly[!original.is_empty()] value=(value(form,"id"));
            label for="rule-account" { "Account" }
            select id="rule-account" name="account" {
                option value="" { "All accounts (destination must exist in each)" }
                @for a in &accounts { option value=(a[0]) selected[value(form,"account") == a[0]] { (a[0]) } }
            }
            label for="rule-action" { "Action" }
            select id="rule-action" name="action" {
                option value="file" selected[value(form,"action") != "delete"] { "File into folder" }
                option value="delete" selected[value(form,"action") == "delete"] { "Move to Trash (including retention matches outside Inbox)" }
            }
            label for="rule-dest" { "Destination (leave blank for Trash)" }
            select id="rule-dest" name="dest" {
                option value="" { "No destination" }
                @for folder in &folders { option value=(folder) selected[value(form,"dest") == folder] { (folder) } }
            }
            label for="rule-position" { "Priority (0 runs first)" }
            input id="rule-position" name="position" type="number" min="0" required value=(if form.contains_key("position") { value(form,"position") } else { "0" });
            p id="condition-help" { "Use one value per line for ‘in’ or multiple suffixes. Present/absent need no value. Age uses ‘gte’ and a positive number of days. Leave the final empty condition unused; Preview adds another row." }
            @for i in 0..count {
                fieldset {
                    legend { "Condition " (i + 1) }
                    label for={"field-" (i)} { "Message field" }
                    select id={"field-" (i)} name={"field_" (i)} aria-describedby="condition-help" {
                        option value="" { "Unused condition" }
                        @for field in rules::SCALAR_FIELDS.iter().chain(rules::LIST_FIELDS.iter()).chain(std::iter::once(&rules::AGE_FIELD)) {
                            option value=(field) selected[value(form,&format!("field_{i}")) == *field] { (field) }
                        }
                    }
                    label for={"op-" (i)} { "Comparison" }
                    select id={"op-" (i)} name={"op_" (i)} {
                        @for op in rules::OPS.iter().chain(std::iter::once(&"gte")) {
                            option value=(op) selected[value(form,&format!("op_{i}")) == *op] { (op) }
                        }
                    }
                    label for={"value-" (i)} { "Value" }
                    textarea id={"value-" (i)} name={"value_" (i)} rows="2" aria-describedby="condition-help" { (value(form,&format!("value_{i}"))) }
                }
            }
            button type="submit" { "Preview rule" }
        }
    };
    Ok(body)
}

async fn form_page(app: &App, form: &BTreeMap<String, String>, error: Option<&str>) -> Page {
    layout(&app.db, "Edit rule", form_content(app, form, error).await?).await
}

async fn edit(State(app): State<App>, Query(q): Query<EditQuery>) -> Page {
    let mut form = BTreeMap::new();
    if let Some(id) = q.id {
        let original = id.clone();
        let rule = app
            .db
            .read(move |c| {
                let tx = c.unchecked_transaction()?;
                let all = rules::load(&tx, None)?;
                let position = all
                    .iter()
                    .position(|r| r.id == id)
                    .ok_or_else(|| anyhow::anyhow!("Rule not found"))?;
                let revision = rules::revision(&tx)?;
                tx.commit()?;
                Ok((all[position].clone(), position, revision))
            })
            .await?;
        form = fields(&rule.0)?;
        form.insert("original".into(), original);
        form.insert("position".into(), rule.1.to_string());
        form.insert("revision".into(), rule.2);
    } else if let (Some(account), Some(level), Some(pattern)) = (q.account, q.level, q.pattern) {
        let values: Vec<String> = serde_json::from_str(&pattern)?;
        let columns = rules::LEARNED_LEVELS
            .iter()
            .find(|(name, _)| *name == level)
            .ok_or_else(|| anyhow::anyhow!("Unknown pattern level"))?
            .1;
        if values.len() != columns.len() {
            return Err(anyhow::anyhow!("Invalid pattern").into());
        }
        form.insert(
            "id".into(),
            format!(
                "override-{}",
                &hex::encode(sha2::Sha256::digest(format!("{account}:{level}:{pattern}")))[..12]
            ),
        );
        form.insert("account".into(), account);
        form.insert("action".into(), "file".into());
        for (i, (field, v)) in columns.iter().zip(values).enumerate() {
            form.insert(format!("field_{i}"), (*field).into());
            form.insert(format!("op_{i}"), "eq".into());
            form.insert(format!("value_{i}"), v);
        }
    }
    form_page(&app, &form, None).await
}

/// The file rule a learned pattern or suggestion stands for, with an id
/// derived from it so accepting twice is refused.
fn pattern_rule(account: &str, level: &str, pattern: &str, dest: &str) -> anyhow::Result<rules::Rule> {
    let values: Vec<String> = serde_json::from_str(pattern)?;
    let columns = rules::LEARNED_LEVELS
        .iter()
        .find(|(name, _)| *name == level)
        .ok_or_else(|| anyhow::anyhow!("Unknown pattern level"))?
        .1;
    anyhow::ensure!(values.len() == columns.len(), "Invalid pattern");
    let when: Vec<Value> = columns
        .iter()
        .zip(&values)
        .map(|(field, v)| json!({"field": field, "op": "eq", "value": v}))
        .collect();
    Ok(rules::validate_rule(&json!({
        "id": format!("learned-{}", &hex::encode(sha2::Sha256::digest(format!("{account}:{level}:{pattern}")))[..12]),
        "account": account, "action": "file", "dest": dest, "when": when,
    }))?)
}

/// Saves a suggested rule as is, after every existing rule.
async fn accept(State(app): State<App>, Form(form): Form<BTreeMap<String, String>>) -> Response {
    if !valid_csrf(&app, value(&form, "csrf")) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let result = async {
        let rule = pattern_rule(
            value(&form, "account"),
            value(&form, "level"),
            value(&form, "pattern"),
            value(&form, "dest"),
        )?;
        let _mutation = app.db.mutations.lock().await;
        app.db
            .write(move |c| {
                validate_scope(c, &rule)?;
                let revision = rules::revision(c)?;
                rules::save(c, rule, "", usize::MAX, &revision)
            })
            .await?;
        app.db.refresh.send_replace(());
        Ok::<_, anyhow::Error>(())
    }
    .await;
    match result {
        Ok(()) => Redirect::to("/rules").into_response(),
        Err(e) => (StatusCode::CONFLICT, format!("Rule was not saved: {e}")).into_response(),
    }
}

async fn preview(State(app): State<App>, Form(form): Form<BTreeMap<String, String>>) -> Response {
    if !valid_csrf(&app, value(&form, "csrf")) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match preview_page(&app, &form).await {
        Ok(page) => page.into_response(),
        Err(e) => match form_page(&app, &form, Some(&e.to_string())).await {
            Ok(page) => (StatusCode::UNPROCESSABLE_ENTITY, page).into_response(),
            Err(e) => e.into_response(),
        },
    }
}

async fn preview_page(app: &App, form: &BTreeMap<String, String>) -> anyhow::Result<Markup> {
    let rule = parse(form)?;
    let candidate = rule.clone();
    let (matches, examples) = app.db.read(move |c| {
        validate_scope(c, &candidate)?;
        let sql = format!("SELECT {} FROM messages m WHERE m.gone_at IS NULL AND m.sent = 0 AND (?1 IS NULL OR m.account = ?1) ORDER BY m.date_ts DESC", rules::MESSAGE_COLUMNS);
        let mut matches = 0;
        let mut examples = Vec::new();
        for m in c.prepare(&sql)?.query_map([&candidate.account], rules::Message::from_row)? {
            let m = m?;
            if candidate.matches(&m, db::now()) {
                matches += 1;
                if examples.len() < 10 { examples.push((m.id, m.subject, m.folder.unwrap_or_else(|| "Inbox/unfiled".into()))); }
            }
        }
        Ok((matches, examples))
    }).await?;
    let document = serde_json::to_string(&rule)?;
    let body = html! {
        p { "These conditions match " (matches) " current messages. This is not an action count: read/flagged state, priority, retention exclusions, and existing decisions still apply." }
        @if rule.action == rules::Action::Delete {
            p class="error" { "This rule can move matching mail outside Inbox to Trash during retention processing. Review its scope carefully." }
        } @else {
            p { "Only eligible Inbox mail will be filed. Existing filed messages will not be reorganized." }
        }
        pre { (serde_json::to_string_pretty(&rule)?) }
        div class="table-wrapper" role="region" aria-label="Sample condition matches" tabindex="0" { table {
            caption { "Sample condition matches" }
            thead { tr { th scope="col" { "Subject" } th scope="col" { "Folder" } } }
            tbody { @for (id, subject, folder) in &examples { tr { td { a href={"/message/" (id)} { (subject_text(subject)) } } td { (folder) } } } }
        } }
        form method="post" action="/rules/save" {
            input type="hidden" name="csrf" value=(app.csrf.as_ref());
            input type="hidden" name="document" value=(document);
            @for name in ["original","position","revision"] { input type="hidden" name=(name) value=(value(form,name)); }
            button type="submit" { "Save this rule" }
        }
        details {
            summary { "Continue editing" }
            (form_content(app, form, None).await.map_err(|e| e.0)?)
        }
    };
    layout(&app.db, "Preview rule", body).await.map_err(|e| e.0)
}

async fn save(State(app): State<App>, Form(form): Form<BTreeMap<String, String>>) -> Response {
    if !valid_csrf(&app, value(&form, "csrf")) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let result = async {
        let rule = rules::validate_rule(&serde_json::from_str::<Value>(value(&form, "document"))?)?;
        let original = value(&form, "original").to_owned();
        let position: usize = value(&form, "position").parse()?;
        let revision = value(&form, "revision").to_owned();
        let _mutation = app.db.mutations.lock().await;
        app.db
            .write(move |c| {
                validate_scope(c, &rule)?;
                rules::save(c, rule, &original, position, &revision)
            })
            .await?;
        app.db.refresh.send_replace(());
        Ok::<_, anyhow::Error>(())
    }
    .await;
    match result {
        Ok(()) => Redirect::to("/rules").into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            format!("Rule was not saved: {e}. Return to the editor and preview again."),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_preserves_every_deletion_safeguard() {
        let mut conditions = vec![json!({"field":"subject","op":"present"}); 39];
        conditions.push(json!({"field":"age_days","op":"gte","value":7}));
        let rule =
            rules::validate_rule(&json!({"id":"retention","action":"delete","when":conditions}))
                .unwrap();
        let edited = parse(&fields(&rule).unwrap()).unwrap();
        assert_eq!(edited.conditions.len(), 40);
        assert!(edited.has_age());
        assert_eq!(edited.action, rules::Action::Delete);
    }

    #[test]
    fn condition_parser_validates_lists_and_forbidden_destinations() {
        let mut form = BTreeMap::from([
            ("id".into(), "test".into()),
            ("action".into(), "file".into()),
            ("dest".into(), "News".into()),
            ("field_0".into(), "from_addr".into()),
            ("op_0".into(), "in".into()),
            ("value_0".into(), "a@example.com\nb@example.com".into()),
        ]);
        assert_eq!(
            parse(&form).unwrap().conditions[0].value,
            Some(json!(["a@example.com", "b@example.com"]))
        );
        form.insert("dest".into(), "Misc/News".into());
        assert!(parse(&form).is_err());
        form.insert("dest".into(), "News".into());
        form.insert("op_0".into(), "present".into());
        assert!(parse(&form).is_err());
    }
}
