//! Read-only web UI.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use maud::{DOCTYPE, Markup, html};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, Row, params_from_iter};
use serde::Deserialize;
use serde_json::Value;

use crate::config::Config;
use crate::db::{self, Db};
use crate::rules;

const PAGE: i64 = 50;

/// Where each message's content lives now: the newest live copy with the
/// same digest, so a move by the owner is seen even though it gets a new row.
const ACTUAL: &str = "(SELECT l.location FROM messages l WHERE l.account = m.account AND l.digest = m.digest \
     AND l.gone_at IS NULL ORDER BY l.id DESC LIMIT 1) AS actual, \
     (SELECT l.in_inbox FROM messages l WHERE l.account = m.account AND l.digest = m.digest \
     AND l.gone_at IS NULL ORDER BY l.id DESC LIMIT 1) AS actual_inbox";

const AGREEMENT: &str = "CASE WHEN actual IS NULL THEN 'gone' WHEN actual_inbox = 1 THEN 'pending' \
     WHEN dest IS NOT NULL AND instr('|' || actual || '|', '|' || dest || '|') > 0 THEN 'agree' \
     ELSE 'disagree' END";

fn latest_sql() -> String {
    format!(
        "SELECT *, {AGREEMENT} AS agreement FROM (SELECT d.id AS decision_id, d.ts, d.account, d.stage, d.key, \
         d.action, d.dest, d.apply_state, d.apply_error, m.id AS message_id, m.from_addr, m.subject, {ACTUAL} \
         FROM decisions d JOIN messages m ON m.id = d.message_id \
         WHERE d.id = (SELECT MAX(x.id) FROM decisions x WHERE x.message_id = d.message_id))"
    )
}

#[derive(Clone)]
struct App {
    db: Db,
    trace_url: Arc<str>,
}

pub fn router(db: Db, config: &Config) -> Router {
    let app = App {
        db,
        trace_url: config.trace_url_template.as_str().into(),
    };
    Router::new()
        .route("/", get(activity))
        .route("/folders", get(folders))
        .route("/message/{id}", get(message))
        .route("/learned", get(learned))
        .route("/rules", get(rules_page))
        .route("/stats", get(stats))
        .layer(axum::middleware::from_fn(crate::telemetry::track_http))
        .with_state(app)
}

struct Failure(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for Failure {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        tracing::error!("web request failed: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    }
}

type Page = Result<Markup, Failure>;

/// Any SQLite value as display text; NULL is empty.
fn text(r: &Row<'_>, i: usize) -> rusqlite::Result<String> {
    Ok(match r.get_ref(i)? {
        ValueRef::Null => String::new(),
        ValueRef::Integer(n) => n.to_string(),
        ValueRef::Real(f) => f.to_string(),
        ValueRef::Text(t) | ValueRef::Blob(t) => String::from_utf8_lossy(t).into_owned(),
    })
}

fn rows(c: &Connection, sql: &str, params: &[String]) -> anyhow::Result<Vec<Vec<String>>> {
    let mut stmt = c.prepare(sql)?;
    let n = stmt.column_count();
    let out = stmt
        .query_map(params_from_iter(params), |r| {
            (0..n).map(|i| text(r, i)).collect()
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(out)
}

/// UTC `YYYY-MM-DD HH:MM` from Unix seconds.
fn when(ts: &str) -> String {
    let Ok(ts) = ts.parse::<f64>() else {
        return String::new();
    };
    let secs = ts as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60
    )
}

fn agreement_badge(agreement: &str, actual: &str) -> Markup {
    let label = match agreement {
        "agree" => "agree".to_owned(),
        "pending" => "still in inbox".to_owned(),
        "gone" => "gone".to_owned(),
        _ => format!("moved by you → {actual}"),
    };
    html! { span class={"badge " (agreement)} { (label) } }
}

async fn layout(db: &Db, title: &str, body: Markup) -> Page {
    let (mode, accounts) = db
        .read(|c| {
            let mode = db::mode(c)?;
            let accounts = rows(
                c,
                "SELECT a.name, a.last_sync_at, (SELECT value FROM state WHERE key = 'error:' || a.name) \
                 FROM accounts a ORDER BY a.name",
                &[],
            )?;
            Ok((mode, accounts))
        })
        .await?;
    Ok(html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · mail-organizer" }
                style { (STYLE) }
            }
            body {
                header {
                    nav {
                        a href="/" { "Activity" } a href="/folders" { "Folders" } a href="/learned" { "Learned" }
                        a href="/rules" { "Rules" } a href="/stats" { "Stats" }
                    }
                    p {
                        span class={"badge " (mode.as_str())} { (mode.as_str()) }
                        @for a in &accounts {
                            " " (a[0]) ": synced " (when(&a[1]))
                            @if !a[2].is_empty() {
                                @let (at, msg) = a[2].split_once('\t').unwrap_or(("", &a[2]));
                                " " span class="badge disagree" title=(msg) { "error " (when(at)) }
                            }
                        }
                    }
                }
                main { h1 { (title) } (body) }
            }
        }
    })
}

const STYLE: &str = "body{font:14px system-ui,sans-serif;margin:0 1.5rem;color:#222}\
header{border-bottom:1px solid #ddd}nav a{margin-right:1rem}\
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.25rem .5rem;border-bottom:1px solid #eee;vertical-align:top}\
.badge{padding:0 .4rem;border-radius:.5rem;background:#eee;white-space:nowrap}\
.agree,.live{background:#d4f4d4}.disagree{background:#f8d4d4}.pending,.shadow{background:#f4ecc4}\
form input,form select{margin-right:.5rem}pre{white-space:pre-wrap;background:#f6f6f6;padding:.5rem}\
.num{text-align:right}";

#[derive(Deserialize, Default)]
struct ActivityQuery {
    account: Option<String>,
    stage: Option<String>,
    agreement: Option<String>,
    folder: Option<String>,
    rule: Option<String>,
    q: Option<String>,
    page: Option<i64>,
}

fn nonblank(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

async fn activity(State(app): State<App>, Query(f): Query<ActivityQuery>) -> Page {
    let mut sql = format!("SELECT * FROM ({}) WHERE 1 = 1", latest_sql());
    let mut params = Vec::new();
    for (column, value) in [
        ("account", nonblank(&f.account)),
        ("stage", nonblank(&f.stage)),
        ("agreement", nonblank(&f.agreement)),
        ("dest", nonblank(&f.folder)),
        ("key", nonblank(&f.rule)),
    ] {
        if let Some(v) = value {
            params.push(v.to_owned());
            sql.push_str(&format!(" AND {column} = ?{}", params.len()));
        }
    }
    if let Some(q) = nonblank(&f.q) {
        params.push(format!("%{q}%"));
        let n = params.len();
        sql.push_str(&format!(" AND (subject LIKE ?{n} OR from_addr LIKE ?{n})"));
    }
    let page = f.page.unwrap_or(0).max(0);
    sql.push_str(&format!(
        " ORDER BY decision_id DESC LIMIT {} OFFSET {}",
        PAGE + 1,
        page * PAGE
    ));
    let mut found = app.db.read(move |c| rows(c, &sql, &params)).await?;
    let more = found.len() as i64 > PAGE;
    found.truncate(PAGE as usize);
    let link = |p: i64| {
        let mut parts = vec![format!("page={p}")];
        for (k, v) in [
            ("account", &f.account),
            ("stage", &f.stage),
            ("agreement", &f.agreement),
            ("folder", &f.folder),
            ("rule", &f.rule),
            ("q", &f.q),
        ] {
            if let Some(v) = nonblank(v) {
                parts.push(format!("{k}={}", encode(v)));
            }
        }
        format!("/?{}", parts.join("&"))
    };
    let select = |name: &str, current: &Option<String>, options: &[&str]| {
        html! {
            select name=(name) {
                option value="" { (name) ": all" }
                @for o in options {
                    option value=(o) selected[nonblank(current) == Some(*o)] { (o) }
                }
            }
        }
    };
    let accounts: Vec<String> = app
        .db
        .read(|c| rows(c, "SELECT name FROM accounts ORDER BY name", &[]))
        .await?
        .into_iter()
        .map(|r| r[0].clone())
        .collect();
    let account_refs: Vec<&str> = accounts.iter().map(String::as_str).collect();
    let body = html! {
        form method="get" action="/" {
            (select("account", &f.account, &account_refs))
            (select("stage", &f.stage, &["operator", "learned", "similar", "retention", "none", "knn", "llm", "correction", "fallback"]))
            (select("agreement", &f.agreement, &["agree", "disagree", "pending", "gone"]))
            input name="folder" placeholder="folder" value=[nonblank(&f.folder)];
            input name="q" placeholder="subject or sender" value=[nonblank(&f.q)];
            button { "Filter" }
        }
        table {
            tr { th { "Time" } th { "Account" } th { "Sender" } th { "Subject" } th { "Stage" } th { "Decided" } th { "Now" } th { "Agreement" } th { "Apply" } }
            @for r in &found {
                // decision_id ts account stage key action dest apply_state apply_error message_id from_addr subject actual actual_inbox agreement
                tr {
                    td { (when(&r[1])) } td { (r[2]) } td { (r[10]) }
                    td { a href={"/message/" (r[9])} { (r[11]) } }
                    td { (r[3]) } td { @if r[5] == "delete" { "Trash" } @else { (r[6]) } }
                    td { (r[12]) } td { (agreement_badge(&r[14], &r[12])) }
                    td title=(r[8]) { (r[7]) }
                }
            }
        }
        p {
            @if page > 0 { a href=(link(page - 1)) { "← newer" } " " }
            @if more { a href=(link(page + 1)) { "older →" } }
        }
    };
    layout(&app.db, "Activity", body).await
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Default)]
struct FolderRow {
    filed: String,
    by_stage: BTreeMap<String, (String, String)>,
    disagree: String,
}

async fn folders(State(app): State<App>) -> Page {
    let since = db::now();
    let latest = latest_sql();
    let table = app
        .db
        .read(move |c| {
            let mut out: BTreeMap<(String, String), FolderRow> = BTreeMap::new();
            for r in rows(
                c,
                "SELECT account, folder, COUNT(*) FROM filed_messages GROUP BY 1, 2",
                &[],
            )? {
                out.entry((r[0].clone(), r[1].clone())).or_default().filed = r[2].clone();
            }
            let sql = format!(
                "SELECT account, dest, stage, SUM(ts >= {w}), SUM(ts >= {m}) FROM decisions \
                 WHERE action = 'file' AND dest IS NOT NULL AND ts >= {m} GROUP BY 1, 2, 3",
                w = since - 7.0 * 86400.0,
                m = since - 30.0 * 86400.0
            );
            for r in rows(c, &sql, &[])? {
                out.entry((r[0].clone(), r[1].clone()))
                    .or_default()
                    .by_stage
                    .insert(r[2].clone(), (r[3].clone(), r[4].clone()));
            }
            let sql = format!(
                "SELECT account, dest, COUNT(*) FROM ({latest}) WHERE agreement = 'disagree' AND dest IS NOT NULL GROUP BY 1, 2"
            );
            for r in rows(c, &sql, &[])? {
                out.entry((r[0].clone(), r[1].clone())).or_default().disagree = r[2].clone();
            }
            Ok(out)
        })
        .await?;
    let body = html! {
        p { "Decisions are counted by stage over the last 7 and 30 days; disagreements are decided messages you moved elsewhere." }
        table {
            tr { th { "Account" } th { "Folder" } th class="num" { "Filed" } th { "Decided into it (7d / 30d)" } th class="num" { "Disagreements" } }
            @for ((account, folder), row) in &table {
                tr {
                    td { (account) }
                    td { a href={"/?account=" (encode(account)) "&folder=" (encode(folder))} { (folder) } }
                    td class="num" { (row.filed) }
                    td { @for (stage, (w, m)) in &row.by_stage { (stage) " " (w) " / " (m) br; } }
                    td class="num" {
                        @if !row.disagree.is_empty() {
                            a href={"/?account=" (encode(account)) "&folder=" (encode(folder)) "&agreement=disagree"} { (row.disagree) }
                        }
                    }
                }
            }
        }
    };
    layout(&app.db, "Folders", body).await
}

const MESSAGE_FIELDS: [&str; 17] = [
    "account",
    "location",
    "folder",
    "category",
    "from_name",
    "from_addr",
    "reply_to",
    "rpath_domain",
    "list_id",
    "subject",
    "subject_tmpl",
    "to_addrs",
    "dkim_d",
    "esp",
    "att_types",
    "att_names",
    "flags",
];

async fn message(State(app): State<App>, Path(id): Path<i64>) -> Response {
    match message_page(app, id).await {
        Ok(Some(page)) => page.into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such message").into_response(),
        Err(e) => e.into_response(),
    }
}

struct Explained {
    decision: Vec<String>,
    rule: Option<String>,
    detail: Value,
    neighbours: Vec<Vec<String>>,
}

async fn message_page(app: App, id: i64) -> Result<Option<Markup>, Failure> {
    let data = app
        .db
        .read(move |c| {
            let sql = format!(
                "SELECT {}, date_ts, gone_at, {ACTUAL} FROM messages m WHERE id = ?1",
                MESSAGE_FIELDS.join(", ")
            );
            let Some(fields) = rows(c, &sql, &[id.to_string()])?.pop() else {
                return Ok(None);
            };
            let decisions = rows(
                c,
                "SELECT id, ts, stage, key, action, dest, confidence, apply_state, applied_at, apply_error, trace_id, detail \
                 FROM decisions WHERE message_id = ?1 ORDER BY id DESC",
                &[id.to_string()],
            )?;
            let mut explained = Vec::new();
            for d in decisions {
                let detail: Value = serde_json::from_str(&d[11]).unwrap_or(Value::Null);
                let rule = if d[2] == "operator" || d[2] == "retention" {
                    rows(c, "SELECT conditions FROM rules WHERE id = ?1", &[d[3].clone()])?
                        .pop()
                        .map(|r| r[0].clone())
                } else {
                    None
                };
                let mut neighbours = Vec::new();
                if let Some(list) = detail.get("neighbours").and_then(Value::as_array) {
                    for n in list {
                        let nid = n.get("id").and_then(Value::as_i64).unwrap_or_default();
                        let subject = rows(c, "SELECT subject FROM messages WHERE id = ?1", &[nid.to_string()])?
                            .pop()
                            .map(|r| r[0].clone())
                            .unwrap_or_default();
                        neighbours.push(vec![
                            nid.to_string(),
                            subject,
                            n.get("folder").and_then(Value::as_str).unwrap_or_default().to_owned(),
                            format!("{:.2}", n.get("score").and_then(Value::as_f64).unwrap_or_default()),
                        ]);
                    }
                }
                explained.push(Explained { decision: d, rule, detail, neighbours });
            }
            let events = rows(
                c,
                "SELECT ts, kind, detail FROM events WHERE message_id = ?1 \
                 OR (kind = 'move' AND json_extract(detail, '$.to_id') = ?1) ORDER BY id",
                &[id.to_string()],
            )?;
            Ok(Some((fields, explained, events)))
        })
        .await?;
    let Some((fields, explained, events)) = data else {
        return Ok(None);
    };
    let n = MESSAGE_FIELDS.len();
    let body = html! {
        table {
            @for (i, name) in MESSAGE_FIELDS.iter().enumerate() {
                @if !fields[i].is_empty() && fields[i] != "[]" { tr { th { (name) } td { (fields[i]) } } }
            }
            tr { th { "date" } td { (when(&fields[n])) } }
            @if !fields[n + 1].is_empty() { tr { th { "gone" } td { (when(&fields[n + 1])) } } }
            tr { th { "now at" } td { @if fields[n + 2].is_empty() { "(gone)" } @else { (fields[n + 2]) } } }
        }
        @for e in &explained {
            @let d = &e.decision;
            h2 { "Decision " (d[0]) ": " (d[2]) " → " @if d[4] == "delete" { "Trash" } @else if d[5].is_empty() { "stays in inbox" } @else { (d[5]) } }
            p {
                (when(&d[1]))
                @if !d[6].is_empty() { " · confidence " (d[6]) }
                @if !d[7].is_empty() { " · apply " (d[7]) @if !d[8].is_empty() { " at " (when(&d[8])) } }
                @if !d[9].is_empty() { " · " (d[9]) }
                @if !d[10].is_empty() {
                    " · trace "
                    @if app.trace_url.is_empty() { code { (d[10]) } }
                    @else { a href=(app.trace_url.replace("{trace_id}", &d[10])) { code { (d[10]) } } }
                }
            }
            @if let Some(rule) = &e.rule { p { "Rule " code { (d[3]) } } pre { (rule) } }
            @if d[2] == "learned" {
                p { "Pattern " code { (d[3]) } ": " (e.detail.get("pattern").and_then(Value::as_str).unwrap_or_default()) }
                @if let Some(counts) = e.detail.get("counts").and_then(Value::as_object) {
                    table { @for (folder, count) in counts { tr { td { (folder) } td class="num" { (count) } } } }
                }
            }
            @if !e.neighbours.is_empty() {
                p { "Nearest filed messages (BM25)" @if let Some(s) = e.detail.get("share").and_then(Value::as_f64) { ", vote share " (format!("{s:.2}")) } }
                table {
                    tr { th { "Subject" } th { "Folder" } th class="num" { "Score" } }
                    @for nb in &e.neighbours { tr { td { a href={"/message/" (nb[0])} { (nb[1]) } } td { (nb[2]) } td class="num" { (nb[3]) } } }
                }
            }
            @if d[2] != "learned" && e.neighbours.is_empty() && e.rule.is_none() && e.detail.as_object().is_some_and(|o| !o.is_empty()) {
                pre { (e.detail.to_string()) }
            }
        }
        @if !events.is_empty() {
            h2 { "Events" }
            table { @for ev in &events { tr { td { (when(&ev[0])) } td { (ev[1]) } td { code { (ev[2]) } } } } }
        }
    };
    let subject = fields[9].clone();
    Ok(Some(layout(&app.db, &subject, body).await?))
}

async fn learned(State(app): State<App>) -> Page {
    let groups = app
        .db
        .read(|c| {
            let mut out = Vec::new();
            for a in rows(c, "SELECT name FROM accounts ORDER BY name", &[])? {
                let patterns = rules::learned_patterns(c, &a[0])?;
                out.push((a[0].clone(), patterns));
            }
            Ok(out)
        })
        .await?;
    let body = html! {
        p { "Sender patterns that file mail today: at least " (rules::MIN_N) " filed messages, " (rules::MIN_PURITY * 100.0) "% in one folder." }
        @for (account, patterns) in &groups {
            h2 { (account) " (" (patterns.len()) ")" }
            table {
                tr { th { "Level" } th { "Pattern" } th { "Folder" } th class="num" { "Messages" } th class="num" { "Purity" } }
                @for p in patterns {
                    tr { td { (p.level) } td { (p.key) } td { (p.dest) } td class="num" { (p.n) } td class="num" { (format!("{:.2}", p.purity)) } }
                }
            }
        }
    };
    layout(&app.db, "Learned patterns", body).await
}

async fn rules_page(State(app): State<App>) -> Page {
    let found = app
        .db
        .read(|c| {
            rows(
                c,
                "SELECT r.position, r.id, r.account, r.action, r.dest, r.conditions, \
                 (SELECT COUNT(*) FROM decisions d WHERE d.stage IN ('operator', 'retention') AND d.key = r.id) \
                 FROM rules r ORDER BY r.position",
                &[],
            )
        })
        .await?;
    let body = html! {
        p { "Operator rules, first match wins. Change them with " code { "mail-organizer rules import" } "." }
        table {
            tr { th { "#" } th { "Id" } th { "Account" } th { "Action" } th { "Conditions" } th class="num" { "Hits" } }
            @for r in &found {
                tr {
                    td { (r[0]) } td { a href={"/?stage=operator&rule=" (encode(&r[1]))} { (r[1]) } } td { @if r[2].is_empty() { "all" } @else { (r[2]) } }
                    td { (r[3]) @if !r[4].is_empty() { " → " (r[4]) } } td { code { (r[5]) } } td class="num" { (r[6]) }
                }
            }
        }
    };
    layout(&app.db, "Rules", body).await
}

async fn stats(State(app): State<App>) -> Page {
    let sql = format!(
        "SELECT CASE WHEN apply_state = 'imported' THEN 'atrium' ELSE 'mail-organizer' END, stage, agreement, COUNT(*) \
         FROM ({}) GROUP BY 1, 2, 3",
        latest_sql()
    );
    let found = app.db.read(move |c| rows(c, &sql, &[])).await?;
    let mut table: BTreeMap<(String, String), BTreeMap<String, i64>> = BTreeMap::new();
    for r in found {
        let n = r[3].parse().unwrap_or(0);
        table
            .entry((r[0].clone(), r[1].clone()))
            .or_default()
            .insert(r[2].clone(), n);
    }
    let columns = ["agree", "disagree", "pending", "gone"];
    let body = html! {
        p { "Latest decision per message, by where the message is now. Accuracy = agree / (agree + disagree)." }
        table {
            tr { th { "Source" } th { "Stage" } @for c in columns { th class="num" { (c) } } th class="num" { "Accuracy" } }
            @for ((source, stage), counts) in &table {
                @let agree = counts.get("agree").copied().unwrap_or(0);
                @let disagree = counts.get("disagree").copied().unwrap_or(0);
                tr {
                    td { (source) } td { (stage) }
                    @for c in columns { td class="num" { (counts.get(c).copied().unwrap_or(0)) } }
                    td class="num" { @if agree + disagree > 0 { (format!("{:.2}", agree as f64 / (agree + disagree) as f64)) } }
                }
            }
        }
    };
    layout(&app.db, "Stats", body).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(when("0"), "1970-01-01 00:00");
        assert_eq!(when("1795534403.0"), "2026-11-24 15:33");
        assert_eq!(when(""), "");
    }
}
