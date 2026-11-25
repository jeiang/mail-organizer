//! Mail activity, exceptions, and rule management.

mod editor;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
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
    csrf: Arc<str>,
    listen_host: Arc<str>,
}

pub fn router(db: Db, config: &Config) -> Router {
    let mut token = [0; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut token)
        .expect("secure randomness");
    let app = App {
        db,
        csrf: hex::encode(token).into(),
        listen_host: config
            .listen
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "127.0.0.1".into())
            .into(),
        trace_url: config.trace_url_template.as_str().into(),
    };
    Router::new()
        .route("/", get(activity))
        .route("/folders", get(folders))
        .route("/message/{id}", get(message))
        .route("/learned", get(learned))
        .route("/rules", get(rules_page))
        .route("/stats", get(stats))
        .route("/inbox", get(inbox))
        .route("/status", get(status))
        .route("/status.js", get(status_script))
        .route("/refresh", axum::routing::post(refresh))
        .route("/retry/{id}", axum::routing::post(retry))
        .merge(editor::routes())
        .layer(DefaultBodyLimit::max(65536))
        .layer(axum::middleware::from_fn_with_state(app.clone(), protect))
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
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

fn agreement_badge(agreement: &str, actual: &str) -> Markup {
    let label = match agreement {
        "agree" => "same folder".to_owned(),
        "pending" => "still in inbox".to_owned(),
        "gone" => "gone".to_owned(),
        _ => format!("different folder → {actual}"),
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
                script type="module" src="/status.js" {}
            }
            body {
                a class="skip-link" href="#main" { "Skip to content" }
                header {
                    nav {
                        @for (href, label, active) in [
                            ("/", "Overview", title == "Activity"),
                            ("/inbox", "Inbox / needs review", title == "Inbox"),
                            ("/folders", "Folders", title == "Folders"),
                            ("/learned", "Learned patterns", title == "Learned patterns"),
                            ("/rules", "Your rules", title.contains("rule") || title == "Your rules"),
                            ("/stats", "Folder agreement", title == "Folder agreement")
                        ] { a href=(href) aria-current=[active.then_some("page")] { (label) } }
                    }
                    p {
                        span class={"badge " (mode.as_str())} { @if mode == db::Mode::Live { "Automatic sorting on" } @else { "Preview only" } }
                        span data-status="" aria-live="polite" { @for a in &accounts {
                            " " (a[0]) ": synced " (when(&a[1]))
                            @if !a[2].is_empty() {
                                @let (at, msg) = a[2].split_once('\t').unwrap_or(("", &a[2]));
                                " " span class="error" { "error " (when(at)) ": " (msg) }
                            }
                        } }
                    }
                }
                main { h1 id="main" tabindex="-1" { (title) } (body) }
            }
        }
    })
}

const STYLE: &str = "body{font:1rem/1.5 system-ui,sans-serif;margin:0 1rem;color:#222}\
header{border-bottom:1px solid #ddd}nav{display:flex;flex-wrap:wrap;gap:.25rem 1rem;padding-block:.5rem}nav a{display:inline-flex;align-items:center;min-block-size:2.75rem}\
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.25rem .5rem;border-bottom:1px solid #eee;vertical-align:top}\
.badge{padding:0 .4rem;border-radius:.5rem;background:#eee;white-space:nowrap}\
.agree,.live{background:#d4f4d4}.disagree{background:#f8d4d4}.pending,.shadow{background:#f4ecc4}\
form input,form select{margin-right:.5rem}pre{white-space:pre-wrap;background:#f6f6f6;padding:.5rem}\
.num{text-align:right}\
.table-wrapper{overflow:auto;max-inline-size:100%;margin-block:1rem}caption{text-align:left;font-weight:600}\
input,select,textarea,button{font:inherit;max-inline-size:100%;box-sizing:border-box}button{min-block-size:2.75rem;cursor:pointer}\
label{display:block;margin-block-start:.75rem}fieldset{margin-block:1rem}textarea{display:block;inline-size:35rem}\
:focus-visible{outline:3px solid #2463b6;outline-offset:3px}[aria-current=page]{font-weight:700;text-decoration-thickness:.2em}\
.skip-link{position:absolute;inset-inline-start:-10000px}.skip-link:focus{position:static}\
.error{color:#8b1717;font-weight:600}form{margin-block:1rem}pre{overflow-wrap:anywhere}\
input:user-invalid,textarea:user-invalid{outline:2px solid #8b1717}";

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
            label for=(name) { @if name == "stage" { "Sorting method" } @else if name == "agreement" { "Folder agreement" } @else { (name) } }
            select id=(name) name=(name) {
                option value="" { (name) ": all" }
                @for o in options {
                    option value=(o) selected[nonblank(current) == Some(*o)] { @if name == "stage" { (stage_label(o)) } @else { (o) } }
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
        (exception_summary(&app).await?)
        search { form method="get" action="/" {
            (select("account", &f.account, &account_refs))
            (select("stage", &f.stage, &["operator", "learned", "similar", "retention", "none", "knn", "llm", "correction", "fallback"]))
            (select("agreement", &f.agreement, &["agree", "disagree", "pending", "gone"]))
            label for="folder" { "Destination folder" }
            input id="folder" name="folder" value=[nonblank(&f.folder)];
            label for="q" { "Subject or sender" }
            input id="q" name="q" type="search" value=[nonblank(&f.q)];
            button type="submit" { "Filter" }
        } }
        div class="table-wrapper" role="region" aria-label="Recent decisions" tabindex="0" { table { caption { "Recent decisions" }
            thead { tr { th scope="col" { "Time" } th scope="col" { "Account" } th scope="col" { "Sender" } th scope="col" { "Subject" } th scope="col" { "Stage" } th scope="col" { "Decided" } th scope="col" { "Now" } th scope="col" { "Agreement" } th scope="col" { "Apply" } } } tbody {
            @for r in &found {
                // decision_id ts account stage key action dest apply_state apply_error message_id from_addr subject actual actual_inbox agreement
                tr {
                    td { (when(&r[1])) } td { (r[2]) } td { (r[10]) }
                    td { a href={"/message/" (r[9])} { (subject_text(&r[11])) } }
                    td { (stage_label(&r[3])) } td { @if r[5] == "delete" { "Trash" } @else { (r[6]) } }
                    td { (r[12]) } td { (agreement_badge(&r[14], &r[12])) }
                    td { (r[7]) @if !r[8].is_empty() { br; (r[8]) } }
                }
            }
        } } }
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
        p { "Decisions are counted by stage over the last 7 and 30 days; differences compare the chosen folder with the current location." }
        div class="table-wrapper" role="region" aria-label="Folder overview" tabindex="0" { table { caption { "Folder overview" }
            thead { tr { th scope="col" { "Account" } th scope="col" { "Folder" } th scope="col" class="num" { "Filed" } th scope="col" { "Decided into it (7d / 30d)" } th scope="col" class="num" { "Disagreements" } } } tbody {
            @for ((account, folder), row) in &table {
                tr {
                    td { (account) }
                    td { a href={"/?account=" (encode(account)) "&folder=" (encode(folder))} { (folder) } }
                    td class="num" { (row.filed) }
                    td { @for (stage, (w, m)) in &row.by_stage { (stage_label(stage)) " " (w) " / " (m) br; } }
                    td class="num" {
                        @if !row.disagree.is_empty() {
                            a href={"/?account=" (encode(account)) "&folder=" (encode(folder)) "&agreement=disagree"} { (row.disagree) }
                        }
                    }
                }
            }
        } } }
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
                let rule = if let Some(snapshot) = detail.get("rule") { Some(serde_json::to_string_pretty(snapshot)?) } else if d[2] == "operator" || d[2] == "retention" {
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
        div class="table-wrapper" role="region" aria-label="Message details" tabindex="0" { table { caption { "Message details" }
            @for (i, name) in MESSAGE_FIELDS.iter().enumerate() {
                @if !fields[i].is_empty() && fields[i] != "[]" { tr { th scope="row" { (name) } td { (fields[i]) } } }
            }
            tr { th scope="row" { "date" } td { (when(&fields[n])) } }
            @if !fields[n + 1].is_empty() { tr { th scope="row" { "gone" } td { (when(&fields[n + 1])) } } }
            tr { th scope="row" { "now at" } td { @if fields[n + 2].is_empty() { "(gone)" } @else { (fields[n + 2]) } } }
        } }
        @for e in &explained {
            @let d = &e.decision;
            h2 { "Decision " (d[0]) ": " (stage_label(&d[2])) " → " @if d[4] == "delete" { "Trash" } @else if d[5].is_empty() { "stays in inbox" } @else { (d[5]) } }
            p {
                (when(&d[1]))
                @if !d[6].is_empty() { " · evidence share " (d[6]) }
                @if !d[7].is_empty() { " · apply " (d[7]) @if !d[8].is_empty() { " at " (when(&d[8])) } }
                @if !d[9].is_empty() { " · " (d[9]) }
                @if !d[10].is_empty() {
                    " · trace "
                    @if app.trace_url.is_empty() { code { (d[10]) } }
                    @else { a href=(app.trace_url.replace("{trace_id}", &d[10])) { code { (d[10]) } } }
                }
            }
            @if let Some(rule) = &e.rule { p { "Rule " code { (d[3]) } @if e.detail.get("rule").is_none() { " (current definition; historical snapshot unavailable)" } } pre { (rule) } }
            @if d[2] == "learned" {
                p { "Pattern " code { (d[3]) } ": " (e.detail.get("pattern").and_then(Value::as_str).unwrap_or_default()) }
                @if let Some(counts) = e.detail.get("counts").and_then(Value::as_object) {
                    div class="table-wrapper" role="region" aria-label="Pattern examples" tabindex="0" { table { caption { "Pattern examples" } thead { tr { th scope="col" { "Folder" } th scope="col" { "Examples" } } } tbody { @for (folder, count) in counts { tr { td { (folder) } td class="num" { (count) } } } } } }
                }
            }
            @if !e.neighbours.is_empty() {
                p { "Similar filed messages (text search; shares are not correctness probabilities)" @if let Some(s) = e.detail.get("share").and_then(Value::as_f64) { ", vote share " (format!("{s:.2}")) } }
                div class="table-wrapper" role="region" aria-label="Similar filed messages" tabindex="0" { table { caption { "Similar filed messages" }
                    thead { tr { th scope="col" { "Subject" } th scope="col" { "Folder" } th scope="col" class="num" { "Score" } } } tbody {
                    @for nb in &e.neighbours { tr { td { a href={"/message/" (nb[0])} { (subject_text(&nb[1])) } } td { (nb[2]) } td class="num" { (nb[3]) } } }
                } } }
            }
            @if d[2] != "learned" && e.neighbours.is_empty() && e.rule.is_none() && e.detail.as_object().is_some_and(|o| !o.is_empty()) {
                pre { (e.detail.to_string()) }
            }
        }
        @if !events.is_empty() {
            h2 { "Events" }
            div class="table-wrapper" role="region" aria-label="Message events" tabindex="0" { table { caption { "Message events" } thead { tr { th scope="col" { "Time" } th scope="col" { "Event" } th scope="col" { "Details" } } } tbody { @for ev in &events { tr { td { (when(&ev[0])) } td { (ev[1]) } td { code { (ev[2]) } } } } } } }
        }
    };
    let subject = subject_text(&fields[9]).to_owned();
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
        p { "Sender patterns that file mail today: at least " (rules::MIN_N) " examples, " (rules::MIN_PURITY * 100.0) "% in one folder. Misc, duplicate copies, and known automatic filings are excluded. Imported examples are not independently verified." }
        @for (account, patterns) in &groups {
            h2 { (account) " (" (patterns.len()) ")" }
            div class="table-wrapper" role="region" aria-label="Learned patterns" tabindex="0" { table { caption { "Learned patterns" }
                thead { tr { th scope="col" { "Level" } th scope="col" { "Pattern" } th scope="col" { "Folder" } th scope="col" class="num" { "Messages" } th scope="col" class="num" { "Folder share" } th scope="col" { "Override" } } } tbody {
                @for p in patterns {
                    tr { td { (p.level) } td { (p.key) } td { (p.dest) } td class="num" { (p.n) } td class="num" { (format!("{:.2}", p.purity)) } td { a href={"/rules/edit?account=" (encode(account)) "&level=" (encode(p.level)) "&pattern=" (encode(&serde_json::to_string(&p.values)?))} { "Edit / override" } } }
                }
            } } }
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
        p { "Your rules take priority over learning. First match wins. CLI import replaces the entire ruleset." }
        p { a href="/rules/edit" { "Add rule" } }
        div class="table-wrapper" role="region" aria-label="Your rules" tabindex="0" { table { caption { "Your rules" }
            thead { tr { th scope="col" { "#" } th scope="col" { "Id" } th scope="col" { "Account" } th scope="col" { "Action" } th scope="col" { "Conditions" } th scope="col" class="num" { "Hits" } th scope="col" { "Edit" } } } tbody {
            @for r in &found {
                tr {
                    td { (r[0]) } td { a href={"/?stage=operator&rule=" (encode(&r[1]))} { (r[1]) } } td { @if r[2].is_empty() { "all" } @else { (r[2]) } }
                    td { (r[3]) @if !r[4].is_empty() { " → " (r[4]) } } td { code { (r[5]) } } td class="num" { (r[6]) } td { a href={"/rules/edit?id=" (encode(&r[1]))} { "Edit" } }
                }
            }
        } } }
    };
    layout(&app.db, "Your rules", body).await
}

async fn stats(State(app): State<App>) -> Page {
    let sql = format!(
        "SELECT CASE WHEN apply_state = 'imported' THEN 'Imported history' ELSE 'Current sorter' END, stage, agreement, COUNT(*) \
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
        p { "Latest decision per message, by where the message is now. Agreement includes automatic filing; it is not independently verified accuracy." }
        div class="table-wrapper" role="region" aria-label="Folder agreement" tabindex="0" { table { caption { "Folder agreement" }
            thead { tr { th scope="col" { "Source" } th scope="col" { "Stage" } @for c in columns { th scope="col" class="num" { (c) } } th scope="col" class="num" { "Folder agreement" } } } tbody {
            @for ((source, stage), counts) in &table {
                @let agree = counts.get("agree").copied().unwrap_or(0);
                @let disagree = counts.get("disagree").copied().unwrap_or(0);
                tr {
                    td { (source) } td { (stage_label(stage)) }
                    @for c in columns { td class="num" { (counts.get(c).copied().unwrap_or(0)) } }
                    td class="num" { @if agree + disagree > 0 { (format!("{:.2}", agree as f64 / (agree + disagree) as f64)) } }
                }
            }
        } } }
    };
    layout(&app.db, "Folder agreement", body).await
}

fn subject_text(subject: &str) -> &str {
    if subject.trim().is_empty() {
        "(No subject)"
    } else {
        subject
    }
}

fn stage_label(stage: &str) -> &str {
    match stage {
        "operator" => "Your rule",
        "learned" => "Learned pattern",
        "similar" => "Similar mail",
        "retention" => "Retention rule",
        "none" => "Needs review",
        "knn" => "Similar mail (imported)",
        "llm" => "AI decision (imported)",
        "correction" => "Correction (imported)",
        "fallback" => "Fallback (imported)",
        other => other,
    }
}

fn valid_csrf(app: &App, supplied: &str) -> bool {
    supplied.len() == app.csrf.len()
        && supplied
            .bytes()
            .zip(app.csrf.bytes())
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}

async fn protect(
    State(app): State<App>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let authority = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<axum::http::uri::Authority>().ok());
    let Some(authority) = authority else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let trusted = host == "localhost"
        || host == app.listen_host.as_ref()
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !trusted {
        return StatusCode::FORBIDDEN.into_response();
    }
    if request.method() != axum::http::Method::GET && request.method() != axum::http::Method::HEAD {
        let origin_ok = request.headers().get("origin").is_none_or(|o| {
            o.to_str().is_ok_and(|o| {
                o == format!("http://{authority}") || o == format!("https://{authority}")
            })
        });
        if !origin_ok
            || request
                .headers()
                .get("sec-fetch-site")
                .is_some_and(|s| s == "cross-site")
        {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    let mut response = next.run(request).await;
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        (
            "content-security-policy",
            "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'",
        ),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(name),
            axum::http::HeaderValue::from_static(value),
        );
    }
    response
}

async fn status_script() -> impl IntoResponse {
    (
        [("content-type", "text/javascript; charset=utf-8")],
        r#"
const status = document.querySelector('[data-status]');
async function update() {
  if (!status || document.hidden) return;
  try {
    const response = await fetch('/status');
    if (!response.ok) return;
    const data = await response.json();
    if (status.textContent !== data.summary) status.textContent = data.summary;
  } catch {}
}
update();
setInterval(update, 15000);
"#,
    )
}

async fn status(State(app): State<App>) -> Result<axum::Json<Value>, Failure> {
    let summary = app.db.read(|c| {
        let accounts = rows(c, "SELECT name,last_sync_at,(SELECT value FROM state WHERE key = 'error:' || name) FROM accounts ORDER BY name", &[])?;
        let mut summary = Vec::new();
        for a in accounts {
            let stale = a[1].parse::<f64>().is_ok_and(|t| db::now() - t > 20.0 * 60.0);
            let error = a[2].split_once('\t').map(|(_,m)| m).unwrap_or(&a[2]);
            summary.push(format!("{}: synced {}{}{}",a[0],when(&a[1]),if stale { " (stale)" } else { "" },
                if error.is_empty() { String::new() } else { format!(" — error: {error}") }));
        }
        let inbox: i64 = c.query_row("SELECT COUNT(*) FROM messages WHERE gone_at IS NULL AND in_inbox = 1 AND sent = 0", [], |r| r.get(0))?;
        summary.push(format!("{inbox} messages in Inbox"));
        Ok(summary.join(" · "))
    }).await?;
    Ok(axum::Json(serde_json::json!({"summary":summary})))
}

async fn exception_summary(app: &App) -> Page {
    let counts = app
        .db
        .read(|c| {
            rows(
                c,
                "SELECT account,COUNT(*),SUM(seen = 0),SUM(flagged = 1),MIN(first_seen)
         FROM messages WHERE gone_at IS NULL AND in_inbox = 1 AND sent = 0 GROUP BY account",
                &[],
            )
        })
        .await?;
    Ok(html! {
        section aria-label="Needs attention" {
            h2 { a href="/inbox" { "Inbox / needs review" } }
            @if counts.is_empty() { p { "Inbox is clear." } }
            @for c in &counts { p { (c[0]) ": " (c[1]) " in Inbox; " (c[2]) " unread, " (c[3]) " flagged. Oldest first seen " (when(&c[4])) "." } }
            p { "Unread and flagged mail stays protected. Unmatched mail is reconsidered after each sync. Misc is excluded from learning." }
            form method="post" action="/refresh" {
                input type="hidden" name="csrf" value=(app.csrf.as_ref());
                button type="submit" { "Refresh mail now" }
            }
        }
    })
}

async fn inbox(State(app): State<App>) -> Page {
    let messages = app.db.read(|c| rows(c,
        "SELECT m.id,m.account,m.date_ts,m.from_addr,m.subject,m.seen,m.flagged,d.id,d.stage,d.apply_state,d.apply_error,d.detail,m.first_seen
         FROM messages m LEFT JOIN decisions d ON d.id = (SELECT MAX(id) FROM decisions WHERE message_id = m.id)
         WHERE m.gone_at IS NULL AND m.in_inbox = 1 AND m.sent = 0 ORDER BY m.first_seen,m.id", &[])).await?;
    let body = html! {
        (exception_summary(&app).await?)
        p { "Account status updates every 15 seconds without changing forms or focus. " a href="/inbox" { "Reload this message list" } "." }
        div class="table-wrapper" role="region" aria-label="Current Inbox messages" tabindex="0" { table {
            caption { "Current Inbox messages" }
            thead { tr { th scope="col" { "Account / received" } th scope="col" { "Sender / subject" } th scope="col" { "Why it remains" } th scope="col" { "Action" } } }
            tbody { @for m in &messages {
                @let detail = serde_json::from_str::<Value>(&m[11]).unwrap_or_default();
                tr {
                    td { (m[1]) br; (when(&m[2])) }
                    td { (m[3]) br; a href={"/message/" (m[0])} { (subject_text(&m[4])) } }
                    td {
                        @if m[6] == "1" { "Flagged: protected" }
                        @else if m[5] == "0" { "Unread: waiting until read" }
                        @else if m[9] == "pending" { "Queued for application" }
                        @else if m[9] == "failed" { "Server refused the action: " (m[10]) }
                        @else if m[9] == "done" || m[9] == "imported" { "Previously decided; not automatically replayed" }
                        @else if !m[10].is_empty() { "Waiting after safety check: " (m[10]) }
                        @else if m[8] == "none" { (detail.get("reason").and_then(Value::as_str).unwrap_or("No confident match; reconsidered after each sync")) }
                        @else if m[7].is_empty() { "Awaiting evaluation" }
                        @else { "Preview decision; no action queued" }
                    }
                    td { @if m[9] == "failed" {
                        form method="post" action={"/retry/" (m[7])} {
                            input type="hidden" name="csrf" value=(app.csrf.as_ref());
                            button type="submit" { "Retry with safety checks" }
                        }
                    } }
                }
            } }
        } }
    };
    layout(&app.db, "Inbox", body).await
}

async fn refresh(
    State(app): State<App>,
    axum::Form(form): axum::Form<BTreeMap<String, String>>,
) -> Response {
    if !valid_csrf(
        &app,
        form.get("csrf").map(String::as_str).unwrap_or_default(),
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    app.db.refresh.send_replace(());
    axum::response::Redirect::to("/inbox").into_response()
}

async fn retry(
    State(app): State<App>,
    Path(id): Path<i64>,
    axum::Form(form): axum::Form<BTreeMap<String, String>>,
) -> Response {
    if !valid_csrf(
        &app,
        form.get("csrf").map(String::as_str).unwrap_or_default(),
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let _mutation = app.db.mutations.lock().await;
    let result = app.db.write(move |c| {
        c.execute("UPDATE decisions SET apply_state = 'pending',apply_error = NULL WHERE id = ?1 AND apply_state = 'failed'
            AND id = (SELECT MAX(d.id) FROM decisions d WHERE d.message_id = decisions.message_id)
            AND EXISTS(SELECT 1 FROM messages m WHERE m.id = decisions.message_id AND m.gone_at IS NULL)", [id])?;
        Ok(())
    }).await;
    match result {
        Ok(()) => {
            app.db.refresh.send_replace(());
            axum::response::Redirect::to("/inbox").into_response()
        }
        Err(e) => Failure(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(when("0"), "1970-01-01 00:00 UTC");
        assert_eq!(when("1795534403.0"), "2026-11-24 15:33 UTC");
        assert_eq!(when(""), "");
    }
}
