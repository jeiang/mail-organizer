//! Prometheus metrics on a separate internal listener.

use anyhow::{Context, Result};
use axum::{Router, routing::get};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

fn latency_buckets() -> Vec<f64> {
    vec![
        0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 900.0,
    ]
}

pub fn install() -> Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Suffix("_duration_seconds".into()),
            &latency_buckets(),
        )?
        .install_recorder()
        .context("installing the Prometheus recorder")?;
    metrics::gauge!("mail_organizer_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
    metrics::gauge!("process_start_time_seconds").set(crate::db::now());
    Ok(handle)
}

pub fn router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route(
            "/metrics",
            get(move || {
                let handle = handle.clone();
                async move { handle.render() }
            }),
        )
        .route("/healthz", get(|| async { "ok" }))
}

pub fn pass_finished(account: &str, seconds: f64, ok: bool) {
    let account = account.to_owned();
    metrics::histogram!("mail_organizer_pass_duration_seconds", "account" => account.clone())
        .record(seconds);
    if ok {
        metrics::gauge!("mail_organizer_last_pass_success_timestamp_seconds", "account" => account)
            .set(crate::db::now());
    } else {
        metrics::counter!("mail_organizer_pass_errors_total", "account" => account).increment(1);
    }
}

pub fn synced(account: &str, kind: &'static str, n: u64) {
    metrics::counter!("mail_organizer_sync_messages_total", "account" => account.to_owned(), "kind" => kind)
        .increment(n);
}

pub fn decided(account: &str, stage: &str, action: &str, dest: Option<&str>) {
    metrics::counter!(
        "mail_organizer_decisions_total",
        "account" => account.to_owned(), "stage" => stage.to_owned(), "action" => action.to_owned(),
    )
    .increment(1);
    if let (Some(folder), "file") = (dest, action) {
        metrics::counter!(
            "mail_organizer_filed_total",
            "account" => account.to_owned(), "stage" => stage.to_owned(), "folder" => folder.to_owned(),
        )
        .increment(1);
    }
}

pub fn applied(account: &str, result: &'static str, reason: &str) {
    metrics::counter!(
        "mail_organizer_apply_total",
        "account" => account.to_owned(), "result" => result, "reason" => reason.to_owned(),
    )
    .increment(1);
}

pub fn inbox(account: &str, n: i64) {
    metrics::gauge!("mail_organizer_inbox_messages", "account" => account.to_owned()).set(n as f64);
}

pub fn live(account: &str, live: bool) {
    metrics::gauge!("mail_organizer_live", "account" => account.to_owned()).set(if live {
        1.0
    } else {
        0.0
    });
}
