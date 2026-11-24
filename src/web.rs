//! Read-only web UI.

use axum::{Router, routing::get};

use crate::config::Config;
use crate::db::Db;

pub fn router(_db: Db, _config: &Config) -> Router {
    Router::new()
        .route("/", get(|| async { "mail-organizer" }))
        .layer(axum::middleware::from_fn(crate::telemetry::track_http))
}
