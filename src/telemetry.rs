//! Logs to stdout (journald), and optionally the same `tracing` spans bridged to
//! OpenTelemetry and posted over OTLP/HTTP. garret's telemetry, trimmed to one
//! binary.

use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use opentelemetry::trace::{SpanContext, TraceContextExt, TracerProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    trace::{Sampler, SdkTracer, SdkTracerProvider},
};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::config::TelemetryConfig;

/// One export attempt; the batch processor exports on its own thread, so a dead
/// collector only drops spans.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Telemetry {
    provider: Option<SdkTracerProvider>,
}

impl Telemetry {
    pub fn disabled() -> Self {
        Self { provider: None }
    }

    pub fn start(config: &TelemetryConfig) -> Result<Self> {
        if !config.enabled {
            return Ok(Self::disabled());
        }
        let endpoint = format!("{}/v1/traces", config.endpoint.trim_end_matches('/'));
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_timeout(EXPORT_TIMEOUT)
            .build()
            .context("building the OTLP span exporter")?;
        let provider = SdkTracerProvider::builder()
            .with_resource(
                Resource::builder()
                    .with_service_name(config.service_name.clone())
                    .build(),
            )
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                config.sample_ratio,
            ))))
            .with_batch_exporter(exporter)
            .build();
        Ok(Self {
            provider: Some(provider),
        })
    }

    pub fn tracer(&self) -> Option<SdkTracer> {
        self.provider
            .as_ref()
            .map(|p| p.tracer(env!("CARGO_PKG_NAME")))
    }

    pub fn shutdown(mut self) {
        self.stop();
    }

    /// On a plain thread: the exporter's blocking reqwest client panics when
    /// shut down or dropped inside the tokio runtime.
    fn stop(&mut self) {
        let Some(provider) = self.provider.take() else {
            return;
        };
        let flushed = std::thread::spawn(move || {
            let flushed = provider.shutdown();
            drop(provider);
            flushed
        })
        .join();
        match flushed {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("flushing spans on shutdown: {e}"),
            Err(_) => tracing::warn!("the span exporter's flush thread panicked"),
        }
    }
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Plain text to stdout at `RUST_LOG` (default `info`), colour only on a
/// terminal. With a tracer, this crate's spans are also exported; dependency
/// spans are not, and their WARN/ERROR events attach to the active span.
pub fn init_tracing(tracer: Option<SdkTracer>) {
    use std::io::IsTerminal;
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::prelude::*;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt = tracing_subscriber::fmt::layer()
        .with_ansi(std::io::stdout().is_terminal())
        .with_filter(filter);
    let registry = tracing_subscriber::registry().with(fmt);
    match tracer {
        Some(tracer) => registry
            .with(
                tracing_opentelemetry::layer()
                    .with_tracer(tracer)
                    .with_location(false)
                    .with_threads(false)
                    .with_tracked_inactivity(false)
                    .with_filter(
                        Targets::new()
                            .with_target("mail_organizer", LevelFilter::TRACE)
                            .with_default(LevelFilter::WARN),
                    ),
            )
            .init(),
        None => registry.init(),
    }
}

/// Hex trace and span ids of the current span, when it is being exported.
pub fn current_ids() -> Option<(String, String)> {
    let context = tracing::Span::current().context();
    let span = context.span();
    let sc = span.span_context();
    sc.is_valid()
        .then(|| (sc.trace_id().to_string(), sc.span_id().to_string()))
}

/// Links the current span to an earlier span given by hex ids.
pub fn link_to(trace_id: &str, span_id: &str) {
    let (Ok(trace), Ok(span)) = (
        opentelemetry::trace::TraceId::from_hex(trace_id),
        opentelemetry::trace::SpanId::from_hex(span_id),
    ) else {
        return;
    };
    let context = SpanContext::new(
        trace,
        span,
        opentelemetry::trace::TraceFlags::SAMPLED,
        true,
        Default::default(),
    );
    tracing::Span::current().add_link(context);
}

/// One server span per request, named `{method} {route}` after the matched
/// route so ids in paths never become span names.
pub async fn track_http(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned());
    let name = match &route {
        Some(route) => format!("{method} {route}"),
        None => format!("{method} unmatched"),
    };
    let span = tracing::debug_span!(
        "http.request",
        otel.name = name.as_str(),
        otel.kind = "server",
        http.request.method = %method,
        http.route = route.as_deref().unwrap_or("unmatched"),
        http.response.status_code = tracing::field::Empty,
    );
    let response = next.run(request).instrument(span.clone()).await;
    span.record("http.response.status_code", response.status().as_u16());
    response
}
