//! Prometheus metrics + HTTP health/readiness endpoint.
//!
//! Starts a lightweight HTTP server (using axum 0.8) that exposes:
//!
//! - `GET /healthz` → 200 OK with body `"ok"`
//! - `GET /readyz`  → 200 OK when the instance is ready
//! - `GET /metrics` → Prometheus text format
//! - `GET /version` → JSON `{"version":"0.1.0"}`
//!
//! # Metrics
//!
//! | Metric | Type | Labels |
//! |--------|------|--------|
//! | `proxy_connections_total` | Counter | `inbound`, `protocol` |
//! | `proxy_bytes_total` | Counter | `direction` (rx/tx), `inbound` |
//! | `proxy_active_connections` | Gauge | `inbound` |
//! | `proxy_connection_duration_seconds` | Histogram | `inbound` |
//! | `proxy_inbound_parse_seconds` | Histogram | `inbound` |
//! | `proxy_route_seconds` | Histogram | `inbound` |
//! | `proxy_dns_seconds` | Histogram | `inbound` |
//! | `proxy_outbound_connect_seconds` | Histogram | `inbound`, `outbound` |
//! | `proxy_relay_errors_total` | Counter | `inbound` |
//! | `proxy_relay_first_byte_failures_total` | Counter | `inbound` |
//! | `proxy_relay_splice_selected_total` | Counter | `policy` |
//! | `proxy_relay_splice_fallback_total` | Counter | `reason` |
//! | `proxy_relay_bytes_total` | Counter | `direction`, `path` |
//! | `freedom_pool_leases_total` | Counter | `outbound` |
//!
//! # Usage
//!
//! Call [`start_metrics_server`] once during startup to bind the HTTP server.
//! Recording metrics is done via the `metrics` crate macros anywhere in the
//! codebase after the recorder has been installed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::runtime_stats;

/// Shared state for the metrics HTTP server.
#[derive(Clone)]
struct MetricsState {
    prometheus_handle: Arc<PrometheusHandle>,
    ready: bool,
}

/// Start the metrics HTTP server.
///
/// Installs the Prometheus recorder globally and starts listening on `addr`.
/// Call this once at proxy startup.
///
/// # Arguments
/// * `addr` — bind address, e.g. `"127.0.0.1:8080"`
///
/// # Returns
/// A `JoinHandle` for the background server task. Keep alive as long as
/// the proxy is running.
///
/// # Errors
/// Returns an error if the address is invalid or the server fails to bind.
pub fn start_metrics_server(addr: &str) -> anyhow::Result<JoinHandle<()>> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid metrics addr '{addr}': {e}"))?;

    // Install the Prometheus recorder.
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("failed to install Prometheus recorder: {e}"))?;

    // Describe metrics so Prometheus scrape shows help text.
    describe_metrics();

    let state = MetricsState {
        prometheus_handle: Arc::new(handle),
        ready: true,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .route("/version", get(version_handler))
        .with_state(state);

    let std_listener = std::net::TcpListener::bind(addr)
        .map_err(|e| anyhow::anyhow!("metrics server failed to bind {addr}: {e}"))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("metrics server failed to set nonblocking {addr}: {e}"))?;
    let listener = tokio::net::TcpListener::from_std(std_listener)
        .map_err(|e| anyhow::anyhow!("metrics server failed to adopt listener {addr}: {e}"))?;

    let task = tokio::spawn(async move {
        info!(addr = %addr, "metrics server starting");
        if let Err(e) = axum::serve(listener, app).await {
            error!(error = %e, "metrics server error");
        }
    });

    Ok(task)
}

/// Describe all metrics so the Prometheus scrape output includes help/type annotations.
fn describe_metrics() {
    metrics::describe_counter!(
        "proxy_connections_total",
        metrics::Unit::Count,
        "Total number of proxy connections accepted"
    );
    metrics::describe_counter!(
        "proxy_bytes_total",
        metrics::Unit::Bytes,
        "Total bytes relayed through the proxy"
    );
    metrics::describe_gauge!(
        "proxy_active_connections",
        metrics::Unit::Count,
        "Currently open proxy connections"
    );
    metrics::describe_histogram!(
        "proxy_connection_duration_seconds",
        metrics::Unit::Seconds,
        "Connection lifetime in seconds"
    );
    metrics::describe_histogram!(
        "proxy_inbound_parse_seconds",
        metrics::Unit::Seconds,
        "Time to decode the inbound protocol header (VLESS/Trojan/etc.)"
    );
    metrics::describe_histogram!(
        "proxy_route_seconds",
        metrics::Unit::Seconds,
        "Time to select an outbound via the routing engine"
    );
    metrics::describe_histogram!(
        "proxy_dns_seconds",
        metrics::Unit::Seconds,
        "Time spent in DNS resolution during routing (IpOnDemand / IpIfNonMatch)"
    );
    metrics::describe_histogram!(
        "proxy_outbound_connect_seconds",
        metrics::Unit::Seconds,
        "Time to establish the outbound connection (TCP dial + TLS/REALITY handshake)"
    );
    metrics::describe_counter!(
        "proxy_relay_errors_total",
        metrics::Unit::Count,
        "Total relay errors by inbound"
    );
    metrics::describe_counter!(
        "proxy_relay_first_byte_failures_total",
        metrics::Unit::Count,
        "Relay errors before the dispatcher could record transferred bytes"
    );
    metrics::describe_counter!(
        "proxy_relay_splice_selected_total",
        metrics::Unit::Count,
        "Raw TCP relays selected for splice by policy"
    );
    metrics::describe_counter!(
        "proxy_relay_splice_fallback_total",
        metrics::Unit::Count,
        "Raw TCP relays that fell back from splice"
    );
    metrics::describe_counter!(
        "proxy_relay_bytes_total",
        metrics::Unit::Bytes,
        "Bytes relayed by path-specific relay implementation"
    );
    metrics::describe_counter!(
        "freedom_pool_hits_total",
        metrics::Unit::Count,
        "Freedom outbound preconnect pool hits after first client write succeeds"
    );
    metrics::describe_counter!(
        "freedom_pool_leases_total",
        metrics::Unit::Count,
        "Freedom outbound preconnect pool sockets leased before first-use validation"
    );
    metrics::describe_counter!(
        "freedom_pool_misses_total",
        metrics::Unit::Count,
        "Freedom outbound preconnect pool misses"
    );
    metrics::describe_counter!(
        "freedom_pool_stales_total",
        metrics::Unit::Count,
        "Freedom outbound stale pooled sockets discarded"
    );
    metrics::describe_counter!(
        "freedom_pool_errors_total",
        metrics::Unit::Count,
        "Freedom outbound background pool dial errors"
    );
    metrics::describe_counter!(
        "freedom_pool_refill_success_total",
        metrics::Unit::Count,
        "Freedom outbound background refill sockets added to the idle pool"
    );
    metrics::describe_counter!(
        "freedom_pool_refill_dropped_total",
        metrics::Unit::Count,
        "Freedom outbound background refill sockets dropped before entering the idle pool"
    );
    metrics::describe_counter!(
        "freedom_pool_first_use_retries_total",
        metrics::Unit::Count,
        "Pooled Freedom sockets discarded after failing the first client write"
    );
    metrics::describe_counter!(
        "freedom_pool_first_use_guard_skipped_total",
        metrics::Unit::Count,
        "Pooled Freedom first-use guard skipped because client bytes were not immediately available"
    );
    metrics::describe_counter!(
        "freedom_pool_fresh_retry_success_total",
        metrics::Unit::Count,
        "Fresh Freedom retries that succeeded after a pooled socket failed first use"
    );
    metrics::describe_counter!(
        "freedom_pool_fresh_retry_failures_total",
        metrics::Unit::Count,
        "Fresh Freedom retries that failed after a pooled socket failed first use"
    );
    metrics::describe_histogram!(
        "freedom_pool_idle_age_seconds",
        metrics::Unit::Seconds,
        "Age of a pooled Freedom socket when reused"
    );
    metrics::describe_gauge!(
        "freedom_pool_capacity",
        metrics::Unit::Count,
        "Current adaptive per-destination Freedom pool capacity tier"
    );
    metrics::describe_gauge!(
        "freedom_pool_hotness",
        metrics::Unit::Count,
        "Current adaptive per-destination Freedom pool hotness estimate"
    );
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

async fn healthz() -> impl IntoResponse {
    "ok"
}

async fn readyz(State(state): State<MetricsState>) -> impl IntoResponse {
    if state.ready {
        (axum::http::StatusCode::OK, "ready")
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn metrics_handler(State(state): State<MetricsState>) -> impl IntoResponse {
    let body = state.prometheus_handle.render();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

async fn version_handler() -> impl IntoResponse {
    Json(serde_json::json!({"version": "0.1.0"}))
}

// ── Metrics helpers ───────────────────────────────────────────────────────────

/// Record that a new connection was accepted on `inbound` using `protocol`.
pub fn record_connection_accepted(inbound: &str, protocol: &str) {
    runtime_stats::record_connection_accepted(inbound, protocol);
    metrics::counter!(
        "proxy_connections_total",
        "inbound" => inbound.to_owned(),
        "protocol" => protocol.to_owned()
    )
    .increment(1);

    metrics::gauge!(
        "proxy_active_connections",
        "inbound" => inbound.to_owned()
    )
    .increment(1.0);
}

/// Record how long the inbound protocol header parse took.
pub fn record_inbound_parse(inbound: &str, elapsed: std::time::Duration) {
    metrics::histogram!(
        "proxy_inbound_parse_seconds",
        "inbound" => inbound.to_owned()
    )
    .record(elapsed.as_secs_f64());
}

/// Record how long the routing decision took.
pub fn record_route(inbound: &str, elapsed: std::time::Duration) {
    metrics::histogram!(
        "proxy_route_seconds",
        "inbound" => inbound.to_owned()
    )
    .record(elapsed.as_secs_f64());
}

/// Record how long a DNS resolution took during routing.
pub fn record_dns(inbound: &str, elapsed: std::time::Duration) {
    metrics::histogram!(
        "proxy_dns_seconds",
        "inbound" => inbound.to_owned()
    )
    .record(elapsed.as_secs_f64());
}

/// Record how long the outbound connect (dial + handshake) took.
pub fn record_outbound_connect(inbound: &str, outbound: &str, elapsed: std::time::Duration) {
    metrics::histogram!(
        "proxy_outbound_connect_seconds",
        "inbound" => inbound.to_owned(),
        "outbound" => outbound.to_owned()
    )
    .record(elapsed.as_secs_f64());
}

/// Increment the relay error counter for an inbound.
pub fn record_relay_error(inbound: &str) {
    metrics::counter!(
        "proxy_relay_errors_total",
        "inbound" => inbound.to_owned()
    )
    .increment(1);
}

/// Record that a connection on `inbound` has closed.
///
/// Call this after the relay finishes to decrement the active gauge and
/// record bytes / duration.
pub fn record_connection_closed(inbound: &str, rx_bytes: u64, tx_bytes: u64, duration: Duration) {
    runtime_stats::record_relay_traffic(inbound, None, rx_bytes, tx_bytes);
    metrics::gauge!(
        "proxy_active_connections",
        "inbound" => inbound.to_owned()
    )
    .decrement(1.0);

    metrics::counter!(
        "proxy_bytes_total",
        "direction" => "rx",
        "inbound" => inbound.to_owned()
    )
    .increment(rx_bytes);

    metrics::counter!(
        "proxy_bytes_total",
        "direction" => "tx",
        "inbound" => inbound.to_owned()
    )
    .increment(tx_bytes);

    metrics::histogram!(
        "proxy_connection_duration_seconds",
        "inbound" => inbound.to_owned()
    )
    .record(duration.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `record_connection_accepted` and `record_connection_closed` should not panic.
    #[test]
    fn metrics_helpers_do_not_panic() {
        // Without a recorder installed, these are no-ops.
        record_connection_accepted("test-inbound", "ss2022");
        record_connection_closed("test-inbound", 1024, 2048, Duration::from_secs(1));
    }
}
