//! gRPC server wiring for Stats + Handler services.

use std::net::SocketAddr;

use anyhow::Context;
use serde_json::Value;
use tokio::task::JoinHandle;
use tonic::transport::Server;
use tracing::{error, info};

use crate::handler_proto::handler_service_server::HandlerServiceServer;
use crate::handler_service::HandlerServiceImpl;
use crate::management::ManagementHandle;
use crate::proto::stats_service_server::StatsServiceServer;
use crate::stats_service::StatsServiceImpl;

/// Parse `api` listen address from config (`"host:port"` string or object).
pub fn api_listen_addr(api: &Value) -> Option<String> {
    if let Some(addr) = api.as_str() {
        return Some(addr.to_string());
    }
    api.get("listen")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            let host = api.get("host").and_then(Value::as_str)?;
            let port = api.get("port").and_then(Value::as_u64)?;
            Some(format!("{host}:{port}"))
        })
}

/// Spawn the combined Stats + Handler gRPC server on `addr`.
pub fn start_api_server(
    addr: &str,
    management: ManagementHandle,
) -> anyhow::Result<JoinHandle<()>> {
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid API listen address '{addr}'"))?;
    let task = tokio::spawn(async move {
        info!(addr = %addr, "blackwire-api gRPC server starting");
        if let Err(e) = Server::builder()
            .add_service(StatsServiceServer::new(StatsServiceImpl))
            .add_service(HandlerServiceServer::new(HandlerServiceImpl::new(
                management,
            )))
            .serve(addr)
            .await
        {
            error!(error = %e, "blackwire-api gRPC server failed");
        }
    });
    Ok(task)
}
