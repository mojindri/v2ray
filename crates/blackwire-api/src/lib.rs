//! Xray-compatible gRPC management API (StatsService + HandlerService).

pub mod handler_service;
pub mod management;
pub mod server;
pub mod stats_service;

/// Generated StatsService protobuf types.
#[allow(missing_docs)]
pub mod proto {
    tonic::include_proto!("xray.app.stats.command");
}

/// Generated HandlerService protobuf types.
#[allow(missing_docs)]
pub mod handler_proto {
    tonic::include_proto!("xray.app.proxyman.command");
}

/// Generated VLESS account protobuf types.
#[allow(missing_docs)]
pub mod vless_account_proto {
    tonic::include_proto!("xray.proxy.vless");
}
