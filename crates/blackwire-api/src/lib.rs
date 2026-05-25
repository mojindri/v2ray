pub mod handler_service;
pub mod management;
pub mod server;
pub mod stats_service;

pub mod proto {
    tonic::include_proto!("xray.app.stats.command");
}

pub mod handler_proto {
    tonic::include_proto!("xray.app.proxyman.command");
}

pub mod vless_account_proto {
    tonic::include_proto!("xray.proxy.vless");
}
