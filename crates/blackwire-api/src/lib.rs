pub mod server;
pub mod stats_service;

pub mod proto {
    tonic::include_proto!("xray.app.stats.command");
}
