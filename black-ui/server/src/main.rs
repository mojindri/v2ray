mod app;
mod auth;
mod capabilities;
mod config;
mod db;
mod enforcement;
mod error;
mod handlers;
mod models;
mod runtime;
mod service;
mod state;
mod util;

use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let state = state::AppState::open()?;
    enforcement::spawn(state.clone());

    let addr: SocketAddr = std::env::var("BLACK_UI_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:18080".into())
        .parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "black-ui server listening");

    axum::serve(listener, app::router(state)).await?;
    Ok(())
}
