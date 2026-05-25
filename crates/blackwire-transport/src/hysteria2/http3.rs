//! HTTP/3 front door for Hysteria2 — authentication then raw QUIC TCP streams.

use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use blackwire_app::context::Context;
use blackwire_app::dispatcher::Dispatcher;
use blackwire_common::{BoxedStream, ReunionStream};
use h3_quinn::Connection as H3QuinnConnection;
use http::{Response, StatusCode};
use quinn::Connection;
use tracing::warn;

use super::auth::AuthError;
use super::proto::{auth_response_to_headers, is_auth_request, AuthResponse, STATUS_AUTH_OK};
use super::tcp;
use super::Hysteria2ServerConfig;

/// Serve one QUIC connection: HTTP/3 auth, then TCP proxy streams on QUIC bidi streams.
pub async fn serve_connection(
    conn: Connection,
    config: Hysteria2ServerConfig,
    dispatcher: Arc<dyn Dispatcher>,
) -> Result<()> {
    let server_rx_bps = config.up_mbps.saturating_mul(1_000_000 / 8);

    let mut h3_conn = h3::server::Connection::new(H3QuinnConnection::new(conn.clone()))
        .await
        .context("start HTTP/3 server")?;

    let resolver = match h3_conn.accept().await.context("accept HTTP/3 auth")? {
        Some(resolver) => resolver,
        None => bail!("connection closed before Hysteria2 auth"),
    };

    handle_h3_auth_request(resolver, &config.password, server_rx_bps, true).await?;
    // Keep the HTTP/3 server driver alive for the QUIC session without calling
    // `accept()` again. Official hysteria uses http3.StreamDispatcher to hijack
    // proxy streams (varint 0x401); the Rust `h3` crate has no equivalent, so we
    // take proxy streams via `conn.accept_bi()` below. A competing `h3_conn.accept()`
    // would treat 0x401 TCPRequest bytes as HTTP/3 and reset the connection.
    tokio::spawn(async move {
        let _h3_conn = h3_conn;
        std::future::pending::<()>().await
    });

    let inbound_tag = config.tag.clone();
    loop {
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .context("accept Hysteria2 TCP stream")?;

        let dispatcher = Arc::clone(&dispatcher);
        let tag = inbound_tag.clone();
        tokio::spawn(async move {
            let dest = match tcp::server_read_request(&mut recv).await {
                Ok(d) => d,
                Err(e) => {
                    warn!("Hysteria2 bad TCP request: {e}");
                    let _ = tcp::server_write_response(&mut send, false, &e.to_string()).await;
                    return;
                }
            };

            if let Err(e) = tcp::server_write_response(&mut send, true, "").await {
                warn!("Hysteria2 TCP response write failed: {e}");
                return;
            }

            let stream: BoxedStream = Box::new(ReunionStream::new(recv, send));
            let ctx = Context {
                sniffed_domain: None,
                source: None,
                inbound_tag: tag,
                user: None,
                sniffed_protocol: None,
                vision_flow: false,
            };

            if let Err(e) = dispatcher.dispatch(ctx, dest, stream).await {
                warn!("Hysteria2 dispatch error: {e}");
            }
        });
    }
}

async fn handle_h3_auth_request(
    resolver: h3::server::RequestResolver<H3QuinnConnection, bytes::Bytes>,
    password: &str,
    server_rx_bps: u64,
    udp_enabled: bool,
) -> Result<()> {
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .context("resolve HTTP/3 request")?;

    let method = req.method().as_str();
    let path = req.uri().path();
    let authority = req.uri().host().or_else(|| {
        req.headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
    });

    if !is_auth_request(method, path, authority) {
        let resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .context("build 404 response")?;
        stream.send_response(resp).await.context("send 404")?;
        return stream.finish().await.context("finish 404 stream");
    }

    match super::auth::verify_auth_request(req.headers(), password) {
        Ok(_) => {
            let mut headers = http::HeaderMap::new();
            auth_response_to_headers(
                &mut headers,
                &AuthResponse {
                    ok: true,
                    udp_enabled,
                    rx_bps: server_rx_bps,
                    rx_auto: server_rx_bps == 0,
                },
            );
            let mut resp_builder = Response::builder().status(STATUS_AUTH_OK);
            for (name, value) in headers.iter() {
                resp_builder = resp_builder.header(name, value);
            }
            let resp = resp_builder.body(()).context("build 233 response")?;
            stream
                .send_response(resp)
                .await
                .context("send auth success")?;
            stream.finish().await.context("finish auth stream")
        }
        Err(AuthError::WrongPassword) => {
            let resp = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .context("build auth failure response")?;
            stream.send_response(resp).await.context("send auth 404")?;
            stream.finish().await.context("finish auth failure")
        }
        Err(AuthError::Protocol(msg)) => Err(anyhow::anyhow!("auth protocol error: {msg}")),
    }
}
