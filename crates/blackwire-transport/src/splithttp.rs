//! SplitHTTP / xHTTP transport — HTTP/2 (stream-one via h2) with HTTP/1.1 fallback.
//!
//! **Supported for interop:** `stream-one` (matrix `vless-splithttp`).
//! Upstream: Xray 26.x `transport/internet/splithttp` (HTTP/2 via ALPN h2),
//! sing-box HTTP transport (also HTTP/2 via ALPN h2).
//!
//! Wire format: both Xray 26.x and sing-box negotiate ALPN "h2" and send
//! the standard HTTP/2 connection preface. After the handshake the client
//! sends a single `PUT /split` request; the bidirectional DATA frame stream
//! maps directly onto the VLESS tunnel — no gRPC framing.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use blackwire_common::{BoxedStream, ProxyError, ReunionStream};
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use blackwire_config::schema::{SplitHttpConfig, StreamSettingsConfig};

use crate::splithttp_packet_up::{
    extract_session_seq, UploadPacket, UploadQueue, UploadQueueReader,
};

/// Result of an inbound SplitHTTP handshake.
pub enum SplitHttpAcceptResult {
    /// Bidirectional tunnel (stream-one or download GET).
    Tunnel(BoxedStream),
    /// Upload POST handled; no VLESS stream on this HTTP transaction.
    UploadOnly,
    /// OPTIONS preflight completed.
    Preflight,
    /// HTTP/2 packet-up: connection handled in the accept loop (one or more tunnels spawned via callback).
    H2PacketUpManaged,
}

/// Invoked for each packet-up download GET on an HTTP/2 connection (sing-box may multiplex many sessions per conn).
pub type PacketUpH2TunnelFn = Arc<dyn Fn(SplitHttpAcceptResult) + Send + Sync>;

const MAX_HEADER_BYTES: usize = 16384;

/// Normalized XHTTP mode (subset implemented in this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitHttpMode {
    /// One HTTP request; upload body + download response (Xray `stream-one`).
    StreamOne,
    /// Split upload/download (Xray packet-up / stream-up).
    PacketUp,
    /// Other / legacy alias — treated like stream-one when dialing.
    Other,
}

/// Parse `splithttpSettings.mode` (empty → stream-one for lab / interop).
pub fn normalize_splithttp_mode(mode: &str) -> SplitHttpMode {
    match mode.trim().to_ascii_lowercase().as_str() {
        "" | "stream-one" => SplitHttpMode::StreamOne,
        "packet-up" => SplitHttpMode::PacketUp,
        "stream-up" | "auto" => SplitHttpMode::Other,
        _ => SplitHttpMode::Other,
    }
}

/// Dial SplitHTTP: send request headers and return a chunked full-duplex stream.
pub async fn splithttp_connect(
    mut stream: BoxedStream,
    authority: &str,
    stream_settings: &StreamSettingsConfig,
) -> Result<BoxedStream, ProxyError> {
    let cfg = split_http_config(stream_settings);
    let path = cfg.path.clone();
    let mode = normalize_splithttp_mode(&cfg.mode);
    let method = uplink_method(&cfg, mode);
    let host = cfg
        .host
        .first()
        .cloned()
        .unwrap_or_else(|| authority.to_string());

    let mut request =
        String::with_capacity(96 + method.len() + path.len() + host.len() + cfg.headers.len() * 24);
    request.push_str(&method);
    request.push(' ');
    request.push_str(&path);
    request.push_str(" HTTP/1.1\r\nHost: ");
    request.push_str(&host);
    request.push_str("\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n");
    for (key, value) in &cfg.headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if let Some((key, value)) = x_padding_header(&cfg) {
        request.push_str(&key);
        request.push_str(": ");
        request.push_str(&value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_headers(&mut stream).await?;
    let status = response.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return Err(ProxyError::Protocol(format!(
            "SplitHTTP expected 200 response, got '{status}'"
        )));
    }

    Ok(Box::new(SplitHttpStream::new(stream)))
}

static PACKET_UP_SESSIONS: LazyLock<DashMap<String, Arc<UploadQueue>>> =
    LazyLock::new(DashMap::new);

fn upsert_packet_up_session(session_id: &str) -> Arc<UploadQueue> {
    PACKET_UP_SESSIONS
        .entry(session_id.to_string())
        .or_insert_with(|| UploadQueue::new(64))
        .clone()
}

fn x_padding_header(cfg: &SplitHttpConfig) -> Option<(String, String)> {
    let len = x_padding_len(cfg.x_padding_bytes.as_ref())?;
    if len == 0 {
        return None;
    }
    let key = if cfg.x_padding_header.is_empty() {
        "X-Padding".to_string()
    } else {
        cfg.x_padding_header.clone()
    };
    let value = match cfg.x_padding_method.as_str() {
        "tokenish" => "A".repeat(len),
        _ => "X".repeat(len),
    };
    Some((key, value))
}

fn x_padding_len(value: Option<&serde_json::Value>) -> Option<usize> {
    let value = value?;
    if let Some(n) = value.as_u64() {
        return Some(n.min(4096) as usize);
    }
    if let Some(s) = value.as_str() {
        let first = s
            .split(['-', ','])
            .next()
            .and_then(|v| v.trim().parse::<usize>().ok())?;
        return Some(first.min(4096));
    }
    if let Some(obj) = value.as_object() {
        for key in ["from", "min", "Min", "minLength"] {
            if let Some(n) = obj.get(key).and_then(|v| v.as_u64()) {
                return Some(n.min(4096) as usize);
            }
        }
    }
    None
}

fn remove_packet_up_session(session_id: &str) {
    PACKET_UP_SESSIONS.remove(session_id);
}

/// Accept SplitHTTP/xHTTP: auto-detects HTTP/2 (ALPN h2, Xray 26.x / sing-box)
/// vs HTTP/1.1 and dispatches accordingly.
pub async fn splithttp_accept(
    mut stream: BoxedStream,
    expected_path: Option<&str>,
    expected_method: Option<&str>,
    mode: SplitHttpMode,
    packet_up_h2_tunnel: Option<PacketUpH2TunnelFn>,
) -> Result<SplitHttpAcceptResult, ProxyError> {
    // Peek at the first 3 bytes to distinguish HTTP/2 from HTTP/1.1.
    // HTTP/2 connection preface begins with "PRI" (RFC 7540 §3.5).
    let mut peek = [0u8; 3];
    stream.read_exact(&mut peek).await?;
    if &peek == b"PRI" {
        // HTTP/2: reconstruct the stream by prepending the peeked bytes.
        let stream: BoxedStream = Box::new(PrependStream::new(stream, peek.to_vec()));
        if mode == SplitHttpMode::PacketUp {
            let on_tunnel = packet_up_h2_tunnel.ok_or_else(|| {
                ProxyError::Protocol(
                    "xHTTP h2 packet-up requires a per-session tunnel handler".into(),
                )
            })?;
            splithttp_accept_h2_packet_up(stream, expected_path, on_tunnel).await?;
            return Ok(SplitHttpAcceptResult::H2PacketUpManaged);
        }
        return splithttp_accept_h2(stream, expected_path, expected_method).await;
    }
    // HTTP/1.1 path — prepend the 3 bytes we already consumed.
    let mut stream: BoxedStream = Box::new(PrependStream::new(stream, peek.to_vec()));

    let request = read_headers(&mut stream).await?;
    let mut lines = request.lines();
    let first = lines
        .next()
        .ok_or_else(|| ProxyError::Protocol("SplitHTTP missing request line".into()))?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    if method.eq_ignore_ascii_case("OPTIONS") {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n")
            .await?;
        stream.flush().await?;
        return Ok(SplitHttpAcceptResult::Preflight);
    }

    if mode == SplitHttpMode::PacketUp {
        return packet_up_accept(stream, expected_path, method, &request).await;
    }

    if let Some(expected) = expected_path {
        let got = path.split('?').next().unwrap_or(path);
        // Accept "*" (Xray 26.x xHTTP Xmux handshake path) in addition to the configured path.
        if got != expected && got != "*" {
            return Err(ProxyError::Protocol(format!(
                "SplitHTTP path mismatch: got '{got}', want '{expected}'"
            )));
        }
    }

    let stream_one = mode == SplitHttpMode::StreamOne || mode == SplitHttpMode::Other;
    if stream_one {
        let allowed = expected_method
            .map(|m| method.eq_ignore_ascii_case(m))
            .unwrap_or_else(|| {
                method.eq_ignore_ascii_case("POST")
                    || method.eq_ignore_ascii_case("GET")
                    || method.eq_ignore_ascii_case("PUT")
            });
        if !allowed {
            return Err(ProxyError::Protocol(format!(
                "SplitHTTP stream-one method not allowed: '{method}'"
            )));
        }
        write_stream_one_response(&mut stream).await?;
    } else if let Some(expected) = expected_method {
        if !method.eq_ignore_ascii_case(expected) {
            return Err(ProxyError::Protocol(format!(
                "SplitHTTP method mismatch: got '{method}', want '{expected}'"
            )));
        }
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
    }

    Ok(SplitHttpAcceptResult::Tunnel(Box::new(
        SplitHttpStream::new(stream),
    )))
}

/// Path, uplink method, and mode for an inbound's stream settings.
///
/// Returns `None` for the method when no explicit method is configured — in that case
/// the caller should accept any standard method (GET/POST/PUT).
pub fn splithttp_listen_params(
    stream_settings: &StreamSettingsConfig,
) -> (Option<String>, Option<String>, SplitHttpMode) {
    let cfg = split_http_config(stream_settings);
    let mode = normalize_splithttp_mode(&cfg.mode);
    let method = if cfg.method.is_empty() {
        None
    } else {
        Some(cfg.method.clone())
    };
    (Some(cfg.path.clone()), method, mode)
}

/// Accept an xHTTP connection over HTTP/2 (Xray 26.x / sing-box default).
///
/// Both Xray 26.x and sing-box negotiate ALPN "h2" for xHTTP over TLS.  After
/// the HTTP/2 handshake the client sends a single PUT (or configured method)
/// request; we bridge its bidirectional DATA frames directly to the VLESS
/// tunnel without any additional framing.
pub async fn splithttp_accept_h2(
    stream: BoxedStream,
    expected_path: Option<&str>,
    expected_method: Option<&str>,
) -> Result<SplitHttpAcceptResult, ProxyError> {
    use bytes::Bytes;
    use h2::server;

    let mut conn = server::Builder::new()
        .handshake(stream)
        .await
        .map_err(|e| ProxyError::Transport(format!("xHTTP h2 server handshake failed: {e}")))?;

    let (request, mut respond) = conn
        .accept()
        .await
        .ok_or_else(|| ProxyError::Transport("xHTTP h2: no incoming request".into()))?
        .map_err(|e| ProxyError::Transport(format!("xHTTP h2 accept error: {e}")))?;

    let method = request.method().as_str();
    let path = request.uri().path();
    debug!(method = %method, path = %path, "xHTTP h2 inbound request");

    if let Some(expected) = expected_path {
        let got = path.trim_end_matches('/');
        let want = expected.trim_end_matches('/');
        if got != want {
            return Err(ProxyError::Protocol(format!(
                "xHTTP h2 path mismatch: got '{path}', want '{expected}'"
            )));
        }
    }
    if let Some(expected) = expected_method {
        if !method.eq_ignore_ascii_case(expected) {
            return Err(ProxyError::Protocol(format!(
                "xHTTP h2 method mismatch: got '{method}', want '{expected}'"
            )));
        }
    }

    let response = http::Response::builder()
        .status(200)
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .body(())
        .map_err(|e| ProxyError::Protocol(format!("xHTTP h2: invalid response builder: {e}")))?;

    let send_stream = respond
        .send_response(response, false)
        .map_err(|e| ProxyError::Transport(format!("xHTTP h2 send_response failed: {e}")))?;

    let recv_body = request.into_body();

    // Drive the connection in background so flow-control frames are handled.
    tokio::spawn(async move { while conn.accept().await.is_some() {} });

    // Bridge the h2 recv body + send stream into a BoxedStream duplex pipe.
    let (proxy_end, user_end) = tokio::io::duplex(256 * 1024);
    let (mut proxy_reader, mut proxy_writer) = tokio::io::split(proxy_end);

    let mut recv = recv_body;
    let mut send = send_stream;

    tokio::spawn(async move {
        loop {
            match recv.data().await {
                None => break,
                Some(Err(_)) => break,
                Some(Ok(chunk)) => {
                    let _ = recv.flow_control().release_capacity(chunk.len());
                    if proxy_writer.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            let n = match proxy_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let data = Bytes::copy_from_slice(&buf[..n]);
            if send.send_data(data, false).is_err() {
                break;
            }
        }
    });

    Ok(SplitHttpAcceptResult::Tunnel(Box::new(user_end)))
}

/// Accept HTTP/2 xHTTP `packet-up` on an inbound connection.
///
/// Handles per-session `POST` uploads and `GET` downloads on the shared h2 connection.
/// Each completed download invokes `on_tunnel` with a [`SplitHttpAcceptResult::Tunnel`]
/// for the VLESS handler to process.
pub async fn splithttp_accept_h2_packet_up(
    stream: BoxedStream,
    expected_path: Option<&str>,
    on_tunnel: PacketUpH2TunnelFn,
) -> Result<(), ProxyError> {
    use bytes::Bytes;
    use h2::server;
    use std::collections::HashSet;

    let mut conn = server::Builder::new()
        .handshake(stream)
        .await
        .map_err(|e| ProxyError::Transport(format!("xHTTP h2 packet-up handshake failed: {e}")))?;

    let base = expected_path.unwrap_or("/").to_string();
    let prefix = crate::splithttp_packet_up::normalized_path_prefix(&base);
    let prefix = prefix.trim_end_matches('/').to_string();
    let mut download_sessions: HashSet<String> = HashSet::new();

    loop {
        let incoming = match conn.accept().await {
            Some(Ok(parts)) => parts,
            Some(Err(e)) => {
                return Err(ProxyError::Transport(format!(
                    "xHTTP h2 packet-up accept error: {e}"
                )));
            }
            None => return Ok(()),
        };

        let (request, mut respond) = incoming;
        let method = request.method().as_str();
        let path = request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or_else(|| request.uri().path());
        debug!(method = %method, path = %path, "xHTTP h2 packet-up inbound request");

        if !path.starts_with(prefix.as_str()) {
            let _ = respond.send_response(
                http::Response::builder().status(404).body(()).unwrap(),
                true,
            );
            continue;
        }

        let (session, seq) = extract_session_seq(path, &base);

        if method.eq_ignore_ascii_case("OPTIONS") {
            let response = http::Response::builder()
                .status(200)
                .header("access-control-allow-origin", "*")
                .body(())
                .map_err(|e| {
                    ProxyError::Protocol(format!(
                        "xHTTP h2 packet-up: invalid OPTIONS response builder: {e}"
                    ))
                })?;
            let _ = respond.send_response(response, true);
            continue;
        }

        if method.eq_ignore_ascii_case("POST") {
            if session.is_empty() {
                let _ = respond.send_response(
                    http::Response::builder().status(400).body(()).unwrap(),
                    true,
                );
                continue;
            }
            let seq_num: u64 = match seq.parse() {
                Ok(v) => v,
                Err(_) => {
                    let _ = respond.send_response(
                        http::Response::builder().status(400).body(()).unwrap(),
                        true,
                    );
                    continue;
                }
            };

            let queue = upsert_packet_up_session(&session);
            let mut body = request.into_body();
            let mut payload = Vec::new();
            let mut body_error = false;
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(chunk) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        payload.extend_from_slice(&chunk);
                    }
                    Err(_) => {
                        body_error = true;
                        break;
                    }
                }
            }

            if body_error {
                let _ = respond.send_response(
                    http::Response::builder().status(502).body(()).unwrap(),
                    true,
                );
                continue;
            }

            if queue
                .push(UploadPacket {
                    seq: seq_num,
                    payload,
                })
                .await
                .is_err()
            {
                let _ = respond.send_response(
                    http::Response::builder().status(503).body(()).unwrap(),
                    true,
                );
                continue;
            }

            let response = http::Response::builder()
                .status(200)
                .header("cache-control", "no-store")
                .body(())
                .map_err(|e| {
                    ProxyError::Protocol(format!(
                        "xHTTP h2 packet-up: invalid POST response builder: {e}"
                    ))
                })?;
            let _ = respond.send_response(response, true);
            continue;
        }

        if method.eq_ignore_ascii_case("GET") {
            if session.is_empty() {
                let _ = respond.send_response(
                    http::Response::builder().status(400).body(()).unwrap(),
                    true,
                );
                continue;
            }
            if !download_sessions.insert(session.clone()) {
                let _ = respond.send_response(
                    http::Response::builder().status(409).body(()).unwrap(),
                    true,
                );
                continue;
            }

            let queue = upsert_packet_up_session(&session);
            let mut body = request.into_body();
            tokio::spawn(async move {
                while let Some(chunk) = body.data().await {
                    match chunk {
                        Ok(chunk) => {
                            let _ = body.flow_control().release_capacity(chunk.len());
                        }
                        Err(_) => break,
                    }
                }
            });
            let response = http::Response::builder()
                .status(200)
                .header("cache-control", "no-store")
                .header("x-accel-buffering", "no")
                .header("content-type", "text/event-stream")
                .body(())
                .map_err(|e| {
                    ProxyError::Protocol(format!(
                        "xHTTP h2 packet-up: invalid GET response builder: {e}"
                    ))
                })?;
            let mut send_stream = respond.send_response(response, false).map_err(|e| {
                ProxyError::Transport(format!("xHTTP h2 packet-up send_response failed: {e}"))
            })?;

            let (proxy_end, user_end) = tokio::io::duplex(256 * 1024);
            let (mut proxy_reader, _) = tokio::io::split(proxy_end);
            let (_, user_writer) = tokio::io::split(user_end);

            let cleanup_session = session.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    let n = match proxy_reader.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let data = Bytes::copy_from_slice(&buf[..n]);
                    if send_stream.send_data(data, false).is_err() {
                        break;
                    }
                }
                let _ = send_stream.send_data(Bytes::new(), true);
                remove_packet_up_session(&cleanup_session);
            });

            let tunnel = SplitHttpAcceptResult::Tunnel(Box::new(ReunionStream::new(
                UploadQueueReader::new(queue),
                user_writer,
            )));
            on_tunnel(tunnel);
            continue;
        }

        let _ = respond.send_response(
            http::Response::builder().status(405).body(()).unwrap(),
            true,
        );
    }
}

async fn write_stream_one_response(stream: &mut BoxedStream) -> Result<(), ProxyError> {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\nCache-Control: no-store\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await?;
    stream.flush().await?;
    Ok(())
}

fn uplink_method(cfg: &SplitHttpConfig, mode: SplitHttpMode) -> String {
    if !cfg.uplink_http_method.is_empty() {
        return cfg.uplink_http_method.clone();
    }
    if !cfg.method.is_empty() {
        return cfg.method.clone();
    }
    if mode == SplitHttpMode::StreamOne {
        return "POST".to_string();
    }
    "PUT".to_string()
}

fn split_http_config(stream_settings: &StreamSettingsConfig) -> SplitHttpConfig {
    stream_settings
        .splithttp_settings
        .clone()
        .unwrap_or_else(|| SplitHttpConfig {
            path: stream_settings
                .ws_settings
                .as_ref()
                .map(|ws| ws.path.clone())
                .unwrap_or_else(|| "/".to_string()),
            host: Vec::new(),
            method: "PUT".to_string(),
            mode: String::new(),
            uplink_http_method: String::new(),
            headers: Default::default(),
            x_padding_bytes: None,
            x_padding_method: String::new(),
            x_padding_header: String::new(),
            x_padding_key: String::new(),
            x_padding_placement: String::new(),
            session_placement: String::new(),
            session_key: String::new(),
            seq_placement: String::new(),
            seq_key: String::new(),
            uplink_data_placement: String::new(),
            uplink_data_key: String::new(),
            uplink_chunk_size: 0,
            sc_max_buffered_posts: 0,
            xmux: None,
            download_settings: None,
        })
}

async fn read_headers(stream: &mut BoxedStream) -> Result<String, ProxyError> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < MAX_HEADER_BYTES {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(ProxyError::Protocol(
                "SplitHTTP unexpected EOF while reading headers".into(),
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buf)
                .map_err(|_| ProxyError::Protocol("SplitHTTP headers not valid UTF-8".into()));
        }
    }
    Err(ProxyError::Protocol("SplitHTTP headers too large".into()))
}

async fn packet_up_accept(
    mut stream: BoxedStream,
    expected_path: Option<&str>,
    method: &str,
    request: &str,
) -> Result<SplitHttpAcceptResult, ProxyError> {
    let base = expected_path.unwrap_or("/");
    let path_and_query = request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");
    let prefix = crate::splithttp_packet_up::normalized_path_prefix(base);
    if !path_and_query.starts_with(prefix.trim_end_matches('/')) {
        return Err(ProxyError::Protocol(format!(
            "SplitHTTP path mismatch: got '{path_and_query}', want prefix '{prefix}'"
        )));
    }

    let (session, seq) = extract_session_seq(path_and_query, base);

    if method.eq_ignore_ascii_case("OPTIONS") {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
        return Ok(SplitHttpAcceptResult::Preflight);
    }

    if method.eq_ignore_ascii_case("POST") {
        if session.is_empty() {
            return Err(ProxyError::Protocol(
                "packet-up POST requires session id in path".into(),
            ));
        }
        let seq_num: u64 = seq
            .parse()
            .map_err(|_| ProxyError::Protocol(format!("packet-up invalid seq '{seq}'")))?;
        let body = read_request_body(&mut stream, request).await?;
        let queue = upsert_packet_up_session(&session);
        queue
            .push(UploadPacket {
                seq: seq_num,
                payload: body,
            })
            .await
            .map_err(|e| ProxyError::Protocol(format!("packet-up push: {e}")))?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n")
            .await?;
        stream.flush().await?;
        return Ok(SplitHttpAcceptResult::UploadOnly);
    }

    if method.eq_ignore_ascii_case("GET") {
        if session.is_empty() {
            return Err(ProxyError::Protocol(
                "packet-up GET requires session id in path".into(),
            ));
        }
        let queue = upsert_packet_up_session(&session);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nCache-Control: no-store\r\nX-Accel-Buffering: no\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
        let reader = UploadQueueReader::new(queue);
        return Ok(SplitHttpAcceptResult::Tunnel(Box::new(PacketUpConn {
            reader,
            writer: stream,
        })));
    }

    Err(ProxyError::Protocol(format!(
        "SplitHTTP packet-up: unsupported method '{method}'"
    )))
}

/// Download GET leg: read uplink bytes from the session queue, write downlink on HTTP body.
struct PacketUpConn {
    reader: UploadQueueReader,
    writer: BoxedStream,
}

impl AsyncRead for PacketUpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for PacketUpConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

fn parse_http_headers(request: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in request.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    map
}

async fn read_request_body(stream: &mut BoxedStream, request: &str) -> Result<Vec<u8>, ProxyError> {
    let headers = parse_http_headers(request);
    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        let mut framed = SplitHttpStream::new(stream);
        let mut body = Vec::new();
        framed.read_to_end(&mut body).await?;
        return Ok(body);
    }
    if let Some(clen) = headers.get("content-length") {
        let n: usize = clen
            .parse()
            .map_err(|_| ProxyError::Protocol("SplitHTTP invalid Content-Length".into()))?;
        let mut body = vec![0u8; n];
        stream.read_exact(&mut body).await?;
        return Ok(body);
    }
    Ok(Vec::new())
}

/// Prepend a small byte slice to a stream without any additional framing.
/// Used to put back bytes we peeked at for protocol detection.
struct PrependStream {
    inner: BoxedStream,
    prepended: Vec<u8>,
    prep_offset: usize,
}

impl PrependStream {
    fn new(inner: BoxedStream, prepended: Vec<u8>) -> Self {
        Self {
            inner,
            prepended,
            prep_offset: 0,
        }
    }
}

impl AsyncRead for PrependStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prep_offset < self.prepended.len() {
            let n = buf.remaining().min(self.prepended.len() - self.prep_offset);
            buf.put_slice(&self.prepended[self.prep_offset..self.prep_offset + n]);
            self.prep_offset += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrependStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[allow(dead_code)]
struct PrependedChunkStream {
    inner: SplitHttpStream<BoxedStream>,
    prepended: Vec<u8>,
    prep_offset: usize,
}

impl PrependedChunkStream {
    #[allow(dead_code)]
    fn new(stream: BoxedStream, prepended: Vec<u8>) -> Self {
        Self {
            inner: SplitHttpStream::new(stream),
            prepended,
            prep_offset: 0,
        }
    }
}

impl AsyncRead for PrependedChunkStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prep_offset < self.prepended.len() {
            let n = buf.remaining().min(self.prepended.len() - self.prep_offset);
            buf.put_slice(&self.prepended[self.prep_offset..self.prep_offset + n]);
            self.prep_offset += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrependedChunkStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct SplitHttpStream<S> {
    inner: S,
    read_buf: Vec<u8>,
    chunk_remaining: usize,
    need_chunk_crlf: bool,
    eof: bool,
}

impl<S> SplitHttpStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            chunk_remaining: 0,
            need_chunk_crlf: false,
            eof: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SplitHttpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.eof {
                return Poll::Ready(Ok(()));
            }

            if self.need_chunk_crlf {
                if self.read_buf.len() < 2 {
                    let mut tmp = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            if rb.filled().is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            self.read_buf.extend_from_slice(rb.filled());
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                self.read_buf.drain(..2);
                self.need_chunk_crlf = false;
            }

            if self.chunk_remaining == 0 {
                if let Some(line_end) = self.read_buf.windows(2).position(|w| w == b"\r\n") {
                    let line = String::from_utf8_lossy(&self.read_buf[..line_end]);
                    let size = usize::from_str_radix(line.trim(), 16)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    self.read_buf.drain(..line_end + 2);
                    if size == 0 {
                        self.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    self.chunk_remaining = size;
                    continue;
                }

                let mut tmp = [0u8; 4096];
                let mut rb = ReadBuf::new(&mut tmp);
                match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        if rb.filled().is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        self.read_buf.extend_from_slice(rb.filled());
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if !self.read_buf.is_empty() {
                let n = buf
                    .remaining()
                    .min(self.chunk_remaining)
                    .min(self.read_buf.len());
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
                self.chunk_remaining -= n;
                if self.chunk_remaining == 0 {
                    self.need_chunk_crlf = true;
                }
                return Poll::Ready(Ok(()));
            }

            let mut tmp = [0u8; 4096];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    self.read_buf.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use h2::client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn stream_one_accepts_post_and_returns_chunked_sse() {
        let (mut client, server) = tokio::io::duplex(8192);
        let server = Box::new(server) as BoxedStream;
        let accept_task = tokio::spawn(async move {
            splithttp_accept(
                server,
                Some("/split"),
                Some("POST"),
                SplitHttpMode::StreamOne,
                None,
            )
            .await
        });

        client
            .write_all(
                b"POST /split HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        client.write_all(b"5\r\nhello\r\n").await.unwrap();
        client.flush().await.unwrap();

        let mut raw = vec![0u8; 512];
        let n = client.read(&mut raw).await.unwrap();
        let resp = String::from_utf8_lossy(&raw[..n]);
        assert!(resp.contains("200 OK"), "response: {resp}");
        assert!(resp.contains("text/event-stream"));
        assert!(resp.contains("chunked"));

        let SplitHttpAcceptResult::Tunnel(mut tunnel) =
            accept_task.await.unwrap().expect("accept failed")
        else {
            panic!("expected stream-one tunnel");
        };
        let mut buf = [0u8; 8];
        let n = tunnel.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn packet_up_h2_accepts_get_and_post_on_one_connection() {
        use std::sync::Mutex;
        use tokio::sync::oneshot; // tunnel ready signal

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = Box::new(server_io) as BoxedStream;
        let (tunnel_tx, tunnel_rx) = oneshot::channel();
        let ready_tx = Arc::new(Mutex::new(Some(tunnel_tx)));
        let tunnel_slot: Arc<Mutex<Option<BoxedStream>>> = Arc::new(Mutex::new(None));
        let tunnel_slot_cb = tunnel_slot.clone();
        let ready_tx_cb = ready_tx.clone();
        let on_tunnel: PacketUpH2TunnelFn = Arc::new(move |accepted| {
            if let SplitHttpAcceptResult::Tunnel(stream) = accepted {
                if let Some(tx) = ready_tx_cb.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                *tunnel_slot_cb.lock().unwrap() = Some(stream);
            }
        });
        let accept_task = tokio::spawn(async move {
            splithttp_accept(
                server,
                Some("/split"),
                None,
                SplitHttpMode::PacketUp,
                Some(on_tunnel),
            )
            .await
        });

        let (mut client, conn) = client::Builder::new().handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let get_req = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/split/sess-1")
            .body(())
            .unwrap();
        let (get_resp_fut, mut send_get_end) = client.send_request(get_req, false).unwrap();
        send_get_end.send_data(Bytes::new(), true).unwrap();

        tunnel_rx.await.unwrap();
        let mut tunnel = tunnel_slot.lock().unwrap().take().expect("tunnel stored");

        let post_req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.test/split/sess-1/0")
            .body(())
            .unwrap();
        let (post_resp_fut, mut send_post) = client.send_request(post_req, false).unwrap();
        send_post
            .send_data(Bytes::from_static(b"hello"), true)
            .unwrap();

        let post_resp = post_resp_fut.await.unwrap();
        assert_eq!(post_resp.status(), http::StatusCode::OK);

        let mut buf = [0u8; 8];
        let n = tunnel.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        tunnel.write_all(b"world").await.unwrap();
        tunnel.flush().await.unwrap();
        drop(tunnel);

        let mut get_resp = get_resp_fut.await.unwrap();
        assert_eq!(get_resp.status(), http::StatusCode::OK);
        let mut got = Vec::new();
        while let Some(chunk) = get_resp.body_mut().data().await {
            let chunk = chunk.unwrap();
            get_resp
                .body_mut()
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
            got.extend_from_slice(&chunk);
        }
        assert_eq!(got, b"world");

        drop(client);
        accept_task.abort();
    }

    #[tokio::test]
    async fn packet_up_h2_multiplexes_sessions_on_one_connection() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;

        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let server = Box::new(server_io) as BoxedStream;
        let tunnel_count = Arc::new(AtomicUsize::new(0));
        let tunnels: Arc<Mutex<Vec<BoxedStream>>> = Arc::new(Mutex::new(Vec::new()));
        let tunnels_cb = tunnels.clone();
        let count_cb = tunnel_count.clone();
        let on_tunnel: PacketUpH2TunnelFn = Arc::new(move |accepted| {
            if let SplitHttpAcceptResult::Tunnel(stream) = accepted {
                tunnels_cb.lock().unwrap().push(stream);
                count_cb.fetch_add(1, Ordering::SeqCst);
            }
        });
        let accept_task = tokio::spawn(async move {
            splithttp_accept(
                server,
                Some("/split"),
                None,
                SplitHttpMode::PacketUp,
                Some(on_tunnel),
            )
            .await
        });

        let (mut client, conn) = client::Builder::new().handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        for sid in ["sess-a", "sess-b"] {
            let before = tunnel_count.load(Ordering::SeqCst);
            let get_req = http::Request::builder()
                .method(http::Method::GET)
                .uri(format!("https://example.test/split/{sid}"))
                .body(())
                .unwrap();
            let (_get_resp_fut, mut send_get_end) = client.send_request(get_req, false).unwrap();
            send_get_end.send_data(Bytes::new(), true).unwrap();
            for _ in 0..100 {
                if tunnel_count.load(Ordering::SeqCst) > before {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(tunnel_count.load(Ordering::SeqCst) > before);
            let (post_resp_fut, mut send_post) = client
                .send_request(
                    http::Request::builder()
                        .method(http::Method::POST)
                        .uri(format!("https://example.test/split/{sid}/0"))
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            send_post
                .send_data(Bytes::from_static(b"ping"), true)
                .unwrap();
            assert_eq!(post_resp_fut.await.unwrap().status(), http::StatusCode::OK);
        }

        assert_eq!(tunnels.lock().unwrap().len(), 2);
        drop(client);
        accept_task.abort();
    }

    #[tokio::test]
    async fn packet_up_h2_accepts_stream_up_get_with_seq() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = Box::new(server_io) as BoxedStream;
        let tunnel_count = Arc::new(AtomicUsize::new(0));
        let count_cb = tunnel_count.clone();
        let on_tunnel: PacketUpH2TunnelFn = Arc::new(move |accepted| {
            if matches!(accepted, SplitHttpAcceptResult::Tunnel(_)) {
                count_cb.fetch_add(1, Ordering::SeqCst);
            }
        });
        let accept_task = tokio::spawn(async move {
            splithttp_accept(
                server,
                Some("/split"),
                None,
                SplitHttpMode::PacketUp,
                Some(on_tunnel),
            )
            .await
        });

        let (mut client, conn) = client::Builder::new().handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let get_req = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/split/sess-stream-up/0")
            .body(())
            .unwrap();
        let (get_resp_fut, mut send_get_end) = client.send_request(get_req, false).unwrap();
        send_get_end.send_data(Bytes::new(), true).unwrap();

        let response = get_resp_fut.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        for _ in 0..100 {
            if tunnel_count.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(tunnel_count.load(Ordering::SeqCst), 1);

        drop(client);
        accept_task.abort();
    }

    #[tokio::test]
    async fn packet_up_http1_accepts_stream_up_get_with_seq() {
        let (mut client, server) = tokio::io::duplex(8192);
        let server = Box::new(server) as BoxedStream;
        let accept_task = tokio::spawn(async move {
            splithttp_accept(server, Some("/split"), None, SplitHttpMode::PacketUp, None).await
        });

        client
            .write_all(b"GET /split/sess-http1/0 HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        let mut raw = vec![0u8; 512];
        let n = client.read(&mut raw).await.unwrap();
        let resp = String::from_utf8_lossy(&raw[..n]);
        assert!(resp.contains("200 OK"), "response: {resp}");

        let accepted = accept_task.await.unwrap().expect("accept failed");
        assert!(matches!(accepted, SplitHttpAcceptResult::Tunnel(_)));
    }

    #[tokio::test]
    async fn connect_emits_xpadding_header() {
        let (mut client, server) = tokio::io::duplex(8192);
        let server = Box::new(server) as BoxedStream;

        let settings = StreamSettingsConfig {
            splithttp_settings: Some(SplitHttpConfig {
                path: "/split".into(),
                mode: "stream-one".into(),
                x_padding_bytes: Some(serde_json::Value::String("4-8".into())),
                x_padding_method: "repeat-x".into(),
                x_padding_header: "X-Test-Padding".into(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let connect_task =
            tokio::spawn(async move { splithttp_connect(server, "example.test", &settings).await });

        let mut raw = vec![0u8; 1024];
        let n = client.read(&mut raw).await.unwrap();
        let request = String::from_utf8_lossy(&raw[..n]);
        assert!(
            request.contains("X-Test-Padding: XXXX"),
            "request: {request}"
        );

        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        connect_task.await.unwrap().expect("connect failed");
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SplitHttpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut framed = format!("{:X}\r\n", buf.len()).into_bytes();
        framed.extend_from_slice(buf);
        framed.extend_from_slice(b"\r\n");
        match Pin::new(&mut self.inner).poll_write(cx, &framed) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_write(cx, b"0\r\n\r\n") {
            Poll::Ready(Ok(_)) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
