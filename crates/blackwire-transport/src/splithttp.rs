//! SplitHTTP / xHTTP transport over HTTP/1.1 chunked bodies.
//!
//! **Supported for interop:** `stream-one` only (matrix `vless-splithttp`).
//! Upstream: Xray `transport/internet/splithttp`, sing-box HTTP transport with `method: PUT`.
//!
//! `packet-up` is gated on `splithttpSettings.mode` but is **not** sing-box-complete
//! (no seq reorder, Xmux, padding, or `downloadSettings`). Do not enable in the
//! external-client matrix until [xray-parity-roadmap.md](../../docs/xray-parity-roadmap.md) P2.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use blackwire_common::{BoxedStream, ProxyError};
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;

use blackwire_config::schema::{SplitHttpConfig, StreamSettingsConfig};

/// Result of an inbound SplitHTTP handshake.
pub enum SplitHttpAcceptResult {
    /// Bidirectional tunnel (stream-one or download GET).
    Tunnel(BoxedStream),
    /// Upload POST handled; no VLESS stream on this HTTP transaction.
    UploadOnly,
    /// OPTIONS preflight completed.
    Preflight,
}

const MAX_HEADER_BYTES: usize = 16384;

/// Normalized XHTTP mode (subset implemented in this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitHttpMode {
    /// One HTTP request; upload body + download response (Xray `stream-one`).
    StreamOne,
    /// Split upload/download (not implemented server-side).
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

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n"
    );
    for (key, value) in &cfg.headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
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

static PACKET_UP_SESSIONS: LazyLock<DashMap<String, Arc<Mutex<Vec<u8>>>>> = LazyLock::new(DashMap::new);

/// Accept SplitHTTP: validate request line and return a tunnel or upload-only result.
pub async fn splithttp_accept(
    mut stream: BoxedStream,
    expected_path: Option<&str>,
    expected_method: Option<&str>,
    mode: SplitHttpMode,
) -> Result<SplitHttpAcceptResult, ProxyError> {
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
        if got != expected {
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

    Ok(SplitHttpAcceptResult::Tunnel(Box::new(SplitHttpStream::new(stream))))
}

/// Path, uplink method, and mode for an inbound's stream settings.
pub fn splithttp_listen_params(
    stream_settings: &StreamSettingsConfig,
) -> (Option<String>, Option<String>, SplitHttpMode) {
    let cfg = split_http_config(stream_settings);
    let mode = normalize_splithttp_mode(&cfg.mode);
    let method = uplink_method(&cfg, mode);
    (Some(cfg.path.clone()), Some(method), mode)
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
    if !cfg.method.is_empty() && cfg.method != "PUT" {
        return cfg.method.clone();
    }
    if mode == SplitHttpMode::StreamOne {
        return "POST".to_string();
    }
    cfg.method.clone()
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
    let path_only = request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .map(|p| p.split('?').next().unwrap_or(p))
        .unwrap_or("");
    if let Some(expected) = expected_path {
        if path_only != expected {
            return Err(ProxyError::Protocol(format!(
                "SplitHTTP path mismatch: got '{path_only}', want '{expected}'"
            )));
        }
    }

    let headers = parse_http_headers(request);
    let session = headers
        .get("x-session")
        .cloned()
        .unwrap_or_else(|| "default".to_string());

    if method.eq_ignore_ascii_case("GET") {
        write_stream_one_response(&mut stream).await?;
        let buf = if let Some(entry) = PACKET_UP_SESSIONS.get(&session) {
            entry.value().lock().await.clone()
        } else {
            Vec::new()
        };
        return Ok(SplitHttpAcceptResult::Tunnel(Box::new(PrependedChunkStream::new(
            stream, buf,
        ))));
    }

    if method.eq_ignore_ascii_case("POST") {
        let body = read_request_body(&mut stream, request).await?;
        let slot = PACKET_UP_SESSIONS
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(Vec::new())));
        slot.lock().await.extend_from_slice(&body);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await?;
        stream.flush().await?;
        return Ok(SplitHttpAcceptResult::UploadOnly);
    }

    Err(ProxyError::Protocol(format!(
        "SplitHTTP packet-up: unsupported method '{method}'"
    )))
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

async fn read_request_body(
    stream: &mut BoxedStream,
    request: &str,
) -> Result<Vec<u8>, ProxyError> {
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

struct PrependedChunkStream {
    inner: SplitHttpStream<BoxedStream>,
    prepended: Vec<u8>,
    prep_offset: usize,
}

impl PrependedChunkStream {
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
            let n = buf
                .remaining()
                .min(self.prepended.len() - self.prep_offset);
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
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn stream_one_accepts_post_and_returns_chunked_sse() {
        let (mut client, server) = tokio::io::duplex(8192);
        let server = Box::new(server) as BoxedStream;
        let accept_task = tokio::spawn(async move {
            splithttp_accept(server, Some("/split"), Some("POST"), SplitHttpMode::StreamOne).await
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

        let tunnel = accept_task.await.unwrap().expect("accept failed");
        let mut tunnel = tunnel;
        let mut buf = [0u8; 8];
        let n = tunnel.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
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
