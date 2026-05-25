//! Minimal SplitHTTP / xHTTP transport over one HTTP/1.1 full-duplex request.
//!
//! This is the repo's first non-schema implementation of `network=splithttp`.
//! It supports the common host/path/method/header shape and a chunked
//! request/response tunnel similar to sing-box's HTTP transport.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use blackwire_common::{BoxedStream, ProxyError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use blackwire_config::schema::{SplitHttpConfig, StreamSettingsConfig};

const MAX_HEADER_BYTES: usize = 16384;

pub async fn splithttp_connect(
    mut stream: BoxedStream,
    authority: &str,
    stream_settings: &StreamSettingsConfig,
) -> Result<BoxedStream, ProxyError> {
    let cfg = split_http_config(stream_settings);
    let path = cfg.path.clone();
    let method = cfg.method.clone();
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

pub async fn splithttp_accept(
    mut stream: BoxedStream,
    expected_path: Option<&str>,
    expected_method: Option<&str>,
) -> Result<BoxedStream, ProxyError> {
    let request = read_headers(&mut stream).await?;
    let mut lines = request.lines();
    let first = lines
        .next()
        .ok_or_else(|| ProxyError::Protocol("SplitHTTP missing request line".into()))?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if let Some(expected) = expected_method {
        if !method.eq_ignore_ascii_case(expected) {
            return Err(ProxyError::Protocol(format!(
                "SplitHTTP method mismatch: got '{method}', want '{expected}'"
            )));
        }
    }
    if let Some(expected) = expected_path {
        let got = path.split('?').next().unwrap_or(path);
        if got != expected {
            return Err(ProxyError::Protocol(format!(
                "SplitHTTP path mismatch: got '{got}', want '{expected}'"
            )));
        }
    }

    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await?;
    stream.flush().await?;
    Ok(Box::new(SplitHttpStream::new(stream)))
}

pub fn splithttp_listen_params(
    stream_settings: &StreamSettingsConfig,
) -> (Option<String>, Option<String>) {
    let cfg = split_http_config(stream_settings);
    (Some(cfg.path.clone()), Some(cfg.method.clone()))
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
