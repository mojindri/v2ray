//! XTLS Vision framing — Xray `proxy/proxy.go` `XtlsUnpadding` / passthrough fallback.
//!
//! When `flow == "xtls-rprx-vision"`, bytes after the VLESS response may carry Vision
//! padding blocks. If no Vision header is present, data is forwarded unchanged
//! (Xray initial state).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use blackwire_common::BoxedStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const INITIAL: i32 = -1;

/// Per-direction Vision unpadding state (Xray `TrafficState` inbound/outbound fields).
#[derive(Debug, Clone, Default)]
struct UnpaddingState {
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: i32,
}

impl UnpaddingState {
    fn new() -> Self {
        Self {
            remaining_command: INITIAL,
            remaining_content: INITIAL,
            remaining_padding: INITIAL,
            ..Default::default()
        }
    }

    /// Feed bytes; returns plaintext to deliver upstream.
    fn feed(&mut self, uuid: &[u8; 16], input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < input.len() {
            if self.remaining_command == INITIAL
                && self.remaining_content == INITIAL
                && self.remaining_padding == INITIAL
            {
                if input.len().saturating_sub(pos) >= 21 && input[pos..pos + 16] == uuid[..] {
                    pos += 16;
                    self.remaining_command = 5;
                } else {
                    out.extend_from_slice(&input[pos..]);
                    return out;
                }
            }

            if self.remaining_command > 0 {
                let byte = input[pos];
                pos += 1;
                match self.remaining_command {
                    5 => self.current_command = i32::from(byte),
                    4 => self.remaining_content = i32::from(byte) << 8,
                    3 => self.remaining_content |= i32::from(byte),
                    2 => self.remaining_padding = i32::from(byte) << 8,
                    1 => self.remaining_padding |= i32::from(byte),
                    _ => {}
                }
                self.remaining_command -= 1;
            } else if self.remaining_content > 0 {
                let take = (self.remaining_content as usize).min(input.len() - pos);
                out.extend_from_slice(&input[pos..pos + take]);
                pos += take;
                self.remaining_content -= take as i32;
            } else if self.remaining_padding > 0 {
                let skip = (self.remaining_padding as usize).min(input.len() - pos);
                pos += skip;
                self.remaining_padding -= skip as i32;
            }

            if self.remaining_command <= 0 && self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if self.current_command == 0 {
                    self.remaining_command = 5;
                } else {
                    self.remaining_command = INITIAL;
                    self.remaining_content = INITIAL;
                    self.remaining_padding = INITIAL;
                    if pos < input.len() {
                        out.extend_from_slice(&input[pos..]);
                    }
                    break;
                }
            }
        }
        out
    }
}

/// Wrap a stream with Vision unpadding on read; writes pass through (Xray-compatible
/// fallback when the peer sends raw TLS/application bytes).
pub struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    read_state: UnpaddingState,
    read_buf: Vec<u8>,
    /// First downlink write includes the 16-byte UUID prefix (Xray `XtlsPadding`).
    write_uuid_once: bool,
}

impl<S> VisionStream<S> {
    pub fn new(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            read_state: UnpaddingState::new(),
            read_buf: Vec::new(),
            write_uuid_once: true,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = buf.remaining().min(self.read_buf.len());
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
                return Poll::Ready(Ok(()));
            }

            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    let uuid = self.uuid;
                    let plain = self.read_state.feed(&uuid, rb.filled());
                    if plain.is_empty() {
                        continue;
                    }
                    let n = buf.remaining().min(plain.len());
                    buf.put_slice(&plain[..n]);
                    if n < plain.len() {
                        self.read_buf.extend_from_slice(&plain[n..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Vision padding block: optional UUID + 5-byte header + content (Xray `XtlsPadding`).
fn pad_chunk(uuid: &[u8; 16], content: &[u8], command: u8, include_uuid: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(21 + content.len());
    if include_uuid {
        out.extend_from_slice(uuid);
    }
    let cl = content.len();
    out.push(command);
    out.push((cl >> 8) as u8);
    out.push((cl & 0xff) as u8);
    out.push(0);
    out.push(0);
    out.extend_from_slice(content);
    out
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        let include_uuid = self.write_uuid_once;
        if include_uuid {
            self.write_uuid_once = false;
        }
        // Command 1 = padding end (Xray); passthrough content inside the frame.
        let framed = pad_chunk(&self.uuid, buf, 1, include_uuid);
        match Pin::new(&mut self.inner).poll_write(cx, &framed) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Wrap a boxed stream for Vision flow.
pub fn wrap_vision_stream(stream: BoxedStream, uuid: [u8; 16]) -> BoxedStream {
    Box::new(VisionStream::new(stream, uuid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_without_vision_header() {
        let mut st = UnpaddingState::new();
        let uuid = [0u8; 16];
        let out = st.feed(&uuid, b"hello world");
        assert_eq!(out, b"hello world");
    }
}
