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
const COMMAND_PADDING_CONTINUE: i32 = 0;
const COMMAND_PADDING_END: i32 = 1;
const COMMAND_PADDING_DIRECT: i32 = 2;
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

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

    /// Feed bytes into `out`; returns `true` when the stream should switch to direct copy.
    ///
    /// Writing into a caller-provided Vec avoids a heap allocation per call.
    fn feed(&mut self, uuid: &[u8; 16], input: &[u8], out: &mut Vec<u8>) -> bool {
        let mut switch_to_direct = false;
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
                    return switch_to_direct;
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

            if self.remaining_command <= 0
                && self.remaining_content <= 0
                && self.remaining_padding <= 0
            {
                if self.current_command == COMMAND_PADDING_CONTINUE {
                    self.remaining_command = 5;
                } else {
                    switch_to_direct = self.current_command == COMMAND_PADDING_DIRECT;
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
        switch_to_direct
    }
}

/// Wrap a stream with Vision unpadding on read; writes pass through (Xray-compatible
/// fallback when the peer sends raw TLS/application bytes).
pub struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    read_state: UnpaddingState,
    /// Overflow buffer: plaintext that didn't fit in the caller's ReadBuf last poll.
    read_buf: Vec<u8>,
    /// Reusable scratch buffer for `feed()` — avoids one heap alloc per read poll.
    feed_scratch: Vec<u8>,
    read_direct_copy: bool,
    /// First downlink write includes the 16-byte UUID prefix (Xray `XtlsPadding`).
    write_uuid_once: bool,
    write_direct_copy: bool,
}

impl<S> VisionStream<S> {
    /// Wrap `inner` with XTLS Vision padding/unpadding for the given VLESS UUID.
    pub fn new(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            read_state: UnpaddingState::new(),
            read_buf: Vec::new(),
            feed_scratch: Vec::new(),
            read_direct_copy: false,
            write_uuid_once: true,
            write_direct_copy: false,
        }
    }

    /// Unwrap the underlying stream after Vision processing.
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
        if self.read_direct_copy {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

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
                    // Take feed_scratch out so we can borrow read_state mutably at the same time.
                    let mut scratch = std::mem::take(&mut self.feed_scratch);
                    scratch.clear();
                    let switch_to_direct = self.read_state.feed(&uuid, rb.filled(), &mut scratch);
                    self.feed_scratch = scratch;
                    if switch_to_direct {
                        self.read_direct_copy = true;
                    }
                    if self.feed_scratch.is_empty() {
                        continue;
                    }
                    let n = buf.remaining().min(self.feed_scratch.len());
                    buf.put_slice(&self.feed_scratch[..n]);
                    if n < self.feed_scratch.len() {
                        let extra = self.feed_scratch[n..].to_vec();
                        self.read_buf.extend_from_slice(&extra);
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
        if self.write_direct_copy {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        let include_uuid = self.write_uuid_once;
        if include_uuid {
            self.write_uuid_once = false;
        }
        let command = if looks_like_tls_application_data(buf) && is_complete_tls_record(buf) {
            self.write_direct_copy = true;
            COMMAND_PADDING_DIRECT as u8
        } else {
            COMMAND_PADDING_END as u8
        };
        let framed = pad_chunk(&self.uuid, buf, command, include_uuid);
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

fn looks_like_tls_application_data(buf: &[u8]) -> bool {
    buf.len() >= 6 && buf[..3] == TLS_APPLICATION_DATA_START
}

fn is_complete_tls_record(buf: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < buf.len() {
        if buf.len() - pos < 5 {
            return false;
        }
        if buf[pos..pos + 3] != TLS_APPLICATION_DATA_START {
            return false;
        }
        let record_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        pos += 5;
        if buf.len() - pos < record_len {
            return false;
        }
        pos += record_len;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_without_vision_header() {
        let mut st = UnpaddingState::new();
        let uuid = [0u8; 16];
        let mut out = Vec::new();
        let direct = st.feed(&uuid, b"hello world", &mut out);
        assert_eq!(out, b"hello world");
        assert!(!direct);
    }

    #[test]
    fn switches_to_direct_copy_after_direct_command() {
        let uuid = [7u8; 16];
        let mut frame = uuid.to_vec();
        frame.extend_from_slice(&[COMMAND_PADDING_DIRECT as u8, 0, 3, 0, 0, b'a', b'b', b'c']);
        frame.extend_from_slice(b"tail");

        let mut st = UnpaddingState::new();
        let mut out = Vec::new();
        let direct = st.feed(&uuid, &frame, &mut out);
        assert_eq!(out, b"abctail");
        assert!(direct);
    }

    #[test]
    fn detects_complete_tls_records() {
        let tls_record = [
            0x17, 0x03, 0x03, 0x00, 0x03, b'a', b'b', b'c', 0x17, 0x03, 0x03, 0x00, 0x01, b'z',
        ];
        assert!(looks_like_tls_application_data(&tls_record));
        assert!(is_complete_tls_record(&tls_record));
        assert!(!is_complete_tls_record(&tls_record[..tls_record.len() - 1]));
    }
}
