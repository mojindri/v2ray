//! Mux.Cool outbound client — multiplexes multiple logical TCP streams over one
//! underlying VLESS connection, reducing TLS handshake count for short-lived flows.
//!
//! Wire protocol: <https://xtls.github.io/en/development/protocols/muxcool.html>
//!
//! # Architecture
//!
//! ```text
//! sub-stream A ─┐                ┌─ upstream dest A
//! sub-stream B ─┼─ MuxCoolSession ─┼─ upstream dest B
//! sub-stream C ─┘  (one VLESS)   └─ upstream dest C
//! ```
//!
//! Each `MuxCoolSession` owns one VLESS connection.  `MuxCoolSession::open_stream`
//! sends a `New` frame and returns a `MuxStream` that implements `AsyncRead +
//! AsyncWrite` — ready to use as a `BoxedStream`.  When all sub-streams are used
//! (>= `max_concurrency`) or the underlying connection dies, `MuxCoolOutbound`
//! opens a fresh VLESS connection and starts a new session.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::{Buf, Bytes};
use dashmap::DashMap;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use blackwire_common::{Address, BoxedStream, ProxyError};

use super::mux::{
    encode_end_metadata, encode_frame, encode_keep_metadata, encode_new_metadata, read_mux_frame,
    SessionStatus, OPT_DATA, XUDP_SESSION_ID,
};

enum WriterMsg {
    Frame(Vec<u8>),
}

/// One Mux.Cool VLESS connection multiplexing up to `max_concurrency` sub-streams.
pub struct MuxCoolSession {
    write_tx: UnboundedSender<WriterMsg>,
    sub_streams: Arc<DashMap<u16, UnboundedSender<Bytes>>>,
    next_id: AtomicU16,
    active: Arc<AtomicUsize>,
    max_concurrency: usize,
    dead: Arc<AtomicBool>,
}

impl MuxCoolSession {
    /// Wrap an already-authenticated VLESS mux connection.
    ///
    /// Spawns a reader task (routes incoming frames to sub-streams) and a writer
    /// task (serialises outbound frames with batched flush).
    pub fn new(stream: BoxedStream, max_concurrency: usize) -> Arc<Self> {
        let (read_half, write_half) = tokio::io::split(stream);
        let sub_streams: Arc<DashMap<u16, UnboundedSender<Bytes>>> = Arc::new(DashMap::new());
        let dead = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let (write_tx, write_rx) = mpsc::unbounded_channel::<WriterMsg>();

        let sub_r = Arc::clone(&sub_streams);
        let dead_r = Arc::clone(&dead);
        tokio::spawn(async move {
            reader_loop(read_half, sub_r, dead_r).await;
        });

        let dead_w = Arc::clone(&dead);
        tokio::spawn(async move {
            writer_loop(write_half, write_rx, dead_w).await;
        });

        Arc::new(Self {
            write_tx,
            sub_streams,
            next_id: AtomicU16::new(1),
            active,
            max_concurrency,
            dead,
        })
    }

    /// True when there is room for another sub-stream.
    pub fn has_capacity(&self) -> bool {
        !self.dead.load(Ordering::Relaxed)
            && self.active.load(Ordering::Relaxed) < self.max_concurrency
    }

    /// True when the underlying VLESS connection has died.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    /// Open a new logical sub-stream to `dest`.
    ///
    /// Sends a Mux `New` frame over the shared VLESS connection and returns a
    /// `MuxStream` that can be used as a `BoxedStream`.
    pub fn open_stream(&self, dest: &Address) -> Result<MuxStream, ProxyError> {
        if self.dead.load(Ordering::Relaxed) {
            return Err(ProxyError::Transport("mux: session is dead".into()));
        }
        // Skip 0 (XUDP_SESSION_ID reserved).
        let session_id = loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != XUDP_SESSION_ID {
                break id;
            }
        };

        let (data_tx, data_rx) = mpsc::unbounded_channel::<Bytes>();
        self.sub_streams.insert(session_id, data_tx);
        self.active.fetch_add(1, Ordering::Relaxed);

        // Send New frame (no initial payload — data comes via write()).
        let meta = encode_new_metadata(session_id, dest, 0)?;
        let frame = encode_frame(&meta, None)?;
        self.write_tx
            .send(WriterMsg::Frame(frame))
            .map_err(|_| ProxyError::Transport("mux: writer channel closed".into()))?;

        Ok(MuxStream {
            session_id,
            rx: data_rx,
            rx_buf: Bytes::new(),
            write_tx: self.write_tx.clone(),
            sub_streams: Arc::clone(&self.sub_streams),
            active: Arc::clone(&self.active),
            eof: false,
            closed: false,
        })
    }
}

async fn reader_loop(
    mut reader: tokio::io::ReadHalf<BoxedStream>,
    sub_streams: Arc<DashMap<u16, UnboundedSender<Bytes>>>,
    dead: Arc<AtomicBool>,
) {
    while let Ok((meta, payload)) = read_mux_frame(&mut reader).await {
        match meta.status {
            SessionStatus::Keep => {
                if let Some(data) = payload {
                    if !data.is_empty() {
                        if let Some(tx) = sub_streams.get(&meta.session_id) {
                            let _ = tx.send(Bytes::from(data));
                        }
                    }
                }
            }
            // Server-sent End: drop sender → receiver gets None → EOF
            SessionStatus::End => {
                sub_streams.remove(&meta.session_id);
            }
            SessionStatus::KeepAlive | SessionStatus::New => {}
        }
    }
    dead.store(true, Ordering::Relaxed);
    sub_streams.clear();
}

async fn writer_loop(
    mut writer: tokio::io::WriteHalf<BoxedStream>,
    mut rx: UnboundedReceiver<WriterMsg>,
    dead: Arc<AtomicBool>,
) {
    loop {
        // Wait for first frame.
        let Some(WriterMsg::Frame(frame)) = rx.recv().await else {
            break;
        };
        if writer.write_all(&frame).await.is_err() {
            break;
        }
        // Drain any frames that are already queued (batch write, one flush).
        while let Ok(WriterMsg::Frame(frame)) = rx.try_recv() {
            if writer.write_all(&frame).await.is_err() {
                dead.store(true, Ordering::Relaxed);
                return;
            }
        }
        if writer.flush().await.is_err() {
            break;
        }
    }
    dead.store(true, Ordering::Relaxed);
}

/// A single multiplexed sub-stream; implements `AsyncRead + AsyncWrite`.
pub struct MuxStream {
    session_id: u16,
    rx: UnboundedReceiver<Bytes>,
    rx_buf: Bytes,
    write_tx: UnboundedSender<WriterMsg>,
    sub_streams: Arc<DashMap<u16, UnboundedSender<Bytes>>>,
    active: Arc<AtomicUsize>,
    eof: bool,
    closed: bool,
}

impl tokio::io::AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.rx_buf.is_empty() {
            let n = self.rx_buf.len().min(buf.remaining());
            buf.put_slice(&self.rx_buf[..n]);
            self.rx_buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.rx_buf = data.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let meta = encode_keep_metadata(self.session_id, OPT_DATA);
        match encode_frame(&meta, Some(buf)) {
            Ok(frame) => {
                if self.write_tx.send(WriterMsg::Frame(frame)).is_err() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "mux writer closed",
                    )));
                }
                Poll::Ready(Ok(buf.len()))
            }
            Err(e) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                e.to_string(),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // Flushing is handled by the writer task after each batch.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            self.sub_streams.remove(&self.session_id);
            self.active.fetch_sub(1, Ordering::Relaxed);
            let meta = encode_end_metadata(self.session_id, 0);
            if let Ok(frame) = encode_frame(&meta, None) {
                let _ = self.write_tx.send(WriterMsg::Frame(frame));
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Build a pair of in-process streams that are cross-wired:
    /// bytes written to `a_write` appear on `b_read`, and vice-versa.
    fn duplex_pair() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    /// Build a minimal Mux.Cool server that handles exactly one sub-stream:
    /// opens a `MuxCoolSession` on the server half, accepts one New frame,
    /// echoes all Keep payloads back, then sends End when it sees End.
    async fn run_echo_server(server_stream: tokio::io::DuplexStream) {
        use super::super::mux::{
            encode_end_metadata, encode_frame, encode_keep_metadata, OPT_DATA,
        };
        use tokio::io::AsyncReadExt;

        let mut server = server_stream;

        // Read frames until we see End.
        while let Ok(n) = server.read_u16().await {
            let meta_len = n as usize;
            let mut meta_buf = vec![0u8; meta_len];
            if server.read_exact(&mut meta_buf).await.is_err() {
                break;
            }
            let meta = super::super::mux::parse_metadata(&meta_buf).unwrap();
            let payload = if meta.option & OPT_DATA != 0 {
                let data_len = server.read_u16().await.unwrap() as usize;
                let mut data = vec![0u8; data_len];
                if data_len > 0 {
                    server.read_exact(&mut data).await.unwrap();
                }
                Some(data)
            } else {
                None
            };

            match meta.status {
                SessionStatus::New => {} // ack implicitly (no response needed)
                SessionStatus::Keep => {
                    if let Some(data) = payload {
                        // Echo back
                        let reply_meta = encode_keep_metadata(meta.session_id, OPT_DATA);
                        let frame = encode_frame(&reply_meta, Some(&data)).unwrap();
                        server.write_all(&frame).await.unwrap();
                        server.flush().await.unwrap();
                    }
                }
                SessionStatus::End => {
                    // Send End back
                    let end_meta = encode_end_metadata(meta.session_id, 0);
                    let frame = encode_frame(&end_meta, None).unwrap();
                    let _ = server.write_all(&frame).await;
                    let _ = server.flush().await;
                    break;
                }
                SessionStatus::KeepAlive => {}
            }
        }
    }

    #[tokio::test]
    async fn mux_stream_echo_roundtrip() {
        use blackwire_common::Address;
        use std::net::Ipv4Addr;

        let (client_half, server_half) = duplex_pair();
        let client_stream: BoxedStream = Box::new(client_half);

        tokio::spawn(run_echo_server(server_half));

        let session = MuxCoolSession::new(client_stream, 8);
        let dest = Address::Ipv4(Ipv4Addr::LOCALHOST, 80);
        let mut stream = session.open_stream(&dest).unwrap();

        let payload = b"hello mux";
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("timed out")
            .expect("read failed");

        assert_eq!(&buf[..n], payload.as_ref());
    }

    #[tokio::test]
    async fn mux_stream_shutdown_sends_end() {
        use blackwire_common::Address;
        use std::net::Ipv4Addr;

        let (client_half, server_half) = duplex_pair();
        let client_stream: BoxedStream = Box::new(client_half);

        tokio::spawn(run_echo_server(server_half));

        let session = MuxCoolSession::new(client_stream, 8);
        let dest = Address::Ipv4(Ipv4Addr::LOCALHOST, 80);
        let mut stream = session.open_stream(&dest).unwrap();

        // Shutdown should send End to the server (which triggers server End back → EOF).
        stream.shutdown().await.unwrap();

        // Reading should eventually return EOF.
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("timed out")
            .expect("read after shutdown failed");
        assert_eq!(n, 0, "expected EOF after End exchange");
    }
}
