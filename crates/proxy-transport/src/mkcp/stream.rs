use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use std::task::ready;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// Async byte stream backed by an mKCP session driver.
pub struct MkcpStream {
    tx: PollSender<Bytes>,
    rx: mpsc::Receiver<Bytes>,
    read_buf: BytesMut,
}

impl MkcpStream {
    /// Create a new stream from driver channels.
    pub fn new(tx: mpsc::Sender<Bytes>, rx: mpsc::Receiver<Bytes>) -> Self {
        Self {
            tx: PollSender::new(tx),
            rx,
            read_buf: BytesMut::new(),
        }
    }
}

impl AsyncRead for MkcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MkcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let broken = || io::Error::new(io::ErrorKind::BrokenPipe, "KCP driver closed");
        ready!(self.tx.poll_reserve(cx)).map_err(|_| broken())?;
        self.tx
            .send_item(Bytes::copy_from_slice(buf))
            .map_err(|_| broken())?;
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
