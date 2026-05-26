//! SplitHTTP `packet-up` server support (Xray `splithttp` upload queue semantics).

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use tokio::sync::{mpsc, Mutex};

const DEFAULT_MAX_BUFFERED: usize = 64;

/// One upload chunk in packet-up mode.
pub struct UploadPacket {
    pub seq: u64,
    pub payload: Vec<u8>,
}

struct QueueState {
    next_seq: u64,
    heap: BinaryHeap<Reverse<(u64, Vec<u8>)>>,
    pending: Vec<u8>,
    closed: bool,
    max_buffered: usize,
}

impl QueueState {
    fn fill_pending(&mut self) -> Result<(), io::Error> {
        loop {
            match self.heap.pop() {
                Some(Reverse((seq, payload))) if seq == self.next_seq => {
                    self.pending.extend_from_slice(&payload);
                    self.next_seq = self.next_seq.saturating_add(1);
                }
                Some(Reverse((seq, payload))) if seq > self.next_seq => {
                    if self.heap.len() >= self.max_buffered {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "packet-up reorder buffer exceeded",
                        ));
                    }
                    self.heap.push(Reverse((seq, payload)));
                    return Ok(());
                }
                Some(Reverse((_seq, _payload))) => {}
                None if self.closed && self.pending.is_empty() => {
                    return Err(io::ErrorKind::UnexpectedEof.into())
                }
                None => return Ok(()),
            }
        }
    }
}

/// Reorders packet-up POST bodies by `seq` for the download GET leg.
pub struct UploadQueue {
    state: Mutex<QueueState>,
    wake_tx: mpsc::UnboundedSender<()>,
    wake_rx: StdMutex<Option<mpsc::UnboundedReceiver<()>>>,
}

impl UploadQueue {
    pub fn new(max_buffered: usize) -> Arc<Self> {
        let max_buffered = if max_buffered == 0 {
            DEFAULT_MAX_BUFFERED
        } else {
            max_buffered
        };
        let (wake_tx, wake_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            state: Mutex::new(QueueState {
                next_seq: 0,
                heap: BinaryHeap::new(),
                pending: Vec::new(),
                closed: false,
                max_buffered,
            }),
            wake_tx,
            wake_rx: StdMutex::new(Some(wake_rx)),
        })
    }

    fn bump_wake(&self) {
        let _ = self.wake_tx.send(());
    }

    pub async fn push(self: &Arc<Self>, packet: UploadPacket) -> Result<(), io::Error> {
        let mut st = self.state.lock().await;
        if st.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "queue closed"));
        }
        st.heap.push(Reverse((packet.seq, packet.payload)));
        drop(st);
        self.bump_wake();
        Ok(())
    }

    pub async fn close(self: &Arc<Self>) {
        let mut st = self.state.lock().await;
        st.closed = true;
        drop(st);
        self.bump_wake();
    }

    fn take_reader(self: &Arc<Self>) -> UploadQueueReader {
        let wake_rx = self
            .wake_rx
            .lock()
            .unwrap()
            .take()
            .expect("only one UploadQueueReader per session");
        UploadQueueReader {
            queue: Arc::clone(self),
            wake_rx,
        }
    }
}

/// Single-consumer async reader over an [`UploadQueue`].
pub struct UploadQueueReader {
    queue: Arc<UploadQueue>,
    wake_rx: mpsc::UnboundedReceiver<()>,
}

impl UploadQueueReader {
    pub fn new(queue: Arc<UploadQueue>) -> Self {
        queue.take_reader()
    }
}

impl tokio::io::AsyncRead for UploadQueueReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.queue.state.try_lock().is_err() {
                match self.wake_rx.poll_recv(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(())) => continue,
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                }
            }
            let mut st = self.queue.state.try_lock().expect("lock free after wait");

            match st.fill_pending() {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Poll::Ready(Ok(())),
                Err(e) => return Poll::Ready(Err(e)),
            }

            if !st.pending.is_empty() {
                let n = buf.remaining().min(st.pending.len());
                buf.put_slice(&st.pending[..n]);
                st.pending.drain(..n);
                return Poll::Ready(Ok(()));
            }

            if st.closed {
                return Poll::Ready(Ok(()));
            }

            drop(st);
            match self.wake_rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(())) => continue,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
            }
        }
    }
}

/// Normalize configured path to a trailing-slash prefix.
pub fn normalized_path_prefix(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let mut p = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if !p.ends_with('/') {
        p.push('/');
    }
    p
}

/// Extract session id and seq from path + query (defaults: path / path).
pub fn extract_session_seq(path_and_query: &str, base_path: &str) -> (String, String) {
    let (path_only, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_and_query, ""),
    };
    let prefix = normalized_path_prefix(base_path);
    let rest = path_only
        .strip_prefix(prefix.trim_end_matches('/'))
        .unwrap_or(path_only)
        .trim_start_matches('/');

    let parts: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let mut session = parts.first().unwrap_or(&"").to_string();
    let mut seq = parts.get(1).unwrap_or(&"").to_string();

    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k == "x_session" && session.is_empty() {
            session = v.to_string();
        }
        if k == "x_seq" && seq.is_empty() {
            seq = v.to_string();
        }
    }

    (session, seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn path_meta_defaults() {
        let (sid, seq) = extract_session_seq("/split/abc/3", "/split");
        assert_eq!(sid, "abc");
        assert_eq!(seq, "3");
    }

    #[tokio::test]
    async fn reorder_by_seq() {
        let q = UploadQueue::new(8);
        q.push(UploadPacket {
            seq: 1,
            payload: b"B".to_vec(),
        })
        .await
        .unwrap();
        q.push(UploadPacket {
            seq: 0,
            payload: b"A".to_vec(),
        })
        .await
        .unwrap();
        let mut reader = UploadQueueReader::new(Arc::clone(&q));
        let mut buf = [0u8; 4];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"AB");
    }

    #[tokio::test]
    async fn read_waits_for_out_of_order_push() {
        let q = UploadQueue::new(8);
        q.push(UploadPacket {
            seq: 1,
            payload: b"B".to_vec(),
        })
        .await
        .unwrap();
        let mut reader = UploadQueueReader::new(Arc::clone(&q));
        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            let n = reader.read(&mut buf).await.unwrap();
            buf[..n].to_vec()
        });
        tokio::task::yield_now().await;
        q.push(UploadPacket {
            seq: 0,
            payload: b"A".to_vec(),
        })
        .await
        .unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), read_task)
            .await
            .expect("read should not hang")
            .unwrap();
        assert_eq!(got, b"AB");
    }
}
