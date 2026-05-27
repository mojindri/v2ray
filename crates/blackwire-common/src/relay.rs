//! Relay helpers aligned with Xray policy defaults.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::pin;

use crate::{BufferPool, ProxyError};

/// Default idle timeout for established connections (Xray `ConnectionIdle`).
pub const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Milliseconds elapsed since the relay module was first used.
/// Provides a lightweight monotonic clock for idle-timeout tracking without
/// allocating a mutex or taking a lock on every packet.
fn now_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Shared buffer pool for the idle relay helper.
/// Reusing 16 KiB buffers avoids per-connection heap allocations.
fn relay_pool() -> &'static Arc<BufferPool> {
    static POOL: OnceLock<Arc<BufferPool>> = OnceLock::new();
    POOL.get_or_init(BufferPool::new)
}

/// Bidirectional relay using pooled 16 KiB buffers.
///
/// Equivalent to `tokio::io::copy_bidirectional` but reuses buffers from the
/// shared pool instead of allocating fresh per call. This matters when
/// connections are short-lived (benchmarks, many small requests).
///
/// Takes ownership of both streams (uses `tokio::io::split` internally).
/// Returns `(bytes_a_to_b, bytes_b_to_a)`.
pub async fn copy_bidirectional_pooled<A, B>(a: A, b: B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_rx, a_tx) = tokio::io::split(a);
    let (b_rx, b_tx) = tokio::io::split(b);
    let pool = relay_pool();
    let (r_up, r_down) = tokio::join!(
        copy_one_pooled(a_rx, b_tx, Arc::clone(pool)),
        copy_one_pooled(b_rx, a_tx, Arc::clone(pool)),
    );
    Ok((r_up?, r_down?))
}

async fn copy_one_pooled<R, W>(mut reader: R, mut writer: W, pool: Arc<BufferPool>) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    const BUF_SIZE: usize = 16 * 1024;
    let mut buf = pool.acquire(BUF_SIZE);
    buf.resize(BUF_SIZE, 0);
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf[..]).await?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    pool.release(buf);
    Ok(total)
}

/// Run an async handshake step with an optional wall-clock limit.
pub async fn with_handshake_timeout<T, F>(
    timeout: Option<Duration>,
    fut: F,
) -> Result<T, ProxyError>
where
    F: std::future::Future<Output = Result<T, ProxyError>>,
{
    match timeout {
        Some(limit) => match tokio::time::timeout(limit, fut).await {
            Ok(result) => result,
            Err(_) => Err(ProxyError::Timeout),
        },
        None => fut.await,
    }
}

/// Bidirectional relay that closes when neither direction moves data for `idle`.
pub async fn copy_bidirectional_with_idle<A, B>(a: &mut A, b: &mut B, idle: Duration)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);

    // AtomicU64 stores the last-activity timestamp (ms since module init).
    // Both relay halves update it lock-free; `sleep_until_idle` reads it.
    let last_activity = Arc::new(AtomicU64::new(now_ms()));

    let up = copy_one_way_with_idle(b_read, a_write, idle, Arc::clone(&last_activity));
    let down = copy_one_way_with_idle(a_read, b_write, idle, last_activity);

    let _ = tokio::join!(up, down);
}

async fn copy_one_way_with_idle<R, W>(
    mut reader: R,
    mut writer: W,
    idle: Duration,
    last_activity: Arc<AtomicU64>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    const BUF_SIZE: usize = 16 * 1024; // medium size class — matches BufferPool
    let pool = relay_pool();
    let mut buf = pool.acquire(BUF_SIZE);
    buf.resize(BUF_SIZE, 0); // make the full capacity addressable for reads

    loop {
        let read_fut = reader.read(&mut buf[..]);
        pin!(read_fut);

        let idle_fut = sleep_until_idle(&last_activity, idle);
        pin!(idle_fut);

        let n = tokio::select! {
            biased;
            res = &mut read_fut => match res {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
            _ = &mut idle_fut => break,
        };

        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        last_activity.store(now_ms(), Ordering::Relaxed);
    }

    pool.release(buf);
}

/// Sleeps until the idle deadline (last_activity + idle) expires without renewal.
async fn sleep_until_idle(last_activity: &Arc<AtomicU64>, idle: Duration) {
    let idle_ms = idle.as_millis() as u64;
    loop {
        let last_ms = last_activity.load(Ordering::Relaxed);
        let deadline_ms = last_ms.saturating_add(idle_ms);
        let now = now_ms();
        if now >= deadline_ms {
            break;
        }
        tokio::time::sleep(Duration::from_millis(deadline_ms - now)).await;
        // If activity didn't change during sleep, the connection is idle.
        if last_activity.load(Ordering::Relaxed) == last_ms {
            break;
        }
        // Activity occurred during sleep — recompute and sleep again.
    }
}

/// Reject domain names longer than the SOCKS5 wire format allows (1-byte length field).
pub fn domain_wire_len(name: &str) -> Result<u8, ProxyError> {
    if name.len() > 255 {
        return Err(ProxyError::Protocol(format!(
            "domain too long: {} bytes",
            name.len()
        )));
    }
    Ok(name.len() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn domain_wire_len_matches_xray_limit() {
        assert!(domain_wire_len(&"a".repeat(255)).is_ok());
        assert!(domain_wire_len(&"a".repeat(256)).is_err());
    }

    #[tokio::test]
    async fn idle_copy_completes_on_eof() {
        let mut a = std::io::Cursor::new(Vec::<u8>::new());
        let mut b = std::io::Cursor::new(Vec::<u8>::new());
        copy_bidirectional_with_idle(&mut a, &mut b, Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn handshake_timeout_returns_error() {
        let slow = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok::<(), ProxyError>(())
        };
        let err = with_handshake_timeout(Some(Duration::from_millis(10)), slow)
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Timeout));
    }
}
