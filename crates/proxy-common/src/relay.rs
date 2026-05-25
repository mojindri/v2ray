//! Relay helpers aligned with Xray policy defaults.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::pin;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::ProxyError;

/// Default idle timeout for established connections (Xray `ConnectionIdle`).
pub const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

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

    let last_activity = Arc::new(Mutex::new(Instant::now()));

    let up = copy_one_way_with_idle(b_read, a_write, idle, Arc::clone(&last_activity));
    let down = copy_one_way_with_idle(a_read, b_write, idle, last_activity);

    let _ = tokio::join!(up, down);
}

async fn copy_one_way_with_idle<R, W>(
    mut reader: R,
    mut writer: W,
    idle: Duration,
    last_activity: Arc<Mutex<Instant>>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    loop {
        let read_fut = reader.read(&mut buf);
        pin!(read_fut);

        let sleep_fut = sleep_until_activity_deadline(&last_activity, idle);
        pin!(sleep_fut);

        let n = tokio::select! {
            biased;
            res = &mut read_fut => match res {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
            _ = &mut sleep_fut => break,
        };

        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        *last_activity.lock().await = Instant::now();
    }
}

async fn sleep_until_activity_deadline(last_activity: &Arc<Mutex<Instant>>, idle: Duration) {
    loop {
        let deadline = {
            let guard = last_activity.lock().await;
            *guard + idle
        };
        let sleep = tokio::time::sleep_until(deadline);
        pin!(sleep);
        sleep.await;
        let still_active = {
            let guard = last_activity.lock().await;
            Instant::now() < *guard + idle
        };
        if !still_active {
            break;
        }
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
