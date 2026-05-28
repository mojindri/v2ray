//! Bidirectional relay — copy bytes between client and upstream until one side closes.
//!
//! # How relay works
//!
//! After the dispatcher opens an outbound connection, it runs a relay loop:
//!
//!   client ←→ inbound stream ←→ outbound stream ←→ destination
//!
//! Both directions run concurrently until either side closes or errors.
//!
//! # Linux splice(2)
//!
//! On Linux, when **both** sides are raw `TcpStream`s, we try `splice(2)` first.
//! Splice moves data through kernel pipes — bytes never touch userspace buffers,
//! which saves CPU on large transfers. If either stream is wrapped (TLS, WebSocket,
//! REALITY, etc.) or splice fails, we fall back to `tokio::io::copy_bidirectional`.

use std::io;
use std::time::Duration;

use blackwire_common::BoxedStream;
use blackwire_config::schema::FastSplicePolicy;
#[cfg(target_os = "linux")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Minimum bytes transferred before the adaptive splice policy kicks in (Linux).
#[cfg(target_os = "linux")]
pub const ADAPTIVE_SPLICE_MIN_BYTES: u64 = 256 * 1024;
#[cfg(target_os = "linux")]
pub const ADAPTIVE_SPLICE_LONG_STREAM_AFTER: Duration = Duration::from_millis(30);
#[cfg(target_os = "linux")]
const ADAPTIVE_COPY_BUFFER_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const ADAPTIVE_SPLICE_FULL_READ_STREAK: u8 = 4;
#[cfg(target_os = "linux")]
const ADAPTIVE_SPLICE_FULL_READ_MIN_BYTES: u64 = 64 * 1024;

/// Minimum bytes transferred before the adaptive splice policy kicks in (non-Linux stub).
#[cfg(not(target_os = "linux"))]
pub const ADAPTIVE_SPLICE_MIN_BYTES: u64 = 0;
#[cfg(not(target_os = "linux"))]
pub const ADAPTIVE_SPLICE_LONG_STREAM_AFTER: Duration = Duration::from_millis(0);

/// Relay bytes between two streams until either side closes.
///
/// Returns `(bytes_client_to_server, bytes_server_to_client)`.
#[allow(dead_code)]
pub async fn relay_bidirectional(
    inbound: BoxedStream,
    outbound: BoxedStream,
) -> io::Result<(u64, u64)> {
    relay_bidirectional_with_splice_policy(inbound, outbound, FastSplicePolicy::Always).await
}

/// Relay bytes with an explicit Fast Profile splice policy.
pub async fn relay_bidirectional_with_splice_policy(
    inbound: BoxedStream,
    outbound: BoxedStream,
    splice_policy: FastSplicePolicy,
) -> io::Result<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        use blackwire_common::{try_into_tcp_stream_with_prefix, PrependedStream};

        let (mut inbound, inbound_prefix) = match try_into_tcp_stream_with_prefix(inbound) {
            Ok(parts) => parts,
            Err(inbound) => {
                metrics::counter!(
                    "proxy_relay_splice_fallback_total",
                    "reason" => "inbound_wrapped"
                )
                .increment(1);
                return tokio_copy_bidirectional(inbound, outbound).await;
            }
        };

        let (mut outbound, outbound_prefix) = match try_into_tcp_stream_with_prefix(outbound) {
            Ok(parts) => parts,
            Err(outbound) => {
                metrics::counter!(
                    "proxy_relay_splice_fallback_total",
                    "reason" => "outbound_wrapped"
                )
                .increment(1);
                let inbound: BoxedStream = if inbound_prefix.is_empty() {
                    Box::new(inbound)
                } else {
                    Box::new(PrependedStream::new(inbound, inbound_prefix))
                };
                return tokio_copy_bidirectional(inbound, outbound).await;
            }
        };

        let prefix_up = inbound_prefix.len() as u64;
        let prefix_down = outbound_prefix.len() as u64;

        if !inbound_prefix.is_empty() {
            outbound.write_all(&inbound_prefix).await?;
        }
        if !outbound_prefix.is_empty() {
            inbound.write_all(&outbound_prefix).await?;
        }

        if splice_policy == FastSplicePolicy::Disabled {
            metrics::counter!(
                "proxy_relay_splice_fallback_total",
                "reason" => "policy_disabled"
            )
            .increment(1);
            let (up, down) =
                tokio_copy_bidirectional(Box::new(inbound), Box::new(outbound)).await?;
            record_relay_path_bytes("copy", up + prefix_up, down + prefix_down);
            return Ok((up + prefix_up, down + prefix_down));
        }

        if splice_policy == FastSplicePolicy::Adaptive {
            return adaptive_copy_then_splice(inbound, outbound, prefix_up, prefix_down).await;
        }

        metrics::counter!("proxy_relay_splice_selected_total", "policy" => "always").increment(1);

        if let Ok((up, down)) =
            blackwire_common::splice::splice_bidirectional(&mut inbound, &mut outbound).await
        {
            record_relay_path_bytes("splice", up + prefix_up, down + prefix_down);
            return Ok((up + prefix_up, down + prefix_down));
        }
        // splice can fail on exotic socket types — fall back safely.
        metrics::counter!(
            "proxy_relay_splice_fallback_total",
            "reason" => "splice_error"
        )
        .increment(1);
        let (up, down) = tokio_copy_bidirectional(Box::new(inbound), Box::new(outbound)).await?;
        record_relay_path_bytes("copy", up + prefix_up, down + prefix_down);
        Ok((up + prefix_up, down + prefix_down))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = splice_policy;
        tokio_copy_bidirectional(inbound, outbound).await
    }
}

#[cfg(target_os = "linux")]
async fn adaptive_copy_then_splice(
    mut inbound: tokio::net::TcpStream,
    mut outbound: tokio::net::TcpStream,
    prefix_up: u64,
    prefix_down: u64,
) -> io::Result<(u64, u64)> {
    let mut up = 0u64;
    let mut down = 0u64;
    let mut up_eof = false;
    let mut down_eof = false;
    let mut up_buf = vec![0u8; ADAPTIVE_COPY_BUFFER_BYTES];
    let mut down_buf = vec![0u8; ADAPTIVE_COPY_BUFFER_BYTES];
    let started_at = tokio::time::Instant::now();
    let mut full_read_streak = 0u8;

    loop {
        let copied_total = prefix_up + prefix_down + up + down;
        if !up_eof
            && !down_eof
            && adaptive_splice_ready(copied_total, started_at.elapsed(), full_read_streak)
        {
            metrics::counter!("proxy_relay_splice_selected_total", "policy" => "adaptive")
                .increment(1);
            match blackwire_common::splice::splice_bidirectional(&mut inbound, &mut outbound).await
            {
                Ok((more_up, more_down)) => {
                    up += more_up;
                    down += more_down;
                    record_relay_path_bytes("adaptive_splice", up + prefix_up, down + prefix_down);
                    return Ok((up + prefix_up, down + prefix_down));
                }
                Err(_) => {
                    metrics::counter!(
                        "proxy_relay_splice_fallback_total",
                        "reason" => "adaptive_splice_error"
                    )
                    .increment(1);
                    // Continue on the copy path. The streams are still owned and
                    // usable here; splice failed before consuming user-space data.
                }
            }
        }

        if up_eof && down_eof {
            metrics::counter!(
                "proxy_relay_splice_fallback_total",
                "reason" => "adaptive_below_threshold"
            )
            .increment(1);
            record_relay_path_bytes("adaptive_copy", up + prefix_up, down + prefix_down);
            return Ok((up + prefix_up, down + prefix_down));
        }

        tokio::select! {
            read = inbound.read(&mut up_buf), if !up_eof => {
                let n = read?;
                if n == 0 {
                    up_eof = true;
                    outbound.shutdown().await?;
                } else {
                    outbound.write_all(&up_buf[..n]).await?;
                    up += n as u64;
                    full_read_streak = update_full_read_streak(full_read_streak, n, up_buf.len());
                }
            }
            read = outbound.read(&mut down_buf), if !down_eof => {
                let n = read?;
                if n == 0 {
                    down_eof = true;
                    inbound.shutdown().await?;
                } else {
                    inbound.write_all(&down_buf[..n]).await?;
                    down += n as u64;
                    full_read_streak = update_full_read_streak(full_read_streak, n, down_buf.len());
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn adaptive_splice_ready(copied_total: u64, elapsed: Duration, full_read_streak: u8) -> bool {
    let bulk_reads = full_read_streak >= ADAPTIVE_SPLICE_FULL_READ_STREAK;
    bulk_reads
        && (copied_total >= ADAPTIVE_SPLICE_MIN_BYTES
            || (copied_total >= ADAPTIVE_SPLICE_FULL_READ_MIN_BYTES
                && elapsed >= ADAPTIVE_SPLICE_LONG_STREAM_AFTER))
}

#[cfg(target_os = "linux")]
fn update_full_read_streak(current: u8, read_len: usize, buf_len: usize) -> u8 {
    if read_len == buf_len {
        current.saturating_add(1)
    } else {
        0
    }
}

#[allow(dead_code)]
fn record_relay_path_bytes(path: &'static str, up: u64, down: u64) {
    metrics::counter!(
        "proxy_relay_bytes_total",
        "direction" => "up",
        "path" => path
    )
    .increment(up);
    metrics::counter!(
        "proxy_relay_bytes_total",
        "direction" => "down",
        "path" => path
    )
    .increment(down);
}

async fn tokio_copy_bidirectional(
    inbound: BoxedStream,
    outbound: BoxedStream,
) -> io::Result<(u64, u64)> {
    blackwire_common::relay::copy_bidirectional_pooled(inbound, outbound).await
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::*;
    #[cfg(target_os = "linux")]
    use blackwire_common::PrependedStream;
    #[cfg(target_os = "linux")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(target_os = "linux")]
    use tokio::net::{TcpListener, TcpStream};

    #[cfg(target_os = "linux")]
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn relay_drains_prepended_prefix_before_raw_tcp_splice() {
        let (mut client_a, server_a) = tcp_pair().await;
        let (mut client_b, server_b) = tcp_pair().await;

        let relay = tokio::spawn(async move {
            relay_bidirectional(
                Box::new(PrependedStream::new(server_a, b"pre-a-".to_vec())),
                Box::new(PrependedStream::new(server_b, b"pre-b-".to_vec())),
            )
            .await
            .unwrap()
        });

        client_a.write_all(b"from-a").await.unwrap();
        client_b.write_all(b"from-b").await.unwrap();
        client_a.shutdown().await.unwrap();
        client_b.shutdown().await.unwrap();

        let mut got_a = Vec::new();
        let mut got_b = Vec::new();
        client_a.read_to_end(&mut got_a).await.unwrap();
        client_b.read_to_end(&mut got_b).await.unwrap();

        let (up, down) = relay.await.unwrap();

        assert_eq!(got_a, b"pre-b-from-b");
        assert_eq!(got_b, b"pre-a-from-a");
        assert_eq!(up, b"pre-a-from-a".len() as u64);
        assert_eq!(down, b"pre-b-from-b".len() as u64);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adaptive_splice_waits_for_bulk_evidence() {
        assert!(!adaptive_splice_ready(
            64 * 1024,
            ADAPTIVE_SPLICE_LONG_STREAM_AFTER,
            ADAPTIVE_SPLICE_FULL_READ_STREAK - 1
        ));
        assert!(!adaptive_splice_ready(
            ADAPTIVE_SPLICE_MIN_BYTES - 1,
            Duration::ZERO,
            ADAPTIVE_SPLICE_FULL_READ_STREAK
        ));
        assert!(!adaptive_splice_ready(
            ADAPTIVE_SPLICE_MIN_BYTES,
            Duration::ZERO,
            ADAPTIVE_SPLICE_FULL_READ_STREAK - 1
        ));
        assert!(adaptive_splice_ready(
            ADAPTIVE_SPLICE_MIN_BYTES,
            Duration::ZERO,
            ADAPTIVE_SPLICE_FULL_READ_STREAK
        ));
        assert!(adaptive_splice_ready(
            64 * 1024,
            ADAPTIVE_SPLICE_LONG_STREAM_AFTER,
            ADAPTIVE_SPLICE_FULL_READ_STREAK
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adaptive_splice_full_read_streak_resets_on_short_read() {
        let streak = update_full_read_streak(0, 16 * 1024, 16 * 1024);
        let streak = update_full_read_streak(streak, 16 * 1024, 16 * 1024);
        assert_eq!(streak, 2);
        assert_eq!(update_full_read_streak(streak, 1024, 16 * 1024), 0);
    }
}
