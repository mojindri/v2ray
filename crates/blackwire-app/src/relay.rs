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

use blackwire_common::BoxedStream;
#[cfg(target_os = "linux")]
use tokio::io::AsyncWriteExt;

/// Relay bytes between two streams until either side closes.
///
/// Returns `(bytes_client_to_server, bytes_server_to_client)`.
pub async fn relay_bidirectional(
    inbound: BoxedStream,
    outbound: BoxedStream,
) -> io::Result<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        use blackwire_common::{try_into_tcp_stream_with_prefix, PrependedStream};

        let (mut inbound, inbound_prefix) = match try_into_tcp_stream_with_prefix(inbound) {
            Ok(parts) => parts,
            Err(inbound) => {
                return tokio_copy_bidirectional(inbound, outbound).await;
            }
        };

        let (mut outbound, outbound_prefix) = match try_into_tcp_stream_with_prefix(outbound) {
            Ok(parts) => parts,
            Err(outbound) => {
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

        if let Ok((up, down)) =
            blackwire_common::splice::splice_bidirectional(&mut inbound, &mut outbound).await
        {
            return Ok((up + prefix_up, down + prefix_down));
        }
        // splice can fail on exotic socket types — fall back safely.
        let (up, down) = tokio_copy_bidirectional(Box::new(inbound), Box::new(outbound)).await?;
        Ok((up + prefix_up, down + prefix_down))
    }

    #[cfg(not(target_os = "linux"))]
    {
        tokio_copy_bidirectional(inbound, outbound).await
    }
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
}
