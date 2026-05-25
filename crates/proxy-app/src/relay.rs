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

use proxy_common::BoxedStream;

/// Relay bytes between two streams until either side closes.
///
/// Returns `(bytes_client_to_server, bytes_server_to_client)`.
pub async fn relay_bidirectional(
    inbound: BoxedStream,
    outbound: BoxedStream,
) -> io::Result<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        use proxy_common::try_into_tcp_stream;

        // Wrapped streams (TLS/WS/REALITY) cannot splice — use async copy.
        let inbound = match try_into_tcp_stream(inbound) {
            Ok(stream) => stream,
            Err(inbound) => {
                return tokio_copy_bidirectional(inbound, outbound).await;
            }
        };

        let outbound = match try_into_tcp_stream(outbound) {
            Ok(stream) => stream,
            Err(outbound) => {
                return tokio_copy_bidirectional(Box::new(inbound), outbound).await;
            }
        };

        if let Ok(result) = proxy_common::splice::splice_bidirectional(&inbound, &outbound).await {
            return Ok(result);
        }
        // splice can fail on exotic socket types — fall back safely.
        tokio_copy_bidirectional(Box::new(inbound), Box::new(outbound)).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        tokio_copy_bidirectional(inbound, outbound).await
    }
}

async fn tokio_copy_bidirectional(
    mut inbound: BoxedStream,
    mut outbound: BoxedStream,
) -> io::Result<(u64, u64)> {
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
}
