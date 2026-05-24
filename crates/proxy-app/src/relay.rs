//! Bidirectional relay implementations.
//!
//! The default relay uses `tokio::io::copy_bidirectional`, which works for any
//! async stream. On Linux, raw TCP streams can use `splice(2)` to move bytes
//! through kernel pipes without copying them into userspace.

use std::io;

use proxy_common::BoxedStream;

/// Relay bytes between two streams until either side closes.
pub async fn relay_bidirectional(
    inbound: BoxedStream,
    outbound: BoxedStream,
) -> io::Result<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        use proxy_common::{try_into_tcp_stream, BoxedStream};

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
        return tokio_copy_bidirectional(Box::new(inbound), Box::new(outbound)).await;
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
