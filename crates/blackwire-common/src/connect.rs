//! Outbound TCP connect helpers.
//!
//! Xray-core caps the system TCP dialer at 16 seconds
//! (`transport/internet/system_dialer.go`). We apply the same limit so outbound
//! dials fail fast instead of waiting on OS defaults.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, ToSocketAddrs};

use crate::ProxyError;

/// Default outbound TCP connect timeout (matches Xray `net.Dialer.Timeout`).
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(16);

static OUTBOUND_BYPASS_MARK: AtomicU32 = AtomicU32::new(0);

/// Configure the process-wide outbound routing bypass mark.
///
/// Linux TUN mode uses this value as `SO_MARK` on outbound TCP sockets before
/// `connect()`, so the SYN itself bypasses the TUN policy route. Other
/// platforms keep the value for a future protected-socket backend but do not
/// apply it yet.
pub fn set_outbound_bypass_mark(mark: u32) {
    OUTBOUND_BYPASS_MARK.store(mark, Ordering::Relaxed);
}

/// Clear the process-wide outbound routing bypass mark.
pub fn clear_outbound_bypass_mark() {
    OUTBOUND_BYPASS_MARK.store(0, Ordering::Relaxed);
}

/// Return the currently configured outbound routing bypass mark.
pub fn outbound_bypass_mark() -> Option<u32> {
    let mark = OUTBOUND_BYPASS_MARK.load(Ordering::Relaxed);
    (mark != 0).then_some(mark)
}

/// Dial `addr` with [`TCP_CONNECT_TIMEOUT`].
pub async fn tcp_connect(addr: SocketAddr) -> Result<TcpStream, ProxyError> {
    let socket = protected_tcp_socket(addr)?;
    match tokio::time::timeout(TCP_CONNECT_TIMEOUT, socket.connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(ProxyError::Io(e)),
        Err(_) => Err(ProxyError::Timeout),
    }
}

/// Dial a host/port string (e.g. `"127.0.0.1:80"`) with [`TCP_CONNECT_TIMEOUT`].
pub async fn tcp_connect_to(addr: impl ToSocketAddrs) -> Result<TcpStream, ProxyError> {
    let mut last_err = None;
    for socket_addr in tokio::net::lookup_host(addr)
        .await
        .map_err(ProxyError::Io)?
    {
        match tcp_connect(socket_addr).await {
            Ok(stream) => return Ok(stream),
            Err(ProxyError::Io(e)) => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }

    Err(last_err.map_or_else(
        || ProxyError::Transport("TCP connect failed: address resolved to no endpoints".into()),
        ProxyError::Io,
    ))
}

fn protected_tcp_socket(addr: SocketAddr) -> Result<TcpSocket, ProxyError> {
    let socket = if addr.is_ipv6() {
        TcpSocket::new_v6()
    } else {
        TcpSocket::new_v4()
    }
    .map_err(ProxyError::Io)?;

    #[cfg(target_os = "linux")]
    if let Some(mark) = outbound_bypass_mark() {
        use nix::sys::socket::{setsockopt, sockopt::Mark};
        setsockopt(&socket, Mark, &mark)
            .map_err(|e| ProxyError::Transport(format!("SO_MARK failed: {e}")))?;
    }

    socket.set_nodelay(true).map_err(ProxyError::Io)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_bypass_mark_roundtrips() {
        clear_outbound_bypass_mark();
        assert_eq!(outbound_bypass_mark(), None);

        set_outbound_bypass_mark(0x1234);
        assert_eq!(outbound_bypass_mark(), Some(0x1234));

        clear_outbound_bypass_mark();
        assert_eq!(outbound_bypass_mark(), None);
    }
}
