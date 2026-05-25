//! Outbound TCP connect helpers.
//!
//! Xray-core caps the system TCP dialer at 16 seconds
//! (`transport/internet/system_dialer.go`). We apply the same limit so outbound
//! dials fail fast instead of waiting on OS defaults.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::ProxyError;

/// Default outbound TCP connect timeout (matches Xray `net.Dialer.Timeout`).
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(16);

/// Dial `addr` with [`TCP_CONNECT_TIMEOUT`].
pub async fn tcp_connect(addr: SocketAddr) -> Result<TcpStream, ProxyError> {
    match tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(ProxyError::Io(e)),
        Err(_) => Err(ProxyError::Timeout),
    }
}

/// Dial a host/port string (e.g. `"127.0.0.1:80"`) with [`TCP_CONNECT_TIMEOUT`].
pub async fn tcp_connect_to(addr: impl tokio::net::ToSocketAddrs) -> Result<TcpStream, ProxyError> {
    match tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(ProxyError::Io(e)),
        Err(_) => Err(ProxyError::Timeout),
    }
}
