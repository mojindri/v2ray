//! TCP transport: accept inbound connections and dial outbound connections.
//!
//! TCP is the most basic transport — bytes flow directly over a TCP socket
//! with no extra framing. It is used in Phase 1 before TLS or WebSocket are
//! added.
//!
//! # Socket options applied
//!
//! For every accepted or dialled socket we set:
//!
//!   - **TCP_NODELAY** (no Nagle algorithm): send small packets immediately
//!     rather than waiting to batch them. Proxy traffic is latency-sensitive,
//!     so batching would add unnecessary delay.
//!
//!   - **SO_REUSEPORT** (server only): allows multiple threads to bind to the
//!     same port. The OS kernel distributes incoming connections across them,
//!     giving better multi-core scaling.
//!
//!   - **SO_MARK** (optional, Linux only): sets a routing mark on outbound
//!     packets. Used to bypass the proxy's own routing rules and send traffic
//!     directly to the network (prevents routing loops in TUN mode).

use std::net::SocketAddr;
use std::sync::Arc;

use socket2::SockRef;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use proxy_common::{BoxedStream, ProxyError};
use proxy_app::features::ConnectionHandler;

/// Configuration for the TCP transport.
#[derive(Debug, Clone)]
pub struct TcpConfig {
    /// If `Some(mark)`, outbound sockets are tagged with this routing mark.
    /// The mark is used by `iptables` / `ip rule` to route the packets through
    /// a specific network interface, bypassing the proxy's own routing table.
    /// Set to `None` if you do not use policy routing.
    pub so_mark: Option<u32>,

    /// Whether to enable TCP Fast Open on outbound connections.
    /// TFO allows data to be sent in the SYN packet, saving one round trip.
    /// Only effective if both client and server support TFO.
    pub tcp_fast_open: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            so_mark: None,
            tcp_fast_open: false,
        }
    }
}

/// Server-side TCP transport: listens on a port and accepts connections.
///
/// For each accepted connection, it spawns a Tokio task that calls the
/// `ConnectionHandler`. This way, one slow or stuck connection cannot block
/// other connections from being accepted.
pub struct TcpServerTransport {
    /// Stored for future use (Phase 2: SO_MARK on accepted streams, TFO).
    #[allow(dead_code)]
    config: TcpConfig,
}

impl TcpServerTransport {
    /// Create a new TCP server transport with the given config.
    pub fn new(config: TcpConfig) -> Self {
        Self { config }
    }

    /// Start listening on `addr` and call `handler` for each connection.
    ///
    /// This method runs indefinitely (until the listener is closed or an error
    /// occurs). Spawn it as a Tokio task.
    ///
    /// # Arguments
    /// * `addr` — the socket address to listen on (e.g. "0.0.0.0:1080")
    /// * `handler` — called for each accepted connection
    pub async fn serve(
        &self,
        addr: SocketAddr,
        handler: Arc<dyn ConnectionHandler>,
    ) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(addr).await?;
        info!(addr = %addr, "TCP listener started");

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!(error = %e, "TCP accept error");
                    continue; // keep accepting, don't crash
                }
            };

            // Apply socket options to the accepted stream.
            if let Err(e) = Self::apply_socket_opts(&stream) {
                debug!(error = %e, "failed to set socket options");
            }

            debug!(peer = %peer_addr, "TCP connection accepted");

            // Spawn a new task for this connection so the accept loop is not blocked.
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let stream: BoxedStream = Box::new(stream);
                if let Err(e) = handler.handle_connection(stream, peer_addr).await {
                    if !e.is_benign() {
                        debug!(peer = %peer_addr, error = %e, "connection error");
                    }
                }
            });
        }
    }

    /// Apply TCP socket options to an accepted stream.
    fn apply_socket_opts(stream: &TcpStream) -> std::io::Result<()> {
        let sock = SockRef::from(stream);

        // TCP_NODELAY: disable Nagle's algorithm.
        // Without this, the OS buffers small writes and sends them together.
        // For proxy traffic this adds latency — we want each write sent immediately.
        sock.set_tcp_nodelay(true)?;

        // SO_REUSEPORT: allow multiple sockets to bind to the same port.
        // This enables the accept loop to be distributed across CPU cores.
        sock.set_reuse_port(true)?;

        Ok(())
    }
}

/// Client-side TCP transport: dials outbound connections.
pub struct TcpClientTransport {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    config: TcpConfig,
}

impl TcpClientTransport {
    /// Create a new TCP client transport with the given config.
    pub fn new(config: TcpConfig) -> Self {
        Self { config }
    }

    /// Dial a TCP connection to `addr` and return it as a `BoxedStream`.
    ///
    /// # Arguments
    /// * `addr` — the remote address to connect to
    pub async fn dial(&self, addr: SocketAddr) -> Result<BoxedStream, ProxyError> {
        let stream = TcpStream::connect(addr).await?;

        // Apply socket options.
        let sock = SockRef::from(&stream);
        sock.set_tcp_nodelay(true)?;

        // Apply SO_MARK if configured (Linux only).
        // SO_MARK lets the OS route this socket's packets through a specific
        // routing table, bypassing the main table. This prevents routing loops
        // when the proxy itself runs in TUN mode.
        #[cfg(target_os = "linux")]
        if let Some(mark) = self.config.so_mark {
            use nix::sys::socket::{setsockopt, sockopt::Mark};
            setsockopt(&stream, Mark, &mark)
                .map_err(|e| ProxyError::Transport(format!("SO_MARK failed: {e}")))?;
        }

        debug!(addr = %addr, "TCP outbound connected");
        Ok(Box::new(stream))
    }
}
