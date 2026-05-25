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
//!
//! Linux note for beginners:
//! `SO_REUSEPORT` and `SO_MARK` are OS-level socket knobs. They do not change
//! the proxy protocol bytes. They only tell the Linux kernel how to schedule or
//! route packets for this socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use socket2::SockRef;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use blackwire_app::features::ConnectionHandler;
use blackwire_common::{BoxedStream, ProxyError, TCP_CONNECT_TIMEOUT};

/// Configuration for the TCP transport.
#[derive(Debug, Clone, Default)]
pub struct TcpConfig {
    /// If `Some(mark)`, outbound sockets are tagged with this routing mark.
    /// The mark is used by `iptables` / `ip rule` to route the packets through
    /// a specific network interface, bypassing the proxy's own routing table.
    /// Set to `None` if you do not use policy routing.
    ///
    /// Linux only: other platforms ignore this field because `SO_MARK` is a
    /// Linux socket option. A typical use is TUN mode, where the proxy must
    /// avoid accidentally routing its own outbound connection back into itself.
    pub so_mark: Option<u32>,

    /// Whether to enable TCP Fast Open on outbound connections.
    /// TFO allows data to be sent in the SYN packet, saving one round trip.
    /// Only effective if both client and server support TFO.
    pub tcp_fast_open: bool,

    /// Maximum simultaneous connections accepted by this listener.
    ///
    /// When the limit is reached, the listener accepts and immediately drops
    /// excess connections. This bounds tasks and file descriptors in overload.
    pub max_connections: Option<usize>,
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
        self.serve_listener(listener, handler).await
    }

    /// Serve connections from an already-bound listener.
    ///
    /// This lets higher layers bind synchronously during startup so bind
    /// failures are surfaced before background tasks are spawned.
    pub async fn serve_listener(
        &self,
        listener: TcpListener,
        handler: Arc<dyn ConnectionHandler>,
    ) -> Result<(), ProxyError> {
        let addr = listener.local_addr()?;
        info!(addr = %addr, max_connections = ?self.config.max_connections, "TCP listener started");

        let limiter = self
            .config
            .max_connections
            .map(|n| Arc::new(Semaphore::new(n)));
        let max_connections = self.config.max_connections;

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    if e.raw_os_error() == Some(24) {
                        error!(error = %e, "TCP accept error: file descriptor exhaustion");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    } else {
                        error!(error = %e, "TCP accept error");
                    }
                    continue; // keep accepting, don't crash
                }
            };

            // Apply socket options to the accepted stream.
            if let Err(e) = Self::apply_socket_opts(&stream) {
                debug!(error = %e, "failed to set socket options");
            }

            debug!(peer = %peer_addr, "TCP connection accepted");

            let permit = if let Some(limiter) = &limiter {
                match Arc::clone(limiter).try_acquire_owned() {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        warn!(
                            peer = %peer_addr,
                            max_connections = ?max_connections,
                            "connection limit reached; dropping accepted TCP connection"
                        );
                        continue;
                    }
                }
            } else {
                None
            };

            // Spawn a new task for this connection so the accept loop is not blocked.
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let _permit = permit;
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
        // On Linux this lets the kernel spread incoming connections across
        // several listener sockets. For now we still create one listener, but
        // setting it here keeps the transport ready for multi-listener scaling.
        sock.set_reuse_port(true)?;

        Ok(())
    }
}

/// Client-side TCP transport: dials outbound connections.
pub struct TcpClientTransport {
    // `config` is only read on Linux today because the only client-side option
    // we currently apply from it is `SO_MARK`. Keep the field on all platforms
    // so the public struct layout and constructor stay the same.
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
    /// SO_MARK is applied **before** `connect()` so the TCP SYN packet also
    /// carries the mark. This matches xray's `net.Dialer.Control` callback,
    /// which fires after `socket()` but before `connect()`.
    ///
    /// # Arguments
    /// * `addr` — the remote address to connect to
    pub async fn dial(&self, addr: SocketAddr) -> Result<BoxedStream, ProxyError> {
        use tokio::net::TcpSocket;

        let socket = if addr.is_ipv6() {
            TcpSocket::new_v6()
        } else {
            TcpSocket::new_v4()
        }
        .map_err(ProxyError::Io)?;

        // Set SO_MARK *before* connect so the TCP SYN carries the routing mark.
        // Xray uses net.Dialer.Control for the same reason — the callback runs
        // after socket creation but before the kernel sends the SYN.
        #[cfg(target_os = "linux")]
        if let Some(mark) = self.config.so_mark {
            use nix::sys::socket::{setsockopt, sockopt::Mark};
            setsockopt(&socket, Mark, &mark)
                .map_err(|e| ProxyError::Transport(format!("SO_MARK failed: {e}")))?;
        }

        socket.set_nodelay(true).map_err(ProxyError::Io)?;

        let stream = match tokio::time::timeout(TCP_CONNECT_TIMEOUT, socket.connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(ProxyError::Io(e)),
            Err(_) => return Err(ProxyError::Timeout),
        };

        debug!(addr = %addr, "TCP outbound connected");
        Ok(Box::new(stream))
    }
}
