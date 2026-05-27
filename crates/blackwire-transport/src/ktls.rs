//! Linux kernel TLS (kTLS) upgrade support.
//!
//! This module intentionally keeps kTLS separate from the generic TLS transport
//! path. A kTLS socket is not treated as a plain `TcpStream`, so the relay layer
//! cannot accidentally send it through the raw TCP `splice(2)` fast path.

use std::io;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use blackwire_common::{AsyncReadWrite, BoxedStream, ProxyError};
use rustls::ConnectionTrafficSecrets;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;

/// kTLS enablement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KtlsMode {
    /// Never attempt kTLS.
    Off,
    /// Attempt kTLS only when the rustls and socket state is known-safe.
    Auto,
    /// Attempt kTLS after handshake even when conservative guards would skip it.
    Force,
}

impl KtlsMode {
    /// Read the current env-gated policy.
    ///
    /// This preserves the previous default: kTLS is disabled unless explicitly
    /// requested with `BLACKWIRE_ENABLE_KTLS`.
    pub(crate) fn from_env() -> Self {
        Self::from_env_value(std::env::var("BLACKWIRE_ENABLE_KTLS").ok().as_deref())
    }

    fn from_env_value(value: Option<&str>) -> Self {
        match value {
            Some("force" | "FORCE") => Self::Force,
            Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON") => Self::Auto,
            _ => Self::Off,
        }
    }
}

/// Why a kTLS upgrade did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KtlsSkipReason {
    /// kTLS mode is off.
    ModeOff,
    /// The transport underneath rustls is not a raw TCP stream.
    NonTcpTransport,
    /// rustls still has pending state that must remain in userspace.
    UnsafeRustlsState,
}

/// Result of attempting to upgrade a server TLS stream to kTLS.
pub(crate) enum KtlsDecision {
    /// Keep using the original rustls stream.
    Skipped {
        stream: ServerTlsStream<BoxedStream>,
        reason: KtlsSkipReason,
    },
    /// Use the kTLS stream.
    Upgraded(BoxedStream),
}

/// Try to convert a completed rustls server stream into a guarded kTLS stream.
pub(crate) fn try_upgrade_server_stream(
    tls_stream: ServerTlsStream<BoxedStream>,
    mode: KtlsMode,
) -> Result<KtlsDecision, ProxyError> {
    if mode == KtlsMode::Off {
        return Ok(KtlsDecision::Skipped {
            stream: tls_stream,
            reason: KtlsSkipReason::ModeOff,
        });
    }

    if mode != KtlsMode::Force && !upgrade_safe(tls_stream.get_ref().1) {
        return Ok(KtlsDecision::Skipped {
            stream: tls_stream,
            reason: KtlsSkipReason::UnsafeRustlsState,
        });
    }

    let fd = {
        // Cast to &dyn AsyncReadWrite to force vtable dispatch on as_any();
        // calling stream.as_any() would use the blanket impl on Box<dyn ..>
        // and return the Box type rather than the concrete inner type.
        let inner_dyn: &dyn AsyncReadWrite = tls_stream.get_ref().0.as_ref();
        if !inner_dyn.as_any().is::<TcpStream>() {
            return Ok(KtlsDecision::Skipped {
                stream: tls_stream,
                reason: KtlsSkipReason::NonTcpTransport,
            });
        }
        inner_dyn
            .as_any()
            .downcast_ref::<TcpStream>()
            .expect("confirmed TcpStream before fd extraction")
            .as_raw_fd()
    };

    // Probe TCP_ULP before consuming the rustls stream so old kernels can still
    // fall back cleanly. A successful probe mutates the socket and must be
    // followed by key installation or treated as fatal for this connection.
    if let Err(e) = enable_ulp(fd) {
        tracing::debug!("kTLS skipped because TCP_ULP was rejected: {e}");
        return Ok(KtlsDecision::Skipped {
            stream: tls_stream,
            reason: KtlsSkipReason::NonTcpTransport,
        });
    }

    let (inner, server_conn) = tls_stream.into_inner();
    let secrets = server_conn.dangerous_extract_secrets().map_err(|e| {
        tracing::warn!("kTLS secret extraction failed: {e}; dropping connection");
        ProxyError::Tls(format!("kTLS secret extraction failed: {e}"))
    })?;

    install_keys(fd, secrets.tx.0, &secrets.tx.1, secrets.rx.0, &secrets.rx.1).map_err(|e| {
        tracing::warn!("kTLS key install failed: {e}; dropping connection");
        ProxyError::Tls(format!("kTLS key install failed: {e}"))
    })?;

    let tcp = *inner
        .into_any()
        .downcast::<TcpStream>()
        .expect("confirmed TcpStream before kTLS upgrade");
    tracing::debug!("kTLS enabled on inbound TLS connection");
    Ok(KtlsDecision::Upgraded(Box::new(KtlsTcpStream(tcp))))
}

fn upgrade_safe(conn: &rustls::ServerConnection) -> bool {
    // `dangerous_extract_secrets` rejects pending TLS writes internally, but
    // checking first lets us fall back to rustls before mutating the socket with
    // TCP_ULP. `wants_read == false` after the handshake can mean rustls already
    // has plaintext buffered; consuming the connection there would drop bytes.
    !conn.is_handshaking() && !conn.wants_write() && conn.wants_read()
}

struct KtlsTcpStream(TcpStream);

impl AsyncRead for KtlsTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for KtlsTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

// SOL_TLS is not in all libc versions; use the numeric value.
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
// TCP_ULP is not exported by libc; numeric value from <linux/tcp.h>.
const TCP_ULP: libc::c_int = 31;

const TLS_1_3_VERSION: u16 = 0x0304;
const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;

#[repr(C)]
struct TlsCryptoInfo {
    version: u16,
    cipher_type: u16,
}

#[repr(C)]
struct AesGcm128Info {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 16],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

#[repr(C)]
struct AesGcm256Info {
    info: TlsCryptoInfo,
    iv: [u8; 8],
    key: [u8; 32],
    salt: [u8; 4],
    rec_seq: [u8; 8],
}

fn enable_ulp(fd: libc::c_int) -> io::Result<()> {
    let ulp = b"tls\0";
    // SAFETY: setsockopt with a NUL-terminated "tls" string.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_ULP,
            ulp.as_ptr() as *const libc::c_void,
            (ulp.len() - 1) as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn install_keys(
    fd: libc::c_int,
    seq_tx: u64,
    secrets_tx: &ConnectionTrafficSecrets,
    seq_rx: u64,
    secrets_rx: &ConnectionTrafficSecrets,
) -> io::Result<()> {
    set_tls_key(fd, TLS_TX, seq_tx, secrets_tx)?;
    set_tls_key(fd, TLS_RX, seq_rx, secrets_rx)
}

fn set_tls_key(
    fd: libc::c_int,
    direction: libc::c_int,
    seq: u64,
    secrets: &ConnectionTrafficSecrets,
) -> io::Result<()> {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            let iv_bytes = iv.as_ref();
            let key_bytes = key.as_ref();
            if key_bytes.len() < 16 || iv_bytes.len() < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short AES-128-GCM key/iv",
                ));
            }
            let info = AesGcm128Info {
                info: TlsCryptoInfo {
                    version: TLS_1_3_VERSION,
                    cipher_type: TLS_CIPHER_AES_GCM_128,
                },
                salt: iv_bytes[..4].try_into().unwrap(),
                iv: iv_bytes[4..12].try_into().unwrap(),
                key: key_bytes[..16].try_into().unwrap(),
                rec_seq: seq.to_be_bytes(),
            };
            setsockopt_tls(fd, direction, &info)
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            let iv_bytes = iv.as_ref();
            let key_bytes = key.as_ref();
            if key_bytes.len() < 32 || iv_bytes.len() < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short AES-256-GCM key/iv",
                ));
            }
            let info = AesGcm256Info {
                info: TlsCryptoInfo {
                    version: TLS_1_3_VERSION,
                    cipher_type: TLS_CIPHER_AES_GCM_256,
                },
                salt: iv_bytes[..4].try_into().unwrap(),
                iv: iv_bytes[4..12].try_into().unwrap(),
                key: key_bytes[..32].try_into().unwrap(),
                rec_seq: seq.to_be_bytes(),
            };
            setsockopt_tls(fd, direction, &info)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cipher not supported by kTLS path",
        )),
    }
}

fn setsockopt_tls<T: Sized>(fd: libc::c_int, direction: libc::c_int, info: &T) -> io::Result<()> {
    // SAFETY: `info` is a repr(C) struct whose layout matches the kernel struct.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            direction,
            info as *const T as *const libc::c_void,
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ktls_mode_preserves_env_gate_semantics() {
        assert_eq!(KtlsMode::from_env_value(None), KtlsMode::Off);
        assert_eq!(KtlsMode::from_env_value(Some("0")), KtlsMode::Off);
        assert_eq!(KtlsMode::from_env_value(Some("1")), KtlsMode::Auto);
        assert_eq!(KtlsMode::from_env_value(Some("true")), KtlsMode::Auto);
        assert_eq!(KtlsMode::from_env_value(Some("ON")), KtlsMode::Auto);
        assert_eq!(KtlsMode::from_env_value(Some("force")), KtlsMode::Force);
    }

    #[tokio::test]
    async fn ktls_stream_is_not_recovered_as_raw_tcp() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        drop(client.unwrap());
        let stream: BoxedStream = Box::new(KtlsTcpStream(accepted.unwrap().0));

        let recovered = blackwire_common::try_into_tcp_stream_with_prefix(stream);
        assert!(recovered.is_err());
    }
}
