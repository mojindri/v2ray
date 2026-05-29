//! Outbound TCP connect helpers.
//!
//! Xray-core caps the system TCP dialer at 16 seconds
//! (`transport/internet/system_dialer.go`). We apply the same limit so outbound
//! dials fail fast instead of waiting on OS defaults.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, ConvertInterfaceNameToLuidW,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF},
};

use crate::ProxyError;

/// Default outbound TCP connect timeout (matches Xray `net.Dialer.Timeout`).
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(16);

static OUTBOUND_BYPASS_MARK: AtomicU32 = AtomicU32::new(0);
static OUTBOUND_INTERFACE_INDEX: AtomicU32 = AtomicU32::new(0);

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

/// Configure a process-wide outbound interface index for protected sockets.
///
/// macOS and Windows TUN modes use this to bind Blackwire's own outbound
/// sockets to a physical interface before `connect()`, preventing those sockets
/// from being captured by full-device routes.
pub fn set_outbound_interface_index(index: u32) {
    OUTBOUND_INTERFACE_INDEX.store(index, Ordering::Relaxed);
}

/// Clear the process-wide outbound interface index.
pub fn clear_outbound_interface_index() {
    OUTBOUND_INTERFACE_INDEX.store(0, Ordering::Relaxed);
}

/// Return the currently configured outbound interface index.
pub fn outbound_interface_index() -> Option<u32> {
    let index = OUTBOUND_INTERFACE_INDEX.load(Ordering::Relaxed);
    (index != 0).then_some(index)
}

/// Resolve a platform interface name and configure it for protected outbound sockets.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn set_outbound_interface_name(name: &str) -> Result<(), ProxyError> {
    set_platform_outbound_interface_name(name)
}

/// Configure a named outbound interface on platforms that support it.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn set_outbound_interface_name(_name: &str) -> Result<(), ProxyError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_platform_outbound_interface_name(name: &str) -> Result<(), ProxyError> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| ProxyError::Transport("outbound interface contains NUL byte".into()))?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(ProxyError::Io(std::io::Error::last_os_error()));
    }
    set_outbound_interface_index(index);
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_platform_outbound_interface_name(name: &str) -> Result<(), ProxyError> {
    let index = windows_interface_index(name)?;
    set_outbound_interface_index(index);
    Ok(())
}

/// Apply process-wide outbound protection options to a UDP socket.
pub fn protect_udp_socket(socket: &UdpSocket) -> Result<(), ProxyError> {
    protect_udp_socket_with_bypass_mark(socket, None)
}

/// Apply outbound protection options to a UDP socket, optionally overriding
/// the process-wide Linux bypass mark.
pub fn protect_udp_socket_with_bypass_mark(
    socket: &UdpSocket,
    _bypass_mark: Option<u32>,
) -> Result<(), ProxyError> {
    #[cfg(target_os = "linux")]
    if let Some(mark) = _bypass_mark.or_else(outbound_bypass_mark) {
        use nix::sys::socket::{setsockopt, sockopt::Mark};
        setsockopt(socket, Mark, &mark)
            .map_err(|e| ProxyError::Transport(format!("SO_MARK failed: {e}")))?;
    }

    #[cfg(target_os = "macos")]
    if let Some(index) = outbound_interface_index() {
        protect_macos_socket(socket, false, index)?;
        protect_macos_socket(socket, true, index)?;
    }

    #[cfg(target_os = "windows")]
    if let Some(index) = outbound_interface_index() {
        let ipv6 = socket
            .local_addr()
            .map(|addr| addr.is_ipv6())
            .unwrap_or(false);
        protect_windows_socket(socket, ipv6, index)?;
    }

    Ok(())
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

    #[cfg(target_os = "macos")]
    if let Some(index) = outbound_interface_index() {
        protect_macos_socket(&socket, addr.is_ipv6(), index)?;
    }

    #[cfg(target_os = "windows")]
    if let Some(index) = outbound_interface_index() {
        protect_windows_socket(&socket, addr.is_ipv6(), index)?;
    }

    socket.set_nodelay(true).map_err(ProxyError::Io)?;
    Ok(socket)
}

#[cfg(target_os = "macos")]
fn protect_macos_socket<S: std::os::fd::AsRawFd>(
    socket: &S,
    ipv6: bool,
    index: u32,
) -> Result<(), ProxyError> {
    let level = if ipv6 {
        libc::IPPROTO_IPV6
    } else {
        libc::IPPROTO_IP
    };
    let option = if ipv6 {
        libc::IPV6_BOUND_IF
    } else {
        libc::IP_BOUND_IF
    };
    let value = index as libc::c_uint;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            &value as *const libc::c_uint as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(ProxyError::Io(std::io::Error::last_os_error()))
    }
}

#[cfg(target_os = "windows")]
fn windows_interface_index(name: &str) -> Result<u32, ProxyError> {
    if name.contains('\0') {
        return Err(ProxyError::Transport(
            "outbound interface contains NUL byte".into(),
        ));
    }

    let wide_name = windows_wide_name(name);
    let mut luid = NET_LUID_LH { Value: 0 };
    let alias_rc = unsafe { ConvertInterfaceAliasToLuid(wide_name.as_ptr(), &mut luid) };
    let name_rc = if alias_rc == 0 {
        0
    } else {
        unsafe { ConvertInterfaceNameToLuidW(wide_name.as_ptr(), &mut luid) }
    };
    if alias_rc != 0 && name_rc != 0 {
        return Err(ProxyError::Io(std::io::Error::from_raw_os_error(
            name_rc as i32,
        )));
    }

    let mut index = 0u32;
    let index_rc = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if index_rc != 0 {
        return Err(ProxyError::Io(std::io::Error::from_raw_os_error(
            index_rc as i32,
        )));
    }
    if index == 0 {
        return Err(ProxyError::Transport(format!(
            "outbound interface '{name}' resolved to index 0"
        )));
    }
    Ok(index)
}

#[cfg(target_os = "windows")]
fn windows_wide_name(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn protect_windows_socket<S: std::os::windows::io::AsRawSocket>(
    socket: &S,
    ipv6: bool,
    index: u32,
) -> Result<(), ProxyError> {
    let level = if ipv6 { IPPROTO_IPV6 } else { IPPROTO_IP };
    let option = if ipv6 { IPV6_UNICAST_IF } else { IP_UNICAST_IF };
    let value = windows_unicast_if_value(index, ipv6);
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            option,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(ProxyError::Io(std::io::Error::last_os_error()))
    }
}

#[cfg(any(test, target_os = "windows"))]
fn windows_unicast_if_value(index: u32, ipv6: bool) -> u32 {
    if ipv6 {
        index
    } else {
        index.to_be()
    }
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

    #[test]
    fn outbound_interface_index_roundtrips() {
        clear_outbound_interface_index();
        assert_eq!(outbound_interface_index(), None);

        set_outbound_interface_index(7);
        assert_eq!(outbound_interface_index(), Some(7));

        clear_outbound_interface_index();
        assert_eq!(outbound_interface_index(), None);
    }

    #[test]
    fn windows_unicast_if_value_uses_network_order_for_ipv4() {
        assert_eq!(windows_unicast_if_value(0x0102_0304, false), 0x0403_0201);
        assert_eq!(windows_unicast_if_value(0x0102_0304, true), 0x0102_0304);
    }
}
