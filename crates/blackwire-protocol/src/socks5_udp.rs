//! SOCKS5 UDP ASSOCIATE relay (RFC 1928 UDP framing).
//!
//! After UDP ASSOCIATE, the client sends datagrams to the bound relay address:
//! `RSV(2) | FRAG(1) | ATYP | DST.ADDR | DST.PORT | DATA`.

use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;

use blackwire_common::{
    decode_socks5_address, write_socks5_address, Address, BoxedStream, ProxyError,
};

const SOCKS_UDP_HEADER: usize = 3;

/// Parse a SOCKS5 UDP datagram; returns destination and payload slice.
pub fn parse_udp_datagram(buf: &[u8]) -> Result<(Address, &[u8]), ProxyError> {
    if buf.len() < SOCKS_UDP_HEADER {
        return Err(ProxyError::Protocol("SOCKS5 UDP datagram too short".into()));
    }
    if buf[0] != 0 || buf[1] != 0 {
        return Err(ProxyError::Protocol("SOCKS5 UDP RSV must be zero".into()));
    }
    if buf[2] != 0 {
        return Err(ProxyError::Protocol(format!(
            "SOCKS5 UDP fragment {:#x} not supported",
            buf[2]
        )));
    }
    let atyp = buf[3];
    let (dest, consumed) = decode_socks5_address(&buf[4..], atyp, "SOCKS5 UDP")?;
    let off = 4 + consumed;
    if off > buf.len() {
        return Err(ProxyError::Protocol("SOCKS5 UDP truncated payload".into()));
    }
    Ok((dest, &buf[off..]))
}

/// Encode a SOCKS5 UDP response datagram.
pub fn encode_udp_datagram(dest: &Address, payload: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let mut buf = BytesMut::with_capacity(SOCKS_UDP_HEADER + 256 + payload.len());
    buf.extend_from_slice(&[0, 0, 0]);
    write_socks5_address(&mut buf, dest)?;
    buf.extend_from_slice(payload);
    Ok(buf.into())
}

async fn resolve_udp_dest(dest: &Address) -> Result<SocketAddr, ProxyError> {
    match dest {
        Address::Ipv4(ip, port) => Ok(SocketAddr::new((*ip).into(), *port)),
        Address::Ipv6(ip, port) => Ok(SocketAddr::new((*ip).into(), *port)),
        Address::Domain(name, port) => {
            let mut addrs = tokio::net::lookup_host((name.as_str(), *port))
                .await
                .map_err(|e| ProxyError::DnsResolutionFailed(format!("{name}: {e}")))?;
            addrs
                .next()
                .ok_or_else(|| ProxyError::DnsResolutionFailed(name.clone()))
        }
    }
}

/// Relay UDP until the SOCKS5 TCP control connection closes.
pub async fn relay_socks5_udp(
    mut control: BoxedStream,
    udp: UdpSocket,
    client_ip: std::net::IpAddr,
) -> Result<(), ProxyError> {
    let mut buf = vec![0u8; 65535];
    let mut ctrl = [0u8; 64];

    loop {
        tokio::select! {
            res = udp.recv_from(&mut buf) => {
                let (n, peer) = res.map_err(|e| ProxyError::Transport(e.to_string()))?;
                if peer.ip() != client_ip {
                    continue;
                }
                if n < SOCKS_UDP_HEADER + 4 {
                    continue;
                }
                let (dest, payload) = match parse_udp_datagram(&buf[..n]) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if payload.is_empty() {
                    continue;
                }
                let upstream = match resolve_udp_dest(&dest).await {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let sock = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if sock.send_to(payload, upstream).await.is_err() {
                    continue;
                }
                let mut reply_buf = vec![0u8; 65535];
                if let Ok(Ok(m)) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv(&mut reply_buf))
                        .await
                {
                    if m > 0 {
                        if let Ok(pkt) = encode_udp_datagram(&dest, &reply_buf[..m]) {
                            let _ = udp.send_to(&pkt, peer).await;
                        }
                    }
                }
            }
            res = control.read(&mut ctrl) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }

    Ok(())
}
