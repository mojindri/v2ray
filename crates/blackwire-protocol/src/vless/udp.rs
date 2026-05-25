//! VLESS UDP packet framing — matches Xray `proxy/vless/encoding` UDP encoding.
//!
//! Each datagram on the stream: `u16_be(addr_len) | address(port+atyp+host) | payload`.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use blackwire_common::{Address, ProxyError};

use super::codec::{decode_address_port, encode_address_port};

/// Read the address header of one VLESS UDP packet.
pub async fn read_udp_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Address, ProxyError> {
    let addr_len = reader.read_u16().await? as usize;
    if addr_len == 0 || addr_len > 512 {
        return Err(ProxyError::Protocol(format!(
            "invalid VLESS UDP address length {addr_len}"
        )));
    }
    let mut addr_buf = vec![0u8; addr_len];
    reader.read_exact(&mut addr_buf).await?;
    decode_address_port(&addr_buf)
}

/// Read payload bytes for the current UDP packet (bounded read for one datagram).
pub async fn read_udp_payload<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, ProxyError> {
    let mut buf = vec![0u8; 65507];
    let n = tokio::time::timeout(Duration::from_millis(500), reader.read(&mut buf))
        .await
        .map_err(|_| ProxyError::Protocol("VLESS UDP payload read timeout".into()))?
        .map_err(|e| ProxyError::Transport(e.to_string()))?;
    Ok(buf[..n].to_vec())
}

/// Write one VLESS UDP packet to the stream.
pub async fn write_udp_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    dest: &Address,
    payload: &[u8],
) -> Result<(), ProxyError> {
    let addr_bytes = encode_address_port(dest)?;
    if addr_bytes.len() > u16::MAX as usize {
        return Err(ProxyError::Protocol("VLESS UDP address too long".into()));
    }
    writer.write_u16(addr_bytes.len() as u16).await?;
    writer.write_all(&addr_bytes).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Relay VLESS UDP packets between client stream and upstream UDP socket.
pub async fn relay_vless_udp<S: AsyncRead + AsyncWrite + Unpin>(
    mut client: S,
) -> Result<(), ProxyError> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| ProxyError::Transport(format!("VLESS UDP bind failed: {e}")))?;

    loop {
        let dest = match read_udp_header(&mut client).await {
            Ok(d) => d,
            Err(ProxyError::Transport(e)) if e.contains("early eof") => break,
            Err(e) => return Err(e),
        };
        let payload = read_udp_payload(&mut client).await?;
        if payload.is_empty() {
            continue;
        }

        let upstream = resolve_udp_dest(&dest).await?;
        socket
            .send_to(&payload, upstream)
            .await
            .map_err(|e| ProxyError::Transport(format!("VLESS UDP send: {e}")))?;

        let mut buf = vec![0u8; 65535];
        match tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                write_udp_packet(&mut client, &dest, &buf[..n]).await?;
            }
            _ => {}
        }
    }

    Ok(())
}

async fn resolve_udp_dest(dest: &Address) -> Result<std::net::SocketAddr, ProxyError> {
    match dest {
        Address::Ipv4(ip, port) => Ok(std::net::SocketAddr::new((*ip).into(), *port)),
        Address::Ipv6(ip, port) => Ok(std::net::SocketAddr::new((*ip).into(), *port)),
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
