//! SOCKS5-style address encoding (ATYP + address + port).
//!
//! Used by SOCKS5, Trojan, and SS-2022. VLESS/VMess use port-first layouts and
//! must not use these helpers.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::address::Address;
use crate::error::ProxyError;
use crate::relay::domain_wire_len;

/// ATYP: IPv4 (4-byte address follows).
pub const ATYP_IPV4: u8 = 0x01;

/// ATYP: domain name (1-byte length + name follows).
pub const ATYP_DOMAIN: u8 = 0x03;

/// ATYP: IPv6 (16-byte address follows).
pub const ATYP_IPV6: u8 = 0x04;

/// Read a SOCKS5-style destination from an async stream after the ATYP byte.
pub async fn read_socks5_address<R: AsyncRead + Unpin>(
    reader: &mut R,
    atyp: u8,
    protocol: &str,
) -> Result<Address, ProxyError> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await?;
            let port = reader.read_u16().await?;
            Ok(Address::Ipv4(Ipv4Addr::from(buf), port))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf).await?;
            let port = reader.read_u16().await?;
            Ok(Address::Ipv6(Ipv6Addr::from(buf), port))
        }
        ATYP_DOMAIN => {
            let len = reader.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            reader.read_exact(&mut name).await?;
            let port = reader.read_u16().await?;
            let domain = String::from_utf8(name).map_err(|_| {
                ProxyError::Protocol(format!("{protocol}: domain name is not valid UTF-8"))
            })?;
            Ok(Address::Domain(domain, port))
        }
        other => Err(ProxyError::Protocol(format!(
            "{protocol}: unknown ATYP {other:#x}"
        ))),
    }
}

/// Decode a SOCKS5-style address from `data` starting immediately after ATYP.
///
/// Returns the address and the number of bytes consumed from `data`.
pub fn decode_socks5_address(
    data: &[u8],
    atyp: u8,
    protocol: &str,
) -> Result<(Address, usize), ProxyError> {
    match atyp {
        ATYP_IPV4 => {
            if data.len() < 6 {
                return Err(ProxyError::Protocol(format!(
                    "{protocol}: truncated IPv4 address"
                )));
            }
            let ip = Ipv4Addr::from([data[0], data[1], data[2], data[3]]);
            let port = u16::from_be_bytes([data[4], data[5]]);
            Ok((Address::Ipv4(ip, port), 6))
        }
        ATYP_IPV6 => {
            if data.len() < 18 {
                return Err(ProxyError::Protocol(format!(
                    "{protocol}: truncated IPv6 address"
                )));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[..16]);
            let port = u16::from_be_bytes([data[16], data[17]]);
            Ok((Address::Ipv6(Ipv6Addr::from(ip), port), 18))
        }
        ATYP_DOMAIN => {
            if data.is_empty() {
                return Err(ProxyError::Protocol(format!(
                    "{protocol}: truncated domain length"
                )));
            }
            let n = data[0] as usize;
            if data.len() < 1 + n + 2 {
                return Err(ProxyError::Protocol(format!(
                    "{protocol}: truncated domain address"
                )));
            }
            let name = std::str::from_utf8(&data[1..1 + n])
                .map_err(|_| ProxyError::Protocol(format!("{protocol}: invalid domain UTF-8")))?
                .to_string();
            let port = u16::from_be_bytes([data[1 + n], data[1 + n + 1]]);
            Ok((Address::Domain(name, port), 1 + n + 2))
        }
        other => Err(ProxyError::Protocol(format!(
            "{protocol}: unknown ATYP {other:#x}"
        ))),
    }
}

/// Write ATYP + address + port in SOCKS5 wire order.
pub fn write_socks5_address(buf: &mut impl BufMut, dest: &Address) -> Result<(), ProxyError> {
    match dest {
        Address::Ipv4(ip, port) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&ip.octets());
            buf.put_u16(*port);
        }
        Address::Ipv6(ip, port) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&ip.octets());
            buf.put_u16(*port);
        }
        Address::Domain(name, port) => {
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(domain_wire_len(name)?);
            buf.put_slice(name.as_bytes());
            buf.put_u16(*port);
        }
    }
    Ok(())
}
