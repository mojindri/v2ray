//! VLESS wire format: encoding and decoding the request/response headers.
//!
//! # Request format (client → server)
//!
//! ```text
//! ┌──────────┬────────────────┬───────────────┬───────────┬──────────────┬──────────────────────┐
//! │ VER (1B) │  UUID (16B)    │ ADDONS_LEN(1B)│ ADDONS(N) │   CMD (1B)   │ PORT+ADDR+PAYLOAD... │
//! └──────────┴────────────────┴───────────────┴───────────┴──────────────┴──────────────────────┘
//! ```
//!
//! - **VER**: Always 0x00. If 0x01 is received, it is a future version — reject it.
//! - **UUID**: 16 raw bytes (not the hyphenated string form). Used to identify the user.
//! - **ADDONS_LEN**: Length of the optional addons field. Usually 0 in Phase 1.
//!   When non-zero, contains protobuf-encoded data including the `flow` field
//!   (e.g. `"xtls-rprx-vision"` for the XTLS Vision splice mode).
//! - **CMD**: 0x01 = TCP CONNECT, 0x02 = UDP ASSOCIATE, 0x03 = Mux.Cool (deprecated).
//! - **PORT**: 2 bytes, big-endian.
//! - **ATYP**: 0x01 = IPv4 (4 bytes), 0x02 = domain (1-byte len + bytes), 0x03 = IPv6 (16 bytes).
//!
//! # Response format (server → client)
//!
//! ```text
//! ┌──────────┬───────────────┬───────────┐
//! │ VER (1B) │ ADDONS_LEN(1B)│ ADDONS(N) │  then raw payload immediately
//! └──────────┴───────────────┴───────────┘
//! ```
//!
//! The response header is minimal — version byte, then addons length (usually 0),
//! then raw bytes. There is no per-chunk framing in the payload.
//!
//! # Source
//!
//! Wire format defined in XTLS/Xray-core `proxy/vless/encoding/encoding.go`.

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use blackwire_common::{domain_wire_len, Address, ProxyError};

// ── Command byte constants ────────────────────────────────────────────────────

/// VLESS command: open a TCP connection to the destination.
pub const CMD_TCP: u8 = 0x01;

/// VLESS command: UDP association.
pub const CMD_UDP: u8 = 0x02;

/// VLESS command: Mux.Cool (deprecated in Xray; still decoded for compatibility).
pub const CMD_MUX: u8 = 0x03;

/// Xray internal mux marker (`RequestCommandMux` sends no address/port on the wire).
pub const MUX_COOL_DOMAIN: &str = "v1.mux.cool";

// ── Address type constants ────────────────────────────────────────────────────

/// Address type: IPv4 — the next 4 bytes are the IPv4 address.
const ATYP_IPV4: u8 = 0x01;

/// Address type: domain name — the next byte is the length, then the name bytes.
const ATYP_DOMAIN: u8 = 0x02;

/// Address type: IPv6 — the next 16 bytes are the IPv6 address.
const ATYP_IPV6: u8 = 0x03;

/// The only supported VLESS version. Reject any other value.
const VLESS_VERSION: u8 = 0x00;

// ── Decoded request ───────────────────────────────────────────────────────────

/// A decoded VLESS request header.
#[derive(Debug)]
pub struct VlessRequest {
    /// The 16-byte user UUID extracted from the header.
    pub uuid: [u8; 16],

    /// The command: TCP connect or UDP associate.
    pub command: Command,

    /// The destination the client wants to reach.
    pub dest: Address,

    /// The optional `flow` string from the addons field.
    /// "xtls-rprx-vision" means the client wants XTLS Vision splice mode.
    /// Empty string means no special flow.
    pub flow: String,
}

/// VLESS command byte decoded into an enum for clarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Open a TCP connection to the destination.
    Tcp,
    /// UDP association.
    Udp,
    /// Mux.Cool (Xray CMD 0x03) — relayed like TCP until full mux framing is implemented.
    Mux,
}

// ── Decoder ───────────────────────────────────────────────────────────────────

/// Read and decode a VLESS request header from an async byte stream.
///
/// After this function returns, the stream is positioned at the start of the
/// raw payload — ready for bidirectional relay with the destination.
///
/// # Errors
///
/// Returns `ProxyError::Protocol` if:
///   - The version byte is not 0x00
///   - The command byte is not 0x01 or 0x02
///   - The address type is unknown
///   - The domain name is not valid UTF-8
///   - The stream ended unexpectedly (e.g. client disconnected mid-header)
pub async fn decode_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<VlessRequest, ProxyError> {
    // Read version byte.
    let ver = reader.read_u8().await?;
    if ver != VLESS_VERSION {
        return Err(ProxyError::Protocol(format!(
            "VLESS version {ver:#x} not supported"
        )));
    }

    // Read UUID (16 bytes).
    let mut uuid = [0u8; 16];
    reader.read_exact(&mut uuid).await?;

    // Read addons length and the addons bytes.
    // In Phase 1 we read the bytes but only look for the `flow` field.
    let addons_len = reader.read_u8().await? as usize;
    let flow = if addons_len > 0 {
        let mut addons_buf = vec![0u8; addons_len];
        reader.read_exact(&mut addons_buf).await?;
        // Parse the `flow` field from the protobuf addons.
        // The addons message has field 1 = flow (string).
        // We do a minimal parse rather than pulling in a full protobuf crate.
        parse_flow_from_addons(&addons_buf)
    } else {
        String::new()
    };

    // Read command byte.
    let cmd_byte = reader.read_u8().await?;
    let command = match cmd_byte {
        CMD_TCP => Command::Tcp,
        CMD_UDP => Command::Udp,
        CMD_MUX => Command::Mux,
        other => {
            return Err(ProxyError::Protocol(format!(
                "unknown VLESS CMD {other:#x}"
            )));
        }
    };

    // Mux / Rvs commands omit address+port on the wire (Xray `EncodeRequestHeader`).
    let dest = if command == Command::Mux {
        Address::Domain(MUX_COOL_DOMAIN.into(), 0)
    } else {
        let port = reader.read_u16().await?;
        let atyp = reader.read_u8().await?;
        read_address(reader, atyp, port).await?
    };

    Ok(VlessRequest {
        uuid,
        command,
        dest,
        flow,
    })
}

/// Read a destination address based on the ATYP byte.
async fn read_address<R: AsyncRead + Unpin>(
    reader: &mut R,
    atyp: u8,
    port: u16,
) -> Result<Address, ProxyError> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await?;
            Ok(Address::Ipv4(std::net::Ipv4Addr::from(buf), port))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf).await?;
            Ok(Address::Ipv6(std::net::Ipv6Addr::from(buf), port))
        }
        ATYP_DOMAIN => {
            // Domain: 1-byte length prefix + name bytes.
            let len = reader.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            reader.read_exact(&mut name).await?;
            let domain = String::from_utf8(name)
                .map_err(|_| ProxyError::Protocol("domain name is not valid UTF-8".into()))?;
            Ok(Address::Domain(domain, port))
        }
        other => Err(ProxyError::Protocol(format!(
            "unknown VLESS ATYP {other:#x}"
        ))),
    }
}

/// Minimal protobuf parser for the VLESS addons field (Xray `proto.Unmarshal`).
///
/// The addons message has one field: field 1 = flow (string).
fn parse_flow_from_addons(data: &[u8]) -> String {
    let mut cursor = 0usize;
    while cursor < data.len() {
        let Some(tag) = read_varint(data, &mut cursor) else {
            break;
        };
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        match wire_type {
            2 => {
                let Some(len) = read_varint(data, &mut cursor) else {
                    break;
                };
                let len = len as usize;
                if cursor + len > data.len() {
                    break;
                }
                if field_number == 1 {
                    if let Ok(s) = std::str::from_utf8(&data[cursor..cursor + len]) {
                        return s.to_string();
                    }
                }
                cursor += len;
            }
            0 => {
                let Some(_value) = read_varint(data, &mut cursor) else {
                    break;
                };
            }
            1 => cursor = cursor.saturating_add(8),
            5 => cursor = cursor.saturating_add(4),
            _ => break,
        }
    }
    String::new()
}

fn read_varint(data: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    while *cursor < data.len() {
        let byte = data[*cursor];
        *cursor += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

fn put_varint(buf: &mut BytesMut, mut value: u64) {
    while value >= 0x80 {
        buf.put_u8((value as u8) | 0x80);
        value >>= 7;
    }
    buf.put_u8(value as u8);
}

// ── Encoder ───────────────────────────────────────────────────────────────────

/// Encode a VLESS request header into bytes.
///
/// Used by the client (outbound) when connecting to a VLESS server.
/// Returns the header bytes — the caller should send these, then send
/// the payload bytes immediately after.
///
/// # Arguments
/// * `uuid`    — the 16-byte user UUID
/// * `flow`    — optional flow string (e.g. "xtls-rprx-vision"); empty for normal connections
/// * `command` — TCP or UDP
/// * `dest`    — the destination address and port
pub fn encode_request(
    uuid: &[u8; 16],
    flow: &str,
    command: Command,
    dest: &Address,
) -> Result<Bytes, ProxyError> {
    let mut buf = BytesMut::with_capacity(256);

    // Version byte.
    buf.put_u8(VLESS_VERSION);

    // UUID (16 bytes).
    buf.put_slice(uuid);

    // Addons field.
    if flow.is_empty() {
        // No addons — length = 0.
        buf.put_u8(0);
    } else {
        let mut addons = BytesMut::new();
        addons.put_u8(0x0A); // field 1, wire type 2
        let flow_bytes = flow.as_bytes();
        put_varint(&mut addons, flow_bytes.len() as u64);
        addons.put_slice(flow_bytes);
        let addons_len = addons.len();
        if addons_len > 255 {
            return Err(ProxyError::Protocol("VLESS addons too long".into()));
        }
        buf.put_u8(addons_len as u8);
        buf.put_slice(&addons);
    }

    // Command byte.
    buf.put_u8(match command {
        Command::Tcp => CMD_TCP,
        Command::Udp => CMD_UDP,
        Command::Mux => CMD_MUX,
    });

    if command != Command::Mux {
        buf.put_u16(dest.port());
        match dest {
            Address::Ipv4(ip, _) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&ip.octets());
            }
            Address::Ipv6(ip, _) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&ip.octets());
            }
            Address::Domain(name, _) => {
                buf.put_u8(ATYP_DOMAIN);
                buf.put_u8(domain_wire_len(name)?);
                buf.put_slice(name.as_bytes());
            }
        }
    }

    Ok(buf.freeze())
}

/// Encode port + address for a VLESS UDP packet (Xray `EncodeUDPPacket` address section).
pub fn encode_address_port(dest: &Address) -> Result<Vec<u8>, ProxyError> {
    let mut buf = BytesMut::with_capacity(64);
    buf.put_u16(dest.port());
    match dest {
        Address::Ipv4(ip, _) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&ip.octets());
        }
        Address::Ipv6(ip, _) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&ip.octets());
        }
        Address::Domain(name, _) => {
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(domain_wire_len(name)?);
            buf.put_slice(name.as_bytes());
        }
    }
    Ok(buf.to_vec())
}

/// Decode port + address from a VLESS UDP packet address section.
pub fn decode_address_port(data: &[u8]) -> Result<Address, ProxyError> {
    decode_address_port_with_len(data).map(|(addr, _)| addr)
}

/// Bytes consumed by a port+address section (Xray `PortThenAddress` / mux / XUDP).
pub fn address_port_wire_len(data: &[u8]) -> Result<usize, ProxyError> {
    if data.len() < 4 {
        return Err(ProxyError::Protocol("VLESS UDP address too short".into()));
    }
    let atyp = data[2];
    let addr_len = match atyp {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let name_len = usize::from(data[3]);
            if data.len() < 4 + name_len {
                return Err(ProxyError::Protocol("VLESS UDP address truncated".into()));
            }
            let name = std::str::from_utf8(&data[4..4 + name_len])
                .map_err(|_| ProxyError::Protocol("domain name is not valid UTF-8".into()))?;
            domain_wire_len(name)?;
            1 + name_len
        }
        other => {
            return Err(ProxyError::Protocol(format!(
                "VLESS UDP: unsupported address type {other:#x}"
            )));
        }
    };
    Ok(2 + 1 + addr_len)
}

/// Decode port + address and return bytes consumed.
pub fn decode_address_port_with_len(data: &[u8]) -> Result<(Address, usize), ProxyError> {
    if data.len() < 4 {
        return Err(ProxyError::Protocol("VLESS UDP address too short".into()));
    }
    let port = u16::from_be_bytes([data[0], data[1]]);
    let atyp = data[2];
    let consumed = address_port_wire_len(data)?;
    if data.len() < consumed {
        return Err(ProxyError::Protocol("VLESS UDP address truncated".into()));
    }
    let mut cursor = std::io::Cursor::new(&data[3..]);
    let addr = decode_address_sync(&mut cursor, atyp, port)?;
    Ok((addr, consumed))
}

fn decode_address_sync(
    cursor: &mut std::io::Cursor<&[u8]>,
    atyp: u8,
    port: u16,
) -> Result<Address, ProxyError> {
    use std::io::Read;
    let read_err = |e: std::io::Error| ProxyError::Protocol(e.to_string());
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            Read::read_exact(cursor, &mut buf).map_err(read_err)?;
            Ok(Address::Ipv4(std::net::Ipv4Addr::from(buf), port))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            Read::read_exact(cursor, &mut buf).map_err(read_err)?;
            Ok(Address::Ipv6(std::net::Ipv6Addr::from(buf), port))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            Read::read_exact(cursor, &mut len).map_err(read_err)?;
            let len = len[0] as usize;
            let mut name = vec![0u8; len];
            Read::read_exact(cursor, &mut name).map_err(read_err)?;
            let domain = String::from_utf8(name)
                .map_err(|_| ProxyError::Protocol("domain name is not valid UTF-8".into()))?;
            Ok(Address::Domain(domain, port))
        }
        other => Err(ProxyError::Protocol(format!(
            "unknown VLESS ATYP {other:#x}"
        ))),
    }
}

/// Encode a VLESS response header (server → client).
///
/// The response header is minimal: just version (0) and addons length (0).
/// After sending this, raw payload bytes follow.
pub fn encode_response() -> Bytes {
    // VER=0, ADDONS_LEN=0
    Bytes::from_static(&[VLESS_VERSION, 0x00])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Helper: decode a request from a byte slice.
    async fn decode_from_bytes(data: &[u8]) -> Result<VlessRequest, ProxyError> {
        let mut cursor = std::io::Cursor::new(data);
        decode_request(&mut cursor).await
    }

    // Checks that a valid VLESS TCP request to an IPv4 address is decoded correctly.
    // These bytes represent a connection to 93.184.216.34:443 (example.com).
    #[tokio::test]
    async fn decode_tcp_ipv4() {
        let uuid = [0xABu8; 16];
        let mut data = vec![
            0x00, // VER = 0
        ];
        data.extend_from_slice(&uuid);
        data.push(0x00); // ADDONS_LEN = 0
        data.push(CMD_TCP); // CMD = TCP
        data.extend_from_slice(&443u16.to_be_bytes()); // PORT = 443
        data.push(ATYP_IPV4); // ATYP = IPv4
        data.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34

        let req = decode_from_bytes(&data).await.unwrap();

        assert_eq!(req.uuid, uuid);
        assert_eq!(req.command, Command::Tcp);
        assert_eq!(
            req.dest,
            Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34), 443)
        );
        assert!(req.flow.is_empty());
    }

    // Checks that a VLESS request with a domain address is decoded correctly.
    #[tokio::test]
    async fn decode_tcp_domain() {
        let uuid = [0x11u8; 16];
        let domain = b"example.com";
        let mut data = vec![0x00]; // VER
        data.extend_from_slice(&uuid);
        data.push(0x00); // ADDONS_LEN = 0
        data.push(CMD_TCP); // CMD
        data.extend_from_slice(&443u16.to_be_bytes());
        data.push(ATYP_DOMAIN); // ATYP = domain
        data.push(domain.len() as u8);
        data.extend_from_slice(domain);

        let req = decode_from_bytes(&data).await.unwrap();
        assert_eq!(req.dest, Address::Domain("example.com".into(), 443));
    }

    // Checks that an unsupported version byte returns a Protocol error.
    #[tokio::test]
    async fn unknown_version_returns_error() {
        let data = [0x01u8]; // VER = 1, not supported
        let result = decode_from_bytes(&data).await;
        assert!(matches!(result, Err(ProxyError::Protocol(_))));
    }

    // Checks that an empty/truncated input returns an error (not a panic).
    #[tokio::test]
    async fn truncated_input_returns_error() {
        let result = decode_from_bytes(&[]).await;
        assert!(result.is_err());

        let result = decode_from_bytes(&[0x00]).await;
        assert!(result.is_err());
    }

    // Checks that encode_request + decode_request is a roundtrip.
    // Encoding then decoding must give back the same values.
    #[tokio::test]
    async fn encode_decode_roundtrip_ipv4() {
        let uuid = [0xCCu8; 16];
        let dest = Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 8080);
        let encoded = encode_request(&uuid, "", Command::Tcp, &dest).unwrap();

        let decoded = decode_from_bytes(&encoded).await.unwrap();
        assert_eq!(decoded.uuid, uuid);
        assert_eq!(decoded.command, Command::Tcp);
        assert_eq!(decoded.dest, dest);
        assert!(decoded.flow.is_empty());
    }

    // Checks that a domain name roundtrips correctly.
    #[tokio::test]
    async fn encode_decode_roundtrip_domain() {
        let uuid = [0xDDu8; 16];
        let dest = Address::Domain("proxy.example.com".into(), 443);
        let encoded = encode_request(&uuid, "", Command::Tcp, &dest).unwrap();
        let decoded = decode_from_bytes(&encoded).await.unwrap();
        assert_eq!(decoded.dest, dest);
    }

    // Xray `RequestCommandMux` omits address/port on the wire.
    #[tokio::test]
    async fn mux_command_has_no_address_on_wire() {
        let uuid = [0xABu8; 16];
        let dest = Address::Domain(MUX_COOL_DOMAIN.into(), 0);
        let encoded = encode_request(&uuid, "", Command::Mux, &dest).unwrap();
        let tcp_len = encode_request(&uuid, "", Command::Tcp, &dest).unwrap().len();
        assert!(encoded.len() < tcp_len);
        let decoded = decode_from_bytes(&encoded).await.unwrap();
        assert_eq!(decoded.command, Command::Mux);
        assert_eq!(decoded.dest, dest);
    }

    // Checks that the flow field survives an encode-decode roundtrip.
    #[tokio::test]
    async fn flow_field_roundtrip() {
        let uuid = [0xEEu8; 16];
        let dest = Address::Domain("example.com".into(), 443);
        let encoded = encode_request(&uuid, "xtls-rprx-vision", Command::Tcp, &dest).unwrap();
        let decoded = decode_from_bytes(&encoded).await.unwrap();
        assert_eq!(decoded.flow, "xtls-rprx-vision");
    }
}
