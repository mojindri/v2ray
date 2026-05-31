//! UDP proxy over Hysteria2 QUIC datagrams.
//!
//! UDP packets are sent as QUIC datagrams (RFC 9221) rather than streams.
//! Each datagram is self-contained and carries: session ID, packet ID,
//! fragmentation info, destination address, and the UDP payload.
//!
//! # Fragmentation
//!
//! QUIC datagram size is bounded by the path MTU (typically ~1200 bytes for
//! the initial datagram). Large UDP payloads are split into fragments. Each
//! fragment has `frag_num > 1`; the last fragment also marks `frag_id =
//! frag_num - 1`. The receiver reassembles fragments by `session_id + packet_id`.
//!
//! # Datagram wire format
//!
//! ```text
//! [session_id: 4 bytes BE]   — identifies the UDP "flow"
//! [packet_id: 2 bytes BE]    — sequence number within session
//! [frag_id: 1 byte]          — which fragment this is (0-indexed)
//! [frag_num: 1 byte]         — total number of fragments (1 = not fragmented)
//! [addr_type: 1 byte]        — 0x01=IPv4, 0x02=IPv6, 0x03=domain
//! [addr + port]              — destination
//! [data: remaining bytes]    — UDP payload fragment
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context as _, Result};

/// Destination inside a UDP datagram using Hysteria2's compact binary address layout.
#[derive(Debug, Clone, PartialEq)]
pub enum Destination {
    /// IPv4 destination and port.
    V4(Ipv4Addr, u16),
    /// IPv6 destination and port.
    V6(Ipv6Addr, u16),
    /// Domain destination and port.
    Domain(String, u16),
}

/// A single UDP datagram (or fragment of one).
#[derive(Debug, Clone, PartialEq)]
pub struct UdpDatagram {
    /// Identifies the UDP flow (one per client UDP socket).
    pub session_id: u32,
    /// Sequence number within the session for fragment ordering.
    pub packet_id: u16,
    /// Zero-based index of this fragment.
    pub frag_id: u8,
    /// Total number of fragments for this packet (1 means unfragmented).
    pub frag_num: u8,
    /// Destination address for this UDP packet.
    pub dest: Destination,
    /// UDP payload fragment.
    pub data: Bytes,
}

/// Encode a `UdpDatagram` into a byte buffer suitable for a QUIC datagram.
pub fn encode_udp_datagram(dg: &UdpDatagram) -> Bytes {
    let mut buf = BytesMut::with_capacity(256 + dg.data.len());

    buf.put_u32(dg.session_id);
    buf.put_u16(dg.packet_id);
    buf.put_u8(dg.frag_id);
    buf.put_u8(dg.frag_num);

    match &dg.dest {
        Destination::V4(ip, port) => {
            buf.put_u8(0x01);
            buf.put_slice(&ip.octets());
            buf.put_u16(*port);
        }
        Destination::V6(ip, port) => {
            buf.put_u8(0x02);
            buf.put_slice(&ip.octets());
            buf.put_u16(*port);
        }
        Destination::Domain(name, port) => {
            let name_bytes = name.as_bytes();
            buf.put_u8(0x03);
            buf.put_u8(name_bytes.len() as u8);
            buf.put_slice(name_bytes);
            buf.put_u16(*port);
        }
    }

    buf.put_slice(&dg.data);
    buf.freeze()
}

/// Decode a `UdpDatagram` from a raw byte slice received as a QUIC datagram.
///
/// # Errors
///
/// Returns an error if the slice is too short or contains invalid data.
pub fn decode_udp_datagram(mut data: &[u8]) -> Result<UdpDatagram> {
    // Each field below consumes bytes from `data` via the `Buf` trait.
    anyhow::ensure!(data.len() >= 9, "datagram too short (< 9 bytes)");

    let session_id = data.get_u32();
    let packet_id = data.get_u16();
    let frag_id = data.get_u8();
    let frag_num = data.get_u8();

    let addr_type = data.get_u8();
    let dest = match addr_type {
        0x01 => {
            anyhow::ensure!(data.len() >= 6, "truncated IPv4 address");
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&data[..4]);
            data.advance(4);
            let port = data.get_u16();
            Destination::V4(Ipv4Addr::from(octets), port)
        }
        0x02 => {
            anyhow::ensure!(data.len() >= 18, "truncated IPv6 address");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[..16]);
            data.advance(16);
            let port = data.get_u16();
            Destination::V6(Ipv6Addr::from(octets), port)
        }
        0x03 => {
            anyhow::ensure!(!data.is_empty(), "missing domain name length");
            let name_len = data.get_u8() as usize;
            anyhow::ensure!(data.len() >= name_len + 2, "truncated domain name");
            let name_bytes = &data[..name_len];
            let name = std::str::from_utf8(name_bytes).context("domain name is not valid UTF-8")?;
            let name = name.to_string();
            data.advance(name_len);
            let port = data.get_u16();
            Destination::Domain(name, port)
        }
        t => anyhow::bail!("unknown UDP address type: 0x{t:02X}"),
    };

    let payload = Bytes::copy_from_slice(data);

    Ok(UdpDatagram {
        session_id,
        packet_id,
        frag_id,
        frag_num,
        dest,
        data: payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dg(dest: Destination) -> UdpDatagram {
        UdpDatagram {
            session_id: 0x1234_5678,
            packet_id: 42,
            frag_id: 0,
            frag_num: 1,
            dest,
            data: Bytes::from_static(b"hello world"),
        }
    }

    #[test]
    fn udp_datagram_ipv4_roundtrip() {
        let dg = make_dg(Destination::V4("192.168.1.1".parse().unwrap(), 53));
        let encoded = encode_udp_datagram(&dg);
        let decoded = decode_udp_datagram(&encoded).unwrap();
        assert_eq!(dg, decoded);
    }

    #[test]
    fn udp_datagram_ipv6_roundtrip() {
        let dg = make_dg(Destination::V6("::1".parse().unwrap(), 5353));
        let encoded = encode_udp_datagram(&dg);
        let decoded = decode_udp_datagram(&encoded).unwrap();
        assert_eq!(dg, decoded);
    }

    #[test]
    fn udp_datagram_domain_roundtrip() {
        let dg = make_dg(Destination::Domain("dns.google".to_string(), 53));
        let encoded = encode_udp_datagram(&dg);
        let decoded = decode_udp_datagram(&encoded).unwrap();
        assert_eq!(dg, decoded);
    }

    #[test]
    fn truncated_datagram_returns_error() {
        assert!(decode_udp_datagram(&[0u8; 4]).is_err());
    }
}
