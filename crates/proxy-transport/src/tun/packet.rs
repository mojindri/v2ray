use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Transport protocol extracted from an IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// TCP (`IPPROTO_TCP` = 6).
    Tcp,
    /// UDP (`IPPROTO_UDP` = 17).
    Udp,
    /// Any other protocol number.
    Other(u8),
}

/// Parsed metadata for one IPv4 or IPv6 packet.
#[derive(Debug, Clone)]
pub struct IpPacket {
    /// Source IP address.
    pub src: std::net::IpAddr,
    /// Destination IP address.
    pub dst: std::net::IpAddr,
    /// Source transport port (TCP/UDP).
    pub src_port: u16,
    /// Destination transport port (TCP/UDP).
    pub dst_port: u16,
    /// Transport protocol kind.
    pub protocol: TransportProtocol,
    /// Length of the IP header section in bytes.
    pub header_len: usize,
    /// Byte offset where transport payload starts.
    pub payload_offset: usize,
    /// Payload length in bytes.
    pub payload_len: usize,
}

impl IpPacket {
    /// Return the packet payload slice using this packet's cached offsets.
    pub fn payload<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        packet.get(self.payload_offset..self.payload_offset + self.payload_len)
    }
}

/// Parse a raw IPv4/IPv6 packet into [`IpPacket`] metadata.
///
/// Returns `None` for unsupported versions or malformed packet layout.
pub fn parse_ip_packet(buf: &[u8]) -> Option<IpPacket> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] >> 4 {
        4 => parse_ipv4(buf),
        6 => parse_ipv6(buf),
        _ => None,
    }
}

fn parse_ipv4(buf: &[u8]) -> Option<IpPacket> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if ihl < 20 {
        return None;
    }
    let total_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total_length < ihl || buf.len() < total_length {
        return None;
    }
    if buf.len() < ihl + 4 {
        return None;
    }
    let proto = buf[9];
    let transport_len = total_length.checked_sub(ihl)?;
    let payload_offset = match proto {
        6 => {
            if transport_len < 20 {
                return None;
            }
            let data_offset = ((buf[ihl + 12] >> 4) as usize) * 4;
            if data_offset < 20 || transport_len < data_offset {
                return None;
            }
            ihl + data_offset
        }
        17 => {
            if transport_len < 8 {
                return None;
            }
            let udp_len = u16::from_be_bytes([buf[ihl + 4], buf[ihl + 5]]) as usize;
            if udp_len < 8 || udp_len > transport_len {
                return None;
            }
            ihl + 8
        }
        _ => ihl + 4,
    };
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let src_port = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
    let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
    Some(IpPacket {
        src: src.into(),
        dst: dst.into(),
        src_port,
        dst_port,
        protocol: match proto {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            p => TransportProtocol::Other(p),
        },
        header_len: ihl,
        payload_offset,
        payload_len: total_length.saturating_sub(payload_offset),
    })
}

fn parse_ipv6(buf: &[u8]) -> Option<IpPacket> {
    if buf.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let total_length = 40usize.checked_add(payload_len)?;
    if buf.len() < total_length {
        return None;
    }

    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).ok()?);

    // Walk extension headers until we reach a transport-layer header.
    let mut next_hdr = buf[6];
    let mut offset = 40usize;
    loop {
        match next_hdr {
            6 | 17 | 58 => break, // TCP / UDP / ICMPv6 — transport header found
            // Extension headers with variable length (RFC 2460 §4.2):
            // each has next_hdr(1) + ext_len(1) + data; ext_len is in 8-octet units excluding first unit.
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                if offset + 2 > total_length {
                    return None;
                }
                next_hdr = buf[offset];
                let ext_len = (buf[offset + 1] as usize + 1) * 8;
                offset = offset.checked_add(ext_len)?;
            }
            // Fragment header (44) is always 8 bytes.
            44 => {
                if offset + 8 > total_length {
                    return None;
                }
                next_hdr = buf[offset];
                offset += 8;
            }
            // Unknown next header — report as Other, no port info.
            other => {
                return Some(IpPacket {
                    src: src.into(),
                    dst: dst.into(),
                    src_port: 0,
                    dst_port: 0,
                    protocol: TransportProtocol::Other(other),
                    header_len: 40,
                    payload_offset: offset,
                    payload_len: total_length.saturating_sub(offset),
                });
            }
        }
    }

    let transport_len = total_length.saturating_sub(offset);
    let payload_offset = match next_hdr {
        6 => {
            if transport_len < 20 || offset + 13 > buf.len() {
                return None;
            }
            let data_offset = ((buf[offset + 12] >> 4) as usize) * 4;
            if data_offset < 20 || transport_len < data_offset {
                return None;
            }
            offset + data_offset
        }
        17 => {
            if transport_len < 8 || offset + 6 > buf.len() {
                return None;
            }
            let udp_len = u16::from_be_bytes([buf[offset + 4], buf[offset + 5]]) as usize;
            if udp_len < 8 || udp_len > transport_len {
                return None;
            }
            offset + 8
        }
        _ => offset + 4,
    };

    if offset + 4 > buf.len() {
        return None;
    }
    let src_port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let dst_port = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);

    Some(IpPacket {
        src: src.into(),
        dst: dst.into(),
        src_port,
        dst_port,
        protocol: match next_hdr {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            p => TransportProtocol::Other(p),
        },
        header_len: 40,
        payload_offset,
        payload_len: total_length.saturating_sub(payload_offset),
    })
}

/// Build a TCP RST packet in response to `request`.
///
/// Swaps src/dst so the RST flows back toward the original sender.
/// Used to reject TCP flows that the TUN runtime cannot proxy (e.g. when the
/// proxy's TCP listener is not reachable or when iptables REDIRECT misfires).
pub fn build_tcp_rst(request: &IpPacket) -> Option<Vec<u8>> {
    if request.protocol != TransportProtocol::Tcp {
        return None;
    }
    match (request.src, request.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            build_ipv4_tcp_rst(dst, src, request.dst_port, request.src_port)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            build_ipv6_tcp_rst(dst, src, request.dst_port, request.src_port)
        }
        _ => None,
    }
}

fn build_ipv4_tcp_rst(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Option<Vec<u8>> {
    // IP header (20) + TCP header (20), no payload.
    let mut out = vec![0u8; 40];
    out[0] = 0x45; // version=4, IHL=5
    out[2..4].copy_from_slice(&40u16.to_be_bytes());
    out[8] = 64; // TTL
    out[9] = 6; // TCP
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let ip_csum = internet_checksum(&out[..20]);
    out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // TCP header at offset 20.
    out[20..22].copy_from_slice(&src_port.to_be_bytes());
    out[22..24].copy_from_slice(&dst_port.to_be_bytes());
    // seq=0, ack=0, data_offset=5 (20 bytes), RST flag.
    out[32] = 0x50;
    out[33] = 0x04; // RST
    let tcp_csum = tcp_checksum_ipv4(src, dst, &out[20..]);
    out[36..38].copy_from_slice(&tcp_csum.to_be_bytes());
    Some(out)
}

fn build_ipv6_tcp_rst(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Option<Vec<u8>> {
    // IPv6 header (40) + TCP header (20), no payload.
    let tcp_len: usize = 20;
    let mut out = vec![0u8; 40 + tcp_len];
    out[0] = 0x60; // version=6, traffic class=0
    out[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    out[6] = 6; // TCP
    out[7] = 64; // hop limit
    out[8..24].copy_from_slice(&src.octets());
    out[24..40].copy_from_slice(&dst.octets());

    // TCP header at offset 40.
    out[40..42].copy_from_slice(&src_port.to_be_bytes());
    out[42..44].copy_from_slice(&dst_port.to_be_bytes());
    out[52] = 0x50; // data_offset=5
    out[53] = 0x04; // RST
    let tcp_csum = tcp_checksum_ipv6(src, dst, &out[40..]);
    out[56..58].copy_from_slice(&tcp_csum.to_be_bytes());
    Some(out)
}

fn tcp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6); // TCP
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    internet_checksum(&pseudo)
}

fn tcp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + tcp_segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(tcp_segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]); // next header = TCP
    pseudo.extend_from_slice(tcp_segment);
    internet_checksum(&pseudo)
}

/// Build a UDP response packet by swapping request source/destination.
///
/// This is used by the NAT path to send remote UDP replies back to the
/// original client through TUN.
pub fn build_udp_response_packet(request: &IpPacket, payload: &[u8]) -> Option<Vec<u8>> {
    if request.protocol != TransportProtocol::Udp {
        return None;
    }

    match (request.src, request.dst) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            build_ipv4_udp_packet(dst, src, request.dst_port, request.src_port, payload)
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            build_ipv6_udp_packet(dst, src, request.dst_port, request.src_port, payload)
        }
        _ => None,
    }
}

fn build_ipv4_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    let total_len = 20usize.checked_add(udp_len)?;
    if udp_len > u16::MAX as usize || total_len > u16::MAX as usize {
        return None;
    }

    let mut out = vec![0u8; total_len];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    out[8] = 64;
    out[9] = 17;
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let ip_checksum = internet_checksum(&out[..20]);
    out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = 20;
    out[udp..udp + 2].copy_from_slice(&src_port.to_be_bytes());
    out[udp + 2..udp + 4].copy_from_slice(&dst_port.to_be_bytes());
    out[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[udp + 8..].copy_from_slice(payload);
    let checksum = udp_checksum_ipv4(src, dst, &out[udp..]);
    out[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
    Some(out)
}

fn build_ipv6_udp_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    let total_len = 40usize.checked_add(udp_len)?;
    if udp_len > u16::MAX as usize {
        return None;
    }

    let mut out = vec![0u8; total_len];
    out[0] = 0x60;
    out[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[6] = 17;
    out[7] = 64;
    out[8..24].copy_from_slice(&src.octets());
    out[24..40].copy_from_slice(&dst.octets());

    let udp = 40;
    out[udp..udp + 2].copy_from_slice(&src_port.to_be_bytes());
    out[udp + 2..udp + 4].copy_from_slice(&dst_port.to_be_bytes());
    out[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[udp + 8..].copy_from_slice(payload);
    let checksum = udp_checksum_ipv6(src, dst, &out[udp..]);
    out[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
    Some(out)
}

fn udp_checksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, udp_packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_packet.len() + 1);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_packet.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_packet);
    internet_checksum(&pseudo)
}

fn udp_checksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, udp_packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp_packet.len() + 1);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp_packet.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(udp_packet);
    internet_checksum(&pseudo)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_tcp() {
        let mut pkt = vec![0u8; 40];
        let total_length = pkt.len() as u16;
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_length.to_be_bytes());
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[5, 6, 7, 8]);
        pkt[20..22].copy_from_slice(&[0x00, 0x50]);
        pkt[22..24].copy_from_slice(&[0x01, 0xbb]);
        pkt[32] = 0x50;
        let parsed = parse_ip_packet(&pkt).unwrap();
        assert_eq!(parsed.src_port, 80);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.payload_offset, 40);
    }

    #[test]
    fn empty_returns_none() {
        assert!(parse_ip_packet(&[]).is_none());
    }

    #[test]
    fn build_tcp_rst_swaps_addresses_and_sets_rst_flag() {
        let request = parse_ip_packet(&ipv4_tcp()).unwrap();
        let rst = build_tcp_rst(&request).unwrap();
        let parsed = parse_ip_packet(&rst).unwrap();

        assert_eq!(parsed.src, request.dst);
        assert_eq!(parsed.dst, request.src);
        assert_eq!(parsed.src_port, request.dst_port);
        assert_eq!(parsed.dst_port, request.src_port);
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        // RST flag is byte 13 of the TCP header.
        let tcp_flags = rst[parsed.header_len + 13];
        assert_eq!(tcp_flags & 0x04, 0x04, "RST flag not set");
    }

    fn ipv4_tcp() -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        let total_len = pkt.len() as u16;
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[5, 6, 7, 8]);
        pkt[20..22].copy_from_slice(&[0x00, 0x50]); // src_port=80
        pkt[22..24].copy_from_slice(&[0x01, 0xbb]); // dst_port=443
        pkt[32] = 0x50; // data_offset=5
        pkt
    }

    #[test]
    fn build_tcp_rst_returns_none_for_non_tcp() {
        let request_bytes = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            53000,
            53,
            b"x",
        )
        .unwrap();
        let request = parse_ip_packet(&request_bytes).unwrap();
        assert!(build_tcp_rst(&request).is_none());
    }

    #[test]
    fn build_udp_response_swaps_addresses_and_preserves_payload() {
        let request_bytes = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            53000,
            53,
            b"query",
        )
        .unwrap();
        let request = parse_ip_packet(&request_bytes).unwrap();
        let response = build_udp_response_packet(&request, b"answer").unwrap();
        let parsed = parse_ip_packet(&response).unwrap();

        assert_eq!(parsed.src, request.dst);
        assert_eq!(parsed.dst, request.src);
        assert_eq!(parsed.src_port, request.dst_port);
        assert_eq!(parsed.dst_port, request.src_port);
        assert_eq!(parsed.payload(&response).unwrap(), b"answer");
    }
}
