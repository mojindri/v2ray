use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Other(u8),
}

#[derive(Debug, Clone)]
pub struct IpPacket {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
}

pub fn parse_ip_packet(buf: &[u8]) -> Option<IpPacket> {
    if buf.is_empty() { return None; }
    match buf[0] >> 4 {
        4 => parse_ipv4(buf),
        6 => parse_ipv6(buf),
        _ => None,
    }
}

fn parse_ipv4(buf: &[u8]) -> Option<IpPacket> {
    if buf.len() < 20 { return None; }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if buf.len() < ihl + 4 { return None; }
    let proto = buf[9];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let src_port = u16::from_be_bytes([buf[ihl], buf[ihl + 1]]);
    let dst_port = u16::from_be_bytes([buf[ihl + 2], buf[ihl + 3]]);
    Some(IpPacket {
        src: src.into(),
        dst: dst.into(),
        src_port,
        dst_port,
        protocol: match proto { 6 => TransportProtocol::Tcp, 17 => TransportProtocol::Udp, p => TransportProtocol::Other(p) },
    })
}

fn parse_ipv6(buf: &[u8]) -> Option<IpPacket> {
    if buf.len() < 44 { return None; }
    let next_hdr = buf[6];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).ok()?);
    let src_port = u16::from_be_bytes([buf[40], buf[41]]);
    let dst_port = u16::from_be_bytes([buf[42], buf[43]]);
    Some(IpPacket {
        src: src.into(),
        dst: dst.into(),
        src_port,
        dst_port,
        protocol: match next_hdr { 6 => TransportProtocol::Tcp, 17 => TransportProtocol::Udp, p => TransportProtocol::Other(p) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_tcp() {
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[5, 6, 7, 8]);
        pkt[20..22].copy_from_slice(&[0x00, 0x50]);
        pkt[22..24].copy_from_slice(&[0x01, 0xbb]);
        let parsed = parse_ip_packet(&pkt).unwrap();
        assert_eq!(parsed.src_port, 80);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
    }

    #[test]
    fn empty_returns_none() {
        assert!(parse_ip_packet(&[]).is_none());
    }
}
