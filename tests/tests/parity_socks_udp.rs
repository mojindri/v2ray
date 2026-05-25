//! SOCKS5 UDP datagram framing (RFC 1928).

use std::net::Ipv4Addr;

use blackwire_common::Address;
use blackwire_protocol::socks5_udp::{encode_udp_datagram, parse_udp_datagram};

#[test]
fn socks5_udp_datagram_roundtrip_ipv4() {
    let dest = Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
    let payload = b"\x00\x01";
    let pkt = encode_udp_datagram(&dest, payload).unwrap();
    let (parsed_dest, parsed_payload) = parse_udp_datagram(&pkt).unwrap();
    assert_eq!(parsed_dest, dest);
    assert_eq!(parsed_payload, payload);
}
