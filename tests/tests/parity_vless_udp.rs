//! VLESS UDP framing tests (Xray `EncodeUDPPacket` / `DecodeUDPPacket` address section).

use std::net::Ipv4Addr;

use blackwire_common::Address;
use blackwire_protocol::vless::codec::{decode_address_port, encode_address_port};

#[test]
fn vless_udp_address_roundtrip_ipv4() {
    let dest = Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34), 53);
    let bytes = encode_address_port(&dest).unwrap();
    let decoded = decode_address_port(&bytes).unwrap();
    assert_eq!(decoded, dest);
}
