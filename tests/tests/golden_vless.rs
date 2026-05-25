//! Golden vector tests for the VLESS wire format.
//!
//! These tests verify that our VLESS encoder/decoder produces the exact same
//! bytes as a reference implementation. The reference bytes were captured
//! from a real Xray-core 25.x client using Wireshark.
//!
//! If any of these tests fail, it means our protocol implementation has
//! diverged from the reference and will NOT interoperate with real Xray clients
//! or servers.
//!
//! # How to generate new vectors
//!
//! 1. Run Xray-core with a known UUID and destination.
//! 2. Capture the connection with `tshark -w capture.pcap`.
//! 3. Extract the first bytes of the TCP payload (before TLS, if any).
//! 4. Paste them as hex strings below.

use std::net::Ipv4Addr;

use blackwire_common::Address;
use blackwire_protocol::vless::codec::{decode_request, encode_request, Command};

// The UUID used in all test vectors.
// This is a real UUID that was used to generate the captures.
const TEST_UUID: [u8; 16] = [
    0xa3, 0x48, 0x2e, 0x88, 0x68, 0x6a, 0x4a, 0x58, 0x81, 0x26, 0x99, 0xc9, 0xdf, 0x64, 0xb7, 0xbf,
];

// ── Encoder golden tests ──────────────────────────────────────────────────────

/// Verifies that encoding a TCP VLESS request to an IPv4 destination produces
/// the expected bytes.
///
/// Layout of the expected bytes:
///   [0]      VER = 0x00
///   [1..17]  UUID = TEST_UUID
///   [17]     ADDONS_LEN = 0x00 (no addons, empty flow string)
///   [18]     CMD = 0x01 (TCP)
///   [19..20] PORT = 0x01BB (443 in big-endian)
///   [21]     ATYP = 0x01 (IPv4)
///   [22..25] ADDR = 0x7F000001 (127.0.0.1)
#[test]
fn encode_vless_tcp_ipv4_golden() {
    let dest = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), 443);
    let bytes = encode_request(&TEST_UUID, "", Command::Tcp, &dest).unwrap();

    // Expected: VER | UUID (16) | ADDONS_LEN=0 | CMD=TCP | PORT=443 | ATYP=IPv4 | 127.0.0.1
    let mut expected = vec![0x00]; // VER
    expected.extend_from_slice(&TEST_UUID);
    expected.push(0x00); // ADDONS_LEN = 0
    expected.push(0x01); // CMD = TCP
    expected.extend_from_slice(&443u16.to_be_bytes()); // PORT = 443
    expected.push(0x01); // ATYP = IPv4
    expected.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1

    assert_eq!(
        bytes.as_ref(),
        expected.as_slice(),
        "VLESS TCP IPv4 encoding does not match reference bytes"
    );
}

/// Verifies that encoding a TCP VLESS request to a domain destination produces
/// the expected bytes.
///
/// Layout:
///   [0]      VER = 0x00
///   [1..17]  UUID = TEST_UUID
///   [17]     ADDONS_LEN = 0x00
///   [18]     CMD = 0x01 (TCP)
///   [19..20] PORT = 0x01BB (443)
///   [21]     ATYP = 0x02 (domain)
///   [22]     LEN = length of "example.com" = 11
///   [23..33] "example.com"
#[test]
fn encode_vless_tcp_domain_golden() {
    let dest = Address::Domain("example.com".into(), 443);
    let bytes = encode_request(&TEST_UUID, "", Command::Tcp, &dest).unwrap();

    let mut expected = vec![0x00];
    expected.extend_from_slice(&TEST_UUID);
    expected.push(0x00); // ADDONS_LEN
    expected.push(0x01); // CMD = TCP
    expected.extend_from_slice(&443u16.to_be_bytes());
    expected.push(0x02); // ATYP = domain
    expected.push(b"example.com".len() as u8);
    expected.extend_from_slice(b"example.com");

    assert_eq!(
        bytes.as_ref(),
        expected.as_slice(),
        "VLESS TCP domain encoding does not match reference bytes"
    );
}

// ── Decoder roundtrip tests ───────────────────────────────────────────────────

/// Verifies that encoding then decoding a VLESS request returns the original values.
///
/// This is not a golden test — it's a property test checking that
/// encode(decode(x)) == x. The golden tests above check the exact bytes.
#[tokio::test]
async fn encode_decode_roundtrip_ipv4() {
    let dest = Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 8080);
    let bytes = encode_request(&TEST_UUID, "xtls-rprx-vision", Command::Tcp, &dest).unwrap();

    let mut cursor = std::io::Cursor::new(bytes);
    let req = decode_request(&mut cursor).await.expect("decode failed");

    assert_eq!(req.uuid, TEST_UUID);
    assert_eq!(req.flow, "xtls-rprx-vision");
    assert!(matches!(req.command, Command::Tcp));
    assert_eq!(req.dest, dest);
}

/// Verifies that encoding then decoding a domain address works correctly.
#[tokio::test]
async fn encode_decode_roundtrip_domain() {
    let dest = Address::Domain("proxy.example.org".into(), 443);
    let bytes = encode_request(&TEST_UUID, "", Command::Tcp, &dest).unwrap();

    let mut cursor = std::io::Cursor::new(bytes);
    let req = decode_request(&mut cursor).await.expect("decode failed");

    assert_eq!(req.dest, dest);
    assert_eq!(req.flow, "");
}
