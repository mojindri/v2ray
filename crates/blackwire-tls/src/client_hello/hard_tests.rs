//! Strict parse/validation tests for generated Chrome ClientHello bytes.

use super::ClientHelloBuilder;
use crate::grease::is_grease_u16;
use crate::profile::FingerprintProfile;
use bytes::BytesMut;
use rand::SeedableRng;

#[derive(Debug, Clone)]
struct ParsedClientHello {
    record_type: u8,
    record_version: u16,
    record_len: usize,
    handshake_type: u8,
    handshake_len: usize,
    legacy_version: u16,
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    extensions: Vec<ParsedExtension>,
}

#[derive(Debug, Clone)]
struct ParsedExtension {
    ext_type: u16,
    data: Vec<u8>,
}

fn build_test_hello() -> BytesMut {
    let mut rng = rand::rngs::SmallRng::seed_from_u64(42);

    ClientHelloBuilder::chrome_131().build(
        "example.com",
        &[0x11; 32],
        &[0x22; 32],
        Some(&[0x33; 32]),
        &mut rng,
    )
}

fn build_test_hello_with_sni(sni: &str) -> BytesMut {
    let mut rng = rand::rngs::SmallRng::seed_from_u64(42);

    ClientHelloBuilder::chrome_131().build(
        sni,
        &[0x11; 32],
        &[0x22; 32],
        Some(&[0x33; 32]),
        &mut rng,
    )
}

fn parse_u16(input: &[u8], p: &mut usize) -> Result<u16, String> {
    if *p + 2 > input.len() {
        return Err("truncated u16".into());
    }

    let v = u16::from_be_bytes([input[*p], input[*p + 1]]);
    *p += 2;
    Ok(v)
}

fn parse_u24(input: &[u8], p: &mut usize) -> Result<usize, String> {
    if *p + 3 > input.len() {
        return Err("truncated u24".into());
    }

    let v = ((input[*p] as usize) << 16) | ((input[*p + 1] as usize) << 8) | input[*p + 2] as usize;

    *p += 3;
    Ok(v)
}

fn parse_client_hello(input: &[u8]) -> Result<ParsedClientHello, String> {
    if input.len() < 5 {
        return Err("TLS record too short".into());
    }

    let record_type = input[0];
    if record_type != 0x16 {
        return Err(format!("unexpected record type: {record_type:#04x}"));
    }

    let mut p = 1;
    let record_version = parse_u16(input, &mut p)?;
    let record_len = parse_u16(input, &mut p)? as usize;

    if input.len() != 5 + record_len {
        return Err(format!(
            "record length mismatch: declared={}, actual={}",
            record_len,
            input.len().saturating_sub(5)
        ));
    }

    let record_body = &input[5..];

    if record_body.len() < 4 {
        return Err("handshake too short".into());
    }

    let mut hp = 0;
    let handshake_type = record_body[hp];
    hp += 1;

    if handshake_type != 0x01 {
        return Err(format!("unexpected handshake type: {handshake_type:#04x}"));
    }

    let handshake_len = parse_u24(record_body, &mut hp)?;

    if record_body.len() != 4 + handshake_len {
        return Err(format!(
            "handshake length mismatch: declared={}, actual={}",
            handshake_len,
            record_body.len().saturating_sub(4)
        ));
    }

    let legacy_version = parse_u16(record_body, &mut hp)?;

    if hp + 32 > record_body.len() {
        return Err("truncated random".into());
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&record_body[hp..hp + 32]);
    hp += 32;

    if hp >= record_body.len() {
        return Err("missing session_id length".into());
    }

    let session_id_len = record_body[hp] as usize;
    hp += 1;

    if hp + session_id_len > record_body.len() {
        return Err("truncated session_id".into());
    }

    let session_id = record_body[hp..hp + session_id_len].to_vec();
    hp += session_id_len;

    let cipher_suites_len = parse_u16(record_body, &mut hp)? as usize;

    if !cipher_suites_len.is_multiple_of(2) {
        return Err("cipher_suites length is odd".into());
    }

    if hp + cipher_suites_len > record_body.len() {
        return Err("truncated cipher_suites".into());
    }

    let mut cipher_suites = Vec::new();
    for chunk in record_body[hp..hp + cipher_suites_len].chunks_exact(2) {
        cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    hp += cipher_suites_len;

    if hp >= record_body.len() {
        return Err("missing compression_methods length".into());
    }

    let compression_methods_len = record_body[hp] as usize;
    hp += 1;

    if hp + compression_methods_len > record_body.len() {
        return Err("truncated compression_methods".into());
    }

    let compression_methods = record_body[hp..hp + compression_methods_len].to_vec();
    hp += compression_methods_len;

    let extensions_len = parse_u16(record_body, &mut hp)? as usize;

    if hp + extensions_len != record_body.len() {
        return Err(format!(
            "extensions length mismatch: declared={}, remaining={}",
            extensions_len,
            record_body.len().saturating_sub(hp)
        ));
    }

    let extensions_end = hp + extensions_len;
    let mut extensions = Vec::new();

    while hp < extensions_end {
        if hp + 4 > extensions_end {
            return Err("truncated extension header".into());
        }

        let ext_type = parse_u16(record_body, &mut hp)?;
        let ext_len = parse_u16(record_body, &mut hp)? as usize;

        if hp + ext_len > extensions_end {
            return Err(format!(
                "truncated extension body for extension {ext_type:#06x}"
            ));
        }

        extensions.push(ParsedExtension {
            ext_type,
            data: record_body[hp..hp + ext_len].to_vec(),
        });

        hp += ext_len;
    }

    Ok(ParsedClientHello {
        record_type,
        record_version,
        record_len,
        handshake_type,
        handshake_len,
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
    })
}

fn extension(parsed: &ParsedClientHello, ext_type: u16) -> Option<&ParsedExtension> {
    parsed.extensions.iter().find(|e| e.ext_type == ext_type)
}

fn extract_supported_groups(parsed: &ParsedClientHello) -> Result<Vec<u16>, String> {
    let ext = extension(parsed, 0x000A)
        .ok_or_else(|| "missing supported_groups extension".to_string())?;

    if ext.data.len() < 2 {
        return Err("supported_groups too short".into());
    }

    let declared_len = u16::from_be_bytes([ext.data[0], ext.data[1]]) as usize;

    if declared_len + 2 != ext.data.len() {
        return Err("supported_groups length mismatch".into());
    }

    if !declared_len.is_multiple_of(2) {
        return Err("supported_groups length is odd".into());
    }

    let mut groups = Vec::new();
    for chunk in ext.data[2..].chunks_exact(2) {
        groups.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }

    Ok(groups)
}

fn extract_ec_point_formats(parsed: &ParsedClientHello) -> Result<Vec<u8>, String> {
    let ext = extension(parsed, 0x000B)
        .ok_or_else(|| "missing ec_point_formats extension".to_string())?;

    if ext.data.is_empty() {
        return Err("ec_point_formats too short".into());
    }

    let declared_len = ext.data[0] as usize;

    if declared_len + 1 != ext.data.len() {
        return Err("ec_point_formats length mismatch".into());
    }

    Ok(ext.data[1..].to_vec())
}

fn extract_supported_versions(parsed: &ParsedClientHello) -> Result<Vec<u16>, String> {
    let ext = extension(parsed, 0x002B)
        .ok_or_else(|| "missing supported_versions extension".to_string())?;

    if ext.data.is_empty() {
        return Err("supported_versions too short".into());
    }

    let declared_len = ext.data[0] as usize;

    if declared_len + 1 != ext.data.len() {
        return Err("supported_versions length mismatch".into());
    }

    if !declared_len.is_multiple_of(2) {
        return Err("supported_versions length is odd".into());
    }

    let mut versions = Vec::new();
    for chunk in ext.data[1..].chunks_exact(2) {
        versions.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }

    Ok(versions)
}

fn ja3_string(parsed: &ParsedClientHello) -> String {
    let ciphers = parsed
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease_u16(*v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let extensions = parsed
        .extensions
        .iter()
        .map(|e| e.ext_type)
        .filter(|v| !is_grease_u16(*v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let groups = extract_supported_groups(parsed)
        .unwrap_or_default()
        .into_iter()
        .filter(|v| !is_grease_u16(*v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ec_point_formats = extract_ec_point_formats(parsed)
        .unwrap_or_default()
        .into_iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");

    format!(
        "{},{},{},{},{}",
        parsed.legacy_version, ciphers, extensions, groups, ec_point_formats
    )
}

fn locate_cipher_suites_len_offset(_input: &[u8]) -> usize {
    // TLS record header: 5
    // Handshake header: 4
    // legacy_version: 2
    // random: 32
    // session_id_len: 1
    // session_id: 32
    5 + 4 + 2 + 32 + 1 + 32
}

fn locate_extensions_len_offset(input: &[u8]) -> Result<usize, String> {
    let mut p = 5 + 4;

    p += 2; // legacy_version
    p += 32; // random

    if p >= input.len() {
        return Err("missing session_id length".into());
    }

    let sid_len = input[p] as usize;
    p += 1 + sid_len;

    if p + 2 > input.len() {
        return Err("missing cipher_suites length".into());
    }

    let cipher_len = u16::from_be_bytes([input[p], input[p + 1]]) as usize;
    p += 2 + cipher_len;

    if p >= input.len() {
        return Err("missing compression_methods length".into());
    }

    let comp_len = input[p] as usize;
    p += 1 + comp_len;

    if p + 2 > input.len() {
        return Err("missing extensions length".into());
    }

    Ok(p)
}

fn locate_first_extension_len_offset(input: &[u8]) -> Result<usize, String> {
    let ext_len_offset = locate_extensions_len_offset(input)?;
    let first_ext_start = ext_len_offset + 2;

    if first_ext_start + 4 > input.len() {
        return Err("missing first extension header".into());
    }

    Ok(first_ext_start + 2)
}

#[test]
fn generated_client_hello_is_strictly_parseable() {
    let hello = build_test_hello();

    let parsed = parse_client_hello(&hello).expect("generated ClientHello must strictly parse");

    assert_eq!(parsed.record_type, 0x16);
    assert_eq!(parsed.record_version, 0x0301);
    assert_eq!(parsed.record_len, hello.len() - 5);

    assert_eq!(parsed.handshake_type, 0x01);
    assert_eq!(parsed.handshake_len, hello.len() - 9);

    assert_eq!(parsed.legacy_version, 0x0303);
    assert_eq!(parsed.random, [0x11; 32]);
    assert_eq!(parsed.session_id, vec![0x22; 32]);
    assert_eq!(parsed.compression_methods, vec![0x00]);

    assert!(!parsed.cipher_suites.is_empty());
    assert!(!parsed.extensions.is_empty());
}

#[test]
fn build_is_deterministic_when_keyshare_and_rng_are_fixed() {
    let mut rng1 = rand::rngs::SmallRng::seed_from_u64(42);
    let mut rng2 = rand::rngs::SmallRng::seed_from_u64(42);

    let a = ClientHelloBuilder::chrome_131().build(
        "example.com",
        &[0x11; 32],
        &[0x22; 32],
        Some(&[0x33; 32]),
        &mut rng1,
    );

    let b = ClientHelloBuilder::chrome_131().build(
        "example.com",
        &[0x11; 32],
        &[0x22; 32],
        Some(&[0x33; 32]),
        &mut rng2,
    );

    assert_eq!(a, b);
}

#[test]
fn generated_ja3_matches_declared_chrome_131_profile() {
    let hello = build_test_hello();
    let parsed = parse_client_hello(&hello).unwrap();

    let actual = ja3_string(&parsed);

    let expected = "771,\
4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,\
29-23-24,\
0";

    assert_eq!(actual, expected);
}

#[test]
fn cipher_suites_have_one_grease_value_at_front() {
    let hello = build_test_hello();
    let parsed = parse_client_hello(&hello).unwrap();

    assert!(
        is_grease_u16(parsed.cipher_suites[0]),
        "first cipher suite should be GREASE, got {:#06x}",
        parsed.cipher_suites[0]
    );

    let non_grease: Vec<u16> = parsed
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease_u16(*v))
        .collect();

    assert_eq!(non_grease, FingerprintProfile::chrome_131().cipher_suites);
}

#[test]
fn extension_order_matches_profile_then_one_grease_extension() {
    let hello = build_test_hello();
    let parsed = parse_client_hello(&hello).unwrap();

    let ext_ids: Vec<u16> = parsed.extensions.iter().map(|e| e.ext_type).collect();

    let profile = FingerprintProfile::chrome_131();

    assert_eq!(
        ext_ids.len(),
        profile.extensions.len() + 1,
        "expected profile extensions plus one GREASE extension"
    );

    assert_eq!(
        &ext_ids[..profile.extensions.len()],
        profile.extensions.as_slice(),
        "non-GREASE extension order diverged from profile"
    );

    let last = *ext_ids.last().unwrap();
    assert!(
        is_grease_u16(last),
        "last extension should be GREASE in the current implementation, got {last:#06x}"
    );
}

#[test]
fn supported_groups_has_grease_then_profile_groups() {
    let hello = build_test_hello();
    let parsed = parse_client_hello(&hello).unwrap();

    let groups = extract_supported_groups(&parsed).unwrap();

    assert!(
        is_grease_u16(groups[0]),
        "first supported group should be GREASE, got {:#06x}",
        groups[0]
    );

    assert_eq!(
        &groups[1..],
        FingerprintProfile::chrome_131().supported_groups.as_slice()
    );
}

#[test]
fn supported_versions_is_well_formed_and_contains_grease_tls13_tls12_tls11() {
    let hello = build_test_hello();
    let parsed = parse_client_hello(&hello).unwrap();

    let versions = extract_supported_versions(&parsed).unwrap();

    assert_eq!(versions.len(), 4);

    assert!(
        is_grease_u16(versions[0]),
        "first supported version should be GREASE, got {:#06x}",
        versions[0]
    );

    assert_eq!(versions[1], 0x0304, "TLS 1.3 missing");
    assert_eq!(versions[2], 0x0303, "TLS 1.2 missing");
    assert_eq!(versions[3], 0x0302, "TLS 1.1 compatibility missing");
}

#[test]
fn compress_certificate_extension_has_single_brotli_algorithm() {
    let hello = build_test_hello();
    let parsed = parse_client_hello(&hello).unwrap();
    let ext = extension(&parsed, 0x001B).expect("missing compress_certificate extension");

    assert_eq!(
        ext.data,
        vec![0x02, 0x00, 0x02],
        "compress_certificate must encode one Brotli algorithm without trailing bytes"
    );
}

#[test]
fn alpn_is_h2_then_http11() {
    let hello = build_test_hello();
    let parsed = parse_client_hello(&hello).unwrap();

    let alpn = extension(&parsed, 0x0010).expect("missing ALPN extension");

    assert!(
        alpn.data.windows(b"h2".len()).any(|w| w == b"h2"),
        "ALPN does not contain h2"
    );

    assert!(
        alpn.data
            .windows(b"http/1.1".len())
            .any(|w| w == b"http/1.1"),
        "ALPN does not contain http/1.1"
    );

    let h2_pos = alpn
        .data
        .windows(b"h2".len())
        .position(|w| w == b"h2")
        .unwrap();

    let http11_pos = alpn
        .data
        .windows(b"http/1.1".len())
        .position(|w| w == b"http/1.1")
        .unwrap();

    assert!(h2_pos < http11_pos, "h2 must appear before http/1.1");
}

#[test]
fn sni_hostname_is_encoded_once() {
    let hello = build_test_hello_with_sni("proxy.example.org");
    let parsed = parse_client_hello(&hello).unwrap();

    let sni = extension(&parsed, 0x0000).expect("missing SNI extension");

    let needle = b"proxy.example.org";
    let count = sni
        .data
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count();

    assert_eq!(count, 1, "SNI hostname should appear exactly once");
}

#[test]
fn bad_record_length_is_rejected() {
    let mut hello = build_test_hello();

    hello[3] = 0xff;
    hello[4] = 0xff;

    assert!(parse_client_hello(&hello).is_err());
}

#[test]
fn bad_handshake_length_is_rejected() {
    let mut hello = build_test_hello();

    // Handshake length lives at record offset 6..9:
    // record header 5 bytes, handshake_type at 5, u24 length at 6..9.
    hello[6] = 0xff;
    hello[7] = 0xff;
    hello[8] = 0xff;

    assert!(parse_client_hello(&hello).is_err());
}

#[test]
fn odd_cipher_suite_length_is_rejected() {
    let mut hello = build_test_hello();

    let off = locate_cipher_suites_len_offset(&hello);

    hello[off] = 0x00;
    hello[off + 1] = 0x03;

    assert!(parse_client_hello(&hello).is_err());
}

#[test]
fn oversized_first_extension_length_is_rejected() {
    let mut hello = build_test_hello();

    let off = locate_first_extension_len_offset(&hello).unwrap();

    hello[off] = 0xff;
    hello[off + 1] = 0xff;

    assert!(parse_client_hello(&hello).is_err());
}

#[test]
fn oversized_extensions_total_length_is_rejected() {
    let mut hello = build_test_hello();

    let off = locate_extensions_len_offset(&hello).unwrap();

    hello[off] = 0xff;
    hello[off + 1] = 0xff;

    assert!(parse_client_hello(&hello).is_err());
}

#[test]
fn truncated_input_never_panics() {
    let hello = build_test_hello();

    for len in 0..hello.len() {
        let _ = parse_client_hello(&hello[..len]);
    }
}

#[test]
fn generated_output_has_no_duplicate_non_grease_extensions() {
    let hello = build_test_hello();
    let parsed = parse_client_hello(&hello).unwrap();

    let mut seen = std::collections::HashSet::new();

    for ext in &parsed.extensions {
        if is_grease_u16(ext.ext_type) {
            continue;
        }

        assert!(
            seen.insert(ext.ext_type),
            "duplicate extension found: {:#06x}",
            ext.ext_type
        );
    }
}

#[test]
fn current_builder_generates_parseable_output_for_common_sni_lengths() {
    let cases = [
        "a.com",
        "example.com",
        "proxy.example.org",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
    ];

    for sni in cases {
        let hello = build_test_hello_with_sni(sni);
        let parsed =
            parse_client_hello(&hello).unwrap_or_else(|e| panic!("failed to parse SNI={sni}: {e}"));

        let sni_ext = extension(&parsed, 0x0000).expect("missing SNI extension");
        assert!(
            sni_ext.data.windows(sni.len()).any(|w| w == sni.as_bytes()),
            "SNI extension does not contain hostname {sni}"
        );
    }
}

#[ignore = "self-seeding: first run creates the golden fixture, subsequent runs detect regressions"]
#[test]
fn golden_chrome_131_packet_matches_after_normalization() {
    let golden_path = std::path::Path::new("tests/golden/chrome_131_clienthello.bin");

    // If the fixture doesn't exist yet, generate it from the same builder
    // but with a different RNG seed and SNI so that GREASE values differ.
    // All non-GREASE fields (cipher suites, extension order, supported groups)
    // are profile-driven and must stay identical — that's exactly what this
    // test verifies.
    let golden: Vec<u8> = if golden_path.exists() {
        std::fs::read(golden_path).expect("failed to read golden fixture")
    } else {
        std::fs::create_dir_all(golden_path.parent().unwrap())
            .expect("failed to create tests/golden/");
        let mut rng = rand::rngs::SmallRng::seed_from_u64(7); // seed ≠ build_test_hello's 42
        let bytes = ClientHelloBuilder::chrome_131().build(
            "www.google.com",
            &[0x55u8; 32],
            &[0x66u8; 32],
            Some(&[0x77u8; 32]),
            &mut rng,
        );
        std::fs::write(golden_path, &bytes[..]).expect("failed to write golden fixture");
        bytes.to_vec()
    };

    let generated = build_test_hello();

    let parsed_golden = parse_client_hello(&golden).expect("golden ClientHello must parse");

    let parsed_generated =
        parse_client_hello(&generated).expect("generated ClientHello must parse");

    assert_eq!(
        ja3_string(&parsed_generated),
        ja3_string(&parsed_golden),
        "JA3 mismatch against golden capture"
    );

    let golden_ext_order: Vec<u16> = parsed_golden
        .extensions
        .iter()
        .map(|e| e.ext_type)
        .filter(|v| !is_grease_u16(*v))
        .collect();

    let generated_ext_order: Vec<u16> = parsed_generated
        .extensions
        .iter()
        .map(|e| e.ext_type)
        .filter(|v| !is_grease_u16(*v))
        .collect();

    assert_eq!(
        generated_ext_order, golden_ext_order,
        "extension order mismatch against golden capture"
    );

    let golden_ciphers: Vec<u16> = parsed_golden
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease_u16(*v))
        .collect();

    let generated_ciphers: Vec<u16> = parsed_generated
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease_u16(*v))
        .collect();

    assert_eq!(
        generated_ciphers, golden_ciphers,
        "cipher suite order mismatch against golden capture"
    );

    let golden_groups: Vec<u16> = extract_supported_groups(&parsed_golden)
        .unwrap()
        .into_iter()
        .filter(|v| !is_grease_u16(*v))
        .collect();

    let generated_groups: Vec<u16> = extract_supported_groups(&parsed_generated)
        .unwrap()
        .into_iter()
        .filter(|v| !is_grease_u16(*v))
        .collect();

    assert_eq!(
        generated_groups, golden_groups,
        "supported_groups mismatch against golden capture"
    );
}

#[test]
fn unsupported_extension_must_not_be_silently_omitted() {
    let mut profile = FingerprintProfile::chrome_131();

    let unsupported_ext = 0x1234;
    profile.extensions.insert(3, unsupported_ext);

    let builder = ClientHelloBuilder::new(profile);

    let mut rng = rand::rngs::SmallRng::seed_from_u64(42);

    let hello = builder.build(
        "example.com",
        &[0x11; 32],
        &[0x22; 32],
        Some(&[0x33; 32]),
        &mut rng,
    );

    let parsed = parse_client_hello(&hello).unwrap();

    let ext_ids: Vec<u16> = parsed.extensions.iter().map(|e| e.ext_type).collect();

    assert!(
        ext_ids.contains(&unsupported_ext),
        "extension {unsupported_ext:#06x} was silently omitted — unknown extensions must be passed through as empty bodies"
    );
}
