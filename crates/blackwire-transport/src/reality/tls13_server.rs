//! TLS 1.3 server handshake for REALITY Phase 3 (post-auth camouflage).

use ed25519_dalek::{Signer, SigningKey};
use rand::RngExt;
use x25519_dalek::{PublicKey, StaticSecret};

use blackwire_common::{BoxedStream, ProxyError};
use tokio::io::AsyncWriteExt;

use super::{
    decrypt_app_record, derive_app_keys, derive_handshake_keys, encrypt_app_record,
    read_record_stream, split_handshake_messages, write_handshake_record, AppKeys, CipherSuite,
    HsKeys, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO, HS_ENCRYPTED_EXTENSIONS,
    HS_FINISHED, HS_SERVER_HELLO, RT_ALERT, RT_APPLICATION_DATA, RT_CHANGE_CIPHER_SPEC,
    RT_HANDSHAKE,
};

const SIG_ED25519: u16 = 0x0807;
// Must match Go TLS `serverSignatureContext`; Xray/sing-box verify this with uTLS.
const TLS13_SERVER_CERT_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\x00";

/// Complete TLS 1.3 as server after REALITY auth.
pub async fn complete_tls13_server_handshake(
    stream: &mut BoxedStream,
    auth_key: &[u8; 32],
    cover_sni: &str,
) -> Result<AppKeys, ProxyError> {
    let (ch_header, ch_body) = read_record_stream(stream).await?;
    if ch_header[0] != RT_HANDSHAKE || ch_body.first() != Some(&HS_CLIENT_HELLO) {
        return Err(ProxyError::Protocol(
            "REALITY server TLS: expected ClientHello record".into(),
        ));
    }

    let cs = pick_cipher_suite(&ch_body)?;
    let client_share = crate::reality::parse_client_hello(&ch_body)
        .map_err(|e| ProxyError::Protocol(e.to_string()))?
        .x25519_key_share;
    // External clients (sing-box) strip ML-KEM shares; use the standard cert template.
    let (cert_der, signing_key) =
        crate::reality::cert::tls_cert_for_auth_key(auth_key, cover_sni, false)?;
    crate::reality::cert::verify_reality_cert_hmac(auth_key, &cert_der)
        .map_err(|e| ProxyError::Tls(format!("REALITY cert self-check before send: {e}")))?;

    let server_tls_secret = StaticSecret::random();
    let server_tls_pub = PublicKey::from(&server_tls_secret);
    let server_pub_bytes = *server_tls_pub.as_bytes();

    let mut transcript = ch_body.clone();

    let session_id = parse_client_session_id(&ch_body)?;
    let sh_body = build_server_hello(cs, &server_pub_bytes, session_id);
    stream.write_all(&write_handshake_record(&sh_body)).await?;
    transcript.extend_from_slice(&sh_body);
    let client_tls_pub = PublicKey::from(client_share);
    let tls_dhe = server_tls_secret
        .diffie_hellman(&client_tls_pub)
        .as_bytes()
        .to_vec();
    let tls_dhe: [u8; 32] = tls_dhe
        .try_into()
        .map_err(|_| ProxyError::Protocol("TLS DHE secret length mismatch".into()))?;

    let transcript_hash_after_sh = cs.hash(&transcript);
    let hs_keys = derive_handshake_keys(cs, &tls_dhe, &transcript_hash_after_sh)?;

    // uTLS / BoringSSL peers often expect a legacy CCS before TLS 1.3 encrypted flights.
    stream
        .write_all(&[RT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01])
        .await?;

    let mut srv_seq: u64 = 0;
    let ee_msg = build_encrypted_extensions();
    transcript.extend_from_slice(&ee_msg);
    write_encrypted_hs(stream, cs, &hs_keys, &mut srv_seq, &ee_msg).await?;

    let cert_msg = build_certificate(&cert_der);
    transcript.extend_from_slice(&cert_msg);
    write_encrypted_hs(stream, cs, &hs_keys, &mut srv_seq, &cert_msg).await?;

    let cv_msg = build_certificate_verify(cs, &signing_key, &transcript)?;
    transcript.extend_from_slice(&cv_msg);
    write_encrypted_hs(stream, cs, &hs_keys, &mut srv_seq, &cv_msg).await?;

    let finished_hash = cs.hash(&transcript);
    let server_finished_data = cs.hmac(&hs_keys.server_finished_key, &finished_hash)?;
    let finished_msg = build_finished(server_finished_data);
    transcript.extend_from_slice(&finished_msg);
    write_encrypted_hs(stream, cs, &hs_keys, &mut srv_seq, &finished_msg).await?;

    let app_transcript_hash = cs.hash(&transcript);
    let app_keys = derive_app_keys(cs, &hs_keys.master_secret, &app_transcript_hash)?;

    read_client_finished(stream, cs, &hs_keys, &app_transcript_hash).await?;

    Ok(app_keys)
}

async fn write_encrypted_hs(
    stream: &mut BoxedStream,
    cs: CipherSuite,
    hs_keys: &HsKeys,
    seq: &mut u64,
    hs_msg: &[u8],
) -> Result<(), ProxyError> {
    let record = encrypt_app_record(
        cs,
        &hs_keys.server_key,
        &hs_keys.server_iv,
        *seq,
        hs_msg,
        RT_HANDSHAKE,
    )?;
    *seq += 1;
    stream.write_all(&record).await?;
    Ok(())
}

async fn read_client_finished(
    stream: &mut BoxedStream,
    cs: CipherSuite,
    hs_keys: &HsKeys,
    app_transcript_hash: &[u8],
) -> Result<(), ProxyError> {
    let mut cli_seq: u64 = 0;
    loop {
        let (rec_header, rec_body) = read_record_stream(stream).await?;
        match rec_header[0] {
            RT_CHANGE_CIPHER_SPEC => continue,
            RT_ALERT => {
                let desc = rec_body.get(1).copied().unwrap_or(0);
                return Err(ProxyError::Protocol(format!(
                    "TLS alert from client during handshake: desc={desc}"
                )));
            }
            RT_APPLICATION_DATA => {
                let (inner, inner_type) = decrypt_app_record(
                    cs,
                    &hs_keys.client_key,
                    &hs_keys.client_iv,
                    cli_seq,
                    &rec_body,
                    rec_header,
                )?;
                cli_seq += 1;
                if inner_type != RT_HANDSHAKE {
                    continue;
                }
                for (hs_type, msg_bytes) in split_handshake_messages(&inner) {
                    if hs_type == HS_FINISHED {
                        let body_start = 4;
                        let verify_data = &msg_bytes[body_start..];
                        let expected =
                            cs.hmac(&hs_keys.client_finished_key, app_transcript_hash)?;
                        if verify_data != expected.as_slice() {
                            return Err(ProxyError::Protocol(
                                "client Finished HMAC mismatch".into(),
                            ));
                        }
                        return Ok(());
                    }
                }
            }
            other => {
                return Err(ProxyError::Protocol(format!(
                    "unexpected TLS record 0x{other:02x} waiting for client Finished"
                )));
            }
        }
    }
}

fn pick_cipher_suite(ch_body: &[u8]) -> Result<CipherSuite, ProxyError> {
    let list = crate::reality::parser::client_hello_cipher_suites(ch_body)?;
    for prefer in [0x1301u16, 0x1302] {
        for chunk in list.chunks_exact(2) {
            if u16::from_be_bytes([chunk[0], chunk[1]]) == prefer {
                return CipherSuite::from_u16(prefer);
            }
        }
    }
    Err(ProxyError::Protocol(
        "ClientHello offers no supported TLS 1.3 cipher suite".into(),
    ))
}

fn parse_client_session_id(ch_body: &[u8]) -> Result<&[u8], ProxyError> {
    crate::reality::parser::client_hello_session_id(ch_body)
}

fn build_server_hello(cs: CipherSuite, server_pub: &[u8; 32], session_id: &[u8]) -> Vec<u8> {
    let mut random = [0u8; 32];
    rand::rng().fill(&mut random[..]);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x24]);
    extensions.extend_from_slice(&29u16.to_be_bytes());
    extensions.extend_from_slice(&32u16.to_be_bytes());
    extensions.extend_from_slice(server_pub);

    let body_len = 2 + 32 + 1 + session_id.len() + 2 + 1 + 2 + extensions.len();
    let mut body = Vec::with_capacity(4 + body_len);
    body.push(HS_SERVER_HELLO);
    body.push((body_len >> 16) as u8);
    body.push((body_len >> 8) as u8);
    body.push(body_len as u8);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cs.to_u16().to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    body
}

fn build_encrypted_extensions() -> Vec<u8> {
    let body_len = 2u32;
    vec![
        HS_ENCRYPTED_EXTENSIONS,
        (body_len >> 16) as u8,
        (body_len >> 8) as u8,
        body_len as u8,
        0,
        0,
    ]
}

fn build_certificate(cert_der: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(3 + cert_der.len() + 2);
    let elen = cert_der.len();
    entry.push((elen >> 16) as u8);
    entry.push((elen >> 8) as u8);
    entry.push(elen as u8);
    entry.extend_from_slice(cert_der);
    entry.extend_from_slice(&[0x00, 0x00]);

    let mut cert_list = Vec::with_capacity(3 + entry.len());
    let list_len = entry.len();
    cert_list.push((list_len >> 16) as u8);
    cert_list.push((list_len >> 8) as u8);
    cert_list.push(list_len as u8);
    cert_list.extend_from_slice(&entry);

    let payload_len = 1 + cert_list.len();
    let mut msg = Vec::with_capacity(4 + payload_len);
    msg.push(HS_CERTIFICATE);
    msg.push((payload_len >> 16) as u8);
    msg.push((payload_len >> 8) as u8);
    msg.push(payload_len as u8);
    msg.push(0);
    msg.extend_from_slice(&cert_list);
    msg
}

fn build_certificate_verify(
    cs: CipherSuite,
    signing_key: &SigningKey,
    transcript: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    let mut content = vec![0x20u8; 64];
    content.extend_from_slice(TLS13_SERVER_CERT_VERIFY_CONTEXT);
    content.extend_from_slice(&cs.hash(transcript));

    let signature = signing_key.sign(&content);
    let sig_bytes = signature.to_bytes();

    let payload_len = 2 + 2 + sig_bytes.len();
    let mut msg = Vec::with_capacity(4 + payload_len);
    msg.push(HS_CERTIFICATE_VERIFY);
    msg.push((payload_len >> 16) as u8);
    msg.push((payload_len >> 8) as u8);
    msg.push(payload_len as u8);
    msg.extend_from_slice(&SIG_ED25519.to_be_bytes());
    msg.extend_from_slice(&(sig_bytes.len() as u16).to_be_bytes());
    msg.extend_from_slice(&sig_bytes);
    Ok(msg)
}

fn build_finished(verify_data: Vec<u8>) -> Vec<u8> {
    let vd_len = verify_data.len() as u32;
    let mut msg = Vec::with_capacity(4 + verify_data.len());
    msg.push(HS_FINISHED);
    msg.push((vd_len >> 16) as u8);
    msg.push((vd_len >> 8) as u8);
    msg.push(vd_len as u8);
    msg.extend_from_slice(&verify_data);
    msg
}

#[cfg(test)]
mod tests {
    use super::super::parse_server_hello;
    use super::build_server_hello;
    use super::complete_tls13_server_handshake;
    use super::CipherSuite;
    use crate::reality::parse_client_hello;
    use crate::Tls13Stream;

    #[test]
    fn client_hello_key_share_matches_builder() {
        use blackwire_tls::ClientHelloBuilder;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random();
        let pub_key = *PublicKey::from(&secret).as_bytes();
        let random = [7u8; 32];
        let session_id = [0u8; 32];
        let mut rng = rand::rng();
        let hello = ClientHelloBuilder::chrome_131().build_with_additional_key_share(
            "www.example.com",
            &random,
            &session_id,
            Some(&pub_key),
            None,
            &mut rng,
        );
        let fields = parse_client_hello(&hello[5..]).unwrap();
        assert_eq!(fields.x25519_key_share, pub_key);
    }

    #[test]
    fn encrypted_extensions_record_roundtrips() {
        use super::super::{decrypt_app_record, derive_handshake_keys, encrypt_app_record};

        let dhe = [1u8; 32];
        let th = [2u8; 32];
        let hs = derive_handshake_keys(CipherSuite::Aes128GcmSha256, &dhe, &th).unwrap();
        let ee = build_encrypted_extensions();
        let record = encrypt_app_record(
            CipherSuite::Aes128GcmSha256,
            &hs.server_key,
            &hs.server_iv,
            0,
            &ee,
            RT_HANDSHAKE,
        )
        .unwrap();
        let header: [u8; 5] = record[..5].try_into().unwrap();
        let (plain, ty) = decrypt_app_record(
            CipherSuite::Aes128GcmSha256,
            &hs.server_key,
            &hs.server_iv,
            0,
            &record[5..],
            header,
        )
        .unwrap();
        assert_eq!(plain, ee);
        assert_eq!(ty, RT_HANDSHAKE);
    }

    #[test]
    fn handshake_traffic_keys_match_manual() {
        use super::super::{derive_handshake_keys, parse_server_hello};
        use blackwire_tls::ClientHelloBuilder;
        use x25519_dalek::{PublicKey, StaticSecret};

        let client_secret = StaticSecret::random();
        let client_pub = *PublicKey::from(&client_secret).as_bytes();
        let server_secret = StaticSecret::random();
        let server_pub = *PublicKey::from(&server_secret).as_bytes();

        let mut rng = rand::rng();
        let hello = ClientHelloBuilder::chrome_131().build_with_additional_key_share(
            "www.example.com",
            &[1u8; 32],
            &[0u8; 32],
            Some(&client_pub),
            None,
            &mut rng,
        );
        let ch_body = hello[5..].to_vec();
        let sh_body = build_server_hello(CipherSuite::Aes128GcmSha256, &server_pub, &[0u8; 32]);

        let parsed_client = parse_client_hello(&ch_body).unwrap();
        let (_cs, _g, parsed_server_pub) = parse_server_hello(&sh_body).unwrap();
        assert_eq!(parsed_server_pub.as_slice(), server_pub);

        let mut server_pub_arr = [0u8; 32];
        server_pub_arr.copy_from_slice(&parsed_server_pub);
        let dhe_c = client_secret
            .diffie_hellman(&PublicKey::from(server_pub_arr))
            .as_bytes()
            .to_vec();
        let dhe_s = server_secret
            .diffie_hellman(&PublicKey::from(parsed_client.x25519_key_share))
            .as_bytes()
            .to_vec();
        assert_eq!(dhe_c, dhe_s);

        let mut transcript = ch_body;
        transcript.extend_from_slice(&sh_body);
        let th = CipherSuite::Aes128GcmSha256.hash(&transcript);
        let dhe: [u8; 32] = dhe_c.try_into().unwrap();
        let client_keys = derive_handshake_keys(CipherSuite::Aes128GcmSha256, &dhe, &th).unwrap();
        let server_keys = derive_handshake_keys(CipherSuite::Aes128GcmSha256, &dhe, &th).unwrap();
        assert_eq!(client_keys.server_key, server_keys.server_key);
        assert_eq!(client_keys.client_key, server_keys.client_key);
    }

    #[test]
    fn server_hello_parses_like_client() {
        let pub_key = [0xABu8; 32];
        let sh = build_server_hello(CipherSuite::Aes128GcmSha256, &pub_key, &[0u8; 32]);
        let (cs, group, key) = parse_server_hello(&sh).unwrap();
        assert_eq!(cs, CipherSuite::Aes128GcmSha256);
        assert_eq!(group, 29);
        assert_eq!(key.as_slice(), pub_key);
    }

    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;
    use crate::reality::{RealityClient, RealityClientConfig, RealityServer, RealityServerConfig};

    #[tokio::test]
    async fn self_client_server_tls13_roundtrip() {
        let priv_bytes =
            hex::decode("8cb13706aa547712de8f687dc32e66b0ec2e753ba310e734b72fb52ce5e6a4a8")
                .unwrap()
                .try_into()
                .unwrap();
        let pub_bytes =
            hex::decode("bbf29cec98e1aff519fcd09456d90407804f91ae62be4b8aac48f6d676807865")
                .unwrap()
                .try_into()
                .unwrap();
        let short_id = hex::decode("0123456789abcdef").unwrap();
        let fallback = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Arc::new(RealityServer::new(RealityServerConfig {
            private_key: priv_bytes,
            short_ids: vec![short_id.clone()],
            fallback,
            max_time_diff: 120,
        }));

        let (tx, rx) = oneshot::channel();
        let srv = server.clone();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let accepted = srv.accept_with_key(Box::new(tcp)).await.unwrap();
            let mut stream = accepted.stream;
            let keys =
                complete_tls13_server_handshake(&mut stream, &accepted.auth_key, "www.example.com")
                    .await
                    .unwrap();
            let mut tls = Tls13Stream::new_server(stream, keys);
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
            let _ = tx.send(());
        });

        let client = RealityClient::new(RealityClientConfig {
            server: addr,
            server_public_key: pub_bytes,
            short_id,
            sni: "www.example.com".to_string(),
            fingerprint: "chrome".to_string(),
        });
        let mut stream = client.dial().await.expect("client dial");
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        rx.await.unwrap();
    }

    /// sing-box seals with plaintext in `session_id` + `hello.Raw` AAD (not zeroed).
    #[tokio::test]
    async fn singbox_style_seal_auth_and_tls_roundtrip() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use blackwire_tls::ClientHelloBuilder;
        use hkdf::Hkdf;
        use sha2::Sha256;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;
        use x25519_dalek::{PublicKey, StaticSecret};

        use super::super::complete_tls13_handshake;
        use crate::reality::{REALITY_HKDF_INFO, SESSION_ID_OFFSET_IN_HANDSHAKE_BODY};
        use crate::{RealityServer, RealityServerConfig, Tls13Stream};

        let server_secret = StaticSecret::random();
        let client_secret = StaticSecret::random();
        let client_pub = *PublicKey::from(&client_secret).as_bytes();

        let shared = server_secret
            .diffie_hellman(&PublicKey::from(client_pub))
            .as_bytes()
            .to_vec();
        let mut auth_key = [0u8; 32];
        auth_key.copy_from_slice(shared.as_slice());

        let mut random = [0u8; 32];
        rand::rng().fill(&mut random[..]);
        let hk = Hkdf::<Sha256>::new(Some(&random[..20]), &auth_key);
        hk.expand(REALITY_HKDF_INFO, &mut auth_key).unwrap();

        let short_id = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut session_id = [0u8; 32];
        session_id[0] = 1;
        session_id[1] = 8;
        session_id[2] = 1;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        session_id[4..8].copy_from_slice(&ts.to_be_bytes());
        session_id[8..16].copy_from_slice(&short_id);

        let mut rng = rand::rng();
        let hello_bytes = ClientHelloBuilder::chrome_131().build_with_additional_key_share(
            "www.microsoft.com",
            &random,
            &[0u8; 32],
            Some(&client_pub),
            None,
            &mut rng,
        );
        let hs_body = &hello_bytes[5..];
        // Xray/sing-box: hello.Raw session_id is zero at Seal time; plaintext is SessionId only.
        let aad = hs_body.to_vec();
        let sid = SESSION_ID_OFFSET_IN_HANDSHAKE_BODY;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&auth_key));
        let nonce = Nonce::from_slice(&random[20..32]);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &session_id[..16],
                    aad: &aad,
                },
            )
            .unwrap();
        let mut wire_hello = hello_bytes;
        wire_hello[5 + sid..5 + sid + 32].copy_from_slice(&ct);

        let priv_bytes = *server_secret.as_bytes();
        let fallback = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Arc::new(RealityServer::new(RealityServerConfig {
            private_key: priv_bytes,
            short_ids: vec![short_id.clone()],
            fallback,
            max_time_diff: 120,
        }));

        let (tx, rx) = oneshot::channel();
        let srv = server.clone();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let accepted = srv.accept_with_key(Box::new(tcp)).await.unwrap();
            let mut stream = accepted.stream;
            let keys = complete_tls13_server_handshake(
                &mut stream,
                &accepted.auth_key,
                "www.microsoft.com",
            )
            .await
            .unwrap();
            let mut tls = Tls13Stream::new_server(stream, keys);
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
            let _ = tx.send(());
        });

        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(&wire_hello).await.unwrap();
        let hs_body = &wire_hello[5..];
        let keys = complete_tls13_handshake(&mut tcp, hs_body, &client_secret, None, &auth_key)
            .await
            .expect("client TLS with sing-box-style auth");
        let mut tls = Tls13Stream::new(Box::new(tcp), keys);
        tls.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        tls.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        rx.await.unwrap();
    }
}
