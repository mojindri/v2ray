//! REALITY temporary TLS certificate (ed25519 + HMAC-SHA512 signature).
//!
//! Xray/sing-box clients verify `Signature == HMAC-SHA512(auth_key, ed25519_public_key)`
//! instead of a normal PKIX chain.

use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ED25519};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::Sha512;
use x509_parser::prelude::*;

use proxy_common::ProxyError;

#[derive(Clone)]
struct CertTemplate {
    key_pem: String,
    signing_key: SigningKey,
    verifying_key: [u8; 32],
    cert_der: Vec<u8>,
    signature_range: std::ops::Range<usize>,
}

fn cert_cache() -> &'static DashMap<String, Arc<CertTemplate>> {
    static CACHE: OnceLock<DashMap<String, Arc<CertTemplate>>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn cache_key(sni: &str, mlkem: bool) -> String {
    if mlkem {
        format!("{sni}:mlkem768")
    } else {
        sni.to_string()
    }
}

/// Patched DER cert and ed25519 signing key for the post-REALITY TLS handshake.
pub fn tls_cert_for_auth_key(
    auth_key: &[u8; 32],
    cover_sni: &str,
    mlkem_client: bool,
) -> Result<(Vec<u8>, SigningKey), ProxyError> {
    let sni = normalize_sni(cover_sni);
    let template = get_template(sni, mlkem_client)?;
    let cert_der = patch_cert_der(&template, auth_key)?;
    Ok((cert_der, template.signing_key))
}

/// Build PEM cert/key for the post-REALITY TLS handshake.
pub fn tls_pem_for_auth_key(
    auth_key: &[u8; 32],
    cover_sni: &str,
) -> Result<(String, String), ProxyError> {
    let sni = normalize_sni(cover_sni);
    let template = get_template(sni, false)?;
    let cert_der = patch_cert_der(&template, auth_key)?;
    Ok((der_to_pem("CERTIFICATE", &cert_der)?, template.key_pem))
}

fn normalize_sni(cover_sni: &str) -> &str {
    if cover_sni.is_empty() {
        "localhost"
    } else {
        cover_sni
    }
}

/// HMAC-SHA512(auth_key, ed25519_public_key) — what Xray/sing-box compare to `cert.Signature`.
pub fn reality_cert_hmac(
    auth_key: &[u8; 32],
    ed25519_public_key: &[u8; 32],
) -> Result<[u8; 64], ProxyError> {
    let mut mac = Hmac::<Sha512>::new_from_slice(auth_key)
        .map_err(|e| ProxyError::Tls(format!("REALITY HMAC key: {e}")))?;
    mac.update(ed25519_public_key);
    Ok(mac.finalize().into_bytes().into())
}

/// Verify a REALITY server certificate the same way Xray/sing-box do in `VerifyPeerCertificate`.
pub fn verify_reality_cert_hmac(auth_key: &[u8; 32], cert_der: &[u8]) -> Result<(), ProxyError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| ProxyError::Tls(format!("REALITY cert parse: {e}")))?;
    let pubkey = ed25519_public_key_from_cert(&cert)?;
    let expected = reality_cert_hmac(auth_key, &pubkey)?;
    if signature_matches_go_hmac(cert.signature_value.data.as_ref(), &expected) {
        Ok(())
    } else {
        Err(ProxyError::Tls(
            "REALITY cert signature does not match HMAC-SHA512(auth_key, public_key)".into(),
        ))
    }
}

/// Extract the leaf certificate DER from a TLS 1.3 `Certificate` handshake message body.
pub fn parse_certificate_message_der(msg: &[u8]) -> Result<Vec<u8>, ProxyError> {
    const HS_CERTIFICATE: u8 = 0x0b;
    if msg.first() != Some(&HS_CERTIFICATE) {
        return Err(ProxyError::Tls(
            "TLS Certificate message: bad handshake type".into(),
        ));
    }
    if msg.len() < 4 + 1 + 3 + 3 {
        return Err(ProxyError::Tls(
            "TLS Certificate message: truncated header".into(),
        ));
    }

    let mut pos = 4usize;
    let ctx_len = msg[pos] as usize;
    pos += 1;
    if pos + ctx_len + 3 > msg.len() {
        return Err(ProxyError::Tls(
            "TLS Certificate message: truncated context".into(),
        ));
    }
    pos += ctx_len;

    let list_len = read_u24(&msg[pos..pos + 3])?;
    pos += 3;
    if pos + list_len > msg.len() {
        return Err(ProxyError::Tls(
            "TLS Certificate message: certificate_list truncated".into(),
        ));
    }
    let list_end = pos + list_len;

    if pos + 3 > list_end {
        return Err(ProxyError::Tls(
            "TLS Certificate message: empty certificate_list".into(),
        ));
    }
    let cert_data_len = read_u24(&msg[pos..pos + 3])?;
    pos += 3;
    if pos + cert_data_len > list_end {
        return Err(ProxyError::Tls(
            "TLS Certificate message: cert_data truncated".into(),
        ));
    }
    Ok(msg[pos..pos + cert_data_len].to_vec())
}

fn read_u24(bytes: &[u8]) -> Result<usize, ProxyError> {
    if bytes.len() < 3 {
        return Err(ProxyError::Tls("TLS uint24: truncated".into()));
    }
    Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | (bytes[2] as usize))
}

fn ed25519_public_key_from_cert(cert: &X509Certificate<'_>) -> Result<[u8; 32], ProxyError> {
    if cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_string()
        != "1.3.101.112"
    {
        return Err(ProxyError::Tls(
            "REALITY cert: expected ed25519 subject public key".into(),
        ));
    }
    let key = cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    let raw: &[u8] = match key.len() {
        32 => key,
        33 if key[0] == 0 => &key[1..],
        n => {
            return Err(ProxyError::Tls(format!(
                "REALITY cert: unexpected ed25519 SPKI length {n}"
            )));
        }
    };
    raw.try_into()
        .map_err(|_| ProxyError::Tls("REALITY cert: ed25519 public key length mismatch".into()))
}

/// Bytes compared to HMAC in Go `crypto/x509` for ed25519 certificates.
fn signature_matches_go_hmac(signature_field: &[u8], hmac: &[u8; 64]) -> bool {
    match signature_field.len() {
        64 => signature_field == hmac,
        65 if signature_field.first() == Some(&0) => signature_field[1..] == *hmac,
        n if n > 64 => signature_field[n - 64..] == *hmac,
        _ => false,
    }
}

fn patch_cert_der(template: &CertTemplate, auth_key: &[u8; 32]) -> Result<Vec<u8>, ProxyError> {
    let signature = reality_cert_hmac(auth_key, &template.verifying_key)?;

    let mut cert_der = template.cert_der.clone();
    let range = go_reality_signature_range(&cert_der)?;
    cert_der[range].copy_from_slice(&signature);
    Ok(cert_der)
}

/// Last 64 bytes of the DER cert — where xtls/reality writes HMAC-SHA512.
fn go_reality_signature_range(der: &[u8]) -> Result<std::ops::Range<usize>, ProxyError> {
    if der.len() < 64 {
        return Err(ProxyError::Tls("REALITY cert DER too short".into()));
    }
    let start = der.len() - 64;
    Ok(start..der.len())
}

fn get_template(sni: &str, mlkem_client: bool) -> Result<CertTemplate, ProxyError> {
    let key = cache_key(sni, mlkem_client);
    if let Some(template) = cert_cache().get(&key) {
        return Ok(CertTemplate {
            key_pem: template.key_pem.clone(),
            signing_key: template.signing_key.clone(),
            verifying_key: template.verifying_key,
            cert_der: template.cert_der.clone(),
            signature_range: template.signature_range.clone(),
        });
    }

    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = *signing_key.verifying_key().as_bytes();
    let pkcs8 = signing_key
        .to_pkcs8_der()
        .map_err(|e| ProxyError::Tls(format!("REALITY PKCS#8: {e}")))?;
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
        &PKCS_ED25519,
    )
    .map_err(|e| ProxyError::Tls(format!("REALITY ed25519 key: {e}")))?;

    let mut params = CertificateParams::new(vec![sni.to_string()])
        .map_err(|e| ProxyError::Tls(format!("REALITY cert params: {e}")))?;
    if mlkem_client {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(&[0, 0], vec![0u8; 3309]));
    }
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ProxyError::Tls(format!("REALITY cert sign: {e}")))?;

    let cert_der = cert.der().to_vec();
    let signature_range = go_reality_signature_range(&cert_der)?;

    let template = Arc::new(CertTemplate {
        key_pem: key_pair.serialize_pem(),
        signing_key: signing_key.clone(),
        verifying_key,
        cert_der,
        signature_range,
    });
    Ok(cert_cache()
        .entry(key)
        .or_insert_with(|| Arc::clone(&template))
        .value()
        .as_ref()
        .clone())
}

fn der_to_pem(label: &str, der: &[u8]) -> Result<String, ProxyError> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // Base64 alphabet is ASCII; chunk boundaries cannot split a UTF-8 codepoint.
        pem.push_str(
            std::str::from_utf8(chunk)
                .map_err(|e| ProxyError::Tls(format!("REALITY cert PEM encoding: {e}")))?,
        );
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_patch_changes_cert_bytes() {
        let auth_a = [1u8; 32];
        let auth_b = [2u8; 32];
        let (pem_a, _) = tls_pem_for_auth_key(&auth_a, "www.example.com").unwrap();
        let (pem_b, _) = tls_pem_for_auth_key(&auth_b, "www.example.com").unwrap();
        assert_ne!(pem_a, pem_b);
    }

    #[test]
    fn patched_cert_signature_matches_sing_box_hmac() {
        let auth_key = [9u8; 32];
        let (der, _signing_key) =
            tls_cert_for_auth_key(&auth_key, "www.example.com", false).unwrap();
        verify_reality_cert_hmac(&auth_key, &der).expect("Go-style HMAC verify");
    }

    #[test]
    fn parse_certificate_message_roundtrip() {
        let auth_key = [4u8; 32];
        let (der, _) = tls_cert_for_auth_key(&auth_key, "www.microsoft.com", false).unwrap();
        let msg = tls13_certificate_message(&der);
        let parsed = parse_certificate_message_der(&msg).unwrap();
        assert_eq!(parsed, der);
        verify_reality_cert_hmac(&auth_key, &parsed).unwrap();
    }

    fn tls13_certificate_message(cert_der: &[u8]) -> Vec<u8> {
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
        msg.push(0x0b);
        msg.push((payload_len >> 16) as u8);
        msg.push((payload_len >> 8) as u8);
        msg.push(payload_len as u8);
        msg.push(0);
        msg.extend_from_slice(&cert_list);
        msg
    }

    #[test]
    fn patched_cert_signature_field_is_64_bytes_for_go_equal() {
        let auth = [6u8; 32];
        let (der, _) = tls_cert_for_auth_key(&auth, "www.microsoft.com", false).unwrap();
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        assert_eq!(
            cert.signature_value.data.len(),
            64,
            "Go bytes.Equal requires Signature len 64, got {}",
            cert.signature_value.data.len()
        );
        assert_eq!(&cert.signature_value.data[..], &der[der.len() - 64..]);
    }

    #[test]
    fn go_signature_range_is_last_64_der_bytes() {
        let auth = [5u8; 32];
        let (der, _) = tls_cert_for_auth_key(&auth, "www.microsoft.com", false).unwrap();
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let sig_tail = &cert.signature_value.data[cert.signature_value.data.len() - 64..];
        assert_eq!(sig_tail, &der[der.len() - 64..]);
    }

    #[test]
    fn mlkem_template_differs_from_standard() {
        let auth = [3u8; 32];
        let (std, _) = tls_cert_for_auth_key(&auth, "www.example.com", false).unwrap();
        let (ml, _) = tls_cert_for_auth_key(&auth, "www.example.com", true).unwrap();
        assert_ne!(std, ml);
    }
}
