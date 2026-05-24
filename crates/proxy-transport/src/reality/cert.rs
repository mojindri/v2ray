//! REALITY temporary TLS certificate (ed25519 + HMAC-SHA512 signature).
//!
//! Xray/sing-box clients verify `Signature == HMAC-SHA512(auth_key, ed25519_public_key)`
//! instead of a normal PKIX chain.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::Sha512;
use x509_parser::prelude::*;

use proxy_common::ProxyError;

struct CertTemplate {
    key_pem: String,
    verifying_key: [u8; 32],
    cert_der: Vec<u8>,
    /// Byte range in `cert_der` covering the BIT STRING signature value (64 bytes).
    signature_range: std::ops::Range<usize>,
}

fn cert_cache() -> &'static Mutex<HashMap<String, CertTemplate>> {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<String, CertTemplate>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Build PEM cert/key for the post-REALITY TLS handshake.
pub fn tls_pem_for_auth_key(auth_key: &[u8; 32], cover_sni: &str) -> Result<(String, String), ProxyError> {
    let sni = if cover_sni.is_empty() {
        "localhost"
    } else {
        cover_sni
    };
    let template = get_template(sni)?;

    let mut mac = Hmac::<Sha512>::new_from_slice(auth_key)
        .map_err(|e| ProxyError::Tls(format!("REALITY HMAC key: {e}")))?;
    mac.update(&template.verifying_key);
    let signature: [u8; 64] = mac.finalize().into_bytes().into();

    let mut cert_der = template.cert_der;
    if template.signature_range.len() != 64 {
        return Err(ProxyError::Tls(
            "REALITY cert template signature range invalid".into(),
        ));
    }
    cert_der[template.signature_range.clone()].copy_from_slice(&signature);

    Ok((der_to_pem("CERTIFICATE", &cert_der), template.key_pem))
}

fn get_template(sni: &str) -> Result<CertTemplate, ProxyError> {
    let mut cache = cert_cache()
        .lock()
        .map_err(|_| ProxyError::Tls("REALITY cert cache lock poisoned".into()))?;

    if let Some(t) = cache.get(sni) {
        return Ok(CertTemplate {
            key_pem: t.key_pem.clone(),
            verifying_key: t.verifying_key,
            cert_der: t.cert_der.clone(),
            signature_range: t.signature_range.clone(),
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

    let params = CertificateParams::new(vec![sni.to_string()])
        .map_err(|e| ProxyError::Tls(format!("REALITY cert params: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ProxyError::Tls(format!("REALITY cert sign: {e}")))?;
    let cert_der = cert.der().to_vec();
    let signature_range = find_ed25519_signature_range(&cert_der)?;

    let template = CertTemplate {
        key_pem: key_pair.serialize_pem(),
        verifying_key,
        cert_der: cert_der.clone(),
        signature_range: signature_range.clone(),
    };
    cache.insert(sni.to_string(), template);
    Ok(CertTemplate {
        key_pem: cache.get(sni).unwrap().key_pem.clone(),
        verifying_key,
        cert_der,
        signature_range,
    })
}

fn find_ed25519_signature_range(der: &[u8]) -> Result<std::ops::Range<usize>, ProxyError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| ProxyError::Tls(format!("REALITY cert parse: {e}")))?;
    let sig = cert.signature_value.data;
    let sig_bytes = sig
        .get(sig.len().saturating_sub(64)..)
        .filter(|s| s.len() == 64)
        .ok_or_else(|| {
            ProxyError::Tls(format!(
                "REALITY cert signature BIT STRING length {}, want >= 64",
                sig.len()
            ))
        })?;
    let start = der
        .windows(64)
        .position(|window| window == sig_bytes)
        .ok_or_else(|| ProxyError::Tls("REALITY cert signature offset not found in DER".into()))?;
    Ok(start..start + 64)
}

fn der_to_pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_range_points_at_hmac_input() {
        let auth_a = [1u8; 32];
        let auth_b = [2u8; 32];
        let (pem_a, _) = tls_pem_for_auth_key(&auth_a, "www.example.com").unwrap();
        let (pem_b, _) = tls_pem_for_auth_key(&auth_b, "www.example.com").unwrap();
        assert_ne!(pem_a, pem_b);
    }
}
