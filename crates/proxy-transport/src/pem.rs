//! Minimal PEM block parser shared by TLS and QUIC loaders.

use proxy_common::ProxyError;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};

struct PemBlock {
    label: String,
    contents: Vec<u8>,
}

fn pem_blocks(pem: &str) -> Vec<PemBlock> {
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut label = String::new();
    let mut b64 = String::new();

    for line in pem.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            label = rest.trim_end_matches('-').trim_end_matches(' ').to_string();
            b64.clear();
            in_block = true;
        } else if line.starts_with("-----END ") {
            if in_block {
                if let Ok(bytes) = base64_decode(&b64) {
                    blocks.push(PemBlock {
                        label: label.clone(),
                        contents: bytes,
                    });
                }
            }
            in_block = false;
        } else if in_block {
            b64.push_str(line);
        }
    }
    blocks
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ProxyError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| ProxyError::Tls(format!("base64 decode failed: {e}")))
}

/// Parse PEM-encoded certificates into DER format.
pub fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let mut certs = Vec::new();
    for block in pem_blocks(pem) {
        if block.label == "CERTIFICATE" {
            certs.push(CertificateDer::from(block.contents));
        }
    }
    if certs.is_empty() {
        return Err(ProxyError::Tls("no CERTIFICATE blocks found in PEM".into()));
    }
    Ok(certs)
}

/// Parse a PEM-encoded private key into DER format.
pub fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>, ProxyError> {
    for block in pem_blocks(pem) {
        match block.label.as_str() {
            "PRIVATE KEY" => {
                return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    block.contents,
                )));
            }
            "RSA PRIVATE KEY" => {
                return Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
                    block.contents,
                )));
            }
            "EC PRIVATE KEY" => {
                return Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(block.contents)));
            }
            _ => {}
        }
    }
    Err(ProxyError::Tls("no private key block found in PEM".into()))
}

/// Parse cert + key PEM for QUIC/rustls setup (anyhow at call site if needed).
pub fn parse_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ProxyError> {
    let certs = parse_certs(cert_pem)?;
    let key = parse_private_key(key_pem)?;
    Ok((certs, key))
}
