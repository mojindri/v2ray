# REALITY interop notes

## Source of truth

- Xray REALITY client: [XTLS/Xray-core `transport/internet/reality/reality.go`](https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go)
- sing-box REALITY client: [SagerNet/sing-box v1.13.12 `common/tls/reality_client.go`](https://github.com/SagerNet/sing-box/blob/v1.13.12/common/tls/reality_client.go)
- XTLS REALITY server: [XTLS/REALITY `tls.go`](https://github.com/XTLS/REALITY/blob/main/tls.go) and [`handshake_server_tls13.go`](https://github.com/XTLS/REALITY/blob/main/handshake_server_tls13.go)

## ClientHello auth

Clients seal the first 16 bytes of `SessionId` with AES-GCM using `hello.Raw` as AAD while the raw session-id slot is still zeroed.

## Auth key

`auth_key = HKDF-SHA256(shared_x25519, salt = client_random[..20], info = "REALITY")`

## Certificate HMAC

Server cert signature is replaced with:

`HMAC-SHA512(auth_key, ed25519_public_key)`

## TLS 1.3 CertificateVerify

Must sign:

`64 spaces || "TLS 1.3, server CertificateVerify\0" || transcript_hash`

## Validation

Preferred gate (Docker lab):

```sh
make -C labs/realistic interop-docker
# server-compat only:
make -C labs/realistic interop-server-docker
```

Expected summary:

```text
PASS xray-vless-reality
PASS sing-box-vless-reality
PASS negative-xray-vless-reality rejected
PASS negative-sing-box-vless-reality rejected
```
