# REALITY fixtures

`singbox-chrome-hello.bin` is a TLS ClientHello handshake body captured from sing-box 1.13.x using Chrome fingerprint against the lab matrix REALITY keys.

It is used to verify REALITY auth-key derivation and certificate HMAC behavior. Tests using this fixture intentionally disable normal timestamp freshness because the capture is static.
