#!/usr/bin/env bash
set -euo pipefail
REPORT_DIR="${1:-reports/production}"
mkdir -p "$REPORT_DIR"
OUT="$REPORT_DIR/real-device-test-template-$(date -u +%Y%m%dT%H%M%SZ).md"
cat > "$OUT" <<'MARKDOWN'
# Real-device test report

## Device/network matrix

| Date | Device | OS | Client app | Network | Carrier/ISP | Protocol | Result | Notes |
|---|---|---|---|---|---|---|---|---|
| | Android | | Termux/curl or app | mobile data | | vless-reality | | |
| | iPhone | | app/profile | mobile data | | trojan-tls | | |
| | Laptop | | curl/browser | phone tether | | vmess-grpc | | |
| | Windows | | v2rayN/sing-box | home ISP | | ss2022 | | |

## Minimum checks

- Public IP before/after proxy.
- HTTP fetch through proxy.
- HTTPS fetch through proxy.
- Large download for at least 2 minutes.
- DNS lookup path: direct DNS vs proxy DNS vs FakeIP.
- Reconnect after network toggle airplane mode/off-on.
- Config reload while device is connected.
- Wrong password/UUID rejected.
- Logs contain no secrets.

## Commands

Android Termux example:

```sh
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
curl -x socks5h://127.0.0.1:1080 https://example.com -I
```
MARKDOWN
cat "$OUT"
echo "Wrote $OUT"
