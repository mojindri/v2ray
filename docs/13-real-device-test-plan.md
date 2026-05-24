# Real-device test plan

CI cannot replace real devices. Carrier NAT, mobile radio sleep/wake, client-app behavior, and OS proxy/VPN APIs produce failures that Docker and VPSes will not show.

## Minimum device matrix

| Device | Network | Client path | Required protocols |
|---|---|---|---|
| Android | Mobile data | Termux/curl or Android proxy client | VLESS REALITY, Trojan TLS, SS2022 |
| iPhone | Mobile data | iOS proxy/VPN client | VLESS/Trojan where supported |
| Laptop | Phone tether | browser + curl through SOCKS | VLESS TCP/WS, VMess gRPC |
| Windows | Home ISP | v2rayN/sing-box | Xray/sing-box interop |
| Linux | Home ISP | curl/sing-box | all supported paths |

## Required checks

For each row:

1. Confirm the direct public IP.
2. Connect through the proxy.
3. Confirm proxied public IP.
4. Fetch an HTTP endpoint.
5. Fetch an HTTPS endpoint.
6. Run a 2-minute download.
7. Toggle network and confirm reconnect.
8. Reload config and confirm existing/new connections behave as expected.
9. Try wrong credentials and confirm rejection.
10. Review logs for secret leakage.

Use `make -C labs/realistic real-devices` to create a report template under
`labs/realistic/reports/production/`.
