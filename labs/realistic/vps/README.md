# Two-VPS Realism Gate

Target:

- Ubuntu 24.04 on both hosts.
- Native `systemd` services for `proxy-rs`.
- Real DNS name for TLS/SNI-facing tests.
- Caddy owns ACME certificate issuance.

## Host Roles

Client VPS:

- runs client-side `proxy-rs`
- exposes SOCKS/HTTP only on localhost
- runs traffic checks

Server VPS:

- runs server-side `proxy-rs`
- exposes protocol ports publicly
- runs Caddy for ACME
- runs deterministic HTTP/TCP targets for controlled tests

## Server Setup Sketch

```sh
sudo apt-get update
sudo apt-get install -y curl ca-certificates build-essential pkg-config libssl-dev caddy ufw
sudo useradd --system --home /var/lib/proxy-rs --shell /usr/sbin/nologin proxy-rs || true
sudo mkdir -p /etc/proxy-rs /etc/proxy-rs/certs /var/lib/proxy-rs
sudo chown -R proxy-rs:proxy-rs /var/lib/proxy-rs
```

Build or install `proxy-rs`, then place it at:

```text
/usr/local/bin/proxy-rs
```

## Caddy ACME

Point DNS for your test domain to the server VPS, then configure Caddy to obtain
certificates. `proxy-rs` still terminates TLS for Trojan/TLS scenarios, so copy
or sync cert/key material into `/etc/proxy-rs/certs/` with permissions readable
by the `proxy-rs` user.

Do not use self-signed certs for the production-realism gate unless you are
testing an explicit insecure/dev path.

## Systemd

Use the service templates in this directory:

- [proxy-rs-client.service](proxy-rs-client.service)
- [proxy-rs-server.service](proxy-rs-server.service)

Install example:

```sh
sudo cp proxy-rs-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-rs-server
sudo journalctl -u proxy-rs-server -f
```

## Firewall

Open only the protocol ports needed by the scenario under test.

Example:

```sh
sudo ufw allow OpenSSH
sudo ufw allow 443/tcp
sudo ufw allow 8443/tcp
sudo ufw allow 8443/udp
sudo ufw enable
```

## Promotion Rule

A feature becomes part of the mandatory VPS matrix only after it has:

1. local e2e coverage
2. Docker baseline coverage
3. a passing VPS scenario
