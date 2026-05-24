# Two-VPS Realism Gate

Target:

- Ubuntu 24.04 on both hosts.
- Native `systemd` services for `blackwire`.
- Real DNS name for TLS/SNI-facing tests.
- Caddy owns ACME certificate issuance.

## Host Roles

Client VPS:

- runs client-side `blackwire`
- exposes SOCKS/HTTP only on localhost
- runs traffic checks

Server VPS:

- runs server-side `blackwire`
- exposes protocol ports publicly
- runs Caddy for ACME
- runs deterministic HTTP/TCP targets for controlled tests

## Server Setup Sketch

```sh
sudo apt-get update
sudo apt-get install -y curl ca-certificates build-essential pkg-config libssl-dev caddy ufw
sudo useradd --system --home /var/lib/blackwire --shell /usr/sbin/nologin blackwire || true
sudo mkdir -p /etc/blackwire /etc/blackwire/certs /var/lib/blackwire
sudo chown -R blackwire:blackwire /var/lib/blackwire
```

Build or install `blackwire`, then place it at:

```text
/usr/local/bin/blackwire
```

## Caddy ACME

Point DNS for your test domain to the server VPS, then configure Caddy to obtain
certificates. `blackwire` still terminates TLS for Trojan/TLS scenarios, so copy
or sync cert/key material into `/etc/blackwire/certs/` with permissions readable
by the `blackwire` user.

Do not use self-signed certs for the production-realism gate unless you are
testing an explicit insecure/dev path.

## Systemd

Use the service templates in this directory:

- [blackwire-client.service](blackwire-client.service)
- [blackwire-server.service](blackwire-server.service)

Install example:

```sh
sudo cp blackwire-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now blackwire-server
sudo journalctl -u blackwire-server -f
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
