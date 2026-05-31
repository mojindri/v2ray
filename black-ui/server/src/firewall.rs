use std::collections::BTreeSet;
use std::process::Command;

use anyhow::{anyhow, Result};

use crate::{db, models::Inbound, state::AppState};

pub fn sync_enabled_inbounds(state: &AppState) -> Result<String> {
    if !cfg!(target_os = "linux") {
        return Ok("firewall sync skipped: supported on Linux only".into());
    }
    if Command::new("ufw").arg("status").output().is_err() {
        return Ok("firewall sync skipped: ufw not installed".into());
    }

    let inbounds = {
        let conn = state.db.lock().unwrap();
        db::load_inbounds(&conn)?
    };
    let rules = firewall_rules(&inbounds);
    if rules.is_empty() {
        return Ok("firewall sync: no public enabled inbound ports to open".into());
    }

    let mut opened = Vec::with_capacity(rules.len());
    for rule in rules {
        let output = Command::new("ufw")
            .args(["allow", &rule])
            .output()
            .map_err(|e| anyhow!("failed to run ufw allow {rule}: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("ufw allow {rule} failed: {}", stderr.trim()));
        }
        opened.push(rule);
    }
    Ok(format!(
        "firewall sync opened/confirmed {}",
        opened.join(", ")
    ))
}

fn firewall_rules(inbounds: &[Inbound]) -> Vec<String> {
    let mut rules = BTreeSet::new();
    for inbound in inbounds {
        if !inbound.enabled || is_local_listen(&inbound.listen) {
            continue;
        }
        rules.insert(format!("{}/{}", inbound.port, inbound_protocol(inbound)));
    }
    rules.into_iter().collect()
}

fn is_local_listen(listen: &str) -> bool {
    let listen = listen.trim().trim_matches(['[', ']']);
    listen == "localhost" || listen == "::1" || listen.starts_with("127.")
}

fn inbound_protocol(inbound: &Inbound) -> &'static str {
    if inbound.protocol == "hysteria2" || inbound.transport == "quic" {
        "udp"
    } else {
        "tcp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound(tag: &str, listen: &str, port: u16, protocol: &str, transport: &str) -> Inbound {
        Inbound {
            id: i64::from(port),
            tag: tag.into(),
            listen: listen.into(),
            port,
            protocol: protocol.into(),
            enabled: true,
            transport: transport.into(),
            settings: "{}".into(),
            stream_settings: String::new(),
            sniffing: String::new(),
            limits: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn firewall_rules_skip_localhost_and_deduplicate() {
        let rules = firewall_rules(&[
            inbound("local", "127.0.0.1", 18080, "socks", "tcp"),
            inbound("public-a", "0.0.0.0", 443, "vless", "tcp"),
            inbound("public-b", "::", 443, "vless", "tcp"),
        ]);
        assert_eq!(rules, vec!["443/tcp"]);
    }

    #[test]
    fn firewall_rules_use_udp_for_udp_transports() {
        let rules = firewall_rules(&[
            inbound("hy2", "0.0.0.0", 4433, "hysteria2", "udp"),
            inbound("quic", "0.0.0.0", 8447, "vless", "quic"),
        ]);
        assert_eq!(rules, vec!["4433/udp", "8447/udp"]);
    }
}
