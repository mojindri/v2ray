use std::path::Path;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use validator::Validate;

use crate::{
    db,
    models::{Inbound, ManagedUser, Outbound, Settings},
    state::AppState,
    util,
};

pub fn build_value(state: &AppState) -> Result<Value> {
    let conn = state.db.lock().unwrap();
    let settings = db::load_settings(&conn)?;
    let inbounds = db::load_inbounds(&conn)?;
    let outbounds = db::load_outbounds(&conn)?;
    let sections = db::load_section_map(&conn)?;
    let users = db::load_users(&conn)?;
    let mut inbound_json = Vec::new();

    for inbound in inbounds.into_iter().filter(|i| i.enabled) {
        let clients: Vec<Value> = users
            .iter()
            .filter(|u| u.inbound_id == inbound.id && u.enabled && u.enforcement_status == "active")
            .map(|u| client_entry(&inbound.protocol, u))
            .collect();
        let mut settings_json = object_or_empty(&inbound.settings)?;
        if !clients.is_empty()
            || (protocol_uses_clients(&inbound.protocol) && settings_json.get("clients").is_none())
        {
            settings_json["clients"] = Value::Array(clients);
        }
        let mut entry = json!({
            "tag": inbound.tag,
            "protocol": inbound.protocol,
            "listen": inbound.listen,
            "port": inbound.port,
            "settings": settings_json
        });
        if let Some(stream) = stream_settings(&inbound)? {
            entry["streamSettings"] = stream;
        }
        if let Some(sniffing) = optional_json(&inbound.sniffing)? {
            entry["sniffing"] = sniffing;
        }
        if let Some(limits) = optional_json(&inbound.limits)? {
            entry["limits"] = limits;
        }
        inbound_json.push(entry);
    }

    let enabled_outbounds = outbounds
        .into_iter()
        .filter(|outbound| outbound.enabled)
        .collect::<Vec<_>>();
    let mut outbound_json = Vec::new();
    for outbound in &enabled_outbounds {
        let mut entry = json!({
            "tag": outbound.tag,
            "protocol": outbound.protocol,
            "settings": object_or_empty(&outbound.settings)?
        });
        if let Some(stream) = optional_json(&outbound.stream_settings)? {
            entry["streamSettings"] = stream;
        }
        outbound_json.push(entry);
    }
    if outbound_json.is_empty() {
        outbound_json.push(json!({ "tag": "freedom", "protocol": "freedom" }));
    }

    let mut root = json!({
        "log": section_or_default(&sections, "log", json!({ "level": "info", "json": false }))?,
        "api": section_or_default(&sections, "api", json!({ "listen": settings.grpc_address }))?,
        "inbounds": inbound_json,
        "outbounds": outbound_json,
    });

    for key in ["dns", "routing", "tun", "limits", "stats", "fast"] {
        if let Some(value) = enabled_section(&sections, key)? {
            root[key] = value;
        }
    }
    if settings.adaptive_routing_enabled {
        root["routing"] = adaptive_routing_section(&enabled_outbounds);
    }
    if let Some(value) = enabled_section(&sections, "metricsAddr")? {
        root["metricsAddr"] = value;
    }
    if let Some(value) = enabled_section(&sections, "profile")? {
        root["profile"] = value;
    }

    Ok(root)
}

fn adaptive_routing_section(outbounds: &[Outbound]) -> Value {
    let tags = outbounds
        .iter()
        .map(|outbound| outbound.tag.as_str())
        .collect::<Vec<_>>();
    if tags.len() < 2 {
        return json!({ "rules": [{ "outboundTag": tags.first().copied().unwrap_or("freedom") }] });
    }
    let profiles = tags
        .iter()
        .enumerate()
        .map(|(idx, tag)| {
            json!({
                "name": if idx == 0 { "stable".to_string() } else { format!("backup-{idx}") },
                "outboundTag": tag
            })
        })
        .collect::<Vec<_>>();
    json!({
        "balancers": [{
            "tag": "auto-proxy",
            "selector": tags,
            "strategy": "adaptive",
            "profiles": profiles,
            "adaptive": {
                "failureThreshold": 2,
                "cooldownSecs": 30,
                "ewmaAlpha": 0.2,
                "switchMargin": 0.15
            },
            "health_check": {
                "url": "http://www.gstatic.com/generate_204",
                "interval_secs": 30,
                "timeout_secs": 5,
                "max_failures": 2
            }
        }],
        "rules": [{ "outboundTag": "auto-proxy" }]
    })
}

pub fn validate_value(value: &Value) -> Result<()> {
    let cfg: blackwire_config::Config = serde_json::from_value(value.clone())?;
    cfg.validate().map_err(|e| anyhow!(e.to_string()))
}

pub fn write(state: &AppState) -> Result<()> {
    let settings = {
        let conn = state.db.lock().unwrap();
        db::load_settings(&conn)?
    };
    let value = build_value(state)?;
    validate_value(&value)?;
    if let Some(parent) = Path::new(&settings.config_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&settings.config_path, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

pub fn stream_settings(inbound: &Inbound) -> Result<Option<Value>> {
    if !inbound.stream_settings.trim().is_empty() {
        return Ok(Some(serde_json::from_str(&inbound.stream_settings)?));
    }
    match inbound.transport.as_str() {
        "tcp" => Ok(None),
        "ws" => Ok(Some(json!({
            "network": "ws",
            "security": "none",
            "wsSettings": { "path": format!("/{}", inbound.tag) }
        }))),
        "reality" => Err(anyhow!(
            "REALITY inbound '{}' requires streamSettings",
            inbound.tag
        )),
        "grpc" => Ok(Some(json!({
            "network": "grpc",
            "security": "none",
            "grpcSettings": { "serviceName": inbound.tag }
        }))),
        "httpupgrade" => Ok(Some(json!({
            "network": "httpupgrade",
            "security": "none",
            "httpupgradeSettings": { "path": format!("/{}", inbound.tag) }
        }))),
        "splithttp" => Ok(Some(json!({
            "network": "splithttp",
            "security": "none",
            "splithttpSettings": { "path": format!("/{}", inbound.tag), "mode": "stream-one" }
        }))),
        "kcp" => Ok(Some(json!({ "network": "kcp", "security": "none" }))),
        "quic" => Ok(Some(json!({ "network": "quic", "security": "none" }))),
        _ => Err(anyhow!("unsupported transport '{}'", inbound.transport)),
    }
}

pub fn subscription_link(
    settings: &Settings,
    inbound: &Inbound,
    user: &ManagedUser,
) -> Result<String> {
    match inbound.protocol.as_str() {
        "vless" => Ok(vless_link(settings, inbound, user)),
        "vmess" => Ok(vmess_link(settings, inbound, user)),
        "trojan" => trojan_link(settings, inbound, user),
        "shadowsocks" => shadowsocks_link(settings, inbound, user),
        "hysteria2" => hysteria2_link(settings, inbound, user),
        other => Err(anyhow!(
            "subscription link for protocol '{other}' requires manual config export"
        )),
    }
}

pub fn vless_link(settings: &Settings, inbound: &Inbound, user: &ManagedUser) -> String {
    let mut params = vec![
        format!("type={}", share_network(inbound)),
        "encryption=none".into(),
    ];
    append_transport_params(inbound, &mut params);
    let security = stream_security(inbound).unwrap_or_else(|| {
        if inbound.transport == "reality" {
            "reality".into()
        } else {
            "none".into()
        }
    });
    if security == "reality" {
        params.push("security=reality".into());
        params.push("headerType=none".into());
        if let Some(value) = reality_value(inbound, "/realitySettings/publicKey") {
            params.push(format!(
                "pbk={}",
                util::url_escape(&reality_public_key_share_value(&value))
            ));
        }
        if let Some(value) = reality_value(inbound, "/realitySettings/shortId").or_else(|| {
            serde_json::from_str::<Value>(&inbound.stream_settings)
                .ok()
                .and_then(|v| {
                    v.pointer("/realitySettings/shortIds")
                        .and_then(Value::as_array)
                        .and_then(|ids| ids.first())
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
        }) {
            params.push(format!("sid={}", util::url_escape(&value)));
        }
        if let Some(value) = reality_value(inbound, "/realitySettings/serverName") {
            params.push(format!("sni={}", util::url_escape(&value)));
        }
        if let Some(value) = reality_value(inbound, "/realitySettings/fingerprint") {
            params.push(format!("fp={}", util::url_escape(&value)));
        } else {
            params.push("fp=chrome".into());
        }
        let spider_x =
            reality_value(inbound, "/realitySettings/spiderX").unwrap_or_else(|| "/".into());
        params.push(format!("spx={}", url_escape_query_value(&spider_x)));
    } else if security == "tls" {
        params.push("security=tls".into());
        if let Some(value) = stream_value(inbound, "/tlsSettings/serverName") {
            params.push(format!("sni={}", util::url_escape(&value)));
        }
        if let Some(value) = stream_value(inbound, "/tlsSettings/alpn") {
            params.push(format!("alpn={}", util::url_escape(&value)));
        }
    } else {
        params.push("security=none".into());
    }
    if !user.flow.trim().is_empty() {
        params.push(format!("flow={}", util::url_escape(&user.flow)));
    }
    format!(
        "vless://{}@{}:{}?{}#{}",
        user.uuid,
        settings.subscription_host,
        inbound.port,
        params.join("&"),
        util::url_escape(&user.email)
    )
}

fn vmess_link(settings: &Settings, inbound: &Inbound, user: &ManagedUser) -> String {
    let network = share_network(inbound);
    let security = stream_security(inbound).unwrap_or_else(|| "none".into());
    let host = stream_value(inbound, "/wsSettings/headers/Host")
        .or_else(|| stream_value(inbound, "/httpupgradeSettings/host"))
        .unwrap_or_default();
    let path = stream_value(inbound, "/wsSettings/path")
        .or_else(|| stream_value(inbound, "/httpupgradeSettings/path"))
        .or_else(|| stream_value(inbound, "/splithttpSettings/path"))
        .unwrap_or_default();
    let sni = stream_value(inbound, "/tlsSettings/serverName").unwrap_or_default();
    let alpn = stream_value(inbound, "/tlsSettings/alpn").unwrap_or_default();
    let payload = json!({
        "v": "2",
        "ps": user.email,
        "add": settings.subscription_host,
        "port": inbound.port.to_string(),
        "id": user.uuid,
        "aid": "0",
        "scy": "auto",
        "net": network,
        "type": "none",
        "host": host,
        "path": path,
        "tls": if security == "tls" { "tls" } else { "" },
        "sni": sni,
        "alpn": alpn,
    });
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        serde_json::to_string(&payload).unwrap_or_default(),
    );
    format!("vmess://{encoded}")
}

fn reality_value(inbound: &Inbound, pointer: &str) -> Option<String> {
    stream_value(inbound, pointer)
}

fn reality_public_key_share_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(trimmed) {
            if bytes.len() == 32 {
                return base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    bytes,
                );
            }
        }
    }
    trimmed.to_string()
}

fn url_escape_query_value(value: &str) -> String {
    value
        .bytes()
        .flat_map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![b as char]
            }
            _ => format!("%{b:02X}").chars().collect(),
        })
        .collect()
}

fn trojan_link(settings: &Settings, inbound: &Inbound, user: &ManagedUser) -> Result<String> {
    let password = credential_string(user, "password").unwrap_or_else(|| user.uuid.clone());
    let mut params = vec![format!("type={}", share_network(inbound))];
    append_transport_params(inbound, &mut params);
    let security = stream_security(inbound).unwrap_or_else(|| "tls".into());
    params.push(format!("security={security}"));
    if security == "tls" {
        if let Some(value) = stream_value(inbound, "/tlsSettings/serverName") {
            params.push(format!("sni={}", util::url_escape(&value)));
        }
    }
    Ok(format!(
        "trojan://{}@{}:{}?{}#{}",
        util::url_escape(&password),
        settings.subscription_host,
        inbound.port,
        params.join("&"),
        util::url_escape(&user.email)
    ))
}

fn shadowsocks_link(settings: &Settings, inbound: &Inbound, user: &ManagedUser) -> Result<String> {
    let method = credential_string(user, "method")
        .or_else(|| settings_value(&inbound.settings, "method"))
        .unwrap_or_else(|| "2022-blake3-aes-256-gcm".into());
    let password = credential_string(user, "password").unwrap_or_else(|| user.uuid.clone());
    let userinfo = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        format!("{method}:{password}"),
    );
    Ok(format!(
        "ss://{}@{}:{}#{}",
        userinfo,
        settings.subscription_host,
        inbound.port,
        util::url_escape(&user.email)
    ))
}

fn hysteria2_link(settings: &Settings, inbound: &Inbound, user: &ManagedUser) -> Result<String> {
    let auth = credential_string(user, "auth")
        .or_else(|| credential_string(user, "password"))
        .unwrap_or_else(|| user.uuid.clone());
    let mut params = Vec::new();
    if let Some(value) = stream_value(inbound, "/tlsSettings/serverName") {
        params.push(format!("sni={}", util::url_escape(&value)));
    }
    let query = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };
    Ok(format!(
        "hysteria2://{}@{}:{}{}#{}",
        util::url_escape(&auth),
        settings.subscription_host,
        inbound.port,
        query,
        util::url_escape(&user.email)
    ))
}

fn share_network(inbound: &Inbound) -> String {
    let security = stream_security(inbound);
    if inbound.transport == "reality" || security.as_deref() == Some("reality") {
        "tcp".into()
    } else {
        stream_value(inbound, "/network").unwrap_or_else(|| inbound.transport.clone())
    }
}

fn append_transport_params(inbound: &Inbound, params: &mut Vec<String>) {
    if let Some(path) = stream_value(inbound, "/wsSettings/path")
        .or_else(|| stream_value(inbound, "/httpupgradeSettings/path"))
        .or_else(|| stream_value(inbound, "/splithttpSettings/path"))
    {
        params.push(format!("path={}", util::url_escape(&path)));
    }
    if let Some(host) = stream_value(inbound, "/wsSettings/headers/Host")
        .or_else(|| stream_value(inbound, "/httpupgradeSettings/host"))
    {
        params.push(format!("host={}", util::url_escape(&host)));
    }
    if let Some(service_name) = stream_value(inbound, "/grpcSettings/serviceName") {
        params.push(format!("serviceName={}", util::url_escape(&service_name)));
    }
}

fn client_entry(protocol: &str, user: &ManagedUser) -> Value {
    let mut entry = user.credential.as_object().cloned().unwrap_or_default();
    entry.insert("email".into(), json!(user.email));
    match protocol {
        "vless" | "vmess" => {
            entry.entry("id").or_insert_with(|| json!(user.uuid));
            if protocol == "vless" && !user.flow.is_empty() {
                entry.entry("flow").or_insert_with(|| json!(user.flow));
            }
        }
        "trojan" | "shadowsocks" => {
            entry.entry("password").or_insert_with(|| json!(user.uuid));
        }
        "hysteria2" => {
            entry.entry("auth").or_insert_with(|| json!(user.uuid));
        }
        _ => {}
    }
    Value::Object(entry)
}

fn protocol_uses_clients(protocol: &str) -> bool {
    matches!(
        protocol,
        "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria2"
    )
}

fn optional_json(raw: &str) -> Result<Option<Value>> {
    if raw.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(raw)?))
}

fn object_or_empty(raw: &str) -> Result<Value> {
    Ok(optional_json(raw)?.unwrap_or_else(|| json!({})))
}

fn enabled_section(
    sections: &std::collections::HashMap<String, crate::models::ConfigSection>,
    key: &str,
) -> Result<Option<Value>> {
    let Some(section) = sections.get(key) else {
        return Ok(None);
    };
    if !section.enabled {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&section.value)?))
}

fn section_or_default(
    sections: &std::collections::HashMap<String, crate::models::ConfigSection>,
    key: &str,
    default: Value,
) -> Result<Value> {
    Ok(enabled_section(sections, key)?.unwrap_or(default))
}

fn credential_string(user: &ManagedUser, key: &str) -> Option<String> {
    user.credential
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn settings_value(raw: &str, key: &str) -> Option<String> {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|v| v.get(key).and_then(Value::as_str).map(str::to_string))
}

fn stream_value(inbound: &Inbound, pointer: &str) -> Option<String> {
    serde_json::from_str::<Value>(&inbound.stream_settings)
        .ok()
        .and_then(|v| {
            let value = v.pointer(pointer)?;
            if let Some(raw) = value.as_str() {
                return Some(raw.to_string());
            }
            if let Some(items) = value.as_array() {
                return Some(
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            None
        })
        .filter(|v| !v.is_empty())
}

fn stream_security(inbound: &Inbound) -> Option<String> {
    serde_json::from_str::<Value>(&inbound.stream_settings)
        .ok()
        .and_then(|v| {
            v.get("security")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use rusqlite::{params, Connection};

    use super::*;

    fn test_state() -> AppState {
        let conn = Connection::open_in_memory().unwrap();
        let data_dir = std::env::temp_dir().join(format!("black-ui-test-{}", uuid::Uuid::new_v4()));
        db::init(&conn, &data_dir).unwrap();
        AppState {
            db: Arc::new(Mutex::new(conn)),
        }
    }

    #[test]
    fn generated_minimal_config_validates() {
        let state = test_state();
        {
            let conn = state.db.lock().unwrap();
            let ts = util::now();
            conn.execute(
                "INSERT INTO inbounds (tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at)
                 VALUES ('socks', '127.0.0.1', 18080, 'socks', 1, 'tcp', '{}', '', '', '', ?1, ?1)",
                params![ts],
            )
            .unwrap();
        }
        let value = build_value(&state).unwrap();
        validate_value(&value).unwrap();
    }

    #[test]
    fn generated_vless_ws_user_config_validates() {
        let state = test_state();
        {
            let conn = state.db.lock().unwrap();
            let ts = util::now();
            conn.execute(
                "INSERT INTO inbounds (tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at)
                 VALUES ('vless-ws', '127.0.0.1', 18001, 'vless', 1, 'ws', '{}', '', '', '', ?1, ?1)",
                params![ts],
            )
            .unwrap();
            let inbound_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO users (inbound_id, email, uuid, flow, credential_json, note, enabled, traffic_limit_bytes, expiry_at, sub_token, enforcement_status, created_at, updated_at)
                 VALUES (?1, 'alice@example.test', '00000000-0000-4000-8000-000000000001', '', '{}', '', 1, NULL, NULL, 'token', 'active', ?2, ?2)",
                params![inbound_id, util::now()],
            )
            .unwrap();
        }
        let value = build_value(&state).unwrap();
        validate_value(&value).unwrap();
        assert_eq!(value["inbounds"][0]["protocol"], "vless");
        assert_eq!(
            value["inbounds"][0]["settings"]["clients"][0]["email"],
            "alice@example.test"
        );
    }

    #[test]
    fn generated_adaptive_balancer_routing_config_validates() {
        let state = test_state();
        {
            let conn = state.db.lock().unwrap();
            let ts = util::now();
            conn.execute(
                "INSERT INTO inbounds (tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at)
                 VALUES ('socks', '127.0.0.1', 18080, 'socks', 1, 'tcp', '{}', '', '', '', ?1, ?1)",
                params![ts],
            )
            .unwrap();
            conn.execute(
                "UPDATE outbounds SET tag='primary-vless', protocol='freedom', enabled=1, settings='{}', stream_settings='', updated_at=?1 WHERE tag='freedom'",
                params![ts],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO outbounds (tag, protocol, enabled, settings, stream_settings, created_at, updated_at)
                 VALUES ('backup-ss2022', 'freedom', 1, '{}', '', ?1, ?1)",
                params![ts],
            )
            .unwrap();
            conn.execute(
                "UPDATE config_sections SET enabled=1, value=?1, updated_at=?2 WHERE name='routing'",
                params![
                    r#"{
                      "balancers": [{
                        "tag": "auto-proxy",
                        "selector": ["primary-vless", "backup-ss2022"],
                        "strategy": "adaptive",
                        "profiles": [
                          { "name": "stable", "outboundTag": "primary-vless" },
                          { "name": "backup", "outboundTag": "backup-ss2022" }
                        ],
                        "adaptive": {
                          "failureThreshold": 2,
                          "cooldownSecs": 30,
                          "ewmaAlpha": 0.2,
                          "switchMargin": 0.15
                        },
                        "health_check": {
                          "url": "http://www.gstatic.com/generate_204",
                          "interval_secs": 30,
                          "timeout_secs": 5,
                          "max_failures": 2
                        }
                      }],
                      "rules": [{ "outboundTag": "auto-proxy" }]
                    }"#,
                    ts
                ],
            )
            .unwrap();
        }

        let value = build_value(&state).unwrap();
        validate_value(&value).unwrap();
        assert_eq!(value["routing"]["balancers"][0]["strategy"], "adaptive");
        assert_eq!(
            value["routing"]["balancers"][0]["profiles"][0]["outboundTag"],
            "primary-vless"
        );
    }

    #[test]
    fn adaptive_routing_setting_generates_balancer_only_with_multiple_outbounds() {
        let state = test_state();
        {
            let conn = state.db.lock().unwrap();
            let ts = util::now();
            conn.execute(
                "INSERT INTO inbounds (tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at)
                 VALUES ('socks', '127.0.0.1', 18080, 'socks', 1, 'tcp', '{}', '', '', '', ?1, ?1)",
                params![ts],
            )
            .unwrap();
            db::save_settings(
                &conn,
                &Settings {
                    config_path: "/tmp/config.json".into(),
                    grpc_enabled: false,
                    grpc_address: "127.0.0.1:62789".into(),
                    firewall_auto_open: false,
                    public_base_url: "http://127.0.0.1:18080".into(),
                    subscription_host: "127.0.0.1".into(),
                    enforcement_interval_seconds: 30,
                    adaptive_routing_enabled: true,
                },
            )
            .unwrap();
        }

        let value = build_value(&state).unwrap();
        validate_value(&value).unwrap();
        assert!(value["routing"].get("balancers").is_none());
        assert_eq!(value["routing"]["rules"][0]["outboundTag"], "freedom");

        {
            let conn = state.db.lock().unwrap();
            let ts = util::now();
            conn.execute(
                "INSERT INTO outbounds (tag, protocol, enabled, settings, stream_settings, created_at, updated_at)
                 VALUES ('backup-freedom', 'freedom', 1, '{}', '', ?1, ?1)",
                params![ts],
            )
            .unwrap();
        }

        let value = build_value(&state).unwrap();
        validate_value(&value).unwrap();
        assert_eq!(value["routing"]["balancers"][0]["strategy"], "adaptive");
        assert_eq!(value["routing"]["rules"][0]["outboundTag"], "auto-proxy");
    }

    #[test]
    fn vless_reality_subscription_uses_common_xray_uri_params() {
        let settings = Settings {
            config_path: "/tmp/config.json".into(),
            grpc_enabled: false,
            grpc_address: "127.0.0.1:62789".into(),
            firewall_auto_open: false,
            public_base_url: "http://127.0.0.1:18080".into(),
            subscription_host: "203.0.113.10".into(),
            enforcement_interval_seconds: 30,
            adaptive_routing_enabled: false,
        };
        let inbound = Inbound {
            id: 1,
            tag: "vless-reality-in".into(),
            listen: "0.0.0.0".into(),
            port: 443,
            protocol: "vless".into(),
            enabled: true,
            transport: "reality".into(),
            settings: "{}".into(),
            stream_settings: r#"{
              "network": "tcp",
              "security": "reality",
              "realitySettings": {
                "publicKey": "e1df9c8812b5ce9b3bd36da542896be856ad0a6c6e6df9d910a4040c07268142",
                "shortId": "feedbeef",
                "serverName": "www.microsoft.com",
                "fingerprint": "chrome"
              }
            }"#
            .into(),
            sniffing: String::new(),
            limits: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        let user = ManagedUser {
            id: 1,
            inbound_id: 1,
            email: "Mollah".into(),
            uuid: "459dc0c8-d891-4768-9234-faf11fd26b5d".into(),
            flow: String::new(),
            credential: json!({}),
            note: String::new(),
            enabled: true,
            traffic_limit_bytes: None,
            expiry_at: None,
            upload_bytes: 0,
            download_bytes: 0,
            sub_token: "token".into(),
            enforcement_status: "active".into(),
            created_at: String::new(),
            updated_at: String::new(),
        };

        let link = vless_link(&settings, &inbound, &user);
        assert!(link.starts_with("vless://459dc0c8-d891-4768-9234-faf11fd26b5d@203.0.113.10:443?"));
        assert!(link.contains("type=tcp"));
        assert!(link.contains("security=reality"));
        assert!(link.contains("headerType=none"));
        assert!(link.contains("pbk=4d-ciBK1zps7022lQolr6FatCmxubfnZEKQEDAcmgUI"));
        assert!(link.contains("sid=feedbeef"));
        assert!(link.contains("sni=www.microsoft.com"));
        assert!(link.contains("fp=chrome"));
        assert!(link.contains("spx=%2F"));
        assert!(link.ends_with("#Mollah"));
    }
}
