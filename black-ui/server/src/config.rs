use std::path::Path;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use validator::Validate;

use crate::{
    db,
    models::{Inbound, ManagedUser, Settings},
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

    let mut outbound_json = Vec::new();
    for outbound in outbounds.into_iter().filter(|o| o.enabled) {
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
    if let Some(value) = enabled_section(&sections, "metricsAddr")? {
        root["metricsAddr"] = value;
    }
    if let Some(value) = enabled_section(&sections, "profile")? {
        root["profile"] = value;
    }

    Ok(root)
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
        format!("type={}", inbound.transport),
        "encryption=none".into(),
    ];
    if inbound.transport == "ws" {
        let path = if inbound.stream_settings.trim().is_empty() {
            format!("/{}", inbound.tag)
        } else {
            serde_json::from_str::<Value>(&inbound.stream_settings)
                .ok()
                .and_then(|v| {
                    v.pointer("/wsSettings/path")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_else(|| format!("/{}", inbound.tag))
        };
        params.push(format!("path={}", util::url_escape(&path)));
    }
    if inbound.transport == "reality" {
        params.push("security=reality".into());
    } else {
        params.push("security=none".into());
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

fn trojan_link(settings: &Settings, inbound: &Inbound, user: &ManagedUser) -> Result<String> {
    let password = credential_string(user, "password").unwrap_or_else(|| user.uuid.clone());
    let mut params = vec![format!("type={}", inbound.transport)];
    let security = stream_security(inbound).unwrap_or_else(|| "tls".into());
    params.push(format!("security={security}"));
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
    Ok(format!(
        "hysteria2://{}@{}:{}#{}",
        util::url_escape(&auth),
        settings.subscription_host,
        inbound.port,
        util::url_escape(&user.email)
    ))
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
}
