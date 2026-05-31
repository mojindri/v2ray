use std::path::Path;

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::{
    models::{ConfigSection, Inbound, ManagedUser, Outbound, Settings},
    util,
};

pub fn init(conn: &Connection, data_dir: &Path) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            admin_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS inbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT NOT NULL UNIQUE,
            listen TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'vless',
            enabled INTEGER NOT NULL,
            transport TEXT NOT NULL,
            settings TEXT NOT NULL DEFAULT '',
            stream_settings TEXT NOT NULL,
            sniffing TEXT NOT NULL DEFAULT '',
            limits TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS outbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT NOT NULL UNIQUE,
            protocol TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            settings TEXT NOT NULL,
            stream_settings TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS config_sections (
            name TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inbound_id INTEGER NOT NULL,
            email TEXT NOT NULL UNIQUE,
            uuid TEXT NOT NULL UNIQUE,
            flow TEXT NOT NULL,
            credential_json TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            traffic_limit_bytes INTEGER,
            expiry_at TEXT,
            upload_bytes INTEGER NOT NULL DEFAULT 0,
            download_bytes INTEGER NOT NULL DEFAULT 0,
            sub_token TEXT NOT NULL UNIQUE,
            enforcement_status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
        );
        "#,
    )?;
    migrate_existing_schema(conn)?;
    let config_path = data_dir.join("config.json").to_string_lossy().to_string();
    set_default(conn, "configPath", &config_path)?;
    set_default(conn, "grpcEnabled", "true")?;
    set_default(conn, "grpcAddress", "127.0.0.1:62789")?;
    set_default(conn, "firewallAutoOpen", "false")?;
    set_default(conn, "publicBaseUrl", "http://127.0.0.1:18080")?;
    set_default(conn, "subscriptionHost", "127.0.0.1")?;
    set_default(conn, "enforcementIntervalSeconds", "30")?;
    set_default(conn, "adaptiveRoutingEnabled", "false")?;
    seed_default_outbound(conn)?;
    seed_default_sections(conn)?;
    Ok(())
}

fn migrate_existing_schema(conn: &Connection) -> Result<()> {
    add_column_if_missing(
        conn,
        "inbounds",
        "protocol",
        "TEXT NOT NULL DEFAULT 'vless'",
    )?;
    add_column_if_missing(conn, "inbounds", "settings", "TEXT NOT NULL DEFAULT ''")?;
    add_column_if_missing(conn, "inbounds", "sniffing", "TEXT NOT NULL DEFAULT ''")?;
    add_column_if_missing(conn, "inbounds", "limits", "TEXT NOT NULL DEFAULT ''")?;
    add_column_if_missing(conn, "users", "credential_json", "TEXT NOT NULL DEFAULT ''")?;
    Ok(())
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(());
        }
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

fn seed_default_outbound(conn: &Connection) -> Result<()> {
    let ts = util::now();
    conn.execute(
        "INSERT OR IGNORE INTO outbounds (tag, protocol, enabled, settings, stream_settings, created_at, updated_at)
         VALUES ('freedom', 'freedom', 1, '{}', '', ?1, ?1)",
        params![ts],
    )?;
    Ok(())
}

fn seed_default_sections(conn: &Connection) -> Result<()> {
    let ts = util::now();
    let defaults = [
        ("log", 1, r#"{"level":"info","json":false}"#),
        ("routing", 1, r#"{"rules":[{"outboundTag":"freedom"}]}"#),
        ("dns", 0, r#"{"servers":[]}"#),
        (
            "tun",
            0,
            r#"{"name":"blackwire-tun","address":"198.18.0.1","netmask":"255.255.0.0","mtu":1500,"bypass_mark":4660,"redirect_port":7890,"dns_port":5300}"#,
        ),
        ("limits", 0, r#"{}"#),
        ("stats", 0, r#"{}"#),
        ("api", 1, r#"{"listen":"127.0.0.1:62789"}"#),
        ("metricsAddr", 0, r#""127.0.0.1:9090""#),
        ("profile", 0, r#""compat""#),
        (
            "fast",
            0,
            r#"{"strictProduction":true,"pool":"disabled","splice":"adaptive"}"#,
        ),
    ];
    for (name, enabled, value) in defaults {
        conn.execute(
            "INSERT OR IGNORE INTO config_sections (name, enabled, value, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![name, enabled, value, ts],
        )?;
    }
    Ok(())
}

fn set_default(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

pub fn count(conn: &Connection, table: &str) -> Result<i64> {
    Ok(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
}

pub fn setup_required(conn: &Connection) -> Result<bool> {
    Ok(count(conn, "admins")? == 0)
}

pub fn load_settings(conn: &Connection) -> Result<Settings> {
    let mut stmt = conn.prepare("SELECT key, value FROM settings")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut map = std::collections::HashMap::new();
    for row in rows {
        let (k, v) = row?;
        map.insert(k, v);
    }
    Ok(Settings {
        config_path: map
            .get("configPath")
            .cloned()
            .unwrap_or_else(|| "black-ui/data/config.json".into()),
        grpc_enabled: map.get("grpcEnabled").map(|v| v == "true").unwrap_or(true),
        grpc_address: map
            .get("grpcAddress")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:62789".into()),
        firewall_auto_open: map
            .get("firewallAutoOpen")
            .map(|v| v == "true")
            .unwrap_or(false),
        public_base_url: map
            .get("publicBaseUrl")
            .cloned()
            .unwrap_or_else(|| "http://127.0.0.1:18080".into()),
        subscription_host: map
            .get("subscriptionHost")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".into()),
        enforcement_interval_seconds: map
            .get("enforcementIntervalSeconds")
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
        adaptive_routing_enabled: map
            .get("adaptiveRoutingEnabled")
            .map(|v| v == "true")
            .unwrap_or(false),
    })
}

pub fn save_settings(conn: &Connection, settings: &Settings) -> Result<()> {
    let rows = [
        ("configPath", settings.config_path.clone()),
        ("grpcEnabled", settings.grpc_enabled.to_string()),
        ("grpcAddress", settings.grpc_address.clone()),
        ("firewallAutoOpen", settings.firewall_auto_open.to_string()),
        ("publicBaseUrl", settings.public_base_url.clone()),
        ("subscriptionHost", settings.subscription_host.clone()),
        (
            "enforcementIntervalSeconds",
            settings.enforcement_interval_seconds.to_string(),
        ),
        (
            "adaptiveRoutingEnabled",
            settings.adaptive_routing_enabled.to_string(),
        ),
    ];
    for (key, value) in rows {
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
    }
    Ok(())
}

pub fn load_inbounds(conn: &Connection) -> Result<Vec<Inbound>> {
    let mut stmt = conn.prepare(
        "SELECT id, tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at
         FROM inbounds ORDER BY id",
    )?;
    let rows = stmt.query_map([], row_inbound)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub fn load_inbound(conn: &Connection, id: i64) -> Result<Option<Inbound>> {
    conn.query_row(
        "SELECT id, tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at
         FROM inbounds WHERE id=?1",
        params![id],
        row_inbound,
    )
    .optional()
    .map_err(Into::into)
}

fn row_inbound(r: &Row<'_>) -> rusqlite::Result<Inbound> {
    Ok(Inbound {
        id: r.get(0)?,
        tag: r.get(1)?,
        listen: r.get(2)?,
        port: r.get::<_, i64>(3)? as u16,
        protocol: r.get(4)?,
        enabled: r.get::<_, i64>(5)? == 1,
        transport: r.get(6)?,
        settings: r.get(7)?,
        stream_settings: r.get(8)?,
        sniffing: r.get(9)?,
        limits: r.get(10)?,
        created_at: r.get(11)?,
        updated_at: r.get(12)?,
    })
}

pub fn load_outbounds(conn: &Connection) -> Result<Vec<Outbound>> {
    let mut stmt = conn.prepare(
        "SELECT id, tag, protocol, enabled, settings, stream_settings, created_at, updated_at
         FROM outbounds ORDER BY id",
    )?;
    let rows = stmt.query_map([], row_outbound)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn row_outbound(r: &Row<'_>) -> rusqlite::Result<Outbound> {
    Ok(Outbound {
        id: r.get(0)?,
        tag: r.get(1)?,
        protocol: r.get(2)?,
        enabled: r.get::<_, i64>(3)? == 1,
        settings: r.get(4)?,
        stream_settings: r.get(5)?,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
    })
}

pub fn load_sections(conn: &Connection) -> Result<Vec<ConfigSection>> {
    let mut stmt =
        conn.prepare("SELECT name, enabled, value, updated_at FROM config_sections ORDER BY name")?;
    let rows = stmt.query_map([], |r| {
        Ok(ConfigSection {
            name: r.get(0)?,
            enabled: r.get::<_, i64>(1)? == 1,
            value: r.get(2)?,
            updated_at: r.get(3)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub fn load_section_map(
    conn: &Connection,
) -> Result<std::collections::HashMap<String, ConfigSection>> {
    Ok(load_sections(conn)?
        .into_iter()
        .map(|section| (section.name.clone(), section))
        .collect())
}

pub fn load_users(conn: &Connection) -> Result<Vec<ManagedUser>> {
    let mut stmt = conn.prepare(
        "SELECT id, inbound_id, email, uuid, flow, credential_json, note, enabled, traffic_limit_bytes, expiry_at,
         upload_bytes, download_bytes, sub_token, enforcement_status, created_at, updated_at
         FROM users ORDER BY id",
    )?;
    let rows = stmt.query_map([], row_user)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub fn load_user(conn: &Connection, id: i64) -> Result<Option<ManagedUser>> {
    conn.query_row(
        "SELECT id, inbound_id, email, uuid, flow, credential_json, note, enabled, traffic_limit_bytes, expiry_at,
         upload_bytes, download_bytes, sub_token, enforcement_status, created_at, updated_at
         FROM users WHERE id=?1",
        params![id],
        row_user,
    )
    .optional()
    .map_err(Into::into)
}

pub fn load_user_by_token(conn: &Connection, token: &str) -> Result<Option<ManagedUser>> {
    conn.query_row(
        "SELECT id, inbound_id, email, uuid, flow, credential_json, note, enabled, traffic_limit_bytes, expiry_at,
         upload_bytes, download_bytes, sub_token, enforcement_status, created_at, updated_at
         FROM users WHERE sub_token=?1",
        params![token],
        row_user,
    )
    .optional()
    .map_err(Into::into)
}

fn row_user(r: &Row<'_>) -> rusqlite::Result<ManagedUser> {
    let credential_raw: String = r.get(5)?;
    let credential = if credential_raw.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&credential_raw).unwrap_or_else(|_| serde_json::json!({}))
    };
    Ok(ManagedUser {
        id: r.get(0)?,
        inbound_id: r.get(1)?,
        email: r.get(2)?,
        uuid: r.get(3)?,
        flow: r.get(4)?,
        credential,
        note: r.get(6)?,
        enabled: r.get::<_, i64>(7)? == 1,
        traffic_limit_bytes: r.get(8)?,
        expiry_at: r.get(9)?,
        upload_bytes: r.get(10)?,
        download_bytes: r.get(11)?,
        sub_token: r.get(12)?,
        enforcement_status: r.get(13)?,
        created_at: r.get(14)?,
        updated_at: r.get(15)?,
    })
}

pub fn touch_user_status(conn: &Connection, id: i64, enabled: bool, status: &str) -> Result<()> {
    conn.execute(
        "UPDATE users SET enabled=?1, enforcement_status=?2, updated_at=?3 WHERE id=?4",
        params![util::bool_i(enabled), status, util::now(), id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_migrates_prototype_schema_without_losing_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE sessions (
                token TEXT PRIMARY KEY,
                admin_id INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE inbounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT NOT NULL UNIQUE,
                listen TEXT NOT NULL,
                port INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                transport TEXT NOT NULL,
                stream_settings TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inbound_id INTEGER NOT NULL,
                email TEXT NOT NULL UNIQUE,
                uuid TEXT NOT NULL UNIQUE,
                flow TEXT NOT NULL,
                note TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                traffic_limit_bytes INTEGER,
                expiry_at TEXT,
                upload_bytes INTEGER NOT NULL DEFAULT 0,
                download_bytes INTEGER NOT NULL DEFAULT 0,
                sub_token TEXT NOT NULL UNIQUE,
                enforcement_status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
            );
            INSERT INTO inbounds (tag, listen, port, enabled, transport, stream_settings, created_at, updated_at)
            VALUES ('old', '127.0.0.1', 443, 1, 'ws', '{}', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
            "#,
        )
        .unwrap();

        init(&conn, Path::new("/tmp/black-ui-db-migration-test")).unwrap();

        let inbound = load_inbounds(&conn).unwrap().remove(0);
        assert_eq!(inbound.tag, "old");
        assert_eq!(inbound.protocol, "vless");
        assert_eq!(inbound.settings, "");
        assert_eq!(count(&conn, "outbounds").unwrap(), 1);
        assert_eq!(count(&conn, "config_sections").unwrap(), 10);
    }
}
