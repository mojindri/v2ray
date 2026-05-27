//! Hot-reload helpers — update routing and VLESS users without restarting listeners.
//!
//! # What gets hot-reloaded?
//!
//! When an operator edits `config.json` on disk, blackwire can pick up some
//! changes **without** dropping live connections or rebinding ports:
//!
//!   - **Routing rules** — which outbound each destination uses
//!   - **GeoIP / geosite matchers** — country and domain lists
//!   - **VLESS user lists** — UUIDs allowed on each VLESS inbound
//!
//! # What does NOT hot-reload (yet)?
//!
//! These require a process restart because they are wired at startup:
//!
//!   - Inbound listen addresses / ports
//!   - Outbound server addresses
//!   - TLS / REALITY key material on existing listeners
//!   - New inbound or outbound tags (handlers are not created on the fly)
//!
//! # How it works
//!
//! 1. `ConfigManager::watch()` detects the file change and validates the new JSON.
//! 2. If valid, it stores the new config and pings subscribers via `subscribe()`.
//! 3. `blackwire run` listens on that channel and calls `ReloadState::apply()`.
//! 4. `apply()` atomically swaps the router (`LiveRouter::swap`) and refreshes
//!    each VLESS registry in place. Connections already in flight keep using
//!    the router snapshot they picked up at dispatch time; new connections see
//!    the updated rules and UUID lists immediately.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;
use serde_json::Value;
use tracing::info;

use blackwire_app::geo::{GeoIpMatcher, GeoSiteMatcher};
use blackwire_app::router::LiveRouter;
use blackwire_config::schema::{Config, Protocol};
use blackwire_protocol::vless::VlessUserRegistry;

use crate::instance::{build_rules, build_sniffing_map, load_geo_data, populate_vless_registry};

/// Cached geo data: skip rebuilding matchers when the file hasn't changed.
#[derive(Default)]
struct GeoCache {
    geoip_path: Option<String>,
    geoip_fingerprint: Option<(u64, SystemTime)>,
    geoip: HashMap<String, GeoIpMatcher>,

    geosite_path: Option<String>,
    geosite_fingerprint: Option<(u64, SystemTime)>,
    geosite: HashMap<String, GeoSiteMatcher>,
}

fn file_fingerprint(path: &str) -> Option<(u64, SystemTime)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.len(), meta.modified().ok()?))
}

/// Shared reload handles created at startup and updated on each config reload.
///
/// Clone this cheaply — it only bumps reference counts on the inner `Arc`s.
#[derive(Clone)]
pub struct ReloadState {
    /// Live routing table. Swapped atomically via `LiveRouter::swap`.
    pub router: Arc<LiveRouter>,
    /// One VLESS user registry per inbound tag (key = inbound `tag`).
    pub vless_registries: Arc<DashMap<String, Arc<VlessUserRegistry>>>,
    /// Per-inbound sniffing map (hot-swapped on reload via lock-free ArcSwap).
    pub sniffing:
        Arc<ArcSwap<std::collections::HashMap<String, Arc<blackwire_config::schema::SniffingConfig>>>>,
    /// Inbound tags from the active config (HandlerService ListInbounds).
    pub inbound_tags: Arc<std::sync::RwLock<Vec<String>>>,
    /// Outbound tags from the active config (HandlerService ListOutbounds).
    pub outbound_tags: Arc<std::sync::RwLock<Vec<String>>>,
    /// Cached geo matchers; skips file re-read when path and mtime are unchanged.
    geo_cache: Arc<Mutex<GeoCache>>,
}

impl ReloadState {
    /// Create a new `ReloadState` with the given router, registries and sniffing map.
    pub fn new(
        router: Arc<LiveRouter>,
        vless_registries: Arc<DashMap<String, Arc<VlessUserRegistry>>>,
        sniffing: Arc<
            ArcSwap<std::collections::HashMap<String, Arc<blackwire_config::schema::SniffingConfig>>>,
        >,
        inbound_tags: Arc<std::sync::RwLock<Vec<String>>>,
        outbound_tags: Arc<std::sync::RwLock<Vec<String>>>,
    ) -> Self {
        Self {
            router,
            vless_registries,
            sniffing,
            inbound_tags,
            outbound_tags,
            geo_cache: Arc::new(Mutex::new(GeoCache::default())),
        }
    }

    /// Apply routing rules and VLESS client lists from a freshly validated config.
    ///
    /// Inbound listeners and outbound handlers are not recreated here — only data
    /// consulted per connection (router + UUID registry) is refreshed.
    pub fn apply(&self, config: &Config) -> Result<()> {
        let outbound_tags = collect_outbound_tags(config);
        let default_tag = config
            .outbounds
            .first()
            .map(|o| o.tag.as_str())
            .unwrap_or("direct");

        let rules = if let Some(routing) = &config.routing {
            build_rules(&routing.rules, &outbound_tags)?
        } else {
            vec![]
        };

        let (geoip, geosite) = self.load_geo_data_cached(config);
        let domain_strategy = config
            .routing
            .as_ref()
            .and_then(|r| r.domain_strategy.clone());
        self.router
            .swap(rules, default_tag, geoip, geosite, domain_strategy);
        info!("routing rules hot-swapped");

        let new_sniffing = build_sniffing_map(&config.inbounds);
        let count = new_sniffing.len();
        self.sniffing.store(Arc::new(new_sniffing));
        info!(count, "sniffing map hot-swapped");

        if let Ok(mut tags) = self.inbound_tags.write() {
            *tags = config.inbounds.iter().map(|i| i.tag.clone()).collect();
        }
        if let Ok(mut tags) = self.outbound_tags.write() {
            *tags = config.outbounds.iter().map(|o| o.tag.clone()).collect();
        }

        for in_cfg in &config.inbounds {
            if in_cfg.protocol != Protocol::Vless {
                continue;
            }
            if let Some(registry) = self.vless_registries.get(&in_cfg.tag) {
                populate_vless_registry(&registry, in_cfg)?;
                info!(tag = %in_cfg.tag, users = registry.len(), "VLESS user registry refreshed");
            }
        }

        Ok(())
    }
}

impl blackwire_api::management::InboundManagement for ReloadState {
    fn list_inbound_tags(&self) -> Vec<String> {
        self.inbound_tags
            .read()
            .map(|t| t.clone())
            .unwrap_or_default()
    }

    fn list_outbound_tags(&self) -> Vec<String> {
        self.outbound_tags
            .read()
            .map(|t| t.clone())
            .unwrap_or_default()
    }

    fn vless_user_count(&self, inbound_tag: &str) -> Option<i64> {
        self.vless_registry(inbound_tag).map(|r| r.len() as i64)
    }

    fn list_vless_users(
        &self,
        inbound_tag: &str,
        email: &str,
    ) -> Result<Vec<blackwire_api::management::VlessUserRecord>, String> {
        let registry = self
            .vless_registry(inbound_tag)
            .ok_or_else(|| format!("inbound '{inbound_tag}' has no VLESS user registry"))?;
        Ok(registry
            .list_users(email)
            .into_iter()
            .map(|u| blackwire_api::management::VlessUserRecord {
                email: u.email.clone(),
                uuid: uuid::Uuid::from_bytes(u.uuid).to_string(),
                flow: u.flow.clone(),
                level: 0,
            })
            .collect())
    }

    fn add_vless_user(
        &self,
        inbound_tag: &str,
        email: &str,
        uuid_str: &str,
        flow: &str,
    ) -> Result<(), String> {
        let registry = self
            .vless_registry(inbound_tag)
            .ok_or_else(|| format!("inbound '{inbound_tag}' has no VLESS user registry"))?;
        let uuid = crate::instance::parse_uuid(uuid_str).map_err(|e| e.to_string())?;
        registry.add_user(blackwire_protocol::vless::VlessUser {
            email: email.to_string(),
            uuid,
            flow: flow.to_string(),
        });
        Ok(())
    }

    fn remove_vless_user(&self, inbound_tag: &str, email: &str) -> Result<(), String> {
        let registry = self
            .vless_registry(inbound_tag)
            .ok_or_else(|| format!("inbound '{inbound_tag}' has no VLESS user registry"))?;
        if registry.remove_user_by_email(email) {
            Ok(())
        } else {
            Err(format!(
                "no VLESS user with email '{email}' on inbound '{inbound_tag}'"
            ))
        }
    }
}

impl ReloadState {
    fn vless_registry(&self, inbound_tag: &str) -> Option<Arc<VlessUserRegistry>> {
        if !self
            .inbound_tags
            .read()
            .map(|tags| tags.iter().any(|t| t == inbound_tag))
            .unwrap_or(false)
        {
            return None;
        }
        self.vless_registries
            .get(inbound_tag)
            .map(|r| Arc::clone(r.value()))
    }

    /// Load geo data, reusing the cached matchers when the files haven't changed.
    ///
    /// Checks file size + mtime before re-reading. The expensive part (protobuf
    /// decode + AhoCorasick/regex compilation) is only done when a file changes.
    fn load_geo_data_cached(
        &self,
        config: &Config,
    ) -> (
        HashMap<String, GeoIpMatcher>,
        HashMap<String, GeoSiteMatcher>,
    ) {
        let routing = config.routing.as_ref();
        let geoip_path = routing
            .and_then(|r| r.geoip_file.as_deref())
            .map(str::to_owned);
        let geosite_path = routing
            .and_then(|r| r.geosite_file.as_deref())
            .map(str::to_owned);

        let geoip_fp = geoip_path.as_deref().and_then(file_fingerprint);
        let geosite_fp = geosite_path.as_deref().and_then(file_fingerprint);

        let mut cache = self.geo_cache.lock();

        let geoip_hit = geoip_path == cache.geoip_path
            && (geoip_fp.is_some() && geoip_fp == cache.geoip_fingerprint || geoip_path.is_none());
        let geosite_hit = geosite_path == cache.geosite_path
            && (geosite_fp.is_some() && geosite_fp == cache.geosite_fingerprint
                || geosite_path.is_none());

        // Load from disk only when at least one file needs rebuilding.
        let (fresh_ip, fresh_site) = if !geoip_hit || !geosite_hit {
            load_geo_data(routing)
        } else {
            (HashMap::new(), HashMap::new())
        };

        let geoip = if geoip_hit {
            info!("geo: geoip.dat unchanged; reusing cached matchers");
            cache.geoip.clone()
        } else {
            cache.geoip_fingerprint = geoip_fp;
            cache.geoip_path = geoip_path;
            let cloned = fresh_ip.clone();
            cache.geoip = fresh_ip;
            cloned
        };

        let geosite = if geosite_hit {
            info!("geo: geosite.dat unchanged; reusing cached matchers");
            cache.geosite.clone()
        } else {
            cache.geosite_fingerprint = geosite_fp;
            cache.geosite_path = geosite_path;
            let cloned = fresh_site.clone();
            cache.geosite = fresh_site;
            cloned
        };

        (geoip, geosite)
    }
}

/// Returns inbound tags whose listen address/port changed (requires process restart).
///
/// Matches Xray behavior: listener sockets are not recreated on `reload`.
pub fn inbound_listener_changes(old: &Config, new: &Config) -> Vec<String> {
    let mut changed = Vec::new();
    for new_in in &new.inbounds {
        let Some(old_in) = old.inbounds.iter().find(|i| i.tag == new_in.tag) else {
            changed.push(new_in.tag.clone());
            continue;
        };
        if old_in.listen != new_in.listen || old_in.port != new_in.port {
            changed.push(new_in.tag.clone());
        }
    }
    for new_in in &new.inbounds {
        if !old.inbounds.iter().any(|i| i.tag == new_in.tag) {
            changed.push(new_in.tag.clone());
        }
    }
    changed
}

/// Returns `true` when a validated config change requires rebuilding the running instance.
///
/// Routing, DNS, sniffing, and VLESS user lists are hot-swappable via [`ReloadState::apply`].
/// Structural changes such as listeners, transport wrappers, and outbound definitions
/// need a fresh `Instance` because the handler graph is built at startup.
pub fn requires_instance_restart(old: &Config, new: &Config) -> bool {
    if !inbound_listener_changes(old, new).is_empty() {
        return true;
    }

    if old.metrics_addr != new.metrics_addr || old.api != new.api {
        return true;
    }

    match (
        serde_json::to_value(&old.tun),
        serde_json::to_value(&new.tun),
    ) {
        (Ok(a), Ok(b)) if a != b => return true,
        (Err(_), _) | (_, Err(_)) => return true,
        _ => {}
    }

    match (
        serde_json::to_value(&old.outbounds),
        serde_json::to_value(&new.outbounds),
    ) {
        (Ok(a), Ok(b)) if a != b => return true,
        (Err(_), _) | (_, Err(_)) => return true,
        _ => {}
    }

    if old.inbounds.len() != new.inbounds.len() {
        return true;
    }

    for new_in in &new.inbounds {
        let Some(old_in) = old.inbounds.iter().find(|i| i.tag == new_in.tag) else {
            return true;
        };
        if normalized_inbound_value(old_in) != normalized_inbound_value(new_in) {
            return true;
        }
    }

    false
}

fn normalized_inbound_value(inbound: &blackwire_config::schema::InboundConfig) -> Value {
    let mut value = serde_json::to_value(inbound).unwrap_or(Value::Null);
    let Some(obj) = value.as_object_mut() else {
        return value;
    };

    // Sniffing is hot-swapped separately and VLESS users are refreshed in-place.
    obj.remove("sniffing");
    if inbound.protocol == Protocol::Vless {
        if let Some(settings) = obj.get_mut("settings").and_then(|v| v.as_object_mut()) {
            settings.remove("clients");
        }
    }

    value
}

/// Collect every outbound tag referenced in the config so routing rules can be validated.
fn collect_outbound_tags(config: &Config) -> HashSet<String> {
    let mut tags: HashSet<String> = config.outbounds.iter().map(|o| o.tag.clone()).collect();
    if let Some(routing) = &config.routing {
        for balancer in &routing.balancers {
            tags.insert(balancer.tag.clone());
        }
    }
    tags
}
