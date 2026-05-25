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

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use tracing::info;

use blackwire_app::router::LiveRouter;
use blackwire_config::schema::{Config, Protocol};
use blackwire_protocol::vless::VlessUserRegistry;

use crate::instance::{build_rules, load_geo_data, populate_vless_registry};

/// Shared reload handles created at startup and updated on each config reload.
///
/// Clone this cheaply — it only bumps reference counts on the inner `Arc`s.
#[derive(Clone)]
pub struct ReloadState {
    /// Live routing table. Swapped atomically via `LiveRouter::swap`.
    pub router: Arc<LiveRouter>,
    /// One VLESS user registry per inbound tag (key = inbound `tag`).
    pub vless_registries: Arc<DashMap<String, Arc<VlessUserRegistry>>>,
}

impl ReloadState {
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

        let (geoip, geosite) = load_geo_data(config.routing.as_ref());
        self.router.swap(rules, default_tag, geoip, geosite);
        info!("routing rules hot-swapped");

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
