//! Hot-reload helpers for live routing and VLESS user lists.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;
use tracing::info;

use proxy_app::router::LiveRouter;
use proxy_config::schema::{Config, Protocol};
use proxy_protocol::vless::VlessUserRegistry;

use crate::instance::{build_rules, load_geo_data, populate_vless_registry};

/// Shared reload state wired at startup and updated when the config file changes.
#[derive(Clone)]
pub struct ReloadState {
    pub router: Arc<LiveRouter>,
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

fn collect_outbound_tags(config: &Config) -> HashSet<String> {
    let mut tags: HashSet<String> = config.outbounds.iter().map(|o| o.tag.clone()).collect();
    if let Some(routing) = &config.routing {
        for rule in &routing.rules {
            tags.insert(rule.outbound_tag.clone());
        }
        for balancer in &routing.balancers {
            tags.insert(balancer.tag.clone());
            for selector in &balancer.selector {
                tags.insert(selector.clone());
            }
        }
    }
    tags
}
