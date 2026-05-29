//! Instance construction helpers (outbound/inbound builders, routing, geo).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use blackwire_app::dispatcher::Dispatcher;
use blackwire_app::dns::{DnsModule, DnsModuleConfig};
use blackwire_app::features::{ConnectionHandler, InboundHandler, OutboundHandler};
use blackwire_app::geo::loader::{load_geoip, load_geosite};
use blackwire_app::health::{HealthStates, OutboundState};
use blackwire_app::router::{CompiledRule, DomainMatcher, IpMatcher};
use blackwire_common::{BoxedStream, ProxyError};
use blackwire_config::schema::{NetworkType, Protocol, SecurityType, StreamSettingsConfig};
use blackwire_protocol::vless::{
    VlessInbound, VlessOutbound, VlessOutboundConfig, VlessUser, VlessUserRegistry,
};
use blackwire_transport::MkcpServerConfig;
use dashmap::DashMap;

use crate::outbound_transport::{uses_outbound_transport, TransportVlessOutbound};
use crate::reality::{build_reality_client, uses_reality, RealityVlessOutbound};

pub(crate) fn select_balancer_outbounds(
    cfg: &blackwire_config::schema::BalancerConfig,
    outbounds: &HashMap<String, Arc<dyn OutboundHandler>>,
) -> Result<Vec<(String, Arc<dyn OutboundHandler>)>> {
    if cfg.selector.is_empty() {
        anyhow::bail!("balancer '{}' selector must not be empty", cfg.tag);
    }

    cfg.selector
        .iter()
        .map(|tag| {
            let outbound = outbounds.get(tag).cloned().ok_or_else(|| {
                anyhow::anyhow!("balancer '{}' references missing outbound '{tag}'", cfg.tag)
            })?;
            Ok((tag.clone(), outbound))
        })
        .collect()
}

pub(crate) fn initial_health_states(
    selected: &[(String, Arc<dyn OutboundHandler>)],
) -> HealthStates {
    let states = HealthStates::default();
    for (tag, _) in selected {
        states.insert(tag.clone(), OutboundState::default());
    }
    states
}

pub(crate) fn reject_unfinished_transport_settings(
    side: &str,
    tag: &str,
    _protocol: Protocol,
    stream_settings: &Option<StreamSettingsConfig>,
) -> Result<()> {
    let Some(settings) = stream_settings else {
        return Ok(());
    };

    if settings.security == SecurityType::ShadowTls {
        let shadow = settings.shadow_tls_settings.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "{side} '{tag}' requests security=shadowtls but has no shadowTlsSettings"
            )
        })?;
        if shadow.version != 3 {
            anyhow::bail!(
                "{side} '{tag}' requests unsupported ShadowTLS version {}",
                shadow.version
            );
        }
        if shadow.password.is_empty() || shadow.dest.is_empty() {
            anyhow::bail!("{side} '{tag}' ShadowTLS requires non-empty password and dest");
        }
    }

    if settings.network == NetworkType::Kcp {
        let kcp = settings.kcp_settings.as_ref();
        if let Some(kcp) = kcp {
            kcp.header
                .parse::<blackwire_transport::mkcp::header::HeaderType>()
                .map_err(|e| anyhow::anyhow!("{side} '{tag}' has invalid mKCP header: {e}"))?;
        }
    }

    Ok(())
}

pub(crate) fn uses_kcp(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::Kcp)
}

pub(crate) fn build_mkcp_server_config(
    listen: SocketAddr,
    stream_settings: &Option<StreamSettingsConfig>,
) -> Result<MkcpServerConfig> {
    let settings = stream_settings
        .as_ref()
        .and_then(|s| s.kcp_settings.as_ref());
    let header = settings
        .map(|k| k.header.parse())
        .transpose()
        .map_err(|e: String| anyhow::anyhow!("{e}"))?
        .unwrap_or_default();

    Ok(MkcpServerConfig {
        listen,
        header,
        interval_ms: settings.map(|k| k.tti).unwrap_or(50),
        rcv_wnd: settings.map(|k| k.read_buffer_size as u16).unwrap_or(128),
        snd_wnd: settings.map(|k| k.write_buffer_size as u16).unwrap_or(128),
        nodelay: true,
    })
}

pub(crate) fn load_geo_data(
    routing: Option<&blackwire_config::schema::RoutingConfig>,
) -> (
    HashMap<String, blackwire_app::geo::GeoIpMatcher>,
    HashMap<String, blackwire_app::geo::GeoSiteMatcher>,
) {
    let geoip = routing
        .and_then(|r| r.geoip_file.as_deref())
        .map(load_geoip)
        .unwrap_or_default();
    let geosite = routing
        .and_then(|r| r.geosite_file.as_deref())
        .map(load_geosite)
        .unwrap_or_default();
    (geoip, geosite)
}

pub(crate) async fn build_dns_module(
    dns: Option<&blackwire_config::schema::DnsConfig>,
) -> Result<Option<Arc<DnsModule>>> {
    let Some(dns) = dns else {
        return Ok(None);
    };

    let fake = dns.fake_ip.as_ref();
    let fake_ip_enabled = fake.is_some_and(|cfg| cfg.enabled);
    let fake_ip_range = fake
        .map(|cfg| cfg.pool.clone())
        .unwrap_or_else(|| "198.18.0.0/15".to_string());

    let module = DnsModule::new(DnsModuleConfig {
        servers: dns.servers.clone(),
        fake_ip_enabled,
        fake_ip_range,
        fake_ip_filter: vec!["localhost".into()],
    })
    .await
    .map_err(|e| anyhow::anyhow!("building DNS module: {e}"))?;

    Ok(Some(Arc::new(module)))
}

/// Adapter that lets the transport layer call an `InboundHandler` through
/// the `ConnectionHandler` trait.
pub(crate) struct InboundConnectionHandler {
    pub inbound: Arc<dyn InboundHandler>,
    pub dispatcher: Arc<dyn Dispatcher>,
}

pub(crate) fn handshake_timeout_for(
    in_cfg: &blackwire_config::schema::InboundConfig,
    global: &blackwire_config::schema::LimitsConfig,
) -> Option<Duration> {
    let secs = in_cfg
        .limits
        .as_ref()
        .and_then(|limits| limits.max_handshake_seconds)
        .or(global.max_handshake_seconds)?;
    Some(Duration::from_secs(secs))
}

#[async_trait::async_trait]
impl ConnectionHandler for InboundConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        self.inbound
            .handle(stream, source, Arc::clone(&self.dispatcher))
            .await
    }
}

pub(crate) fn build_vless_outbound(
    cfg: &blackwire_config::schema::OutboundConfig,
) -> Result<Arc<dyn OutboundHandler>> {
    let settings = &cfg.settings;

    let server_str = settings["address"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("VLESS outbound missing 'address'"))?;
    let port = settings["port"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("VLESS outbound missing 'port'"))?;
    let server: SocketAddr = format!("{server_str}:{port}")
        .parse()
        .with_context(|| format!("invalid VLESS server address '{server_str}:{port}'"))?;

    let uuid_str = settings["users"][0]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("VLESS outbound missing users[0].id"))?;
    let uuid = parse_uuid(uuid_str)?;

    let flow = settings["users"][0]["flow"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if uses_reality(&cfg.stream_settings) {
        let reality = build_reality_client(cfg, server)?;
        Ok(RealityVlessOutbound::new(&cfg.tag, reality, uuid, flow))
    } else if uses_outbound_transport(&cfg.stream_settings) {
        Ok(TransportVlessOutbound::new(
            &cfg.tag,
            server,
            uuid,
            flow,
            cfg.stream_settings.clone(),
        ))
    } else {
        Ok(VlessOutbound::new(
            &cfg.tag,
            VlessOutboundConfig { server, uuid, flow },
        ))
    }
}

pub(crate) fn build_vless_inbound(
    cfg: &blackwire_config::schema::InboundConfig,
    registries: &Arc<DashMap<String, Arc<VlessUserRegistry>>>,
    handshake_timeout: Option<Duration>,
) -> Result<Arc<dyn InboundHandler>> {
    #[allow(clippy::unwrap_or_default)]
    let registry = registries
        .entry(cfg.tag.clone())
        .or_insert_with(VlessUserRegistry::new)
        .clone();
    populate_vless_registry(&registry, cfg)?;

    let fallback = cfg.settings["fallback"]["dest"]
        .as_str()
        .and_then(|s| s.parse::<SocketAddr>().ok());

    Ok(VlessInbound::new(
        &cfg.tag,
        registry,
        fallback,
        handshake_timeout,
    ))
}

pub(crate) fn populate_vless_registry(
    registry: &VlessUserRegistry,
    cfg: &blackwire_config::schema::InboundConfig,
) -> Result<()> {
    registry.clear();
    let clients = cfg.settings["clients"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("VLESS inbound '{}' missing 'clients' array", cfg.tag))?;

    if clients.is_empty() {
        anyhow::bail!("VLESS inbound '{}' has no configured clients", cfg.tag);
    }

    for client in clients {
        let id_str = client["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("VLESS client missing 'id'"))?;
        let uuid = parse_uuid(id_str)?;
        let email: std::sync::Arc<str> = client["email"].as_str().unwrap_or("").into();
        let flow = client["flow"].as_str().unwrap_or("").to_string();
        registry.add_user(VlessUser { email, uuid, flow });
    }
    Ok(())
}

pub(crate) fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let uuid = uuid::Uuid::parse_str(s).with_context(|| format!("invalid UUID '{s}'"))?;
    Ok(*uuid.as_bytes())
}

pub(crate) fn build_sniffing_map(
    inbounds: &[blackwire_config::schema::InboundConfig],
) -> std::collections::HashMap<String, Arc<blackwire_config::schema::SniffingConfig>> {
    let mut map = std::collections::HashMap::new();
    for inbound in inbounds {
        if let Some(sniff) = &inbound.sniffing {
            if sniff.enabled {
                map.insert(inbound.tag.clone(), Arc::new(sniff.clone()));
            }
        }
    }
    map
}

pub(crate) fn build_rules(
    rules: &[blackwire_config::schema::RoutingRule],
    outbound_tags: &HashSet<String>,
) -> Result<Vec<CompiledRule>> {
    rules
        .iter()
        .map(|r| {
            if !outbound_tags.contains(&r.outbound_tag) {
                anyhow::bail!(
                    "routing rule references missing outboundTag '{}'",
                    r.outbound_tag
                );
            }

            let mut full = Vec::new();
            let mut suffix = Vec::new();
            let mut keywords = Vec::new();
            let mut regexes = Vec::new();
            let mut geosite_codes = Vec::new();
            let mut ip_ranges = Vec::new();
            let mut geoip_codes = Vec::new();

            for pattern in &r.domain {
                if let Some(rest) = pattern.strip_prefix("domain:") {
                    full.push(rest.to_string());
                } else if let Some(rest) = pattern.strip_prefix("suffix:") {
                    suffix.push(rest.to_string());
                } else if let Some(rest) = pattern.strip_prefix("keyword:") {
                    keywords.push(rest.to_string());
                } else if let Some(rest) = pattern.strip_prefix("regexp:") {
                    regexes.push(rest.to_string());
                } else if let Some(rest) = pattern.strip_prefix("geosite:") {
                    geosite_codes.push(rest.to_uppercase());
                } else {
                    full.push(pattern.clone());
                }
            }

            for pattern in &r.ip {
                if let Some(rest) = pattern.strip_prefix("geoip:") {
                    geoip_codes.push(rest.to_uppercase());
                } else {
                    ip_ranges.push(pattern.clone());
                }
            }

            let domain_matcher = if full.is_empty()
                && suffix.is_empty()
                && keywords.is_empty()
                && regexes.is_empty()
            {
                None
            } else {
                Some(DomainMatcher::new(full, suffix, keywords, regexes)?)
            };

            let ip_matcher = if ip_ranges.is_empty() {
                None
            } else {
                Some(IpMatcher::new(ip_ranges)?)
            };

            let port_ranges = parse_port_ranges(r.port.as_deref().unwrap_or(""))?;

            Ok(blackwire_app::router::CompiledRule {
                outbound_tag: Arc::from(r.outbound_tag.as_str()),
                domain_matcher,
                geosite_codes,
                ip_matcher,
                geoip_codes,
                port_ranges,
                inbound_tags: r.inbound_tag.clone(),
                protocols: r.protocol.clone(),
            })
        })
        .collect()
}

pub(crate) fn parse_port_ranges(s: &str) -> Result<Vec<(u16, u16)>> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    s.split(',')
        .map(|part| {
            let part = part.trim();
            if let Some((lo, hi)) = part.split_once('-') {
                let lo: u16 = lo.parse().with_context(|| format!("invalid port '{lo}'"))?;
                let hi: u16 = hi.parse().with_context(|| format!("invalid port '{hi}'"))?;
                if lo > hi {
                    anyhow::bail!("invalid port range '{part}': lower bound exceeds upper bound");
                }
                Ok((lo, hi))
            } else {
                let p: u16 = part
                    .parse()
                    .with_context(|| format!("invalid port '{part}'"))?;
                Ok((p, p))
            }
        })
        .collect()
}
