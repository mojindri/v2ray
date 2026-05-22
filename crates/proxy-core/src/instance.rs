//! The running proxy instance.
//!
//! `Instance` is the top-level object that holds all the running components:
//! inbound listeners, outbound handlers, dispatcher, and router. Creating and
//! starting an `Instance` is what actually makes the proxy serve traffic.
//!
//! # How it works
//!
//! 1. `Instance::from_config()` reads the config and builds all the handlers.
//! 2. `instance.start()` spawns one Tokio task per inbound listener. Each task
//!    runs a TCP accept loop and calls the inbound handler for each connection.
//! 3. The instance holds `JoinHandle`s for all tasks. If any task panics,
//!    the error is logged but the other tasks keep running.
//!
//! # Transport layering (Phase 4)
//!
//! Each inbound now goes through a layered handler stack:
//!
//!   TCP accept → [TLS] → [WebSocket] → Protocol handler
//!
//! The layers are applied based on `streamSettings.security` and
//! `streamSettings.network` in the config. If neither is set, it is plain TCP.
//!
//! # Hot-reload (Phase 2)
//!
//! When the config file changes, the config manager sends a notification.
//! `Instance` rebuilds the handlers for changed inbounds/outbounds and
//! replaces them without stopping the unchanged ones.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::task::JoinHandle;
use tracing::{error, info};

use proxy_app::dispatcher::{DefaultDispatcher, Dispatcher};
use proxy_app::features::{ConnectionHandler, InboundHandler, OutboundHandler};
use proxy_app::router::{CompiledRule, DomainMatcher, IpMatcher, LiveRouter};
use proxy_common::{BoxedStream, ProxyError};
use proxy_config::schema::{Config, Protocol};
use proxy_protocol::freedom::FreedomOutbound;
use proxy_protocol::socks::Socks5Inbound;
use proxy_protocol::vless::{
    VlessInbound, VlessOutbound, VlessOutboundConfig, VlessUser, VlessUserRegistry,
};

use crate::hysteria2::{build_hysteria2_outbound, start_hysteria2_inbound};
use crate::outbound_transport::{uses_outbound_transport, TransportVlessOutbound};
use crate::reality::{
    build_reality_client, build_reality_server, uses_reality, RealityConnectionHandler,
    RealityVlessOutbound,
};
use crate::trojan::{build_trojan_inbound, build_trojan_outbound};
use crate::ws_tls::{build_conn_handler, uses_tls, uses_ws};

/// The running proxy instance.
pub struct Instance {
    /// Background task handles. Kept alive as long as `Instance` is alive.
    tasks: Vec<JoinHandle<()>>,
}

impl Instance {
    /// Build and start a proxy instance from a validated config.
    ///
    /// This function:
    ///   1. Builds outbound handlers from `config.outbounds`
    ///   2. Builds the router from `config.routing`
    ///   3. Creates the dispatcher
    ///   4. Builds inbound handlers from `config.inbounds`
    ///   5. Starts all inbound listeners
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///   - A listen address is invalid
    ///   - A required config field is missing or malformed
    pub async fn from_config(config: Arc<Config>) -> Result<Self> {
        // ── Step 1: Build outbound handlers ─────────────────────────────────
        let mut outbound_map: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();

        for out_cfg in &config.outbounds {
            let handler: Arc<dyn OutboundHandler> = match out_cfg.protocol {
                Protocol::Freedom => FreedomOutbound::new(&out_cfg.tag),
                Protocol::Vless => build_vless_outbound(out_cfg)
                    .with_context(|| format!("building VLESS outbound '{}'", out_cfg.tag))?,
                Protocol::Hysteria2 => build_hysteria2_outbound(out_cfg)
                    .with_context(|| format!("building Hysteria2 outbound '{}'", out_cfg.tag))?,
                Protocol::Trojan => build_trojan_outbound(out_cfg)
                    .with_context(|| format!("building Trojan outbound '{}'", out_cfg.tag))?,
                ref p => {
                    anyhow::bail!("outbound protocol {:?} not yet implemented", p)
                }
            };
            info!(tag = %handler.tag(), "registered outbound");
            outbound_map.insert(out_cfg.tag.clone(), handler);
        }

        // ── Step 2: Build router ─────────────────────────────────────────────
        let default_tag = config
            .outbounds
            .first()
            .map(|o| o.tag.clone())
            .unwrap_or_else(|| "direct".into());

        let rules = if let Some(routing) = &config.routing {
            build_rules(&routing.rules, &outbound_map)?
        } else {
            vec![]
        };

        let router = LiveRouter::new(rules, default_tag);

        // ── Step 3: Create dispatcher ────────────────────────────────────────
        let dispatcher = DefaultDispatcher::new(router, outbound_map);

        // ── Step 4 & 5: Build inbounds and start listeners ───────────────────
        let mut tasks = Vec::new();

        for in_cfg in &config.inbounds {
            let addr: SocketAddr = format!("{}:{}", in_cfg.listen, in_cfg.port)
                .parse()
                .with_context(|| format!("invalid listen address for inbound '{}'", in_cfg.tag))?;

            // Hysteria2 runs its own QUIC server — it does not use TcpServerTransport.
            if in_cfg.protocol == Protocol::Hysteria2 {
                info!(tag = %in_cfg.tag, addr = %addr, "starting Hysteria2 inbound listener");
                let dispatcher_for_h2 = Arc::clone(&dispatcher) as Arc<dyn Dispatcher>;
                let task = start_hysteria2_inbound(in_cfg, dispatcher_for_h2)
                    .with_context(|| format!("starting Hysteria2 inbound '{}'", in_cfg.tag))?;
                tasks.push(task);
                continue;
            }

            let handler: Arc<dyn InboundHandler> = match in_cfg.protocol {
                Protocol::Socks => Socks5Inbound::new(&in_cfg.tag),
                Protocol::Vless => build_vless_inbound(in_cfg)
                    .with_context(|| format!("building VLESS inbound '{}'", in_cfg.tag))?,
                Protocol::Trojan => build_trojan_inbound(in_cfg)
                    .with_context(|| format!("building Trojan inbound '{}'", in_cfg.tag))?,
                ref p => {
                    anyhow::bail!("inbound protocol {:?} not yet implemented", p)
                }
            };

            info!(tag = %handler.tag(), addr = %addr, "starting inbound listener");

            let dispatcher_for_handler = Arc::clone(&dispatcher) as Arc<dyn Dispatcher>;

            // Choose the connection handler stack based on stream settings.
            let conn_handler: Arc<dyn ConnectionHandler> = if uses_reality(&in_cfg.stream_settings)
            {
                // REALITY: unwrap REALITY TLS camouflage first.
                let reality = build_reality_server(in_cfg)
                    .with_context(|| format!("building REALITY inbound '{}'", in_cfg.tag))?;
                RealityConnectionHandler::new(reality, Arc::clone(&handler), dispatcher_for_handler)
            } else if uses_tls(&in_cfg.stream_settings) || uses_ws(&in_cfg.stream_settings) {
                // Phase 4: TLS and/or WebSocket layering.
                build_conn_handler(handler, dispatcher_for_handler, &in_cfg.stream_settings)
                    .with_context(|| {
                        format!(
                            "building TLS/WS connection handler for inbound '{}'",
                            in_cfg.tag
                        )
                    })?
            } else {
                // Plain TCP: no transport wrapping.
                Arc::new(InboundConnectionHandler {
                    inbound: Arc::clone(&handler),
                    dispatcher: dispatcher_for_handler,
                })
            };

            // Start the TCP accept loop for this inbound.
            let transport = proxy_transport::TcpServerTransport::new(
                proxy_transport::tcp::TcpConfig::default(),
            );
            let task = tokio::spawn(async move {
                if let Err(e) = transport.serve(addr, conn_handler).await {
                    error!(addr = %addr, error = %e, "inbound listener failed");
                }
            });
            tasks.push(task);
        }

        Ok(Self { tasks })
    }

    /// Wait for all inbound listeners to exit.
    ///
    /// In normal operation this runs forever. It only returns if all listeners
    /// have exited (e.g. due to an error).
    ///
    /// After this returns, the `Instance` is empty — tasks have already
    /// completed so `Drop` will call `abort()` on zero handles (no-op).
    pub async fn wait(mut self) {
        // Drain the task list before awaiting. This way the Drop impl
        // (which calls abort on remaining tasks) sees an empty list,
        // which is safe and correct.
        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            let _ = task.await;
        }
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        // Abort all listener tasks when the instance is dropped.
        for task in &self.tasks {
            task.abort();
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Adapter that lets the transport layer call an `InboundHandler` through
/// the `ConnectionHandler` trait.
struct InboundConnectionHandler {
    inbound: Arc<dyn InboundHandler>,
    dispatcher: Arc<dyn Dispatcher>,
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

/// Build a VLESS outbound handler from config.
fn build_vless_outbound(
    cfg: &proxy_config::schema::OutboundConfig,
) -> Result<Arc<dyn OutboundHandler>> {
    // Extract server address and UUID from the settings JSON.
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

/// Build a VLESS inbound handler from config.
fn build_vless_inbound(
    cfg: &proxy_config::schema::InboundConfig,
) -> Result<Arc<dyn InboundHandler>> {
    let registry = VlessUserRegistry::new();

    if let Some(clients) = cfg.settings["clients"].as_array() {
        for client in clients {
            let id_str = client["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("VLESS client missing 'id'"))?;
            let uuid = parse_uuid(id_str)?;
            let email = client["email"].as_str().unwrap_or("").to_string();
            let flow = client["flow"].as_str().unwrap_or("").to_string();
            registry.add_user(VlessUser { email, uuid, flow });
        }
    }

    let fallback = cfg.settings["fallback"]["dest"]
        .as_str()
        .and_then(|s| s.parse::<SocketAddr>().ok());

    Ok(VlessInbound::new(&cfg.tag, registry, fallback))
}

/// Parse a UUID string like "a3482e88-686a-4a58-8126-99c9df64b7bf" into 16 bytes.
fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let uuid = uuid::Uuid::parse_str(s).with_context(|| format!("invalid UUID '{s}'"))?;
    Ok(*uuid.as_bytes())
}

/// Build compiled routing rules from config rules.
fn build_rules(
    rules: &[proxy_config::schema::RoutingRule],
    _outbounds: &HashMap<String, Arc<dyn OutboundHandler>>,
) -> Result<Vec<CompiledRule>> {
    rules
        .iter()
        .map(|r| {
            let mut full = Vec::new();
            let mut suffix = Vec::new();
            let mut keywords = Vec::new();
            let mut regexes = Vec::new();
            let mut ip_ranges = Vec::new();

            for pattern in &r.domain {
                if let Some(rest) = pattern.strip_prefix("domain:") {
                    full.push(rest.to_string());
                } else if let Some(rest) = pattern.strip_prefix("suffix:") {
                    suffix.push(rest.to_string());
                } else if let Some(rest) = pattern.strip_prefix("keyword:") {
                    keywords.push(rest.to_string());
                } else if let Some(rest) = pattern.strip_prefix("regexp:") {
                    regexes.push(rest.to_string());
                } else {
                    // Default to domain exact match
                    full.push(pattern.clone());
                }
            }

            for pattern in &r.ip {
                if !pattern.starts_with("geoip:") {
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

            Ok(proxy_app::router::CompiledRule {
                outbound_tag: r.outbound_tag.clone(),
                domain_matcher,
                ip_matcher,
                port_ranges,
                inbound_tags: r.inbound_tag.clone(),
            })
        })
        .collect()
}

/// Parse a port specification string into a list of (lo, hi) ranges.
///
/// Formats: "443", "80,443", "8000-9000", "80,443,8000-9000"
fn parse_port_ranges(s: &str) -> Result<Vec<(u16, u16)>> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    s.split(',')
        .map(|part| {
            let part = part.trim();
            if let Some((lo, hi)) = part.split_once('-') {
                let lo: u16 = lo.parse().with_context(|| format!("invalid port '{lo}'"))?;
                let hi: u16 = hi.parse().with_context(|| format!("invalid port '{hi}'"))?;
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
