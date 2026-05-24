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

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use dashmap::DashMap;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use proxy_app::dispatcher::{DefaultDispatcher, Dispatcher};
use proxy_app::dns::{DnsModule, DnsModuleConfig};
use proxy_app::features::{ConnectionHandler, InboundHandler, OutboundHandler};
use proxy_app::geo::loader::{load_geoip, load_geosite};
use proxy_app::health::{HealthChecker, HealthStates, OutboundState};
use proxy_app::router::{CompiledRule, DomainMatcher, IpMatcher, LiveRouter};
use proxy_app::Balancer;
use proxy_common::{BoxedStream, ProxyError};
use proxy_config::schema::{Config, NetworkType, Protocol, SecurityType, StreamSettingsConfig};
use proxy_protocol::freedom::FreedomOutbound;
use proxy_protocol::socks::Socks5Inbound;
use proxy_protocol::vless::{
    VlessInbound, VlessOutbound, VlessOutboundConfig, VlessUser, VlessUserRegistry,
};
use proxy_transport::{mkcp_accept_sessions, MkcpServerConfig, TunRuntime};

use crate::http::build_http_inbound;
use crate::hysteria2::{build_hysteria2_outbound, start_hysteria2_inbound};
use crate::outbound_transport::{uses_outbound_transport, TransportVlessOutbound};
use crate::reality::{
    build_reality_client, build_reality_server, uses_reality, RealityConnectionHandler,
    RealityVlessOutbound,
};
use crate::reload::ReloadState;
use crate::ss2022::{build_ss2022_inbound, build_ss2022_outbound};
use crate::trojan::{build_trojan_inbound, build_trojan_outbound};
use crate::vmess::{build_vmess_inbound, build_vmess_outbound};

use crate::ws_tls::{build_conn_handler, uses_grpc, uses_shadowtls, uses_tls, uses_ws};

/// Running proxy instance plus reload handles for live config updates.
pub struct Instance {
    /// Background task handles. Kept alive as long as `Instance` is alive.
    tasks: Vec<JoinHandle<()>>,
    /// If a TUN runtime is active, sending `true` here triggers graceful
    /// shutdown (which runs `cleanup_routes` before the task exits).
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Hot-reload state shared with the config watcher.
    pub reload: ReloadState,
}

impl fmt::Debug for Instance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Instance")
            .field("task_count", &self.tasks.len())
            .finish()
    }
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
        let mut tasks = Vec::new();
        let mut shutdown_tx: Option<tokio::sync::watch::Sender<bool>> = None;

        // ── Optional: TUN transparent-proxy runtime ──────────────────────────
        if let Some(tun_cfg) = &config.tun {
            use proxy_transport::TunConfig;
            let tc = TunConfig {
                name: tun_cfg.name.clone(),
                address: tun_cfg
                    .address
                    .parse()
                    .with_context(|| format!("invalid TUN address '{}'", tun_cfg.address))?,
                netmask: tun_cfg
                    .netmask
                    .parse()
                    .with_context(|| format!("invalid TUN netmask '{}'", tun_cfg.netmask))?,
                mtu: tun_cfg.mtu,
                bypass_mark: tun_cfg.bypass_mark,
                redirect_port: tun_cfg.redirect_port,
                dns_port: tun_cfg.dns_port,
            };
            let device = proxy_transport::create_tun(&tc)
                .context("TUN device creation failed (are we running as root?)")?;
            let (tx, rx) = tokio::sync::watch::channel(false);
            shutdown_tx = Some(tx);
            let runtime = TunRuntime::new(tc);
            let tun_task = tokio::spawn(async move {
                if let Err(e) = runtime.run(device, rx).await {
                    error!(error = %e, "TUN runtime exited with error");
                }
            });
            tasks.push(tun_task);
            info!("TUN runtime started");
        }

        // ── Step 1: Build outbound handlers ─────────────────────────────────
        let mut outbound_map: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();

        for out_cfg in &config.outbounds {
            reject_unfinished_transport_settings(
                "outbound",
                &out_cfg.tag,
                &out_cfg.stream_settings,
            )?;
            let handler: Arc<dyn OutboundHandler> = match out_cfg.protocol {
                Protocol::Freedom => FreedomOutbound::new(&out_cfg.tag),
                Protocol::Vless => build_vless_outbound(out_cfg)
                    .with_context(|| format!("building VLESS outbound '{}'", out_cfg.tag))?,
                Protocol::Hysteria2 => build_hysteria2_outbound(out_cfg)
                    .with_context(|| format!("building Hysteria2 outbound '{}'", out_cfg.tag))?,
                Protocol::Trojan => build_trojan_outbound(out_cfg)
                    .with_context(|| format!("building Trojan outbound '{}'", out_cfg.tag))?,
                Protocol::Vmess => build_vmess_outbound(out_cfg)
                    .with_context(|| format!("building VMess outbound '{}'", out_cfg.tag))?,
                Protocol::Shadowsocks => build_ss2022_outbound(out_cfg)
                    .with_context(|| format!("building SS-2022 outbound '{}'", out_cfg.tag))?,
                ref p => {
                    anyhow::bail!("outbound protocol {:?} not yet implemented", p)
                }
            };
            info!(tag = %handler.tag(), "registered outbound");
            outbound_map.insert(out_cfg.tag.clone(), handler);
        }

        // ── Step 1b: Build balancer outbounds and health-check tasks ────────
        if let Some(routing) = &config.routing {
            for balancer_cfg in &routing.balancers {
                if outbound_map.contains_key(&balancer_cfg.tag) {
                    anyhow::bail!(
                        "balancer tag '{}' conflicts with an existing outbound",
                        balancer_cfg.tag
                    );
                }

                let selected = select_balancer_outbounds(balancer_cfg, &outbound_map)?;
                let states = if let Some(health_cfg) = &balancer_cfg.health_check {
                    let (checker, states) =
                        HealthChecker::new(selected.clone(), health_cfg.clone()).map_err(|e| {
                            anyhow::anyhow!(
                                "invalid health check for balancer '{}': {e}",
                                balancer_cfg.tag
                            )
                        })?;
                    tasks.push(tokio::spawn(checker.run()));
                    states
                } else {
                    initial_health_states(&selected)
                };

                let balancer = Balancer::new(balancer_cfg, selected, states);
                info!(tag = %balancer.tag(), "registered balancer outbound");
                outbound_map.insert(balancer_cfg.tag.clone(), balancer);
            }
        }

        // ── Step 2: Build router ─────────────────────────────────────────────
        let default_tag = config
            .outbounds
            .first()
            .map(|o| o.tag.clone())
            .unwrap_or_else(|| "direct".into());

        let outbound_tags: HashSet<String> = outbound_map.keys().cloned().collect();

        let rules = if let Some(routing) = &config.routing {
            build_rules(&routing.rules, &outbound_tags)?
        } else {
            vec![]
        };

        let (geoip, geosite) = load_geo_data(config.routing.as_ref());
        let router = LiveRouter::new(rules, default_tag, geoip, geosite);
        let reload = ReloadState {
            router: Arc::clone(&router),
            vless_registries: Arc::new(DashMap::new()),
        };
        let vless_registries = Arc::clone(&reload.vless_registries);

        // ── Step 3: Create dispatcher ────────────────────────────────────────
        let dns = build_dns_module(config.dns.as_ref()).await?;
        let dispatcher = if let Some(dns) = dns {
            DefaultDispatcher::new_with_dns(router, outbound_map, dns)
        } else {
            DefaultDispatcher::new(router, outbound_map)
        };

        // ── Step 4 & 5: Build inbounds and start listeners ───────────────────
        for in_cfg in &config.inbounds {
            reject_unfinished_transport_settings("inbound", &in_cfg.tag, &in_cfg.stream_settings)?;
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
                Protocol::Vless => build_vless_inbound(in_cfg, &vless_registries)
                    .with_context(|| format!("building VLESS inbound '{}'", in_cfg.tag))?,
                Protocol::Trojan => build_trojan_inbound(in_cfg)
                    .with_context(|| format!("building Trojan inbound '{}'", in_cfg.tag))?,
                Protocol::Vmess => build_vmess_inbound(in_cfg)
                    .with_context(|| format!("building VMess inbound '{}'", in_cfg.tag))?,
                Protocol::Http => build_http_inbound(in_cfg)
                    .with_context(|| format!("building HTTP CONNECT inbound '{}'", in_cfg.tag))?,
                Protocol::Shadowsocks => build_ss2022_inbound(in_cfg)
                    .with_context(|| format!("building SS-2022 inbound '{}'", in_cfg.tag))?,
                ref p => {
                    anyhow::bail!("inbound protocol {:?} not yet implemented", p)
                }
            };

            info!(tag = %handler.tag(), addr = %addr, "starting inbound listener");

            let dispatcher_for_handler = Arc::clone(&dispatcher) as Arc<dyn Dispatcher>;

            let handshake_timeout = handshake_timeout_for(in_cfg, &config.limits);

            if uses_kcp(&in_cfg.stream_settings) {
                let conn_handler = Arc::new(HandshakeTimeoutHandler {
                    inner: Arc::new(InboundConnectionHandler {
                        inbound: Arc::clone(&handler),
                        dispatcher: dispatcher_for_handler,
                    }),
                    timeout: handshake_timeout,
                });
                let cfg = build_mkcp_server_config(addr, &in_cfg.stream_settings)
                    .with_context(|| format!("building mKCP inbound '{}'", in_cfg.tag))?;
                let task = tokio::spawn(async move {
                    match mkcp_accept_sessions(&cfg).await {
                        Ok(mut sessions) => {
                            while let Some((stream, peer)) = sessions.recv().await {
                                let conn_handler = Arc::clone(&conn_handler);
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        conn_handler.handle_connection(Box::new(stream), peer).await
                                    {
                                        error!(addr = %addr, error = %e, "mKCP inbound session failed");
                                    }
                                });
                            }
                        }
                        Err(e) => {
                            error!(addr = %addr, error = %e, "mKCP inbound listener failed");
                        }
                    }
                });
                tasks.push(task);
                continue;
            }

            // Choose the connection handler stack based on stream settings.
            let conn_handler: Arc<dyn ConnectionHandler> = {
                let inner: Arc<dyn ConnectionHandler> = if uses_reality(&in_cfg.stream_settings) {
                    // REALITY: unwrap REALITY TLS camouflage first.
                    let reality = build_reality_server(in_cfg)
                        .with_context(|| format!("building REALITY inbound '{}'", in_cfg.tag))?;
                    let cover_sni = in_cfg
                        .stream_settings
                        .as_ref()
                        .and_then(|s| s.reality_settings.as_ref())
                        .map(|r| r.server_name.as_str())
                        .unwrap_or("localhost");
                    RealityConnectionHandler::new(
                        reality,
                        cover_sni,
                        Arc::clone(&handler),
                        dispatcher_for_handler,
                    )
                    .with_context(|| {
                        format!(
                            "building REALITY connection handler for inbound '{}'",
                            in_cfg.tag
                        )
                    })?
                } else if uses_tls(&in_cfg.stream_settings)
                    || uses_shadowtls(&in_cfg.stream_settings)
                    || uses_ws(&in_cfg.stream_settings)
                    || uses_grpc(&in_cfg.stream_settings)
                {
                    // Phase 4/5: TLS, WebSocket, and/or gRPC layering.
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
                Arc::new(HandshakeTimeoutHandler {
                    inner,
                    timeout: handshake_timeout,
                })
            };

            // Start the TCP accept loop for this inbound.
            let tcp_config = proxy_transport::tcp::TcpConfig {
                max_connections: in_cfg
                    .limits
                    .as_ref()
                    .and_then(|limits| limits.max_connections)
                    .or(config.limits.max_connections_per_inbound)
                    .or(config.limits.max_connections),
                ..Default::default()
            };

            let transport = proxy_transport::TcpServerTransport::new(tcp_config);
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding inbound listener '{}'", in_cfg.tag))?;
            let task = tokio::spawn(async move {
                if let Err(e) = transport.serve_listener(listener, conn_handler).await {
                    error!(addr = %addr, error = %e, "inbound listener failed");
                }
            });
            tasks.push(task);
        }

        // ── Optional: start metrics/health HTTP server ───────────────────────
        if let Some(metrics_addr) = &config.metrics_addr {
            let handle = proxy_app::metrics::start_metrics_server(metrics_addr)
                .with_context(|| format!("starting metrics server on '{metrics_addr}'"))?;
            info!(addr = %metrics_addr, "metrics server started");
            tasks.push(handle);
        }

        Ok(Self {
            tasks,
            shutdown_tx,
            reload,
        })
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

impl Instance {
    /// Signal graceful shutdown to the TUN runtime (if active).
    ///
    /// The runtime will run `cleanup_routes` before its task exits. Call this
    /// before `wait()` or before dropping the instance so route cleanup has a
    /// chance to complete.
    pub fn shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(true);
        }
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        // Signal graceful shutdown first so the TUN runtime can clean up
        // iptables rules before we abort the task.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn select_balancer_outbounds(
    cfg: &proxy_config::schema::BalancerConfig,
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

fn initial_health_states(selected: &[(String, Arc<dyn OutboundHandler>)]) -> HealthStates {
    let states = HealthStates::default();
    for (tag, _) in selected {
        states.insert(tag.clone(), OutboundState::default());
    }
    states
}

fn reject_unfinished_transport_settings(
    side: &str,
    tag: &str,
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
                .parse::<proxy_transport::mkcp::header::HeaderType>()
                .map_err(|e| anyhow::anyhow!("{side} '{tag}' has invalid mKCP header: {e}"))?;
        }
    }

    Ok(())
}

fn uses_kcp(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::Kcp)
}

fn build_mkcp_server_config(
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
    routing: Option<&proxy_config::schema::RoutingConfig>,
) -> (
    HashMap<String, proxy_app::geo::GeoIpMatcher>,
    HashMap<String, proxy_app::geo::GeoSiteMatcher>,
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

async fn build_dns_module(
    dns: Option<&proxy_config::schema::DnsConfig>,
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
struct InboundConnectionHandler {
    inbound: Arc<dyn InboundHandler>,
    dispatcher: Arc<dyn Dispatcher>,
}

/// Optional wall-clock limit for inbound handshake phases (REALITY/TLS/VLESS header).
struct HandshakeTimeoutHandler {
    inner: Arc<dyn ConnectionHandler>,
    timeout: Option<Duration>,
}

#[async_trait::async_trait]
impl ConnectionHandler for HandshakeTimeoutHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        if let Some(timeout) = self.timeout {
            match tokio::time::timeout(timeout, self.inner.handle_connection(stream, source)).await
            {
                Ok(result) => result,
                Err(_) => {
                    debug!(?source, ?timeout, "inbound handshake timed out");
                    Err(ProxyError::Timeout)
                }
            }
        } else {
            self.inner.handle_connection(stream, source).await
        }
    }
}

fn handshake_timeout_for(
    in_cfg: &proxy_config::schema::InboundConfig,
    global: &proxy_config::schema::LimitsConfig,
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
    registries: &Arc<DashMap<String, Arc<VlessUserRegistry>>>,
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

    Ok(VlessInbound::new(&cfg.tag, registry, fallback))
}

pub(crate) fn populate_vless_registry(
    registry: &VlessUserRegistry,
    cfg: &proxy_config::schema::InboundConfig,
) -> Result<()> {
    registry.clear();
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
    Ok(())
}

/// Parse a UUID string like "a3482e88-686a-4a58-8126-99c9df64b7bf" into 16 bytes.
pub(crate) fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let uuid = uuid::Uuid::parse_str(s).with_context(|| format!("invalid UUID '{s}'"))?;
    Ok(*uuid.as_bytes())
}

/// Build compiled routing rules from config rules.
pub(crate) fn build_rules(
    rules: &[proxy_config::schema::RoutingRule],
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
                    // Default to domain exact match
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

            Ok(proxy_app::router::CompiledRule {
                outbound_tag: Arc::from(r.outbound_tag.as_str()),
                domain_matcher,
                geosite_codes,
                ip_matcher,
                geoip_codes,
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
