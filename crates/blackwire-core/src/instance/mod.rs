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
//! # Transport layering
//!
//! Each inbound now goes through a layered handler stack:
//!
//!   TCP accept → \[TLS\] → \[WebSocket\] → Protocol handler
//!
//! The layers are applied based on `streamSettings.security` and
//! `streamSettings.network` in the config. If neither is set, it is plain TCP.
//!
//! # Hot-reload
//!
//! When the config file changes, `ConfigManager` validates the new JSON and
//! notifies subscribers. `ReloadState::apply()` (in `reload.rs`) then swaps
//! routing rules and VLESS user lists **without** restarting TCP listeners.
//! Outbound handlers and listen ports are still fixed at startup.

use anyhow::{Context as _, Result};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{error, info};

use blackwire_app::dispatcher::{DefaultDispatcher, Dispatcher};
use blackwire_app::features::{ConnectionHandler, InboundHandler, OutboundHandler};
use blackwire_app::health::HealthChecker;
use blackwire_app::router::LiveRouter;
use blackwire_app::Balancer;
use blackwire_config::schema::{Config, Protocol};
use blackwire_protocol::freedom::FreedomOutbound;
use blackwire_protocol::socks::Socks5Inbound;
use blackwire_transport::{mkcp_accept_sessions, TunRuntime};
use tokio::net::UdpSocket as TokioUdpSocket;

use crate::http::build_http_inbound;
use crate::hysteria2::{build_hysteria2_outbound, start_hysteria2_inbound};
use crate::outbound_transport::uses_quic;
mod helpers;

pub(crate) use helpers::{
    build_rules, build_sniffing_map, load_geo_data, parse_uuid, populate_vless_registry,
};

use crate::reality::{build_reality_server, uses_reality, RealityConnectionHandler};
use crate::reload::ReloadState;
use crate::ss2022::{build_ss2022_inbound, build_ss2022_outbound};
use crate::trojan::{build_trojan_inbound, build_trojan_outbound};
use crate::vmess::{build_vmess_inbound, build_vmess_outbound};
use helpers::{
    build_dns_module, build_mkcp_server_config, build_vless_inbound, build_vless_outbound,
    handshake_timeout_for, initial_health_states, reject_unfinished_transport_settings,
    select_balancer_outbounds, InboundConnectionHandler,
};

use crate::ws_tls::{
    build_conn_handler, uses_grpc, uses_httpupgrade, uses_shadowtls, uses_splithttp, uses_tls,
    uses_ws,
};

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
            use blackwire_transport::TunConfig;
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
            let device = blackwire_transport::create_tun(&tc)
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

        // ── Step 1: DNS module (shared by dispatcher + freedom outbounds) ─────
        let dns = build_dns_module(config.dns.as_ref()).await?;

        // ── Step 2: Build outbound handlers ─────────────────────────────────
        let mut outbound_map: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();

        for out_cfg in &config.outbounds {
            reject_unfinished_transport_settings(
                "outbound",
                &out_cfg.tag,
                out_cfg.protocol.clone(),
                &out_cfg.stream_settings,
            )?;
            let handler: Arc<dyn OutboundHandler> = match out_cfg.protocol {
                Protocol::Freedom => match &dns {
                    Some(module) => FreedomOutbound::new_with_dns(&out_cfg.tag, Arc::clone(module)),
                    None => FreedomOutbound::new(&out_cfg.tag),
                },
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
        let domain_strategy = config
            .routing
            .as_ref()
            .and_then(|r| r.domain_strategy.clone());
        let router = LiveRouter::new(rules, default_tag, geoip, geosite, domain_strategy.clone());
        let sniffing_shared =
            Arc::new(ArcSwap::from_pointee(build_sniffing_map(&config.inbounds)));
        // Shared with the config watcher: router swap + VLESS registry refresh on reload.
        let inbound_tags: Arc<std::sync::RwLock<Vec<String>>> = Arc::new(std::sync::RwLock::new(
            config.inbounds.iter().map(|i| i.tag.clone()).collect(),
        ));
        let outbound_tags: Arc<std::sync::RwLock<Vec<String>>> = Arc::new(std::sync::RwLock::new(
            config.outbounds.iter().map(|o| o.tag.clone()).collect(),
        ));
        let reload = ReloadState {
            router: Arc::clone(&router),
            vless_registries: Arc::new(DashMap::new()),
            sniffing: Arc::clone(&sniffing_shared),
            inbound_tags: Arc::clone(&inbound_tags),
            outbound_tags: Arc::clone(&outbound_tags),
        };
        let vless_registries = Arc::clone(&reload.vless_registries);

        // ── Step 4: Create dispatcher ────────────────────────────────────────
        let dispatcher = match &dns {
            Some(dns) => DefaultDispatcher::new_with_dns_and_sniffing(
                router,
                outbound_map,
                Arc::clone(dns),
                Arc::clone(&sniffing_shared),
            ),
            None => DefaultDispatcher::new_with_sniffing(router, outbound_map, sniffing_shared),
        };

        // ── Step 4 & 5: Build inbounds and start listeners ───────────────────
        for in_cfg in &config.inbounds {
            reject_unfinished_transport_settings(
                "inbound",
                &in_cfg.tag,
                in_cfg.protocol.clone(),
                &in_cfg.stream_settings,
            )?;
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

            // SS-2022 UDP: standalone UDP listener (SIP022).
            if in_cfg.protocol == Protocol::Shadowsocks {
                let net = in_cfg
                    .settings
                    .get("network")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tcp");
                if net == "udp" || net == "tcp,udp" || net == "udp,tcp" {
                    let password = in_cfg
                        .settings
                        .get("password")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "SS-2022 UDP inbound '{}' missing 'password'",
                                in_cfg.tag
                            )
                        })?
                        .to_string();
                    let psk = blackwire_protocol::ss2022::password_to_psk(&password);
                    let socket = TokioUdpSocket::bind(addr).await.with_context(|| {
                        format!("binding SS-2022 UDP inbound '{}' on {}", in_cfg.tag, addr)
                    })?;
                    let socket = std::sync::Arc::new(socket);
                    info!(tag = %in_cfg.tag, addr = %addr, "starting SS-2022 UDP inbound");
                    let task = tokio::spawn(async move {
                        blackwire_protocol::ss2022::udp::relay_ss2022_udp(socket, psk).await;
                    });
                    tasks.push(task);
                    if net == "udp" {
                        continue; // UDP-only: skip TCP listener below
                    }
                }
            }

            let handshake_timeout = handshake_timeout_for(in_cfg, &config.limits);

            let handler: Arc<dyn InboundHandler> = match in_cfg.protocol {
                Protocol::Socks => Socks5Inbound::new(&in_cfg.tag),
                Protocol::Vless => {
                    build_vless_inbound(in_cfg, &vless_registries, handshake_timeout)
                        .with_context(|| format!("building VLESS inbound '{}'", in_cfg.tag))?
                }
                Protocol::Trojan => build_trojan_inbound(in_cfg)
                    .with_context(|| format!("building Trojan inbound '{}'", in_cfg.tag))?,
                Protocol::Vmess => build_vmess_inbound(in_cfg)
                    .with_context(|| format!("building VMess inbound '{}'", in_cfg.tag))?,
                Protocol::Http => build_http_inbound(in_cfg, handshake_timeout)
                    .with_context(|| format!("building HTTP CONNECT inbound '{}'", in_cfg.tag))?,
                Protocol::Shadowsocks => build_ss2022_inbound(in_cfg)
                    .with_context(|| format!("building SS-2022 inbound '{}'", in_cfg.tag))?,
                ref p => {
                    anyhow::bail!("inbound protocol {:?} not yet implemented", p)
                }
            };

            info!(tag = %handler.tag(), addr = %addr, "starting inbound listener");

            let dispatcher_for_handler = Arc::clone(&dispatcher) as Arc<dyn Dispatcher>;

            if helpers::uses_kcp(&in_cfg.stream_settings) {
                let conn_handler = Arc::new(InboundConnectionHandler {
                    inbound: Arc::clone(&handler),
                    dispatcher: dispatcher_for_handler,
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

            if uses_quic(&in_cfg.stream_settings) {
                let tls_cfg = in_cfg
                    .stream_settings
                    .as_ref()
                    .and_then(|s| s.tls_settings.as_ref())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "inbound '{}' uses network=quic but has no tlsSettings",
                            in_cfg.tag
                        )
                    })?;
                if tls_cfg.certificate_file.is_empty() || tls_cfg.key_file.is_empty() {
                    anyhow::bail!(
                        "inbound '{}' uses network=quic and requires certificateFile/keyFile",
                        in_cfg.tag
                    );
                }

                let cert_pem =
                    std::fs::read_to_string(&tls_cfg.certificate_file).with_context(|| {
                        format!("cannot read QUIC cert file '{}'", tls_cfg.certificate_file)
                    })?;
                let key_pem = std::fs::read_to_string(&tls_cfg.key_file)
                    .with_context(|| format!("cannot read QUIC key file '{}'", tls_cfg.key_file))?;
                let endpoint = blackwire_transport::quic_server_endpoint(addr, &cert_pem, &key_pem)
                    .with_context(|| format!("binding QUIC inbound '{}'", in_cfg.tag))?;
                let conn_handler = Arc::new(InboundConnectionHandler {
                    inbound: Arc::clone(&handler),
                    dispatcher: dispatcher_for_handler,
                });

                let task = tokio::spawn(async move {
                    while let Some(connecting) = endpoint.accept().await {
                        let conn_handler = Arc::clone(&conn_handler);
                        tokio::spawn(async move {
                            let connection = match connecting.await {
                                Ok(connection) => connection,
                                Err(e) => {
                                    error!(addr = %addr, error = %e, "QUIC connection handshake failed");
                                    return;
                                }
                            };
                            let peer = connection.remote_address();
                            loop {
                                match connection.accept_bi().await {
                                    Ok((send, recv)) => {
                                        let conn_handler = Arc::clone(&conn_handler);
                                        let stream = blackwire_transport::accepted_quic_stream(
                                            connection.clone(),
                                            recv,
                                            send,
                                        );
                                        tokio::spawn(async move {
                                            if let Err(e) =
                                                conn_handler.handle_connection(stream, peer).await
                                            {
                                                error!(addr = %addr, error = %e, "QUIC inbound stream failed");
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        let _ = e;
                                        break;
                                    }
                                }
                            }
                        });
                    }
                });
                tasks.push(task);
                continue;
            }

            // Choose the connection handler stack based on stream settings.
            let conn_handler: Arc<dyn ConnectionHandler> = if uses_reality(&in_cfg.stream_settings)
            {
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
                    handshake_timeout,
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
                || uses_splithttp(&in_cfg.stream_settings)
                || uses_httpupgrade(&in_cfg.stream_settings)
            {
                // Layered transports: TLS, WebSocket, HTTPUpgrade, and/or gRPC.
                build_conn_handler(
                    handler,
                    dispatcher_for_handler,
                    &in_cfg.stream_settings,
                    handshake_timeout,
                )
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
            let tcp_config = blackwire_transport::tcp::TcpConfig {
                max_connections: in_cfg
                    .limits
                    .as_ref()
                    .and_then(|limits| limits.max_connections)
                    .or(config.limits.max_connections_per_inbound)
                    .or(config.limits.max_connections),
                ..Default::default()
            };

            let transport = blackwire_transport::TcpServerTransport::new(tcp_config);
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
        if let Some(api_addr) = config
            .api
            .as_ref()
            .and_then(blackwire_api::server::api_listen_addr)
        {
            let management: blackwire_api::management::ManagementHandle = Arc::new(reload.clone());
            let handle = blackwire_api::server::start_api_server(&api_addr, management)
                .with_context(|| format!("starting blackwire-api gRPC server on '{api_addr}'"))?;
            info!(addr = %api_addr, "blackwire-api gRPC server started");
            tasks.push(handle);
        }

        if let Some(metrics_addr) = &config.metrics_addr {
            let handle = blackwire_app::metrics::start_metrics_server(metrics_addr)
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
