//! Outbound transport wrapping for protocol clients.
//!
//! Protocol outbounds such as VLESS and Trojan first dial a server, then write
//! their protocol header. Phase 4 adds optional transport layers in between:
//!
//! ```text
//! TCP -> [TLS] -> [WebSocket] -> VLESS/Trojan header -> proxied bytes
//! ```
//!
//! The inbound side unwraps these layers in reverse order before handing the
//! stream to the protocol handler.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use blackwire_app::context::Context;
use blackwire_app::features::OutboundHandler;
use blackwire_common::{tcp_connect, Address, BoxedStream, ProxyError};
use blackwire_config::schema::{NetworkType, SecurityType, StreamSettingsConfig};
use blackwire_protocol::trojan::{compute_token, connect_trojan_on_stream};
use blackwire_protocol::vless::connect_vless_on_stream;
use blackwire_protocol::vmess::{auth::cmd_key, connect_vmess_on_stream};
use blackwire_transport::{
    grpc_connect, mkcp_connect, shadowtls_v3_connect, tls_connect, ws_connect, MkcpClientConfig,
    WsConnectConfig,
};

/// VLESS outbound that honors `streamSettings.network = "ws"` and
/// `streamSettings.security = "tls"` before sending the VLESS header.
pub(crate) struct TransportVlessOutbound {
    tag: String,
    server: SocketAddr,
    uuid: [u8; 16],
    flow: String,
    stream_settings: Option<StreamSettingsConfig>,
}

impl TransportVlessOutbound {
    pub(crate) fn new(
        tag: impl Into<String>,
        server: SocketAddr,
        uuid: [u8; 16],
        flow: String,
        stream_settings: Option<StreamSettingsConfig>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            server,
            uuid,
            flow,
            stream_settings,
        })
    }
}

#[async_trait]
impl OutboundHandler for TransportVlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        debug!(server = %self.server, dest = %dest, "VLESS transport outbound connecting");
        let stream = connect_transport(self.server, &self.stream_settings).await?;
        connect_vless_on_stream(stream, &self.uuid, &self.flow, dest).await
    }
}

/// Trojan outbound that honors Phase 4 transport settings before sending the
/// Trojan auth token and destination header.
pub(crate) struct TransportTrojanOutbound {
    tag: String,
    server: SocketAddr,
    token: String,
    stream_settings: Option<StreamSettingsConfig>,
}

impl TransportTrojanOutbound {
    pub(crate) fn new(
        tag: impl Into<String>,
        server: SocketAddr,
        password: String,
        stream_settings: Option<StreamSettingsConfig>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            server,
            token: compute_token(&password),
            stream_settings,
        })
    }
}

#[async_trait]
impl OutboundHandler for TransportTrojanOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        debug!(server = %self.server, dest = %dest, "Trojan transport outbound connecting");
        let stream = connect_transport(self.server, &self.stream_settings).await?;
        connect_trojan_on_stream(stream, &self.token, dest).await
    }
}

/// VMess outbound that honors Phase 5 transport settings before sending the
/// VMess AEAD handshake.
pub(crate) struct TransportVmessOutbound {
    tag: String,
    server: SocketAddr,
    uuid: [u8; 16],
    cmd_key: [u8; 16],
    stream_settings: Option<StreamSettingsConfig>,
}

impl TransportVmessOutbound {
    pub(crate) fn new(
        tag: impl Into<String>,
        server: SocketAddr,
        uuid: [u8; 16],
        stream_settings: Option<StreamSettingsConfig>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            server,
            uuid,
            cmd_key: cmd_key(&uuid),
            stream_settings,
        })
    }
}

#[async_trait]
impl OutboundHandler for TransportVmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, _ctx: &Context, dest: &Address) -> Result<BoxedStream, ProxyError> {
        debug!(server = %self.server, dest = %dest, "VMess transport outbound connecting");
        let stream = connect_transport(self.server, &self.stream_settings).await?;
        connect_vmess_on_stream(stream, &self.uuid, &self.cmd_key, dest).await
    }
}

/// Dial TCP, then apply client-side TLS and WebSocket layers from config.
async fn connect_transport(
    server: SocketAddr,
    stream_settings: &Option<StreamSettingsConfig>,
) -> Result<BoxedStream, ProxyError> {
    if uses_kcp(stream_settings) {
        let cfg = build_mkcp_client_config(server, stream_settings)?;
        let stream = mkcp_connect(&cfg)
            .await
            .map_err(|e| ProxyError::Transport(format!("mKCP connect failed: {e}")))?;
        return Ok(Box::new(stream));
    }

    let tcp = tcp_connect(server).await?;
    tcp.set_nodelay(true)?;
    let mut stream: BoxedStream = Box::new(tcp);

    if uses_shadowtls(stream_settings) {
        let shadow = stream_settings
            .as_ref()
            .and_then(|s| s.shadow_tls_settings.as_ref())
            .ok_or_else(|| {
                ProxyError::Protocol("security=shadowtls but no shadowTlsSettings provided".into())
            })?;
        if shadow.version != 3 {
            return Err(ProxyError::Protocol(format!(
                "unsupported ShadowTLS version {}",
                shadow.version
            )));
        }
        if shadow.password.is_empty() || shadow.dest.is_empty() {
            return Err(ProxyError::Protocol(
                "ShadowTLS requires non-empty password and dest".into(),
            ));
        }
        stream = shadowtls_v3_connect(stream, shadow.password.as_bytes(), &shadow.dest).await?;
    }

    if uses_tls(stream_settings) {
        let Some(settings) = stream_settings.as_ref() else {
            return Err(ProxyError::Protocol(
                "security=tls requested without streamSettings".into(),
            ));
        };
        let tls = settings.tls_settings.as_ref();
        let server_name = tls
            .map(|t| t.server_name.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("localhost");
        let allow_insecure = tls.is_some_and(|t| t.allow_insecure);
        let alpn = tls
            .map(|t| t.alpn.iter().map(String::as_str).collect::<Vec<_>>())
            .unwrap_or_default();

        stream = tls_connect(stream, server_name, &alpn, allow_insecure).await?;
    }

    if uses_grpc(stream_settings) {
        let Some(settings) = stream_settings.as_ref() else {
            return Err(ProxyError::Protocol(
                "network=grpc requested without streamSettings".into(),
            ));
        };
        let grpc_cfg = settings.grpc_settings.as_ref();
        let service_name = grpc_cfg
            .map(|g| g.service_name.as_str())
            .unwrap_or("GunService");

        let authority = settings
            .tls_settings
            .as_ref()
            .map(|t| t.server_name.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("localhost");

        stream = grpc_connect(stream, authority, service_name).await?;
        return Ok(stream);
    }

    if uses_ws(stream_settings) {
        let Some(settings) = stream_settings.as_ref() else {
            return Err(ProxyError::Protocol(
                "network=ws requested without streamSettings".into(),
            ));
        };
        let ws = settings.ws_settings.as_ref();
        let mut headers = ws
            .map(|w| {
                w.headers
                    .iter()
                    .filter(|(key, _)| !key.eq_ignore_ascii_case("host"))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // The Host header belongs in WsConnectConfig.host because tungstenite
        // also uses it to build the HTTP upgrade request URI.
        let host = ws
            .and_then(|w| {
                w.headers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("host"))
                    .map(|(_, value)| value.clone())
            })
            .or_else(|| {
                stream_settings
                    .as_ref()
                    .and_then(|s| s.tls_settings.as_ref())
                    .map(|t| t.server_name.clone())
                    .filter(|name| !name.is_empty())
            })
            .unwrap_or_else(|| "localhost".to_string());

        // Keep custom headers deterministic for easier debugging.
        headers.sort_by(|a, b| a.0.cmp(&b.0));

        stream = ws_connect(
            stream,
            WsConnectConfig {
                path: ws
                    .map(|w| w.path.clone())
                    .unwrap_or_else(|| "/".to_string()),
                host,
                headers,
            },
        )
        .await?;
    }

    Ok(stream)
}

pub(crate) fn uses_outbound_transport(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    uses_tls(stream_settings)
        || uses_shadowtls(stream_settings)
        || uses_kcp(stream_settings)
        || uses_ws(stream_settings)
        || uses_grpc(stream_settings)
}

fn uses_grpc(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::Grpc)
}

fn uses_tls(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.security == SecurityType::Tls)
}

fn uses_shadowtls(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.security == SecurityType::ShadowTls)
}

fn uses_ws(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::Ws)
}

fn uses_kcp(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::Kcp)
}

fn build_mkcp_client_config(
    server: SocketAddr,
    stream_settings: &Option<StreamSettingsConfig>,
) -> Result<MkcpClientConfig, ProxyError> {
    let settings = stream_settings
        .as_ref()
        .and_then(|s| s.kcp_settings.as_ref());
    let header = settings
        .map(|k| k.header.parse())
        .transpose()
        .map_err(|e: String| ProxyError::Protocol(e))?
        .unwrap_or_default();

    Ok(MkcpClientConfig {
        server,
        conv: rand::random::<u32>(),
        header,
        interval_ms: settings.map(|k| k.tti).unwrap_or(50),
        rcv_wnd: settings.map(|k| k.read_buffer_size as u16).unwrap_or(128),
        snd_wnd: settings.map(|k| k.write_buffer_size as u16).unwrap_or(128),
        nodelay: true,
    })
}
