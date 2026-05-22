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
use tokio::net::TcpStream;
use tracing::debug;

use proxy_app::context::Context;
use proxy_app::features::OutboundHandler;
use proxy_common::{Address, BoxedStream, ProxyError};
use proxy_config::schema::{NetworkType, SecurityType, StreamSettingsConfig};
use proxy_protocol::trojan::{compute_token, connect_trojan_on_stream};
use proxy_protocol::vless::connect_vless_on_stream;
use proxy_transport::{tls_connect, ws_connect, WsConnectConfig};

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

/// Dial TCP, then apply client-side TLS and WebSocket layers from config.
async fn connect_transport(
    server: SocketAddr,
    stream_settings: &Option<StreamSettingsConfig>,
) -> Result<BoxedStream, ProxyError> {
    let tcp = TcpStream::connect(server).await?;
    tcp.set_nodelay(true)?;
    let mut stream: BoxedStream = Box::new(tcp);

    if uses_tls(stream_settings) {
        let settings = stream_settings.as_ref().expect("checked by uses_tls");
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

    if uses_ws(stream_settings) {
        let settings = stream_settings.as_ref().expect("checked by uses_ws");
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
    uses_tls(stream_settings) || uses_ws(stream_settings)
}

fn uses_tls(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.security == SecurityType::Tls)
}

fn uses_ws(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|s| s.network == NetworkType::Ws)
}
