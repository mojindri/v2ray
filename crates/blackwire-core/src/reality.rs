//! REALITY glue used by the instance builder.
//!
//! Protocol crates own VLESS, transport crates own REALITY, and this module
//! wires them together when config asks for `security = "reality"`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};

use blackwire_app::dispatcher::Dispatcher;
use blackwire_app::features::{ConnectionHandler, InboundHandler, OutboundHandler};
use blackwire_common::{with_handshake_timeout, BoxedStream, ProxyError};
use blackwire_config::schema::{SecurityType, StreamSettingsConfig};
use blackwire_protocol::vless::codec::Command;
use blackwire_protocol::vless::connect_vless_on_stream;
use tracing::warn;

use blackwire_transport::{
    complete_tls13_server_handshake, RealityClient, RealityClientConfig, RealityServer,
    RealityServerConfig, Tls13Stream,
};

/// Return true when a config section asks for REALITY transport.
pub(crate) fn uses_reality(stream_settings: &Option<StreamSettingsConfig>) -> bool {
    stream_settings
        .as_ref()
        .is_some_and(|settings| settings.security == SecurityType::Reality)
}

/// Connection adapter that unwraps REALITY before handing bytes to VLESS.
pub(crate) struct RealityConnectionHandler {
    reality: Arc<RealityServer>,
    cover_sni: String,
    handshake_timeout: Option<std::time::Duration>,
    inbound: Arc<dyn InboundHandler>,
    dispatcher: Arc<dyn Dispatcher>,
}

impl RealityConnectionHandler {
    pub(crate) fn new(
        reality: Arc<RealityServer>,
        cover_sni: &str,
        handshake_timeout: Option<std::time::Duration>,
        inbound: Arc<dyn InboundHandler>,
        dispatcher: Arc<dyn Dispatcher>,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            reality,
            cover_sni: if cover_sni.is_empty() {
                "localhost".to_string()
            } else {
                cover_sni.to_string()
            },
            handshake_timeout,
            inbound,
            dispatcher,
        }))
    }
}

#[async_trait::async_trait]
impl ConnectionHandler for RealityConnectionHandler {
    async fn handle_connection(
        &self,
        stream: BoxedStream,
        source: SocketAddr,
    ) -> Result<(), ProxyError> {
        let accepted =
            with_handshake_timeout(self.handshake_timeout, self.reality.accept_with_key(stream))
                .await?;
        let mut stream = accepted.stream;
        // Keep this on the custom TLS path: rustls does not currently negotiate with uTLS REALITY clients.
        let app_keys = with_handshake_timeout(
            self.handshake_timeout,
            complete_tls13_server_handshake(&mut stream, &accepted.auth_key, &self.cover_sni),
        )
        .await
        .map_err(|e| {
            warn!(error = %e, sni = %self.cover_sni, "REALITY Phase 3 TLS handshake failed");
            e
        })?;
        let stream = Box::new(Tls13Stream::new_server(stream, app_keys));
        self.inbound
            .handle(stream, source, Arc::clone(&self.dispatcher))
            .await
            .map_err(|e| {
                warn!(error = %e, "REALITY VLESS inbound failed after TLS");
                e
            })
    }
}

/// VLESS outbound over a REALITY-authenticated TCP stream.
pub(crate) struct RealityVlessOutbound {
    tag: String,
    reality: RealityClient,
    uuid: [u8; 16],
    flow: String,
}

impl RealityVlessOutbound {
    pub(crate) fn new(
        tag: impl Into<String>,
        reality: RealityClient,
        uuid: [u8; 16],
        flow: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            tag: tag.into(),
            reality,
            uuid,
            flow,
        })
    }
}

#[async_trait::async_trait]
impl OutboundHandler for RealityVlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(
        &self,
        _ctx: &blackwire_app::context::Context,
        dest: &blackwire_common::Address,
    ) -> Result<BoxedStream, ProxyError> {
        let stream = self.reality.dial().await?;
        connect_vless_on_stream(stream, &self.uuid, &self.flow, Command::Tcp, dest).await
    }
}

pub(crate) fn build_reality_client(
    cfg: &blackwire_config::schema::OutboundConfig,
    server: SocketAddr,
) -> Result<RealityClient> {
    let reality = cfg
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.reality_settings.as_ref())
        .ok_or_else(|| {
            anyhow::anyhow!("REALITY outbound missing streamSettings.realitySettings")
        })?;

    Ok(RealityClient::new(RealityClientConfig {
        server,
        server_public_key: parse_hex_32(&reality.public_key, "publicKey")?,
        short_id: parse_short_id(&reality.short_id, "shortId")?,
        sni: require_non_empty(&reality.server_name, "serverName")?.to_string(),
        fingerprint: reality.fingerprint.clone(),
    }))
}

pub(crate) fn build_reality_server(
    cfg: &blackwire_config::schema::InboundConfig,
) -> Result<Arc<RealityServer>> {
    let reality = cfg
        .stream_settings
        .as_ref()
        .and_then(|settings| settings.reality_settings.as_ref())
        .ok_or_else(|| anyhow::anyhow!("REALITY inbound missing streamSettings.realitySettings"))?;

    let fallback = require_non_empty(&reality.dest, "dest")?
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid REALITY fallback dest '{}'", reality.dest))?;

    let short_ids = reality
        .short_ids
        .iter()
        .map(|short_id| parse_short_id(short_id, "shortIds[]"))
        .collect::<Result<Vec<_>>>()?;

    if short_ids.is_empty() {
        anyhow::bail!("REALITY inbound requires at least one shortIds entry");
    }

    Ok(Arc::new(RealityServer::new(RealityServerConfig {
        private_key: parse_hex_32(&reality.private_key, "privateKey")?,
        short_ids,
        fallback,
        max_time_diff: reality.max_time_diff as i64,
    })))
}

fn parse_hex_32(value: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(require_non_empty(value, field)?)
        .with_context(|| format!("{field} must be hex"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{field} must be 32 bytes, got {}", bytes.len()))
}

fn parse_short_id(value: &str, field: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(require_non_empty(value, field)?)
        .with_context(|| format!("{field} must be hex"))?;
    if bytes.len() > 8 {
        anyhow::bail!("{field} must be at most 8 bytes");
    }
    Ok(bytes)
}

fn require_non_empty<'a>(value: &'a str, field: &str) -> Result<&'a str> {
    if value.is_empty() {
        anyhow::bail!("{field} must not be empty");
    }
    Ok(value)
}
