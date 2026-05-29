//! Runtime management surface for Xray-compatible HandlerService gRPC.

use std::sync::Arc;

use async_trait::async_trait;

/// VLESS user row returned by HandlerService queries.
#[derive(Debug, Clone)]
pub struct VlessUserRecord {
    /// Panel email / identifier.
    pub email: String,
    /// VLESS UUID string.
    pub uuid: String,
    /// VLESS flow (e.g. `xtls-rprx-vision`).
    pub flow: String,
    /// User level from Handler `User` message.
    pub level: u32,
}

/// Native blackwire endpoint config supplied through HandlerService.
#[derive(Debug, Clone)]
pub struct NativeEndpointConfig {
    /// Endpoint tag.
    pub tag: String,
    /// Full native endpoint JSON (`InboundConfig` or `OutboundConfig`).
    pub config: serde_json::Value,
}

/// Snapshot of inbound/outbound tags and VLESS user management for the API layer.
#[async_trait]
pub trait InboundManagement: Send + Sync {
    /// Tags of inbounds in the active config.
    async fn list_inbound_tags(&self) -> Vec<String>;
    /// Tags of outbounds in the active config.
    async fn list_outbound_tags(&self) -> Vec<String>;
    /// VLESS user count for an inbound tag, or `None` if the tag is unknown.
    async fn vless_user_count(&self, inbound_tag: &str) -> Option<i64>;
    /// List VLESS users on an inbound (optional email filter).
    async fn list_vless_users(
        &self,
        inbound_tag: &str,
        email: &str,
    ) -> Result<Vec<VlessUserRecord>, String>;
    /// Add or update a VLESS user on an inbound registry.
    async fn add_vless_user(
        &self,
        inbound_tag: &str,
        email: &str,
        uuid: &str,
        flow: &str,
    ) -> Result<(), String>;
    /// Remove a VLESS user by email on an inbound registry.
    async fn remove_vless_user(&self, inbound_tag: &str, email: &str) -> Result<(), String>;

    /// Add an inbound from a full native blackwire endpoint config.
    async fn add_inbound(&self, _config: NativeEndpointConfig) -> Result<(), String> {
        Err("AddInbound is not available from this management handle".into())
    }

    /// Remove an inbound by tag.
    async fn remove_inbound(&self, _tag: &str) -> Result<(), String> {
        Err("RemoveInbound is not available from this management handle".into())
    }

    /// Add an outbound from a full native blackwire endpoint config.
    async fn add_outbound(&self, _config: NativeEndpointConfig) -> Result<(), String> {
        Err("AddOutbound is not available from this management handle".into())
    }

    /// Remove an outbound by tag.
    async fn remove_outbound(&self, _tag: &str) -> Result<(), String> {
        Err("RemoveOutbound is not available from this management handle".into())
    }

    /// Replace an outbound with a full native blackwire endpoint config.
    async fn alter_outbound(&self, _config: NativeEndpointConfig) -> Result<(), String> {
        Err("AlterOutbound is not available from this management handle".into())
    }
}

/// Shared handle passed into [`crate::server::start_api_server`].
pub type ManagementHandle = Arc<dyn InboundManagement>;
