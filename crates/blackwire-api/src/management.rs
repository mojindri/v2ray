//! Runtime management surface for Xray-compatible HandlerService gRPC.

use std::sync::Arc;

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

/// Snapshot of inbound/outbound tags and VLESS user management for the API layer.
pub trait InboundManagement: Send + Sync {
    /// Tags of inbounds in the active config.
    fn list_inbound_tags(&self) -> Vec<String>;
    /// Tags of outbounds in the active config.
    fn list_outbound_tags(&self) -> Vec<String>;
    /// VLESS user count for an inbound tag, or `None` if the tag is unknown.
    fn vless_user_count(&self, inbound_tag: &str) -> Option<i64>;
    /// List VLESS users on an inbound (optional email filter).
    fn list_vless_users(
        &self,
        inbound_tag: &str,
        email: &str,
    ) -> Result<Vec<VlessUserRecord>, String>;
    /// Add or update a VLESS user on an inbound registry.
    fn add_vless_user(
        &self,
        inbound_tag: &str,
        email: &str,
        uuid: &str,
        flow: &str,
    ) -> Result<(), String>;
    /// Remove a VLESS user by email on an inbound registry.
    fn remove_vless_user(&self, inbound_tag: &str, email: &str) -> Result<(), String>;
}

/// Shared handle passed into [`crate::server::start_api_server`].
pub type ManagementHandle = Arc<dyn InboundManagement>;
