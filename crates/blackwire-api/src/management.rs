//! Runtime management surface for Xray-compatible HandlerService gRPC.

use std::sync::Arc;

/// VLESS user row returned by HandlerService queries.
#[derive(Debug, Clone)]
pub struct VlessUserRecord {
    pub email: String,
    pub uuid: String,
    pub flow: String,
    pub level: u32,
}

/// Snapshot of inbound/outbound tags and VLESS user management for the API layer.
pub trait InboundManagement: Send + Sync {
    fn list_inbound_tags(&self) -> Vec<String>;
    fn list_outbound_tags(&self) -> Vec<String>;
    fn vless_user_count(&self, inbound_tag: &str) -> Option<i64>;
    fn list_vless_users(&self, inbound_tag: &str, email: &str) -> Result<Vec<VlessUserRecord>, String>;
    fn add_vless_user(&self, inbound_tag: &str, email: &str, uuid: &str, flow: &str) -> Result<(), String>;
    fn remove_vless_user(&self, inbound_tag: &str, email: &str) -> Result<(), String>;
}

pub type ManagementHandle = Arc<dyn InboundManagement>;
