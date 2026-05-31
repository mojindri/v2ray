use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub config_path: String,
    pub grpc_enabled: bool,
    pub grpc_address: String,
    pub public_base_url: String,
    pub subscription_host: String,
    pub enforcement_interval_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub setup_required: bool,
    pub config_path: String,
    pub grpc_enabled: bool,
    pub grpc_address: String,
    pub grpc_reachable: bool,
    pub inbounds: usize,
    pub outbounds: usize,
    pub users: usize,
    pub active_users: usize,
    pub run_command: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Inbound {
    pub id: i64,
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub protocol: String,
    pub enabled: bool,
    pub transport: String,
    pub settings: String,
    pub stream_settings: String,
    pub sniffing: String,
    pub limits: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundInput {
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub protocol: String,
    pub enabled: bool,
    pub transport: String,
    pub settings: Option<String>,
    pub stream_settings: Option<String>,
    pub sniffing: Option<String>,
    pub limits: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Outbound {
    pub id: i64,
    pub tag: String,
    pub protocol: String,
    pub enabled: bool,
    pub settings: String,
    pub stream_settings: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundInput {
    pub tag: String,
    pub protocol: String,
    pub enabled: bool,
    pub settings: Option<String>,
    pub stream_settings: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSection {
    pub name: String,
    pub enabled: bool,
    pub value: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSectionInput {
    pub enabled: bool,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ManagedUser {
    pub id: i64,
    pub inbound_id: i64,
    pub email: String,
    pub uuid: String,
    pub flow: String,
    pub credential: Value,
    pub note: String,
    pub enabled: bool,
    pub traffic_limit_bytes: Option<i64>,
    pub expiry_at: Option<String>,
    pub upload_bytes: i64,
    pub download_bytes: i64,
    pub sub_token: String,
    pub enforcement_status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInput {
    pub inbound_id: i64,
    pub email: String,
    pub uuid: String,
    pub flow: Option<String>,
    pub credential: Option<Value>,
    pub note: Option<String>,
    pub enabled: bool,
    pub traffic_limit_bytes: Option<i64>,
    pub expiry_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkInput {
    pub user_ids: Vec<i64>,
    pub action: String,
    pub traffic_limit_bytes: Option<i64>,
    pub expiry_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupInput {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginInput {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyResult {
    pub config_valid: bool,
    pub config_written: bool,
    pub live_applied: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSnapshot {
    pub users: Vec<UserTraffic>,
    pub inbounds: Vec<InboundTraffic>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityMap {
    pub protocols: Vec<CapabilityItem>,
    pub transports: Vec<CapabilityItem>,
    pub security: Vec<CapabilityItem>,
    pub config: Vec<CapabilityItem>,
    pub runtime: Vec<CapabilityItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityItem {
    pub key: &'static str,
    pub label: &'static str,
    pub status: &'static str,
    pub notes: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub systemd_available: bool,
    pub active_state: String,
    pub sub_state: String,
    pub logs: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserTraffic {
    pub email: String,
    pub upload_bytes: i64,
    pub download_bytes: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundTraffic {
    pub tag: String,
    pub upload_bytes: i64,
    pub download_bytes: i64,
}
