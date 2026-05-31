use std::collections::HashMap;

use anyhow::Result;
use blackwire_api::{
    handler_proto::{
        handler_service_client::HandlerServiceClient, AddInboundRequest, AddOutboundRequest,
        AddUserOperation, AlterInboundRequest, AlterOutboundRequest, InboundHandlerConfig,
        ListInboundsRequest, ListOutboundsRequest, OutboundHandlerConfig, RemoveInboundRequest,
        RemoveOutboundRequest, RemoveUserOperation, TypedMessage, User,
    },
    proto::{stats_service_client::StatsServiceClient, GetUsersStatsRequest, QueryStatsRequest},
    vless_account_proto::Account,
};
use prost::Message;
use tonic::transport::Channel;

use crate::{
    config,
    models::{Inbound, InboundTraffic, ManagedUser, TrafficSnapshot, UserTraffic},
    state::AppState,
};

const ADD_USER_TYPE: &str = "xray.app.proxyman.command.AddUserOperation";
const REMOVE_USER_TYPE: &str = "xray.app.proxyman.command.RemoveUserOperation";
const VLESS_ACCOUNT_TYPE: &str = "xray.proxy.vless.Account";

pub async fn probe(addr: &str) -> bool {
    match HandlerServiceClient::connect(format!("http://{addr}")).await {
        Ok(mut client) => client
            .list_inbounds(ListInboundsRequest { is_only_tags: true })
            .await
            .is_ok(),
        Err(_) => false,
    }
}

pub async fn sync_config(state: &AppState, addr: &str) -> Result<()> {
    let value = config::build_value(state)?;
    let channel = Channel::from_shared(format!("http://{addr}"))?
        .connect()
        .await?;
    let mut client = HandlerServiceClient::new(channel);
    let current = client
        .list_inbounds(ListInboundsRequest { is_only_tags: true })
        .await?
        .into_inner()
        .inbounds
        .into_iter()
        .map(|i| i.tag)
        .collect::<Vec<_>>();
    let target_inbounds = value["inbounds"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(is_live_runnable_inbound)
        .collect::<Vec<_>>();
    let target_inbound_tags = target_inbounds
        .iter()
        .filter_map(|inbound| inbound["tag"].as_str())
        .map(ToString::to_string)
        .collect::<std::collections::HashSet<_>>();
    for tag in current
        .iter()
        .filter(|tag| !target_inbound_tags.contains(*tag))
    {
        let _ = client
            .remove_inbound(RemoveInboundRequest {
                tag: tag.to_string(),
            })
            .await;
    }
    let current_inbound_tags = current
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    for inbound in target_inbounds {
        let tag = inbound["tag"].as_str().unwrap_or_default().to_string();
        if current_inbound_tags.contains(&tag) {
            continue;
        }
        client
            .add_inbound(AddInboundRequest {
                inbound: Some(InboundHandlerConfig {
                    tag,
                    receiver_settings: None,
                    proxy_settings: Some(TypedMessage {
                        r#type: "blackwire.config.inbound".into(),
                        value: serde_json::to_vec(&inbound)?,
                    }),
                }),
            })
            .await?;
    }
    let current_outbounds = client
        .list_outbounds(ListOutboundsRequest {})
        .await?
        .into_inner()
        .outbounds
        .into_iter()
        .map(|o| o.tag)
        .collect::<Vec<_>>();
    let target_outbounds = value["outbounds"].as_array().cloned().unwrap_or_default();
    let target_outbound_tags = target_outbounds
        .iter()
        .filter_map(|outbound| outbound["tag"].as_str())
        .map(ToString::to_string)
        .collect::<std::collections::HashSet<_>>();
    for tag in current_outbounds
        .iter()
        .filter(|tag| !target_outbound_tags.contains(*tag))
    {
        let _ = client
            .remove_outbound(RemoveOutboundRequest {
                tag: tag.to_string(),
            })
            .await;
    }
    let current_outbound_tags = current_outbounds
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    for outbound in target_outbounds {
        let tag = outbound["tag"].as_str().unwrap_or_default().to_string();
        let outbound_config = OutboundHandlerConfig {
            tag: tag.clone(),
            sender_settings: None,
            proxy_settings: Some(TypedMessage {
                r#type: "blackwire.config.outbound".into(),
                value: serde_json::to_vec(&outbound)?,
            }),
            expire: 0,
            comment: String::new(),
        };
        if current_outbound_tags.contains(&tag) {
            client
                .alter_outbound(AlterOutboundRequest {
                    tag,
                    operation: outbound_config.proxy_settings,
                })
                .await?;
        } else {
            client
                .add_outbound(AddOutboundRequest {
                    outbound: Some(outbound_config),
                })
                .await?;
        }
    }
    Ok(())
}

fn is_live_runnable_inbound(inbound: &serde_json::Value) -> bool {
    if inbound.get("protocol").and_then(serde_json::Value::as_str) != Some("vless") {
        return true;
    }
    inbound
        .get("settings")
        .and_then(|settings| settings.get("clients"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|clients| !clients.is_empty())
}

pub async fn add_user(addr: &str, inbound: &Inbound, user: &ManagedUser) -> Result<()> {
    let mut client = HandlerServiceClient::connect(format!("http://{addr}")).await?;
    let account = Account {
        id: user.uuid.clone(),
        flow: user.flow.clone(),
        encryption: "none".into(),
    };
    let operation = AddUserOperation {
        user: Some(User {
            level: 0,
            email: user.email.clone(),
            account: Some(TypedMessage {
                r#type: VLESS_ACCOUNT_TYPE.into(),
                value: account.encode_to_vec(),
            }),
        }),
    };
    client
        .alter_inbound(AlterInboundRequest {
            tag: inbound.tag.clone(),
            operation: Some(TypedMessage {
                r#type: ADD_USER_TYPE.into(),
                value: operation.encode_to_vec(),
            }),
        })
        .await?;
    Ok(())
}

pub async fn remove_user(addr: &str, inbound_tag: &str, email: &str) -> Result<()> {
    let mut client = HandlerServiceClient::connect(format!("http://{addr}")).await?;
    let operation = RemoveUserOperation {
        email: email.into(),
    };
    client
        .alter_inbound(AlterInboundRequest {
            tag: inbound_tag.into(),
            operation: Some(TypedMessage {
                r#type: REMOVE_USER_TYPE.into(),
                value: operation.encode_to_vec(),
            }),
        })
        .await?;
    Ok(())
}

pub async fn fetch_traffic(addr: &str) -> Result<TrafficSnapshot> {
    let channel = Channel::from_shared(format!("http://{addr}"))?
        .connect()
        .await?;
    let mut stats = StatsServiceClient::new(channel);
    let users = stats
        .get_users_stats(GetUsersStatsRequest {
            include_traffic: true,
            reset: false,
        })
        .await?
        .into_inner()
        .users
        .into_iter()
        .map(|u| {
            let t = u.traffic.unwrap_or_default();
            UserTraffic {
                email: u.email,
                upload_bytes: t.uplink,
                download_bytes: t.downlink,
            }
        })
        .collect();

    let mut inbound_map: HashMap<String, (i64, i64)> = HashMap::new();
    for stat in stats
        .query_stats(QueryStatsRequest {
            pattern: "inbound>>>".into(),
            reset: false,
        })
        .await?
        .into_inner()
        .stat
    {
        let parts: Vec<_> = stat.name.split(">>>").collect();
        if parts.len() == 4 && parts[2] == "traffic" {
            let e = inbound_map.entry(parts[1].to_string()).or_default();
            match parts[3] {
                "uplink" => e.0 = stat.value,
                "downlink" => e.1 = stat.value,
                _ => {}
            }
        }
    }

    Ok(TrafficSnapshot {
        users,
        inbounds: inbound_map
            .into_iter()
            .map(|(tag, (upload_bytes, download_bytes))| InboundTraffic {
                tag,
                upload_bytes,
                download_bytes,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use blackwire_api::{
        management::{InboundManagement, NativeEndpointConfig, VlessUserRecord},
        server::start_api_server,
    };
    use rusqlite::{params, Connection};

    use crate::{db, state::AppState, util};

    #[derive(Default)]
    struct FakeManagement {
        inbounds: Mutex<Vec<String>>,
        outbounds: Mutex<Vec<String>>,
        operations: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl InboundManagement for FakeManagement {
        async fn list_inbound_tags(&self) -> Vec<String> {
            self.inbounds.lock().unwrap().clone()
        }

        async fn list_outbound_tags(&self) -> Vec<String> {
            self.outbounds.lock().unwrap().clone()
        }

        async fn vless_user_count(&self, _inbound_tag: &str) -> Option<i64> {
            Some(0)
        }

        async fn list_vless_users(
            &self,
            _inbound_tag: &str,
            _email: &str,
        ) -> std::result::Result<Vec<VlessUserRecord>, String> {
            Ok(vec![])
        }

        async fn add_vless_user(
            &self,
            _inbound_tag: &str,
            _email: &str,
            _uuid: &str,
            _flow: &str,
        ) -> std::result::Result<(), String> {
            Ok(())
        }

        async fn remove_vless_user(
            &self,
            _inbound_tag: &str,
            _email: &str,
        ) -> std::result::Result<(), String> {
            Ok(())
        }

        async fn add_inbound(
            &self,
            config: NativeEndpointConfig,
        ) -> std::result::Result<(), String> {
            self.operations
                .lock()
                .unwrap()
                .push(format!("add-inbound:{}", config.tag));
            self.inbounds.lock().unwrap().push(config.tag);
            Ok(())
        }

        async fn remove_inbound(&self, tag: &str) -> std::result::Result<(), String> {
            self.operations
                .lock()
                .unwrap()
                .push(format!("remove-inbound:{tag}"));
            self.inbounds
                .lock()
                .unwrap()
                .retain(|existing| existing != tag);
            Ok(())
        }

        async fn add_outbound(
            &self,
            config: NativeEndpointConfig,
        ) -> std::result::Result<(), String> {
            self.operations
                .lock()
                .unwrap()
                .push(format!("add-outbound:{}", config.tag));
            self.outbounds.lock().unwrap().push(config.tag);
            Ok(())
        }

        async fn remove_outbound(&self, tag: &str) -> std::result::Result<(), String> {
            self.operations
                .lock()
                .unwrap()
                .push(format!("remove-outbound:{tag}"));
            self.outbounds
                .lock()
                .unwrap()
                .retain(|existing| existing != tag);
            Ok(())
        }

        async fn alter_outbound(
            &self,
            config: NativeEndpointConfig,
        ) -> std::result::Result<(), String> {
            self.operations
                .lock()
                .unwrap()
                .push(format!("alter-outbound:{}", config.tag));
            Ok(())
        }
    }

    #[tokio::test]
    async fn sync_config_skips_empty_vless_and_updates_existing_runtime_tags() {
        let data_dir =
            std::env::temp_dir().join(format!("black-ui-runtime-test-{}", util::random_token(8)));
        std::fs::create_dir_all(&data_dir).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn, &data_dir).unwrap();
        db::save_settings(
            &conn,
            &crate::models::Settings {
                config_path: data_dir.join("config.json").to_string_lossy().to_string(),
                grpc_enabled: true,
                grpc_address: "127.0.0.1:0".into(),
                firewall_auto_open: false,
                public_base_url: "http://127.0.0.1:18080".into(),
                subscription_host: "127.0.0.1".into(),
                enforcement_interval_seconds: 30,
                adaptive_routing_enabled: false,
            },
        )
        .unwrap();
        let now = util::now();
        conn.execute(
            "INSERT INTO inbounds (tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at)
             VALUES ('empty-vless', '127.0.0.1', 443, 'vless', 1, 'ws', '', '{\"network\":\"ws\",\"security\":\"none\",\"wsSettings\":{\"path\":\"/empty\"}}', '', '', ?1, ?1)",
            params![now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO inbounds (tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at)
             VALUES ('active-vless', '127.0.0.1', 444, 'vless', 1, 'ws', '', '{\"network\":\"ws\",\"security\":\"none\",\"wsSettings\":{\"path\":\"/active\"}}', '', '', ?1, ?1)",
            params![now],
        )
        .unwrap();
        let active_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO users (inbound_id, email, uuid, flow, credential_json, note, enabled, traffic_limit_bytes, expiry_at, sub_token, enforcement_status, created_at, updated_at)
             VALUES (?1, 'active@example.com', '11111111-1111-4111-8111-111111111111', '', '{}', '', 1, NULL, NULL, 'token', 'active', ?2, ?2)",
            params![active_id, now],
        )
        .unwrap();
        let state = AppState {
            db: Arc::new(Mutex::new(conn)),
        };

        let fake = Arc::new(FakeManagement {
            inbounds: Mutex::new(vec!["stale-inbound".into()]),
            outbounds: Mutex::new(vec!["freedom".into(), "stale-outbound".into()]),
            operations: Mutex::new(vec![]),
        });
        let port = unused_port();
        let handle = start_api_server(&format!("127.0.0.1:{port}"), fake.clone()).unwrap();
        wait_for_probe(port).await;

        sync_config(&state, &format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        handle.abort();

        let operations = fake.operations.lock().unwrap().clone();
        assert!(operations.contains(&"remove-inbound:stale-inbound".into()));
        assert!(operations.contains(&"add-inbound:active-vless".into()));
        assert!(!operations.contains(&"add-inbound:empty-vless".into()));
        assert!(operations.contains(&"remove-outbound:stale-outbound".into()));
        assert!(operations.contains(&"alter-outbound:freedom".into()));
        assert!(!operations.contains(&"add-outbound:freedom".into()));
    }

    fn unused_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn wait_for_probe(port: u16) {
        for _ in 0..80 {
            if probe(&format!("127.0.0.1:{port}")).await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("test gRPC server did not become reachable");
    }
}
