use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::DateTime;
use rusqlite::params;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth, capabilities, config, db,
    error::{ApiResult, AppError},
    models::{
        ApplyResult, BulkInput, CapabilityMap, ConfigSection, ConfigSectionInput, Inbound,
        InboundInput, LoginInput, LoginResponse, ManagedUser, Outbound, OutboundInput,
        ServiceStatus, Settings, SetupInput, Status, TrafficSnapshot, UserInput,
    },
    runtime, service,
    state::AppState,
    util,
};

pub async fn setup(
    State(state): State<AppState>,
    Json(input): Json<SetupInput>,
) -> ApiResult<LoginResponse> {
    auth::create_first_admin(&state, &input.username, &input.password)?;
    login(
        State(state),
        Json(LoginInput {
            username: input.username,
            password: input.password,
        }),
    )
    .await
}

pub async fn login(
    State(state): State<AppState>,
    Json(input): Json<LoginInput>,
) -> ApiResult<LoginResponse> {
    let (token, username) = auth::create_admin_session(&state, &input.username, &input.password)?;
    Ok(Json(LoginResponse { token, username }))
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Value> {
    let _ = auth::require(&headers, &state)?;
    auth::delete_session(&headers, &state)?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Value> {
    let admin_id = auth::require(&headers, &state)?;
    let conn = state.db.lock().unwrap();
    let username: String = conn
        .query_row(
            "SELECT username FROM admins WHERE id=?1",
            params![admin_id],
            |r| r.get(0),
        )
        .map_err(|e| AppError::internal(e.into()))?;
    Ok(Json(json!({ "username": username })))
}

pub async fn capabilities() -> ApiResult<CapabilityMap> {
    Ok(Json(capabilities::blackwire_capabilities()))
}

pub async fn status(State(state): State<AppState>) -> ApiResult<Status> {
    let (settings, setup_required, inbounds, outbounds, users, active_users) = {
        let conn = state.db.lock().unwrap();
        let settings = db::load_settings(&conn).map_err(AppError::internal)?;
        let setup_required = db::setup_required(&conn).map_err(AppError::internal)?;
        let inbounds = db::count(&conn, "inbounds").map_err(AppError::internal)? as usize;
        let outbounds = db::count(&conn, "outbounds").map_err(AppError::internal)? as usize;
        let users = db::count(&conn, "users").map_err(AppError::internal)? as usize;
        let active_users = conn
            .query_row("SELECT COUNT(*) FROM users WHERE enabled=1", [], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(|e| AppError::internal(e.into()))? as usize;
        (
            settings,
            setup_required,
            inbounds,
            outbounds,
            users,
            active_users,
        )
    };
    let grpc_reachable = settings.grpc_enabled && runtime::probe(&settings.grpc_address).await;
    Ok(Json(Status {
        setup_required,
        config_path: settings.config_path.clone(),
        grpc_enabled: settings.grpc_enabled,
        grpc_address: settings.grpc_address.clone(),
        grpc_reachable,
        inbounds,
        outbounds,
        users,
        active_users,
        run_command: format!("blackwire run -c {}", settings.config_path),
    }))
}

pub async fn get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Settings> {
    let _ = auth::require(&headers, &state)?;
    let conn = state.db.lock().unwrap();
    Ok(Json(db::load_settings(&conn).map_err(AppError::internal)?))
}

pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(settings): Json<Settings>,
) -> ApiResult<Settings> {
    let _ = auth::require(&headers, &state)?;
    let conn = state.db.lock().unwrap();
    db::save_settings(&conn, &settings).map_err(AppError::internal)?;
    Ok(Json(settings))
}

pub async fn runtime_probe(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Value> {
    let _ = auth::require(&headers, &state)?;
    let settings = current_settings(&state)?;
    let reachable = runtime::probe(&settings.grpc_address).await;
    Ok(Json(
        json!({ "reachable": reachable, "address": settings.grpc_address }),
    ))
}

pub async fn runtime_traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<TrafficSnapshot> {
    let _ = auth::require(&headers, &state)?;
    let settings = current_settings(&state)?;
    let snapshot = runtime::fetch_traffic(&settings.grpc_address)
        .await
        .unwrap_or(TrafficSnapshot {
            users: vec![],
            inbounds: vec![],
        });
    Ok(Json(snapshot))
}

pub async fn service_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<ServiceStatus> {
    let _ = auth::require(&headers, &state)?;
    Ok(Json(service::blackwire_status()))
}

pub async fn service_restart_blackwire(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<ServiceStatus> {
    let _ = auth::require(&headers, &state)?;
    service::restart_blackwire()
        .map(Json)
        .map_err(AppError::internal)
}

pub async fn service_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<String>> {
    let _ = auth::require(&headers, &state)?;
    Ok(Json(service::recent_logs()))
}

pub async fn list_inbounds(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<crate::models::Inbound>> {
    let _ = auth::require(&headers, &state)?;
    let conn = state.db.lock().unwrap();
    Ok(Json(db::load_inbounds(&conn).map_err(AppError::internal)?))
}

pub async fn create_inbound(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<InboundInput>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    validate_inbound(&input)?;
    {
        let conn = state.db.lock().unwrap();
        let ts = util::now();
        conn.execute(
            "INSERT INTO inbounds (tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            params![
                input.tag.trim(),
                input.listen.trim(),
                input.port,
                input.protocol.as_str(),
                util::bool_i(input.enabled),
                input.transport.as_str(),
                input.settings.unwrap_or_default(),
                input.stream_settings.unwrap_or_default(),
                input.sniffing.unwrap_or_default(),
                input.limits.unwrap_or_default(),
                ts
            ],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    }
    apply_all(&state, true).await
}

pub async fn update_inbound(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<InboundInput>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    validate_inbound(&input)?;
    {
        let conn = state.db.lock().unwrap();
        conn.execute(
            "UPDATE inbounds SET tag=?1, listen=?2, port=?3, protocol=?4, enabled=?5, transport=?6, settings=?7, stream_settings=?8, sniffing=?9, limits=?10, updated_at=?11 WHERE id=?12",
            params![
                input.tag.trim(),
                input.listen.trim(),
                input.port,
                input.protocol.as_str(),
                util::bool_i(input.enabled),
                input.transport.as_str(),
                input.settings.unwrap_or_default(),
                input.stream_settings.unwrap_or_default(),
                input.sniffing.unwrap_or_default(),
                input.limits.unwrap_or_default(),
                util::now(),
                id
            ],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    }
    apply_all(&state, true).await
}

pub async fn delete_inbound(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    {
        let conn = state.db.lock().unwrap();
        let inbound_count = db::count(&conn, "inbounds").map_err(AppError::internal)?;
        if inbound_count <= 1 {
            return Err(AppError::bad_request(
                "at least one inbound is required; create another inbound before deleting this one",
            ));
        }
        if db::load_inbound(&conn, id)
            .map_err(AppError::internal)?
            .is_none()
        {
            return Err(AppError::bad_request("inbound not found"));
        }
        conn.execute("DELETE FROM users WHERE inbound_id=?1", params![id])
            .map_err(|e| AppError::internal(e.into()))?;
        conn.execute("DELETE FROM inbounds WHERE id=?1", params![id])
            .map_err(|e| AppError::internal(e.into()))?;
    }
    apply_all(&state, true).await
}

pub async fn list_outbounds(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<Outbound>> {
    let _ = auth::require(&headers, &state)?;
    let conn = state.db.lock().unwrap();
    Ok(Json(db::load_outbounds(&conn).map_err(AppError::internal)?))
}

pub async fn create_outbound(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OutboundInput>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    validate_outbound(&input)?;
    {
        let conn = state.db.lock().unwrap();
        let ts = util::now();
        conn.execute(
            "INSERT INTO outbounds (tag, protocol, enabled, settings, stream_settings, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![
                input.tag.trim(),
                input.protocol.as_str(),
                util::bool_i(input.enabled),
                input.settings.unwrap_or_else(|| "{}".into()),
                input.stream_settings.unwrap_or_default(),
                ts
            ],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    }
    apply_all(&state, true).await
}

pub async fn update_outbound(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<OutboundInput>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    validate_outbound(&input)?;
    {
        let conn = state.db.lock().unwrap();
        conn.execute(
            "UPDATE outbounds SET tag=?1, protocol=?2, enabled=?3, settings=?4, stream_settings=?5, updated_at=?6 WHERE id=?7",
            params![
                input.tag.trim(),
                input.protocol.as_str(),
                util::bool_i(input.enabled),
                input.settings.unwrap_or_else(|| "{}".into()),
                input.stream_settings.unwrap_or_default(),
                util::now(),
                id
            ],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    }
    apply_all(&state, true).await
}

pub async fn delete_outbound(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    {
        let conn = state.db.lock().unwrap();
        conn.execute("DELETE FROM outbounds WHERE id=?1", params![id])
            .map_err(|e| AppError::internal(e.into()))?;
    }
    apply_all(&state, true).await
}

pub async fn list_config_sections(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<ConfigSection>> {
    let _ = auth::require(&headers, &state)?;
    let conn = state.db.lock().unwrap();
    Ok(Json(db::load_sections(&conn).map_err(AppError::internal)?))
}

pub async fn update_config_section(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(input): Json<ConfigSectionInput>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    validate_section(&name, &input)?;
    {
        let conn = state.db.lock().unwrap();
        conn.execute(
            "INSERT INTO config_sections (name, enabled, value, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled, value=excluded.value, updated_at=excluded.updated_at",
            params![name, util::bool_i(input.enabled), input.value, util::now()],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    }
    apply_all(&state, true).await
}

pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<ManagedUser>> {
    let _ = auth::require(&headers, &state)?;
    let conn = state.db.lock().unwrap();
    Ok(Json(db::load_users(&conn).map_err(AppError::internal)?))
}

pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UserInput>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    validate_user(&input)?;
    let (inbound, user) = {
        let conn = state.db.lock().unwrap();
        if db::load_inbound(&conn, input.inbound_id)
            .map_err(AppError::internal)?
            .is_none()
        {
            return Err(AppError::bad_request("inbound not found"));
        }
        let ts = util::now();
        conn.execute(
            "INSERT INTO users
             (inbound_id, email, uuid, flow, credential_json, note, enabled, traffic_limit_bytes, expiry_at, sub_token, enforcement_status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'active', ?11, ?11)",
            params![
                input.inbound_id,
                input.email.trim(),
                input.uuid.trim(),
                input.flow.unwrap_or_default(),
                serde_json::to_string(&input.credential.unwrap_or_else(|| json!({}))).unwrap_or_else(|_| "{}".into()),
                input.note.unwrap_or_default(),
                util::bool_i(input.enabled),
                input.traffic_limit_bytes,
                input.expiry_at,
                util::random_token(40),
                ts
            ],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
        let id = conn.last_insert_rowid();
        let user = user_or_404(&conn, id)?;
        let inbound = db::load_inbound(&conn, user.inbound_id)
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::bad_request("inbound not found"))?;
        (inbound, user)
    };
    apply_user_change(&state, None, Some((inbound, user))).await
}

pub async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<UserInput>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    validate_user(&input)?;
    let (remove, add) = {
        let conn = state.db.lock().unwrap();
        let old = user_or_404(&conn, id)?;
        let old_inbound = db::load_inbound(&conn, old.inbound_id)
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::bad_request("old inbound not found"))?;
        if db::load_inbound(&conn, input.inbound_id)
            .map_err(AppError::internal)?
            .is_none()
        {
            return Err(AppError::bad_request("inbound not found"));
        }
        conn.execute(
            "UPDATE users SET inbound_id=?1, email=?2, uuid=?3, flow=?4, credential_json=?5, note=?6, enabled=?7,
             traffic_limit_bytes=?8, expiry_at=?9, enforcement_status=CASE WHEN ?7=1 THEN 'active' ELSE 'disabled manually' END,
             updated_at=?10 WHERE id=?11",
            params![
                input.inbound_id,
                input.email.trim(),
                input.uuid.trim(),
                input.flow.unwrap_or_default(),
                serde_json::to_string(&input.credential.unwrap_or_else(|| json!({}))).unwrap_or_else(|_| "{}".into()),
                input.note.unwrap_or_default(),
                util::bool_i(input.enabled),
                input.traffic_limit_bytes,
                input.expiry_at,
                util::now(),
                id
            ],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
        let user = user_or_404(&conn, id)?;
        let inbound = db::load_inbound(&conn, user.inbound_id)
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::bad_request("inbound not found"))?;
        (Some((old_inbound.tag, old.email)), Some((inbound, user)))
    };
    apply_user_change(&state, remove, add).await
}

pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    let remove = {
        let conn = state.db.lock().unwrap();
        let old = user_or_404(&conn, id)?;
        let inbound = db::load_inbound(&conn, old.inbound_id)
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::bad_request("inbound not found"))?;
        conn.execute("DELETE FROM users WHERE id=?1", params![id])
            .map_err(|e| AppError::internal(e.into()))?;
        Some((inbound.tag, old.email))
    };
    apply_user_change(&state, remove, None).await
}

pub async fn enable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<ApplyResult> {
    set_enabled(&state, &headers, id, true).await
}

pub async fn disable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<ApplyResult> {
    set_enabled(&state, &headers, id, false).await
}

async fn set_enabled(
    state: &AppState,
    headers: &HeaderMap,
    id: i64,
    enabled: bool,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(headers, state)?;
    let (remove, add) = {
        let conn = state.db.lock().unwrap();
        let old = user_or_404(&conn, id)?;
        let inbound = db::load_inbound(&conn, old.inbound_id)
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::bad_request("inbound not found"))?;
        db::touch_user_status(
            &conn,
            id,
            enabled,
            if enabled {
                "active"
            } else {
                "disabled manually"
            },
        )
        .map_err(AppError::internal)?;
        let user = user_or_404(&conn, id)?;
        let remove = if enabled {
            None
        } else {
            Some((inbound.tag.clone(), old.email))
        };
        let add = if enabled { Some((inbound, user)) } else { None };
        (remove, add)
    };
    apply_user_change(state, remove, add).await
}

pub async fn reset_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<ManagedUser> {
    let _ = auth::require(&headers, &state)?;
    let conn = state.db.lock().unwrap();
    conn.execute(
        "UPDATE users SET upload_bytes=0, download_bytes=0, updated_at=?1 WHERE id=?2",
        params![util::now(), id],
    )
    .map_err(|e| AppError::internal(e.into()))?;
    Ok(Json(user_or_404(&conn, id)?))
}

pub async fn rotate_uuid(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    let (remove, add) = {
        let conn = state.db.lock().unwrap();
        let old = user_or_404(&conn, id)?;
        let inbound = db::load_inbound(&conn, old.inbound_id)
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::bad_request("inbound not found"))?;
        conn.execute(
            "UPDATE users SET uuid=?1, updated_at=?2 WHERE id=?3",
            params![Uuid::new_v4().to_string(), util::now(), id],
        )
        .map_err(|e| AppError::internal(e.into()))?;
        let user = user_or_404(&conn, id)?;
        (
            Some((inbound.tag.clone(), old.email)),
            Some((inbound, user)),
        )
    };
    apply_user_change(&state, remove, add).await
}

pub async fn rotate_sub_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<ManagedUser> {
    let _ = auth::require(&headers, &state)?;
    let conn = state.db.lock().unwrap();
    conn.execute(
        "UPDATE users SET sub_token=?1, updated_at=?2 WHERE id=?3",
        params![util::random_token(40), util::now(), id],
    )
    .map_err(|e| AppError::internal(e.into()))?;
    Ok(Json(user_or_404(&conn, id)?))
}

pub async fn bulk_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BulkInput>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    {
        let conn = state.db.lock().unwrap();
        for id in input.user_ids {
            match input.action.as_str() {
                "enable" => db::touch_user_status(&conn, id, true, "active"),
                "disable" => db::touch_user_status(&conn, id, false, "disabled manually"),
                "delete" => conn.execute("DELETE FROM users WHERE id=?1", params![id]).map(|_| ()).map_err(Into::into),
                "resetUsage" => conn.execute("UPDATE users SET upload_bytes=0, download_bytes=0, updated_at=?1 WHERE id=?2", params![util::now(), id]).map(|_| ()).map_err(Into::into),
                "setLimit" => conn.execute("UPDATE users SET traffic_limit_bytes=?1, updated_at=?2 WHERE id=?3", params![input.traffic_limit_bytes, util::now(), id]).map(|_| ()).map_err(Into::into),
                "extendExpiry" => conn.execute("UPDATE users SET expiry_at=?1, updated_at=?2 WHERE id=?3", params![input.expiry_at, util::now(), id]).map(|_| ()).map_err(Into::into),
                _ => return Err(AppError::bad_request("unknown bulk action")),
            }
            .map_err(AppError::internal)?;
        }
    }
    apply_all(&state, true).await
}

pub async fn generate_uuid(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Value> {
    let _ = auth::require(&headers, &state)?;
    Ok(Json(json!({ "uuid": Uuid::new_v4().to_string() })))
}

pub async fn config_preview(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Value> {
    let _ = auth::require(&headers, &state)?;
    Ok(Json(
        config::build_value(&state).map_err(AppError::internal)?,
    ))
}

pub async fn config_import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    config::validate_value(&value).map_err(|e| AppError::bad_request(e.to_string()))?;
    import_config_value(&state, value)?;
    apply_all(&state, false).await
}

pub async fn config_validate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    let _ = auth::require(&headers, &state)?;
    let value = config::build_value(&state).map_err(|e| AppError::bad_request(e.to_string()))?;
    config::validate_value(&value).map_err(|e| AppError::bad_request(e.to_string()))?;
    Ok(Json(json!({ "valid": true })))
}

pub async fn config_write(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    config::write(&state).map_err(|e| AppError::bad_request(e.to_string()))?;
    Ok(Json(ApplyResult {
        config_valid: true,
        config_written: true,
        live_applied: false,
        message: "config written".into(),
    }))
}

pub async fn config_apply(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<ApplyResult> {
    let _ = auth::require(&headers, &state)?;
    apply_all(&state, true).await
}

fn import_config_value(state: &AppState, value: Value) -> Result<(), AppError> {
    let conn = state.db.lock().unwrap();
    conn.execute("DELETE FROM users", [])
        .map_err(|e| AppError::internal(e.into()))?;
    conn.execute("DELETE FROM inbounds", [])
        .map_err(|e| AppError::internal(e.into()))?;
    conn.execute("DELETE FROM outbounds", [])
        .map_err(|e| AppError::internal(e.into()))?;

    let ts = util::now();
    for inbound in value
        .get("inbounds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        conn.execute(
            "INSERT INTO inbounds (tag, listen, port, protocol, enabled, transport, settings, stream_settings, sniffing, limits, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                inbound.get("tag").and_then(Value::as_str).unwrap_or("inbound"),
                inbound.get("listen").and_then(Value::as_str).unwrap_or("0.0.0.0"),
                inbound.get("port").and_then(Value::as_u64).unwrap_or(1) as i64,
                inbound.get("protocol").and_then(Value::as_str).unwrap_or("vless"),
                inbound
                    .get("streamSettings")
                    .and_then(|s| s.get("network"))
                    .and_then(Value::as_str)
                    .unwrap_or("tcp"),
                json_text(inbound.get("settings")),
                json_text(inbound.get("streamSettings")),
                json_text(inbound.get("sniffing")),
                json_text(inbound.get("limits")),
                ts
            ],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    }

    for outbound in value
        .get("outbounds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        conn.execute(
            "INSERT INTO outbounds (tag, protocol, enabled, settings, stream_settings, created_at, updated_at)
             VALUES (?1, ?2, 1, ?3, ?4, ?5, ?5)",
            params![
                outbound.get("tag").and_then(Value::as_str).unwrap_or("outbound"),
                outbound.get("protocol").and_then(Value::as_str).unwrap_or("freedom"),
                json_text(outbound.get("settings")),
                json_text(outbound.get("streamSettings")),
                ts
            ],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    }

    for name in [
        "log",
        "dns",
        "routing",
        "tun",
        "limits",
        "stats",
        "api",
        "metricsAddr",
        "profile",
        "fast",
    ] {
        let section = value.get(name);
        conn.execute(
            "INSERT INTO config_sections (name, enabled, value, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled, value=excluded.value, updated_at=excluded.updated_at",
            params![
                name,
                util::bool_i(section.is_some()),
                json_text(section),
                ts
            ],
        )
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    }
    Ok(())
}

fn json_text(value: Option<&Value>) -> String {
    value
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into()))
        .unwrap_or_default()
}

async fn apply_all(state: &AppState, try_live: bool) -> ApiResult<ApplyResult> {
    config::write(state).map_err(|e| AppError::bad_request(e.to_string()))?;
    let settings = current_settings(state)?;
    if !try_live || !settings.grpc_enabled {
        return Ok(Json(ApplyResult {
            config_valid: true,
            config_written: true,
            live_applied: false,
            message: "config saved; live gRPC disabled".into(),
        }));
    }
    if !runtime::probe(&settings.grpc_address).await {
        return Ok(Json(ApplyResult {
            config_valid: true,
            config_written: true,
            live_applied: false,
            message: "config saved; gRPC unavailable, restart or reload required".into(),
        }));
    }
    match runtime::sync_config(state, &settings.grpc_address).await {
        Ok(()) => Ok(Json(ApplyResult {
            config_valid: true,
            config_written: true,
            live_applied: true,
            message: "config saved and live runtime synchronized".into(),
        })),
        Err(e) => Ok(Json(ApplyResult {
            config_valid: true,
            config_written: true,
            live_applied: false,
            message: format!("config saved; live apply failed: {e}"),
        })),
    }
}

async fn apply_user_change(
    state: &AppState,
    remove: Option<(String, String)>,
    add: Option<(Inbound, ManagedUser)>,
) -> ApiResult<ApplyResult> {
    config::write(state).map_err(|e| AppError::bad_request(e.to_string()))?;
    let settings = current_settings(state)?;
    if !settings.grpc_enabled {
        return Ok(Json(ApplyResult {
            config_valid: true,
            config_written: true,
            live_applied: false,
            message: "config saved; live gRPC disabled".into(),
        }));
    }
    if !runtime::probe(&settings.grpc_address).await {
        return Ok(Json(ApplyResult {
            config_valid: true,
            config_written: true,
            live_applied: false,
            message: "config saved; gRPC unavailable, restart or reload required".into(),
        }));
    }

    let mut failures = Vec::new();
    if let Some((tag, email)) = remove {
        if let Err(e) = runtime::remove_user(&settings.grpc_address, &tag, &email).await {
            if let Err(sync_error) = runtime::sync_config(state, &settings.grpc_address).await {
                failures.push(format!(
                    "remove {email}: {e}; full sync failed: {sync_error}"
                ));
            }
        }
    }
    if let Some((inbound, user)) = add {
        if inbound.enabled && user.enabled && user.enforcement_status == "active" {
            if inbound.protocol == "vless" {
                if let Err(e) = runtime::add_user(&settings.grpc_address, &inbound, &user).await {
                    if let Err(sync_error) = runtime::sync_config(state, &settings.grpc_address).await {
                        failures.push(format!(
                            "add {}: {e}; full sync failed: {sync_error}",
                            user.email
                        ));
                    }
                }
            } else if let Err(e) = runtime::sync_config(state, &settings.grpc_address).await {
                failures.push(format!("sync config for {}: {e}", inbound.protocol));
            }
        }
    }

    if failures.is_empty() {
        Ok(Json(ApplyResult {
            config_valid: true,
            config_written: true,
            live_applied: true,
            message: "config saved and live user operation synchronized".into(),
        }))
    } else {
        Ok(Json(ApplyResult {
            config_valid: true,
            config_written: true,
            live_applied: false,
            message: format!(
                "config saved; live user operation failed: {}",
                failures.join("; ")
            ),
        }))
    }
}

pub async fn subscription_base64(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    match subscription_link(&state, &token) {
        Ok(link) => {
            let body = general_purpose::STANDARD.encode(link);
            ([("content-type", "text/plain; charset=utf-8")], body).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn subscription_raw(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    match subscription_link(&state, &token) {
        Ok(link) => ([("content-type", "text/plain; charset=utf-8")], link).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn subscription_link(state: &AppState, token: &str) -> anyhow::Result<String> {
    let conn = state.db.lock().unwrap();
    let settings = db::load_settings(&conn)?;
    let user = db::load_user_by_token(&conn, token)?.ok_or_else(|| anyhow::anyhow!("not found"))?;
    if !user.enabled || user.enforcement_status != "active" {
        anyhow::bail!("user disabled");
    }
    if let Some(expiry) = &user.expiry_at {
        if DateTime::parse_from_rfc3339(expiry)?.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
            anyhow::bail!("user expired");
        }
    }
    if let Some(limit) = user.traffic_limit_bytes {
        if limit > 0 && user.upload_bytes + user.download_bytes >= limit {
            anyhow::bail!("quota exceeded");
        }
    }
    let inbound = db::load_inbound(&conn, user.inbound_id)?
        .ok_or_else(|| anyhow::anyhow!("inbound missing"))?;
    config::subscription_link(&settings, &inbound, &user)
}

fn current_settings(state: &AppState) -> Result<Settings, AppError> {
    let conn = state.db.lock().unwrap();
    db::load_settings(&conn).map_err(AppError::internal)
}

fn user_or_404(conn: &rusqlite::Connection, id: i64) -> Result<ManagedUser, AppError> {
    db::load_user(conn, id)
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::bad_request("user not found"))
}

fn validate_inbound(input: &InboundInput) -> Result<(), AppError> {
    if input.tag.trim().is_empty() || input.listen.trim().is_empty() {
        return Err(AppError::bad_request("tag and listen are required"));
    }
    if !matches!(
        input.protocol.as_str(),
        "socks" | "http" | "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria2"
    ) {
        return Err(AppError::bad_request("unsupported inbound protocol"));
    }
    if !matches!(
        input.transport.as_str(),
        "tcp" | "ws" | "reality" | "grpc" | "httpupgrade" | "splithttp" | "kcp" | "quic"
    ) {
        return Err(AppError::bad_request("unsupported inbound transport"));
    }
    validate_optional_json("settings", input.settings.as_deref())?;
    validate_optional_json("streamSettings", input.stream_settings.as_deref())?;
    validate_optional_json("sniffing", input.sniffing.as_deref())?;
    validate_optional_json("limits", input.limits.as_deref())?;
    Ok(())
}

fn validate_outbound(input: &OutboundInput) -> Result<(), AppError> {
    if input.tag.trim().is_empty() {
        return Err(AppError::bad_request("tag is required"));
    }
    if !matches!(
        input.protocol.as_str(),
        "freedom" | "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria2"
    ) {
        return Err(AppError::bad_request("unsupported outbound protocol"));
    }
    validate_optional_json("settings", input.settings.as_deref())?;
    validate_optional_json("streamSettings", input.stream_settings.as_deref())?;
    Ok(())
}

fn validate_section(name: &str, input: &ConfigSectionInput) -> Result<(), AppError> {
    if !matches!(
        name,
        "log"
            | "dns"
            | "routing"
            | "tun"
            | "limits"
            | "stats"
            | "api"
            | "metricsAddr"
            | "profile"
            | "fast"
    ) {
        return Err(AppError::bad_request("unknown config section"));
    }
    serde_json::from_str::<Value>(&input.value)
        .map_err(|e| AppError::bad_request(format!("invalid {name} JSON: {e}")))?;
    Ok(())
}

fn validate_optional_json(label: &str, raw: Option<&str>) -> Result<(), AppError> {
    if let Some(raw) = raw {
        if !raw.trim().is_empty() {
            serde_json::from_str::<Value>(raw)
                .map_err(|e| AppError::bad_request(format!("invalid {label} JSON: {e}")))?;
        }
    }
    Ok(())
}

fn validate_user(input: &UserInput) -> Result<(), AppError> {
    if input.email.trim().is_empty() {
        return Err(AppError::bad_request("email is required"));
    }
    Uuid::parse_str(input.uuid.trim())
        .map_err(|e| AppError::bad_request(format!("invalid UUID: {e}")))?;
    if let Some(limit) = input.traffic_limit_bytes {
        if limit < 0 {
            return Err(AppError::bad_request("traffic limit must be positive"));
        }
    }
    if let Some(expiry) = &input.expiry_at {
        DateTime::parse_from_rfc3339(expiry)
            .map_err(|e| AppError::bad_request(format!("invalid expiry_at: {e}")))?;
    }
    Ok(())
}
