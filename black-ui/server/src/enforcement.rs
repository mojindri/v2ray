use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::params;
use tracing::warn;

use crate::{config, db, runtime, state::AppState, util};

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            let interval = {
                let conn = state.db.lock().unwrap();
                db::load_settings(&conn)
                    .map(|s| s.enforcement_interval_seconds)
                    .unwrap_or(30)
                    .max(5)
            };
            tokio::time::sleep(Duration::from_secs(interval)).await;
            if let Err(e) = run_once(&state).await {
                warn!(error = %e, "quota/expiry enforcement failed");
            }
        }
    });
}

async fn run_once(state: &AppState) -> Result<()> {
    let settings = {
        let conn = state.db.lock().unwrap();
        db::load_settings(&conn)?
    };

    if settings.grpc_enabled {
        if let Ok(snapshot) = runtime::fetch_traffic(&settings.grpc_address).await {
            let conn = state.db.lock().unwrap();
            for u in snapshot.users {
                conn.execute(
                    "UPDATE users SET upload_bytes=?1, download_bytes=?2 WHERE email=?3",
                    params![u.upload_bytes, u.download_bytes, u.email],
                )?;
            }
        }
    }

    let mut changed = false;
    {
        let conn = state.db.lock().unwrap();
        for user in db::load_users(&conn)? {
            if !user.enabled {
                continue;
            }
            let mut status = None;
            if let Some(limit) = user.traffic_limit_bytes {
                if limit > 0 && user.upload_bytes + user.download_bytes >= limit {
                    status = Some("quota exceeded");
                }
            }
            if status.is_none() {
                if let Some(expiry) = &user.expiry_at {
                    if DateTime::parse_from_rfc3339(expiry)?.with_timezone(&Utc) <= Utc::now() {
                        status = Some("expired");
                    }
                }
            }
            if let Some(status) = status {
                conn.execute(
                    "UPDATE users SET enabled=0, enforcement_status=?1, updated_at=?2 WHERE id=?3",
                    params![status, util::now(), user.id],
                )?;
                changed = true;
            }
        }
    }

    if changed {
        let _ = config::write(state);
        if settings.grpc_enabled {
            let _ = runtime::sync_config(state, &settings.grpc_address).await;
        }
    }
    Ok(())
}
