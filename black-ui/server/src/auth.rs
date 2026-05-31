use axum::http::{header, HeaderMap};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension};

use crate::{db, error::AppError, state::AppState, util};

const SESSION_COOKIE: &str = "black_ui_session";
const SESSION_MAX_AGE_SECONDS: i64 = 7 * 24 * 60 * 60;

pub fn require(headers: &HeaderMap, state: &AppState) -> Result<i64, AppError> {
    let token = session_token(headers).ok_or_else(AppError::unauthorized)?;
    let conn = state.db.lock().unwrap();
    let row = conn
        .query_row(
            "SELECT admin_id, created_at FROM sessions WHERE token = ?1",
            params![token],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| AppError::internal(e.into()))?;
    let Some((admin_id, created_at)) = row else {
        return Err(AppError::unauthorized());
    };
    let created_at = DateTime::parse_from_rfc3339(&created_at)
        .map_err(|e| AppError::internal(e.into()))?
        .with_timezone(&Utc);
    if created_at + Duration::seconds(SESSION_MAX_AGE_SECONDS) <= Utc::now() {
        conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])
            .map_err(|e| AppError::internal(e.into()))?;
        return Err(AppError::unauthorized());
    }
    Ok(admin_id)
}

pub fn create_admin_session(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<(String, String), AppError> {
    let conn = state.db.lock().unwrap();
    let row = conn
        .query_row(
            "SELECT id, username, password_hash, salt FROM admins WHERE username = ?1",
            params![username.trim()],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|e| AppError::internal(e.into()))?;
    let Some((admin_id, username, expected, salt)) = row else {
        return Err(AppError::unauthorized_message("invalid username or password"));
    };
    if util::hash_password(password, &salt) != expected {
        return Err(AppError::unauthorized_message("invalid username or password"));
    }
    let token = util::random_token(48);
    conn.execute(
        "DELETE FROM sessions WHERE created_at < ?1",
        params![(Utc::now() - Duration::seconds(SESSION_MAX_AGE_SECONDS)).to_rfc3339()],
    )
    .map_err(|e| AppError::internal(e.into()))?;
    conn.execute(
        "INSERT INTO sessions (token, admin_id, created_at) VALUES (?1, ?2, ?3)",
        params![token, admin_id, util::now()],
    )
    .map_err(|e| AppError::internal(e.into()))?;
    Ok((token, username))
}

pub fn create_first_admin(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<(), AppError> {
    if username.trim().is_empty() || password.len() < 8 {
        return Err(AppError::bad_request(
            "username is required and password must be at least 8 characters",
        ));
    }
    let conn = state.db.lock().unwrap();
    if !db::setup_required(&conn).map_err(AppError::internal)? {
        return Err(AppError::bad_request("setup already completed"));
    }
    let salt = util::random_token(24);
    conn.execute(
        "INSERT INTO admins (username, password_hash, salt, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            username.trim(),
            util::hash_password(password, &salt),
            salt,
            util::now()
        ],
    )
    .map_err(|e| AppError::internal(e.into()))?;
    Ok(())
}

pub fn delete_session(headers: &HeaderMap, state: &AppState) -> Result<(), AppError> {
    if let Some(token) = session_token(headers) {
        let conn = state.db.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])
            .map_err(|e| AppError::internal(e.into()))?;
    }
    Ok(())
}

pub fn session_cookie(token: &str) -> String {
    let secure = if std::env::var("BLACK_UI_COOKIE_SECURE")
        .ok()
        .as_deref()
        == Some("1")
    {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_MAX_AGE_SECONDS}{secure}"
    )
}

pub fn expired_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    bearer_token(headers).or_else(|| cookie_token(headers))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{SESSION_COOKIE}=")))
        .filter(|value| !value.is_empty())
}
