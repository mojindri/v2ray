use axum::{
    routing::{get, post, put},
    Router,
};
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};

use crate::{handlers, state::AppState};

pub fn router(state: AppState) -> Router {
    let static_dir =
        std::env::var("BLACK_UI_STATIC_DIR").unwrap_or_else(|_| "black-ui/frontend/dist".into());
    Router::new()
        .nest("/api", api_router())
        .route("/sub/{token}", get(handlers::subscription_base64))
        .route("/sub/{token}/raw", get(handlers::subscription_raw))
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
        .with_state(state)
        .layer(cors_layer())
        .layer(TraceLayer::new_for_http())
}

fn cors_layer() -> CorsLayer {
    if std::env::var("BLACK_UI_DEV_CORS").ok().as_deref() == Some("1") {
        CorsLayer::permissive()
    } else {
        CorsLayer::new()
    }
}

fn api_router() -> Router<AppState> {
    Router::new()
        .route("/auth/setup", post(handlers::setup))
        .route("/auth/login", post(handlers::login))
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/me", get(handlers::me))
        .route("/capabilities", get(handlers::capabilities))
        .route("/status", get(handlers::status))
        .route(
            "/settings",
            get(handlers::get_settings).put(handlers::update_settings),
        )
        .route("/runtime/probe", post(handlers::runtime_probe))
        .route("/runtime/traffic", get(handlers::runtime_traffic))
        .route("/service/status", get(handlers::service_status))
        .route(
            "/service/restart-blackwire",
            post(handlers::service_restart_blackwire),
        )
        .route("/service/logs", get(handlers::service_logs))
        .route(
            "/inbounds",
            get(handlers::list_inbounds).post(handlers::create_inbound),
        )
        .route(
            "/inbounds/{id}",
            put(handlers::update_inbound).delete(handlers::delete_inbound),
        )
        .route(
            "/outbounds",
            get(handlers::list_outbounds).post(handlers::create_outbound),
        )
        .route(
            "/outbounds/{id}",
            put(handlers::update_outbound).delete(handlers::delete_outbound),
        )
        .route(
            "/users",
            get(handlers::list_users).post(handlers::create_user),
        )
        .route(
            "/users/{id}",
            put(handlers::update_user).delete(handlers::delete_user),
        )
        .route("/users/{id}/enable", post(handlers::enable_user))
        .route("/users/{id}/disable", post(handlers::disable_user))
        .route("/users/{id}/reset-usage", post(handlers::reset_usage))
        .route("/users/{id}/rotate-uuid", post(handlers::rotate_uuid))
        .route(
            "/users/{id}/rotate-sub-token",
            post(handlers::rotate_sub_token),
        )
        .route("/users/bulk", post(handlers::bulk_users))
        .route("/uuid", post(handlers::generate_uuid))
        .route("/config/sections", get(handlers::list_config_sections))
        .route(
            "/config/sections/{name}",
            put(handlers::update_config_section),
        )
        .route("/config/preview", get(handlers::config_preview))
        .route("/config/import", post(handlers::config_import))
        .route("/config/validate", post(handlers::config_validate))
        .route("/config/write", post(handlers::config_write))
        .route("/config/apply", post(handlers::config_apply))
}
