use anyhow::Result;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use chrono::Duration;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::users::UserManager;

#[derive(Clone)]
pub struct ApiState {
    pub user_manager: Arc<UserManager>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub quota_gb: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: i64,
    pub username: String,
    pub api_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub user_id: i64,
    pub username: String,
    pub api_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub name: Option<String>,
    pub expires_days: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    pub name: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub quota_used_percentage: f64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

/// Extract Bearer token from Authorization header
fn extract_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| {
            if auth.starts_with("Bearer ") {
                Some(auth[7..].to_string())
            } else {
                None
            }
        })
}

/// Register a new user
pub async fn register(
    State(state): State<ApiState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ErrorResponse> {
    // Validate input
    if req.username.is_empty() || req.email.is_empty() || req.password.len() < 8 {
        return Err(ErrorResponse {
            error: "Invalid input: username and email must not be empty, password must be at least 8 characters".to_string(),
        });
    }

    // Create user
    let quota_bytes = req.quota_gb.map(|gb| (gb as i64) * 1024 * 1024 * 1024);
    let user = state
        .user_manager
        .create_user(&req.username, &req.email, &req.password, quota_bytes)
        .await
        .map_err(|e| ErrorResponse {
            error: format!("Failed to create user: {}", e),
        })?;

    // Create initial API token
    let token = state
        .user_manager
        .create_api_token(user.id, Some("Initial token".to_string()), None)
        .await
        .map_err(|e| ErrorResponse {
            error: format!("Failed to create token: {}", e),
        })?;

    Ok(Json(RegisterResponse {
        user_id: user.id,
        username: user.username,
        api_token: token,
    }))
}

/// Login with username and password
pub async fn login(
    State(state): State<ApiState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ErrorResponse> {
    let user = state
        .user_manager
        .authenticate(&req.username, &req.password)
        .await
        .map_err(|e| ErrorResponse {
            error: format!("Authentication failed: {}", e),
        })?
        .ok_or_else(|| ErrorResponse {
            error: "Invalid username or password".to_string(),
        })?;

    // Create new API token
    let token = state
        .user_manager
        .create_api_token(
            user.id,
            Some("Login token".to_string()),
            Some(Duration::days(30)),
        )
        .await
        .map_err(|e| ErrorResponse {
            error: format!("Failed to create token: {}", e),
        })?;

    Ok(Json(LoginResponse {
        user_id: user.id,
        username: user.username,
        api_token: token,
    }))
}

/// Get current user info
pub async fn get_user_info(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<UserInfoResponse>, ErrorResponse> {
    let token = extract_token(&headers).ok_or(ErrorResponse {
        error: "Missing or invalid authorization header".to_string(),
    })?;

    let user = state
        .user_manager
        .authenticate_token(&token)
        .await
        .map_err(|e| ErrorResponse {
            error: format!("Authentication failed: {}", e),
        })?
        .ok_or_else(|| ErrorResponse {
            error: "Invalid or expired token".to_string(),
        })?;

    let quota_used_percentage = if user.quota_bytes > 0 {
        (user.used_bytes as f64 / user.quota_bytes as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(UserInfoResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        quota_bytes: user.quota_bytes,
        used_bytes: user.used_bytes,
        quota_used_percentage,
        created_at: user.created_at.to_rfc3339(),
    }))
}

/// Create a new API token
pub async fn create_token(
    State(state): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<TokenResponse>, ErrorResponse> {
    let token = extract_token(&headers).ok_or(ErrorResponse {
        error: "Missing or invalid authorization header".to_string(),
    })?;

    let user = state
        .user_manager
        .authenticate_token(&token)
        .await
        .map_err(|e| ErrorResponse {
            error: format!("Authentication failed: {}", e),
        })?
        .ok_or_else(|| ErrorResponse {
            error: "Invalid or expired token".to_string(),
        })?;

    let expires_in = req.expires_days.map(Duration::days);
    let expires_at = expires_in.map(|d| (chrono::Utc::now() + d).to_rfc3339());

    let new_token = state
        .user_manager
        .create_api_token(user.id, req.name.clone(), expires_in)
        .await
        .map_err(|e| ErrorResponse {
            error: format!("Failed to create token: {}", e),
        })?;

    Ok(Json(TokenResponse {
        token: new_token,
        name: req.name,
        expires_at,
    }))
}

/// Health check endpoint
pub async fn health() -> &'static str {
    "OK"
}

/// Create the HTTP API router
pub fn create_router(user_manager: Arc<UserManager>) -> Router {
    let state = ApiState { user_manager };

    Router::new()
        .route("/health", get(health))
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/user", get(get_user_info))
        .route("/api/token", post(create_token))
        .with_state(state)
}
