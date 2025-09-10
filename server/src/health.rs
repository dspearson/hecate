use anyhow::Result;
use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use serde::Serialize;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::info;

/// Shared application state for health monitoring
#[derive(Clone)]
pub struct HealthState {
    pub started_at: SystemTime,
    pub version: String,
    pub storage_path: String,
    pub metrics: Arc<RwLock<ServerMetrics>>,
}

/// Server metrics for monitoring
#[derive(Clone, Default)]
pub struct ServerMetrics {
    pub total_connections: u64,
    pub active_connections: usize,
    pub total_uploads: u64,
    pub successful_uploads: u64,
    pub failed_uploads: u64,
    pub total_downloads: u64,
    pub total_bytes_uploaded: u64,
    pub total_bytes_downloaded: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: String,
    uptime_seconds: u64,
    storage_path: String,
    timestamp: SystemTime,
    metrics: MetricsResponse,
}

#[derive(Serialize)]
struct MetricsResponse {
    connections: ConnectionMetrics,
    uploads: UploadMetrics,
    downloads: DownloadMetrics,
    throughput: ThroughputMetrics,
}

#[derive(Serialize)]
struct ConnectionMetrics {
    total: u64,
    active: usize,
}

#[derive(Serialize)]
struct UploadMetrics {
    total: u64,
    successful: u64,
    failed: u64,
    success_rate: f64,
}

#[derive(Serialize)]
struct DownloadMetrics {
    total: u64,
}

#[derive(Serialize)]
struct ThroughputMetrics {
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    bytes_total: u64,
}

#[derive(Serialize)]
struct LivenessResponse {
    alive: bool,
}

#[derive(Serialize)]
struct ReadinessResponse {
    ready: bool,
    storage_accessible: bool,
    tls_configured: bool,
    auth_configured: bool,
}

#[derive(Serialize)]
struct MetricsOnlyResponse {
    timestamp: SystemTime,
    metrics: MetricsResponse,
}

async fn health_check(State(state): State<Arc<HealthState>>) -> Json<HealthResponse> {
    let uptime = SystemTime::now()
        .duration_since(state.started_at)
        .unwrap_or_default()
        .as_secs();

    let metrics = state.metrics.read().await;

    let success_rate = if metrics.total_uploads > 0 {
        (metrics.successful_uploads as f64 / metrics.total_uploads as f64) * 100.0
    } else {
        0.0
    };

    Json(HealthResponse {
        status: "healthy",
        version: state.version.clone(),
        uptime_seconds: uptime,
        storage_path: state.storage_path.clone(),
        timestamp: SystemTime::now(),
        metrics: MetricsResponse {
            connections: ConnectionMetrics {
                total: metrics.total_connections,
                active: metrics.active_connections,
            },
            uploads: UploadMetrics {
                total: metrics.total_uploads,
                successful: metrics.successful_uploads,
                failed: metrics.failed_uploads,
                success_rate,
            },
            downloads: DownloadMetrics {
                total: metrics.total_downloads,
            },
            throughput: ThroughputMetrics {
                bytes_uploaded: metrics.total_bytes_uploaded,
                bytes_downloaded: metrics.total_bytes_downloaded,
                bytes_total: metrics.total_bytes_uploaded + metrics.total_bytes_downloaded,
            },
        },
    })
}

async fn liveness_check() -> Json<LivenessResponse> {
    // Simple liveness check - if we can respond, we're alive
    Json(LivenessResponse { alive: true })
}

async fn readiness_check(
    State(state): State<Arc<HealthState>>,
) -> (StatusCode, Json<ReadinessResponse>) {
    // Check if storage directory is accessible
    let storage_accessible = tokio::fs::metadata(&state.storage_path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);

    // For now, assume TLS and auth are configured (checked at startup)
    let tls_configured = true;
    let auth_configured = true;

    let ready = storage_accessible && tls_configured && auth_configured;

    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(ReadinessResponse {
            ready,
            storage_accessible,
            tls_configured,
            auth_configured,
        }),
    )
}

async fn metrics_endpoint(State(state): State<Arc<HealthState>>) -> Json<MetricsOnlyResponse> {
    let metrics = state.metrics.read().await;

    let success_rate = if metrics.total_uploads > 0 {
        (metrics.successful_uploads as f64 / metrics.total_uploads as f64) * 100.0
    } else {
        0.0
    };

    Json(MetricsOnlyResponse {
        timestamp: SystemTime::now(),
        metrics: MetricsResponse {
            connections: ConnectionMetrics {
                total: metrics.total_connections,
                active: metrics.active_connections,
            },
            uploads: UploadMetrics {
                total: metrics.total_uploads,
                successful: metrics.successful_uploads,
                failed: metrics.failed_uploads,
                success_rate,
            },
            downloads: DownloadMetrics {
                total: metrics.total_downloads,
            },
            throughput: ThroughputMetrics {
                bytes_uploaded: metrics.total_bytes_uploaded,
                bytes_downloaded: metrics.total_bytes_downloaded,
                bytes_total: metrics.total_bytes_uploaded + metrics.total_bytes_downloaded,
            },
        },
    })
}

/// Run the health check HTTP server
pub async fn run_health_server(port: u16, state: HealthState) -> Result<()> {
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/livez", get(liveness_check))
        .route("/readyz", get(readiness_check))
        .route("/metrics", get(metrics_endpoint))
        .with_state(Arc::new(state));

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;

    info!("Health check endpoint listening on {}", addr);
    info!("Available endpoints:");
    info!("  - http://{}/health   (full health status)", addr);
    info!("  - http://{}/livez    (liveness probe)", addr);
    info!("  - http://{}/readyz   (readiness probe)", addr);
    info!("  - http://{}/metrics  (metrics only)", addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Health server error: {}", e))
}
