use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{error, info};

mod args;
mod auth;
mod config;
mod health;
mod protocol;
mod websocket_server;

use args::Args;
use config::Config;
use health::{run_health_server, HealthState, ServerMetrics};
use websocket_server::WebSocketServer;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle special commands
    if args.generate_config {
        println!("{}", Config::example());
        return Ok(());
    }

    // Load configuration
    let mut config = if let Some(config_path) = &args.config {
        Config::from_file(config_path).await?
    } else {
        Config::default()
    };

    // Merge command-line args with config (CLI takes precedence)
    config.merge_with_args(&args);

    // Check environment variable for auth key if not provided
    if config.auth.auth_key.is_none() {
        if let Ok(env_key) = std::env::var("HECATE_AUTH_KEY") {
            config.auth.auth_key = Some(env_key);
        }
    }

    // Validate configuration
    if args.validate {
        config.validate()?;
        info!("Configuration is valid");
        return Ok(());
    }

    // Set up logging based on config
    let log_level = match config.logging.level.as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    match config.logging.format {
        config::LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_max_level(log_level)
                .init();
        }
        config::LogFormat::Text => {
            tracing_subscriber::fmt().with_max_level(log_level).init();
        }
    }

    info!("Hecate storage server starting");
    info!("Storage directory: {:?}", config.server.storage_path);
    info!("Port: {}", config.server.port);

    // Validate configuration (ensures TLS and auth are configured)
    config.validate()?;

    if config.auth.auth_key.is_some() {
        info!("Authentication enabled (preshared key)");
    } else if config.auth.auth_config_path.is_some() {
        info!("Authentication enabled (config file)");
    }

    info!("TLS enabled with certificate: {:?}", config.tls.cert_path);

    // Create storage directory if it doesn't exist
    tokio::fs::create_dir_all(&config.server.storage_path).await?;

    // Create the WebSocket server with mandatory TLS
    let server = WebSocketServer::new(
        config.server.storage_path.clone(),
        config.auth.auth_key.clone(),
    )
    .await?
    .with_tls(
        config.tls.cert_path.as_ref().unwrap(),
        config.tls.key_path.as_ref().unwrap(),
    )
    .await?;

    let server = Arc::new(server);

    // Start health check server if enabled
    if config.health.enabled {
        let health_state = HealthState {
            started_at: SystemTime::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            storage_path: config.server.storage_path.display().to_string(),
            metrics: Arc::new(tokio::sync::RwLock::new(ServerMetrics::default())),
        };

        tokio::spawn(async move {
            if let Err(e) = run_health_server(config.health.port, health_state).await {
                error!("Health server error: {}", e);
            }
        });
    }

    // Bind address
    let addr = format!("{}:{}", config.server.bind, config.server.port);

    // Run the server
    server.run(&addr).await?;

    Ok(())
}
