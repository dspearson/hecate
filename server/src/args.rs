use clap::Parser;
use std::path::PathBuf;

/// Command-line arguments for the Hecate storage server
#[derive(Parser, Debug)]
#[command(
    name = "hecate-server",
    version,
    author,
    about = "Secure storage server for Hecate encrypted archives",
    long_about = "A WebSocket-based server that receives, stores, and serves encrypted Hecate archives with authentication and TLS security"
)]
pub struct Args {
    /// Path to TOML configuration file
    #[arg(short, long, help = "Path to TOML configuration file")]
    pub config: Option<PathBuf>,

    /// Generate example config file and exit
    #[arg(long, help = "Generate example config file and exit")]
    pub generate_config: bool,

    /// Validate configuration and exit
    #[arg(long, help = "Validate configuration and exit")]
    pub validate: bool,

    /// Directory to store received files (overrides config)
    #[arg(short, long, help = "Directory to store received files")]
    pub store: Option<PathBuf>,

    /// Port to listen on (overrides config)
    #[arg(short, long, help = "Port to listen on")]
    pub port: Option<u16>,

    /// Enable verbose logging (overrides config)
    #[arg(short, long, help = "Enable verbose logging")]
    pub verbose: bool,

    /// Authentication key required for access (overrides config)
    #[arg(short('k'), long, help = "Authentication key required for access")]
    pub auth_key: Option<String>,

    /// Path to JSON file containing client credentials (overrides config)
    #[arg(long, help = "Path to JSON file containing client credentials")]
    pub auth_config: Option<PathBuf>,

    /// TLS certificate file (overrides config)
    #[arg(long, help = "TLS certificate file")]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file (overrides config)
    #[arg(long, help = "TLS private key file")]
    pub tls_key: Option<PathBuf>,
}
