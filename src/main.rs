use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod archive;
mod commands;
mod config;
mod crypto;
mod online;
mod protocol;
mod qr;
mod shamir;
mod streaming_upload;
mod tls_verifiers;
mod websocket_client;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(help = "Files/directories to encrypt or .hecate file to decrypt")]
    paths: Vec<PathBuf>,

    #[arg(
        short,
        long,
        help = "Output filename/directory (default: timestamp-based for encrypt, extracted dir for decrypt)"
    )]
    output: Option<String>,

    #[arg(long, help = "Use remote server for operations")]
    online: bool,

    #[arg(
        long,
        help = "Name for remote storage (for upload) or file to retrieve (for decrypt/unpack)"
    )]
    name: Option<String>,

    #[arg(
        long,
        help = "List files available on remote server",
        requires = "online"
    )]
    list: bool,

    #[arg(
        long,
        help = "Remote server address",
        default_value = "localhost:10112"
    )]
    server: String,

    #[arg(
        short = 'k',
        long,
        default_value = "2",
        help = "Number of shares needed to reconstruct"
    )]
    shares_needed: u8,

    #[arg(
        short = 'n',
        long,
        default_value = "5",
        help = "Total number of shares to generate"
    )]
    total_shares: u8,

    #[arg(short = 'd', long, help = "Decrypt mode - decrypt to .tar.zst")]
    decrypt: bool,

    #[arg(short = 'u', long, help = "Unpack mode - decrypt and extract archive")]
    unpack: bool,

    #[arg(
        long = "key",
        help = "Provide a key share (mnemonic words or QR file path), can be used multiple times"
    )]
    keys: Vec<String>,

    #[arg(short, long, help = "Verbose output")]
    verbose: bool,

    #[arg(long, help = "Path to config file")]
    config: Option<PathBuf>,

    #[arg(long, help = "Generate sample config file at default location")]
    generate_config: bool,

    #[arg(
        short('a'),
        long,
        help = "Preshared authentication key for server (overrides config)"
    )]
    auth_key: Option<String>,

    #[arg(long, help = "Skip TLS certificate verification (insecure)")]
    no_verify_tls: bool,

    #[arg(long, help = "Expected certificate fingerprint (SHA256 hex)")]
    tls_fingerprint: Option<String>,
}

/// Create TLS config from CLI args or server configuration
fn create_tls_config(args: &Args, cfg: &config::Config, server: &str) -> config::TlsConfig {
    if args.no_verify_tls || args.tls_fingerprint.is_some() {
        // CLI args override config
        config::TlsConfig {
            verify: !args.no_verify_tls,
            fingerprint: args.tls_fingerprint.clone(),
        }
    } else {
        // Try to get TLS config from server config
        cfg.find_server(server)
            .map(|s| s.tls.clone())
            .unwrap_or_default()
    }
}

fn main() -> Result<()> {
    // Install the ring crypto provider for musl compatibility
    // Note: ring doesn't support P-521, only P-256 and P-384
    let _ = rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| eprintln!("Note: TLS crypto provider already installed"));

    let mut args = Args::parse();

    // Handle config generation
    if args.generate_config {
        let config_path = config::Config::get_default_config_path()?;
        let sample_config = config::create_sample_config();
        sample_config.save(&config_path)?;
        println!("Sample config file created at: {config_path:?}");
        return Ok(());
    }

    // Load config
    let cfg = if let Some(config_path) = &args.config {
        config::Config::load_from_file(config_path)?
    } else {
        config::Config::load()?
    };

    // Apply config defaults to args (only if not explicitly set)
    apply_config_defaults(&mut args, &cfg);

    // Determine mode
    if args.list {
        list_mode(args, &cfg)
    } else if args.decrypt || args.unpack {
        decrypt_mode(args, &cfg)
    } else {
        encrypt_mode(args, &cfg)
    }
}

fn apply_config_defaults(args: &mut Args, cfg: &config::Config) {
    // Apply defaults only if the user didn't specify them
    // Note: We check if values are still at their CLI defaults

    // Check for embedded server at compile time
    if args.server == "localhost:10112" {
        if let Some(embedded_server) = option_env!("HECATE_EMBEDDED_SERVER") {
            args.server = embedded_server.to_string();
        }
    }

    // Server can be overridden or use config default
    if args.server == "localhost:10112" {
        args.server = cfg.get_default_server();
    }

    // Check for server alias
    if let Some(server_cfg) = cfg.find_server(&args.server) {
        args.server = format!("{}:{}", server_cfg.address, server_cfg.port);
    }

    // Apply authentication key if not specified
    if args.auth_key.is_none() {
        // Check environment variable first
        if let Ok(env_key) = std::env::var("MERCURY_AUTH_KEY") {
            args.auth_key = Some(env_key);
        } else if let Some(embedded_key) = option_env!("HECATE_EMBEDDED_AUTH_KEY") {
            // Check for compile-time embedded key
            args.auth_key = Some(embedded_key.to_string());
        } else {
            // Otherwise use config
            args.auth_key = cfg.get_auth_key(&args.server);
        }
    }

    // Apply shares configuration if still at defaults
    if args.shares_needed == 2 && args.total_shares == 5 {
        args.shares_needed = cfg.defaults.shares_needed;
        args.total_shares = cfg.defaults.total_shares;
    }

    // Apply verbose if not set via CLI
    if !args.verbose {
        args.verbose = cfg.defaults.verbose;
    }

    // Apply output directory if configured and no output specified
    if args.output.is_none() && cfg.defaults.output_dir.is_some() {
        // This will be used as a prefix for generated filenames
        // Could be extended to prepend to default filename
    }
}

fn encrypt_mode(args: Args, cfg: &config::Config) -> Result<()> {
    let tls_config = create_tls_config(&args, cfg, &args.server);

    commands::encrypt_mode(commands::EncryptParams {
        paths: args.paths,
        output: args.output,
        online_mode: args.online,
        name: args.name,
        shares_needed: args.shares_needed,
        total_shares: args.total_shares,
        server_addr: &args.server,
        verbose: args.verbose,
        auth_key: args.auth_key.as_deref(),
        tls_config: &tls_config,
    })
}

fn decrypt_mode(args: Args, cfg: &config::Config) -> Result<()> {
    let tls_config = create_tls_config(&args, cfg, &args.server);

    commands::decrypt_mode(commands::DecryptParams {
        paths: args.paths,
        output: args.output,
        online_mode: args.online,
        name: args.name,
        unpack: args.unpack,
        keys: args.keys,
        server_addr: &args.server,
        verbose: args.verbose,
        auth_key: args.auth_key.as_deref(),
        tls_config: &tls_config,
    })
}

fn list_mode(args: Args, cfg: &config::Config) -> Result<()> {
    if !args.online {
        anyhow::bail!("--list requires --online");
    }

    let tls_config = create_tls_config(&args, cfg, &args.server);

    commands::list_mode(
        &args.server,
        args.verbose,
        args.auth_key.as_deref(),
        &tls_config,
    )
}
