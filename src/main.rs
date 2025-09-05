use anyhow::Result;
use chrono::Local;
use clap::Parser;
use std::io::{self, Write};
use std::path::PathBuf;

mod archive;
mod config;
mod crypto;
mod online;
mod protocol;
mod qr;
mod shamir;
mod streaming_upload;
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

fn generate_default_filename() -> String {
    let now = Local::now();
    format!("{}.hecate", now.format("%Y-%m-%d-%s"))
}

fn main() -> Result<()> {
    // Install the crypto provider for P-521 support
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install aws-lc-rs crypto provider");

    let mut args = Args::parse();

    // Handle config generation
    if args.generate_config {
        let config_path = config::Config::get_default_config_path()?;
        let sample_config = config::create_sample_config();
        sample_config.save(&config_path)?;
        println!("Sample config file created at: {:?}", config_path);
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
    if args.paths.is_empty() {
        anyhow::bail!("At least one file or directory must be specified");
    }

    if args.online && args.output.is_some() {
        anyhow::bail!("--output cannot be used with --online when uploading");
    }

    if args.shares_needed > args.total_shares {
        anyhow::bail!("Shares needed cannot be greater than total shares");
    }

    if args.shares_needed < 1 || args.total_shares < 1 {
        anyhow::bail!("Shares must be at least 1");
    }

    // Create TLS config from CLI args or use server config
    let tls_config = if args.no_verify_tls || args.tls_fingerprint.is_some() {
        // CLI args override config
        config::TlsConfig {
            verify: !args.no_verify_tls,
            fingerprint: args.tls_fingerprint.clone(),
        }
    } else {
        // Try to get TLS config from server config
        cfg.find_server(&args.server)
            .map(|s| s.tls.clone())
            .unwrap_or_default()
    };

    eprintln!("Creating encrypted archive");
    if args.verbose {
        eprintln!("Shamir: {}-of-{}", args.shares_needed, args.total_shares);
        eprintln!("Paths to archive: {:?}", args.paths);
    }

    eprintln!("Generating encryption key");
    let key = crypto::generate_key()?;

    eprintln!(
        "Splitting key into {} shares (need {} to recover)",
        args.total_shares, args.shares_needed
    );
    let shares = shamir::split_secret(&key, args.shares_needed, args.total_shares)?;

    if args.online {
        // Online mode - send to server
        let suggested_name = args
            .name
            .ok_or_else(|| anyhow::anyhow!("--name is required when uploading with --online"))?;

        eprintln!("Uploading to server: {}", args.server);
        if args.verbose {
            eprintln!("Suggested name: {}", suggested_name);
        }

        let accepted_name = online::create_and_send_encrypted_archive(
            &args.paths,
            &args.server,
            &suggested_name,
            &key,
            args.verbose,
            args.auth_key.as_deref(),
            &tls_config,
        )?;

        // Generate QR codes with the accepted name
        let qr_paths = qr::generate_qr_codes(&shares, &accepted_name)?;
        if args.verbose {
            eprintln!("Generated {} QR codes", qr_paths.len());
        }

        println!(
            "Successfully uploaded encrypted archive as: {}",
            accepted_name
        );
        println!("Keys saved as QR codes: {:?}", qr_paths);
    } else {
        // Local mode - save to file
        let output_filename = args.output.unwrap_or_else(generate_default_filename);

        eprintln!("Creating local encrypted archive: {}", output_filename);

        eprintln!("Generating QR codes for shares");
        let qr_paths = qr::generate_qr_codes(&shares, &output_filename)?;

        eprintln!("Encrypting and compressing data");
        archive::create_encrypted_archive(&args.paths, &output_filename, &key, args.verbose)?;

        println!(
            "Successfully created encrypted archive: {}",
            output_filename
        );
        println!("Keys saved as QR codes: {:?}", qr_paths);
    }

    Ok(())
}

fn decrypt_mode(args: Args, cfg: &config::Config) -> Result<()> {
    // Create TLS config from CLI args or use server config
    let tls_config = if args.no_verify_tls || args.tls_fingerprint.is_some() {
        // CLI args override config
        config::TlsConfig {
            verify: !args.no_verify_tls,
            fingerprint: args.tls_fingerprint.clone(),
        }
    } else {
        // Try to get TLS config from server config
        cfg.find_server(&args.server)
            .map(|s| s.tls.clone())
            .unwrap_or_default()
    };

    let (input_str, temp_file) = if args.online {
        // Online mode - download from server
        let mut file_name = args
            .name
            .ok_or_else(|| anyhow::anyhow!("--name is required when downloading with --online"))?;

        // Ensure filename ends with .hecate
        if !file_name.ends_with(".hecate") {
            file_name = format!("{}.hecate", file_name);
        }

        eprintln!("Downloading from server: {}", args.server);
        eprintln!("File: {}", file_name);

        // Download to temp file
        let temp_path = format!("/tmp/{}", file_name);
        online::download_file(
            &args.server,
            &file_name,
            &temp_path,
            args.verbose,
            args.auth_key.as_deref(),
            &tls_config,
        )?;
        eprintln!("Download complete");

        (temp_path.clone(), Some(temp_path))
    } else {
        // Local mode
        if args.paths.len() != 1 {
            anyhow::bail!("Exactly one .hecate file must be specified for decryption");
        }

        let input_file = &args.paths[0];
        if !input_file.exists() {
            anyhow::bail!("Input file does not exist: {:?}", input_file);
        }

        let input_str = input_file
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;

        if !input_str.ends_with(".hecate") {
            anyhow::bail!("Input file must have .hecate extension");
        }

        (input_str.to_string(), None)
    };

    // Recover the key from shares
    eprintln!("Recovering key from {} shares", args.keys.len());
    let key = recover_key_from_shares(&args.keys, args.verbose)?;
    eprintln!("Key recovered successfully");

    // Determine output path
    let output = determine_output_path(&input_str, &args.output, args.unpack)?;

    if args.unpack {
        eprintln!("Decrypting and extracting to: {}", output);
        archive::extract_encrypted_archive(&input_str, &output, &key, args.verbose)?;
        println!("Successfully extracted archive to: {}", output);
    } else {
        eprintln!("Decrypting to: {}", output);
        archive::decrypt_to_file(&input_str, &output, &key, args.verbose)?;
        println!("Successfully decrypted to: {}", output);
    }

    // Clean up temp file if we downloaded it
    if let Some(temp) = temp_file {
        let _ = std::fs::remove_file(temp);
    }

    Ok(())
}

fn list_mode(args: Args, cfg: &config::Config) -> Result<()> {
    if !args.online {
        anyhow::bail!("--list requires --online");
    }

    // Create TLS config from CLI args or use server config
    let tls_config = if args.no_verify_tls || args.tls_fingerprint.is_some() {
        // CLI args override config
        config::TlsConfig {
            verify: !args.no_verify_tls,
            fingerprint: args.tls_fingerprint.clone(),
        }
    } else {
        // Try to get TLS config from server config
        cfg.find_server(&args.server)
            .map(|s| s.tls.clone())
            .unwrap_or_default()
    };

    eprintln!("Connecting to server: {}", args.server);
    let files = online::list_files(
        &args.server,
        args.verbose,
        args.auth_key.as_deref(),
        &tls_config,
    )?;

    if files.is_empty() {
        println!("No files available on server");
    } else {
        println!("Available files on {}:", args.server);
        for file in files {
            println!("  {}", file);
        }
    }

    Ok(())
}

fn determine_output_path(input: &str, output: &Option<String>, unpack: bool) -> Result<String> {
    if let Some(out) = output {
        return Ok(out.clone());
    }

    // Default output based on input filename
    let base = input.trim_end_matches(".hecate");

    if unpack {
        // Default directory name for unpacking
        Ok(base.to_string())
    } else {
        // Default tar.zst filename for decrypt-only
        Ok(format!("{}.tar.zst", base))
    }
}

fn recover_key_from_shares(keys: &[String], verbose: bool) -> Result<Vec<u8>> {
    let shares = if keys.is_empty() {
        // Interactive mode
        eprintln!("No key shares provided. Enter shares interactively.");
        eprintln!("Enter shares one at a time (mnemonic words or QR file path).");
        eprintln!("Press Enter with empty input when done or when reconstruction succeeds.");

        let mut collected_shares = Vec::new();
        let mut share_count = 1;

        loop {
            eprint!("Share {}: ", share_count);
            io::stderr().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            if input.is_empty() {
                if collected_shares.is_empty() {
                    anyhow::bail!("At least one share must be provided");
                }
                break;
            }

            collected_shares.push(input.to_string());
            share_count += 1;

            // Try to reconstruct after each share
            if let Ok(parsed) = shamir::parse_shares(&collected_shares, false) {
                if let Ok(key) = shamir::combine_shares(&parsed) {
                    eprintln!(
                        "Successfully reconstructed the key with {} shares",
                        collected_shares.len()
                    );
                    return Ok(key);
                }
            }
        }

        // Final attempt with all collected shares
        shamir::parse_shares(&collected_shares, verbose)?
    } else {
        // Non-interactive mode with provided keys
        if verbose {
            eprintln!("Processing {} key shares...", keys.len());
        }
        shamir::parse_shares(keys, verbose)?
    };

    let key = shamir::combine_shares(&shares)?;
    Ok(key)
}
