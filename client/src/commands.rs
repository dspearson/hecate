use anyhow::Result;
use chrono::Local;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::{archive, config, crypto, online, qr, shamir};

/// Parameters for encrypt operation
pub struct EncryptParams<'a> {
    pub paths: Vec<PathBuf>,
    pub output: Option<String>,
    pub online_mode: bool,
    pub name: Option<String>,
    pub shares_needed: u8,
    pub total_shares: u8,
    pub server_addr: &'a str,
    pub verbose: bool,
    pub auth_key: Option<&'a str>,
    pub tls_config: &'a config::TlsConfig,
}

/// Generate a default filename with timestamp
pub fn generate_default_filename() -> String {
    let now = Local::now();
    format!("{}.hecate", now.format("%Y-%m-%d-%s"))
}

/// Encrypt mode - create encrypted archives locally or upload to server
pub fn encrypt_mode(params: EncryptParams) -> Result<()> {
    let EncryptParams {
        paths,
        output,
        online_mode,
        name,
        shares_needed,
        total_shares,
        server_addr,
        verbose,
        auth_key,
        tls_config,
    } = params;
    if paths.is_empty() {
        anyhow::bail!("At least one file or directory must be specified");
    }

    if online_mode && output.is_some() {
        anyhow::bail!("--output cannot be used with --online when uploading");
    }

    if shares_needed > total_shares {
        anyhow::bail!("Shares needed cannot be greater than total shares");
    }

    if shares_needed < 1 || total_shares < 1 {
        anyhow::bail!("Shares must be at least 1");
    }

    eprintln!("Creating encrypted archive");
    if verbose {
        eprintln!("Shamir: {shares_needed}-of-{total_shares}");
        eprintln!("Paths to archive: {paths:?}");
    }

    eprintln!("Generating encryption key");
    let key = crypto::generate_key()?;

    eprintln!(
        "Splitting key into {total_shares} shares (need {shares_needed} to recover)"
    );
    let shares = shamir::split_secret(&key, shares_needed, total_shares)?;

    if online_mode {
        // Online mode - send to server
        let suggested_name =
            name.ok_or_else(|| anyhow::anyhow!("--name is required when uploading with --online"))?;

        eprintln!("Uploading to server: {server_addr}");
        if verbose {
            eprintln!("Suggested name: {suggested_name}");
        }

        let accepted_name = online::create_and_send_encrypted_archive(
            &paths,
            server_addr,
            &suggested_name,
            &key,
            verbose,
            auth_key,
            tls_config,
        )?;

        // Generate QR codes with the accepted name
        let qr_paths = qr::generate_qr_codes(&shares, &accepted_name)?;
        if verbose {
            eprintln!("Generated {} QR codes", qr_paths.len());
        }

        println!(
            "Successfully uploaded encrypted archive as: {accepted_name}"
        );
        println!("Keys saved as QR codes: {qr_paths:?}");
    } else {
        // Local mode - save to file
        let output_filename = output.unwrap_or_else(generate_default_filename);

        eprintln!("Creating local encrypted archive: {output_filename}");

        eprintln!("Generating QR codes for shares");
        let qr_paths = qr::generate_qr_codes(&shares, &output_filename)?;

        eprintln!("Encrypting and compressing data");
        archive::create_encrypted_archive(&paths, &output_filename, &key, verbose)?;

        println!(
            "Successfully created encrypted archive: {output_filename}"
        );
        println!("Keys saved as QR codes: {qr_paths:?}");
    }

    Ok(())
}

/// Parameters for decrypt operation
pub struct DecryptParams<'a> {
    pub paths: Vec<PathBuf>,
    pub output: Option<String>,
    pub online_mode: bool,
    pub name: Option<String>,
    pub unpack: bool,
    pub keys: Vec<String>,
    pub server_addr: &'a str,
    pub verbose: bool,
    pub auth_key: Option<&'a str>,
    pub tls_config: &'a config::TlsConfig,
}

/// Decrypt mode - decrypt archives from local files or download from server
pub fn decrypt_mode(params: DecryptParams) -> Result<()> {
    let DecryptParams {
        paths,
        output,
        online_mode,
        name,
        unpack,
        keys,
        server_addr,
        verbose,
        auth_key,
        tls_config,
    } = params;
    let (input_str, temp_file) = if online_mode {
        // Online mode - download from server
        let mut file_name = name
            .ok_or_else(|| anyhow::anyhow!("--name is required when downloading with --online"))?;

        // Ensure filename ends with .hecate
        if !file_name.ends_with(".hecate") {
            file_name = format!("{file_name}.hecate");
        }

        eprintln!("Downloading from server: {server_addr}");
        eprintln!("File: {file_name}");

        // Download to temp file
        let temp_path = format!("/tmp/{file_name}");
        online::download_file(
            server_addr,
            &file_name,
            &temp_path,
            verbose,
            auth_key,
            tls_config,
        )?;
        eprintln!("Download complete");

        (temp_path.clone(), Some(temp_path))
    } else {
        // Local mode
        if paths.len() != 1 {
            anyhow::bail!("Exactly one .hecate file must be specified for decryption");
        }

        let input_file = &paths[0];
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
    eprintln!("Recovering key from {} shares", keys.len());
    let key = recover_key_from_shares(&keys, verbose)?;
    eprintln!("Key recovered successfully");

    // Determine output path
    let output = determine_output_path(&input_str, &output, unpack)?;

    if unpack {
        eprintln!("Decrypting and extracting to: {output}");
        archive::extract_encrypted_archive(&input_str, &output, &key, verbose)?;
        println!("Successfully extracted archive to: {output}");
    } else {
        eprintln!("Decrypting to: {output}");
        archive::decrypt_to_file(&input_str, &output, &key, verbose)?;
        println!("Successfully decrypted to: {output}");
    }

    // Clean up temp file if we downloaded it
    if let Some(temp) = temp_file {
        let _ = std::fs::remove_file(temp);
    }

    Ok(())
}

/// List mode - list files on the server
pub fn list_mode(
    server_addr: &str,
    verbose: bool,
    auth_key: Option<&str>,
    tls_config: &config::TlsConfig,
) -> Result<()> {
    eprintln!("Connecting to server: {server_addr}");
    let files = online::list_files(server_addr, verbose, auth_key, tls_config)?;

    if files.is_empty() {
        println!("No files available on server");
    } else {
        println!("Available files on {server_addr}:");
        for file in files {
            println!("  {file}");
        }
    }

    Ok(())
}

/// Determine output path for decryption based on input and options
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
        Ok(format!("{base}.tar.zst"))
    }
}

/// Recover encryption key from share inputs (interactive or provided)
pub fn recover_key_from_shares(keys: &[String], verbose: bool) -> Result<Vec<u8>> {
    let shares = if keys.is_empty() {
        // Interactive mode
        eprintln!("No key shares provided. Enter shares interactively.");
        eprintln!("Enter shares one at a time (mnemonic words or QR file path).");
        eprintln!("Press Enter with empty input when done or when reconstruction succeeds.");

        let mut collected_shares = Vec::new();
        let mut share_count = 1;

        loop {
            eprint!("Share {share_count}: ");
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
