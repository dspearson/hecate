use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::runtime::Runtime;

use crate::config::TlsConfig;
use crate::streaming_upload;
use crate::websocket_client::SecureWebSocketClient;

/// Create and send an encrypted archive to the server using streaming
pub fn create_and_send_encrypted_archive(
    paths: &[PathBuf],
    server_addr: &str,
    suggested_name: &str,
    key: &[u8],
    verbose: bool,
    auth_key: Option<&str>,
    tls_config: &TlsConfig,
) -> Result<String> {
    // Use the streaming implementation that doesn't buffer the entire archive in memory
    streaming_upload::create_and_stream_encrypted_archive(
        paths,
        server_addr,
        suggested_name,
        key,
        verbose,
        auth_key,
        tls_config,
    )
}

/// List files on the server
pub fn list_files(
    server_addr: &str,
    verbose: bool,
    auth_key: Option<&str>,
    tls_config: &TlsConfig,
) -> Result<Vec<String>> {
    let rt = Runtime::new().context("Failed to create async runtime")?;

    rt.block_on(async {
        // TLS is mandatory - clean up the address for connection
        let clean_addr = server_addr
            .trim_start_matches("wss://")
            .trim_start_matches("ws://");

        if verbose {
            eprintln!("Connecting to secure server: {}", clean_addr);
        }

        let client = SecureWebSocketClient::connect(clean_addr, tls_config)
            .await
            .with_context(|| format!("Failed to connect to {}", server_addr))?;

        if auth_key.is_some() {
            client
                .authenticate(auth_key)
                .await
                .context("Authentication failed")?;
        }

        let files = client
            .list_files(verbose)
            .await
            .context("Failed to list files")?;

        client.close().await?;

        // Convert FileInfo to just names for backward compatibility
        Ok(files.into_iter().map(|f| f.name).collect())
    })
}

/// Download a file from the server
pub fn download_file(
    server_addr: &str,
    file_name: &str,
    output_path: &str,
    verbose: bool,
    auth_key: Option<&str>,
    tls_config: &TlsConfig,
) -> Result<()> {
    let rt = Runtime::new().context("Failed to create async runtime")?;

    rt.block_on(async {
        // TLS is mandatory - clean up the address for connection
        let clean_addr = server_addr
            .trim_start_matches("wss://")
            .trim_start_matches("ws://");

        if verbose {
            eprintln!("Connecting to secure server: {}", clean_addr);
        }

        let client = SecureWebSocketClient::connect(clean_addr, tls_config)
            .await
            .with_context(|| format!("Failed to connect to {}", server_addr))?;

        if auth_key.is_some() {
            client
                .authenticate(auth_key)
                .await
                .context("Authentication failed")?;
        }

        // Ensure filename ends with .hecate for server
        let server_name = if !file_name.ends_with(".hecate") {
            format!("{}.hecate", file_name)
        } else {
            file_name.to_string()
        };

        // Open output file for streaming write
        let file = std::fs::File::create(output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path))?;

        client
            .download_file_streaming(&server_name, file, verbose)
            .await
            .with_context(|| format!("Failed to download {}", server_name))?;

        client.close().await?;

        if verbose {
            eprintln!("Successfully saved to {}", output_path);
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_address_parsing() {
        // Test that addresses are parsed correctly (TLS is now mandatory)
        let test_cases = vec![
            ("ws://localhost:10112", "localhost:10112"),
            ("wss://example.com:443", "example.com:443"),
            ("localhost:10112", "localhost:10112"),
            ("example.com:443", "example.com:443"),
        ];

        for (input, expected_clean) in test_cases {
            let clean = input
                .trim_start_matches("wss://")
                .trim_start_matches("ws://");

            assert_eq!(
                clean, expected_clean,
                "Address cleaning failed for {}",
                input
            );
        }
    }
}
