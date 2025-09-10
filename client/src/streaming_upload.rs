use anyhow::{Context, Result};
use std::io::Write;
use std::path::PathBuf;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::config::TlsConfig;
use crate::protocol::MAX_CHUNK_SIZE;
use crate::websocket_client::SecureWebSocketClient;

/// Streaming writer that sends chunks directly to WebSocket
pub struct StreamingUploadWriter {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl StreamingUploadWriter {
    pub fn new(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            tx,
            buffer: Vec::with_capacity(MAX_CHUNK_SIZE),
        }
    }

    fn flush_buffer(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            let chunk = std::mem::replace(&mut self.buffer, Vec::with_capacity(MAX_CHUNK_SIZE));
            self.tx
                .send(chunk)
                .map_err(|_| anyhow::anyhow!("Upload channel closed"))?;
        }
        Ok(())
    }
}

impl Write for StreamingUploadWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            let space = MAX_CHUNK_SIZE - self.buffer.len();
            let to_write = space.min(remaining.len());

            self.buffer.extend_from_slice(&remaining[..to_write]);
            written += to_write;
            remaining = &remaining[to_write..];

            if self.buffer.len() == MAX_CHUNK_SIZE {
                self.flush_buffer().map_err(std::io::Error::other)?;
            }
        }

        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_buffer().map_err(std::io::Error::other)
    }
}

impl Drop for StreamingUploadWriter {
    fn drop(&mut self) {
        let _ = self.flush_buffer();
    }
}

/// Create and stream an encrypted archive directly to the server
pub fn create_and_stream_encrypted_archive(
    paths: &[PathBuf],
    server_addr: &str,
    suggested_name: &str,
    key: &[u8],
    verbose: bool,
    auth_key: Option<&str>,
    tls_config: &TlsConfig,
) -> Result<String> {
    // Calculate input size for estimation (not exact final size)
    let input_size = estimate_input_size(paths)?;

    // Conservative estimate for compressed/encrypted size
    // Assume 80% compression for average case, plus encryption overhead
    let estimated_size = (input_size as f64 * 0.8 * 1.02) as u64;

    if verbose {
        eprintln!("Input size: {input_size} bytes");
        eprintln!("Estimated upload size: ~{estimated_size} bytes");
    }

    let rt = Runtime::new().context("Failed to create async runtime")?;

    rt.block_on(async {
        // Clean up the address for connection
        let clean_addr = server_addr
            .trim_start_matches("wss://")
            .trim_start_matches("ws://");

        if verbose {
            eprintln!("Connecting to secure server: {clean_addr}");
        }

        // Connect to WebSocket server
        let client = SecureWebSocketClient::connect(clean_addr, tls_config)
            .await
            .with_context(|| format!("Failed to connect to {server_addr}"))?;

        // Authenticate if needed
        if auth_key.is_some() {
            client
                .authenticate(auth_key)
                .await
                .context("Authentication failed")?;
        }

        // Ensure filename ends with .hecate for server
        let server_name = if !suggested_name.ends_with(".hecate") {
            format!("{suggested_name}.hecate")
        } else {
            suggested_name.to_string()
        };

        // Use streaming upload method with estimation
        let accepted_name = client
            .upload_file_streaming(&server_name, estimated_size, paths, key, verbose)
            .await?;

        // Close connection
        client.close().await?;

        Ok(accepted_name)
    })
}

fn estimate_input_size(paths: &[PathBuf]) -> Result<u64> {
    let mut total = 0u64;

    for path in paths {
        if path.is_file() {
            total += path
                .metadata()
                .with_context(|| format!("Failed to get metadata for {path:?}"))?
                .len();
        } else if path.is_dir() {
            // Walk directory recursively
            for entry in walkdir::WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    total += entry
                        .metadata()
                        .with_context(|| format!("Failed to get metadata for {:?}", entry.path()))?
                        .len();
                }
            }
        }
    }

    Ok(total)
}
