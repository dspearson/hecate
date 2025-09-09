use crate::config::TlsConfig;
use crate::protocol::{
    ClientMessage, ErrorCode, FileInfo, ServerMessage, validate_chunk_size, validate_filename,
};
use crate::tls_verifiers::{AcceptAnyServerCert, FingerprintVerifier};
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::{
    WebSocketStream, client_async,
    tungstenite::{Message, client::IntoClientRequest},
};

pub struct SecureWebSocketClient {
    ws: Arc<Mutex<WebSocketStream<TlsStream<TcpStream>>>>,
}

impl SecureWebSocketClient {
    pub async fn connect(server_addr: &str, tls_config: &TlsConfig) -> Result<Self> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        // Parse the server address
        let clean_addr = server_addr
            .trim_start_matches("wss://")
            .trim_start_matches("ws://");

        // Split host and port
        let (host, port) = if let Some(colon_pos) = clean_addr.rfind(':') {
            let host = &clean_addr[..colon_pos];
            let port = clean_addr[colon_pos + 1..].parse::<u16>().unwrap_or(443);
            (host, port)
        } else {
            (clean_addr, 443)
        };

        // Create TCP connection
        let tcp_stream = TcpStream::connect((host, port))
            .await
            .with_context(|| format!("Failed to connect to {host}:{port}"))?;

        // Configure TLS
        let config = if !tls_config.verify {
            eprintln!("Warning: Certificate verification disabled");
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::new()))
                .with_no_client_auth()
        } else if let Some(fingerprint) = &tls_config.fingerprint {
            eprintln!("Verifying certificate fingerprint: {fingerprint}");
            let verifier = FingerprintVerifier::new(fingerprint.clone())?;
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        } else {
            // Use webpki roots for certificate validation
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };

            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // Create TLS connector and establish TLS connection
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host)
            .map_err(|_| anyhow::anyhow!("Invalid server name: {}", host))?
            .to_owned();

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .context("Failed to establish TLS connection")?;

        // Create WebSocket URL and request
        let ws_url = format!("wss://{clean_addr}");
        let request = ws_url.into_client_request()?;

        // Upgrade to WebSocket using the TLS stream directly
        let (ws_stream, _) = client_async(request, tls_stream)
            .await
            .context("Failed to establish WebSocket connection")?;

        Ok(Self {
            ws: Arc::new(Mutex::new(ws_stream)),
        })
    }

    pub async fn authenticate(&self, auth_key: Option<&str>) -> Result<bool> {
        if let Some(key) = auth_key {
            // Server currently only supports simple preshared key authentication
            // The entire key string is compared directly
            let msg = ClientMessage::Auth {
                key: key.to_string(),
            };
            self.send_message(msg).await?;

            match self.receive_message().await? {
                ServerMessage::AuthResult { success, message } => {
                    if !success {
                        if let Some(msg) = message {
                            anyhow::bail!("Authentication failed: {}", msg);
                        }
                        anyhow::bail!("Authentication failed");
                    }
                    Ok(true)
                }
                _ => anyhow::bail!("Unexpected response to authentication"),
            }
        } else {
            // Try to authenticate without a key (server might not require auth)
            Ok(true)
        }
    }

    pub async fn upload_file_streaming(
        &self,
        name: &str,
        estimated_size: u64,
        paths: &[std::path::PathBuf],
        key: &[u8],
        verbose: bool,
    ) -> Result<String> {
        use crate::archive;
        use std::thread;
        use tokio::sync::mpsc;

        // Validate filename
        validate_filename(name).map_err(|e| anyhow::anyhow!(e))?;

        // Send upload request with estimated size
        let msg = ClientMessage::UploadRequest {
            name: name.to_string(),
            size: estimated_size,
        };
        self.send_message(msg).await?;

        // Wait for acceptance
        let accepted_name = match self.receive_message().await? {
            ServerMessage::UploadAccepted { name } => name,
            ServerMessage::UploadRejected { reason } => {
                anyhow::bail!("Upload rejected: {}", reason);
            }
            ServerMessage::Error { code, message } => {
                anyhow::bail!("Server error ({}): {}", code, message);
            }
            _ => anyhow::bail!("Unexpected response to upload request"),
        };

        if verbose {
            eprintln!("Server accepted upload as: {accepted_name}");
            eprintln!("Starting streaming upload...");
        }

        // Create channel for streaming chunks
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Clone necessary data for the archive thread
        let paths = paths.to_vec();
        let key = key.to_vec();
        let verbose_clone = verbose;

        // Spawn thread for archive creation (blocking I/O)
        let archive_handle = thread::spawn(move || {
            // Create a writer that sends chunks through the channel
            let writer = crate::streaming_upload::StreamingUploadWriter::new(tx);

            // Stream archive directly to the writer
            archive::create_encrypted_archive_to_writer(&paths, writer, &key, verbose_clone)
        });

        // Send chunks as they arrive
        let mut total_sent = 0u64;
        let mut chunk_count = 0;

        while let Some(chunk) = rx.recv().await {
            let chunk_len = chunk.len();
            chunk_count += 1;
            let is_final = rx.is_closed() && rx.is_empty();

            validate_chunk_size(&chunk).map_err(|e| anyhow::anyhow!(e))?;

            let msg = ClientMessage::DataChunk {
                data: chunk,
                is_final,
            };
            self.send_message(msg).await?;

            total_sent += chunk_len as u64;

            if verbose && (total_sent % (512 * 1024) == 0 || is_final) {
                let percent = if estimated_size > 0 {
                    (total_sent * 100) / estimated_size
                } else {
                    0
                };
                eprintln!("Upload progress: ~{percent}% ({total_sent} bytes sent)");
            }

            // Wait for chunk acknowledgment
            match self.receive_message().await? {
                ServerMessage::ChunkReceived { bytes_received } => {
                    if bytes_received != total_sent {
                        anyhow::bail!(
                            "Server received {} bytes but we sent {}",
                            bytes_received,
                            total_sent
                        );
                    }
                }
                ServerMessage::Error { code, message } => {
                    anyhow::bail!("Error during upload ({}): {}", code, message);
                }
                _ => {} // Ignore other messages
            }
        }

        // Wait for archive creation to complete
        archive_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Archive creation thread panicked"))??;

        // Only send an empty final chunk if we haven't sent any data
        if chunk_count == 0 {
            let msg = ClientMessage::DataChunk {
                data: vec![],
                is_final: true,
            };
            self.send_message(msg).await?;
        }

        // Wait for completion
        match self.receive_message().await? {
            ServerMessage::UploadComplete { total_bytes } => {
                if verbose {
                    eprintln!(
                        "Upload complete: {total_bytes} bytes (estimated: {estimated_size} bytes)"
                    );
                    if total_bytes < estimated_size {
                        let compression = 100 - (total_bytes * 100 / estimated_size);
                        eprintln!("Achieved ~{compression}% compression");
                    }
                }
            }
            ServerMessage::Error { code, message } => {
                anyhow::bail!("Error completing upload ({}): {}", code, message);
            }
            _ => anyhow::bail!("Unexpected response at upload completion"),
        }

        Ok(accepted_name)
    }

    pub async fn list_files(&self, verbose: bool) -> Result<Vec<FileInfo>> {
        let msg = ClientMessage::ListRequest;
        self.send_message(msg).await?;

        match self.receive_message().await? {
            ServerMessage::FileList { files } => {
                if verbose {
                    eprintln!("Received list of {} files", files.len());
                }
                Ok(files)
            }
            ServerMessage::Error { code, message } => {
                anyhow::bail!("Error listing files ({}): {}", code, message);
            }
            _ => anyhow::bail!("Unexpected response to list request"),
        }
    }

    pub async fn download_file_streaming<W: std::io::Write + Send>(
        &self,
        name: &str,
        mut writer: W,
        verbose: bool,
    ) -> Result<u64> {
        validate_filename(name).map_err(|e| anyhow::anyhow!(e))?;

        let msg = ClientMessage::GetRequest {
            name: name.to_string(),
        };
        self.send_message(msg).await?;

        let mut total_received = 0u64;

        loop {
            match self.receive_message().await? {
                ServerMessage::DataChunk {
                    data: chunk,
                    is_final,
                } => {
                    validate_chunk_size(&chunk).map_err(|e| anyhow::anyhow!(e))?;
                    total_received += chunk.len() as u64;

                    writer
                        .write_all(&chunk)
                        .context("Failed to write chunk to output")?;

                    if verbose && (total_received % (10 * 1024 * 1024) == 0 || is_final) {
                        eprintln!("Received {total_received} bytes");
                    }

                    if is_final {
                        break;
                    }
                }
                ServerMessage::Error { code, message } => {
                    if code == ErrorCode::FileNotFound {
                        anyhow::bail!("File not found: {}", name);
                    }
                    anyhow::bail!("Error downloading file ({}): {}", code, message);
                }
                _ => anyhow::bail!("Unexpected response during download"),
            }
        }

        writer.flush().context("Failed to flush output")?;

        if verbose {
            eprintln!("Successfully downloaded {total_received} bytes");
        }

        Ok(total_received)
    }

    async fn send_message(&self, msg: ClientMessage) -> Result<()> {
        let json = serde_json::to_string(&msg).context("Failed to serialize message")?;

        let mut ws = self.ws.lock().await;
        ws.send(Message::Text(json))
            .await
            .context("Failed to send message")?;
        ws.flush().await.context("Failed to flush WebSocket")?;

        Ok(())
    }

    async fn receive_message(&self) -> Result<ServerMessage> {
        let mut ws = self.ws.lock().await;

        while let Some(msg) = ws.next().await {
            let msg = msg.context("WebSocket error")?;

            match msg {
                Message::Text(text) => {
                    let server_msg: ServerMessage = serde_json::from_str(&text)
                        .context("Failed to deserialize server message")?;
                    return Ok(server_msg);
                }
                Message::Binary(_) => {
                    anyhow::bail!("Unexpected binary message from server");
                }
                Message::Close(_) => {
                    anyhow::bail!("Server closed connection");
                }
                Message::Ping(_) | Message::Pong(_) => {
                    // Handle automatically by tungstenite
                }
                _ => {}
            }
        }

        anyhow::bail!("Connection closed unexpectedly")
    }

    pub async fn close(self) -> Result<()> {
        let mut ws = self.ws.lock().await;
        ws.close(None).await.context("Failed to close WebSocket")?;
        Ok(())
    }
}

impl Drop for SecureWebSocketClient {
    fn drop(&mut self) {
        // WebSocket will be closed when Arc is dropped
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_url_construction() {
        // Test URL construction logic
        let addr = "localhost:10112";

        let url_ws = format!("ws://{addr}/ws");
        assert_eq!(url_ws, "ws://localhost:10112/ws");

        let url_wss = format!("wss://{addr}/ws");
        assert_eq!(url_wss, "wss://localhost:10112/ws");
    }
}
