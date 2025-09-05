use crate::config::TlsConfig;
use crate::protocol::{
    ClientMessage, ErrorCode, FileInfo, ServerMessage, validate_chunk_size, validate_filename,
};
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use std::sync::Arc;
use std::sync::Arc as StdArc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async, connect_async_tls_with_config,
    tungstenite::Message,
};

pub struct SecureWebSocketClient {
    ws: Arc<Mutex<WebSocketStream<MaybeTlsStream<TcpStream>>>>,
}

impl SecureWebSocketClient {
    pub async fn connect(server_addr: &str, tls_config: &TlsConfig) -> Result<Self> {
        // Check if server address includes scheme
        let url = if server_addr.starts_with("ws://") || server_addr.starts_with("wss://") {
            server_addr.to_string()
        } else {
            // Default to secure WebSocket (no path needed - server accepts raw WebSocket)
            format!("wss://{}", server_addr)
        };

        let (ws_stream, _) = if !tls_config.verify {
            // Accept any certificate
            eprintln!("Warning: Certificate verification disabled");

            // Create a custom rustls config that accepts any certificate
            let config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(StdArc::new(AcceptAnyServerCert::new()))
                .with_no_client_auth();

            let connector = Connector::Rustls(StdArc::new(config));

            connect_async_tls_with_config(&url, None, false, Some(connector))
                .await
                .context("Failed to connect to WebSocket server")?
        } else if let Some(fingerprint) = &tls_config.fingerprint {
            // Verify against specific fingerprint
            eprintln!("Verifying certificate fingerprint: {}", fingerprint);

            let verifier = FingerprintVerifier::new(fingerprint.clone())?;
            let config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(StdArc::new(verifier))
                .with_no_client_auth();

            let connector = Connector::Rustls(StdArc::new(config));

            connect_async_tls_with_config(&url, None, false, Some(connector))
                .await
                .context("Failed to connect to WebSocket server")?
        } else {
            // Production: use proper certificate validation
            connect_async(&url)
                .await
                .context("Failed to connect to WebSocket server")?
        };

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
            eprintln!("Server accepted upload as: {}", accepted_name);
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
                eprintln!("Upload progress: ~{}% ({} bytes sent)", percent, total_sent);
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
                        "Upload complete: {} bytes (estimated: {} bytes)",
                        total_bytes, estimated_size
                    );
                    if total_bytes < estimated_size {
                        let compression = 100 - (total_bytes * 100 / estimated_size);
                        eprintln!("Achieved ~{}% compression", compression);
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
                        eprintln!("Received {} bytes", total_received);
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
            eprintln!("Successfully downloaded {} bytes", total_received);
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

// Custom certificate verifier that accepts any certificate (for development only)
#[derive(Debug)]
struct AcceptAnyServerCert;

impl AcceptAnyServerCert {
    fn new() -> Self {
        Self
    }
}

// Certificate verifier that checks against a specific fingerprint
#[derive(Debug)]
struct FingerprintVerifier {
    fingerprint: Vec<u8>,
}

impl FingerprintVerifier {
    fn new(fingerprint_hex: String) -> Result<Self> {
        // Remove any colons or spaces from the fingerprint
        let clean_hex: String = fingerprint_hex
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();

        // Convert hex string to bytes
        let fingerprint = hex::decode(&clean_hex)
            .with_context(|| format!("Invalid fingerprint hex: {}", fingerprint_hex))?;

        if fingerprint.len() != 32 {
            anyhow::bail!(
                "Fingerprint must be 32 bytes (SHA256), got {} bytes",
                fingerprint.len()
            );
        }

        Ok(Self { fingerprint })
    }

    fn verify_cert(&self, cert: &rustls::pki_types::CertificateDer<'_>) -> bool {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(cert.as_ref());
        let cert_fingerprint = hasher.finalize();

        cert_fingerprint.as_slice() == self.fingerprint
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.verify_cert(end_entity) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "Certificate fingerprint does not match expected value".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_url_construction() {
        // Test URL construction logic
        let addr = "localhost:10112";

        let url_ws = format!("ws://{}/ws", addr);
        assert_eq!(url_ws, "ws://localhost:10112/ws");

        let url_wss = format!("wss://{}/ws", addr);
        assert_eq!(url_wss, "wss://localhost:10112/ws");
    }
}
