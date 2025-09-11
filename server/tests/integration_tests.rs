use hecate_server::config::Config;
use hecate_server::protocol::{ClientMessage, ErrorCode, FileInfo, ServerMessage};
use std::path::PathBuf;
use tempfile::tempdir;
use tokio::fs;

#[tokio::test]
async fn test_file_operations() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().to_path_buf();

    // Create test files
    let test_file = store_path.join("test.hecate");
    fs::write(&test_file, b"test content").await.unwrap();

    // Verify file exists
    assert!(test_file.exists());
    let content = fs::read(&test_file).await.unwrap();
    assert_eq!(content, b"test content");
}

#[test]
fn test_config_creation() {
    let config = Config::default();

    // Test defaults
    assert_eq!(config.server.port, 10112);
    assert_eq!(config.server.bind, "0.0.0.0");
    assert_eq!(config.server.max_connections, 50);
    assert_eq!(config.server.connection_timeout_secs, 300);

    assert!(config.health.enabled);
    assert_eq!(config.health.port, 9090);

    assert_eq!(config.logging.level, "info");
}

#[test]
fn test_message_serialisation_roundtrip() {
    // Test all client messages
    let messages = vec![
        ClientMessage::ListRequest,
        ClientMessage::GetRequest {
            name: "test.hecate".to_string(),
        },
        ClientMessage::UploadRequest {
            name: "upload.hecate".to_string(),
            size: 1024,
        },
        ClientMessage::DataChunk {
            data: vec![1, 2, 3, 4, 5],
            is_final: false,
        },
        ClientMessage::Auth {
            key: "test_key".to_string(),
        },
        ClientMessage::Ping,
    ];

    for msg in messages {
        let json = serde_json::to_string(&msg).unwrap();
        let deserialised: ClientMessage = serde_json::from_str(&json).unwrap();

        // Verify roundtrip works
        let json2 = serde_json::to_string(&deserialised).unwrap();
        assert_eq!(json, json2);
    }
}

#[test]
fn test_server_message_serialisation() {
    let messages = vec![
        ServerMessage::FileList {
            files: vec![FileInfo {
                name: "file1.hecate".to_string(),
                size: 1024,
                created: "2024-01-01T00:00:00Z".to_string(),
            }],
        },
        ServerMessage::DataChunk {
            data: vec![1, 2, 3],
            is_final: true,
        },
        ServerMessage::Error {
            code: ErrorCode::FileNotFound,
            message: "Test error".to_string(),
        },
        ServerMessage::UploadAccepted {
            name: "ready.hecate".to_string(),
        },
        ServerMessage::ChunkReceived {
            bytes_received: 1024,
        },
        ServerMessage::UploadComplete { total_bytes: 2048 },
        ServerMessage::AuthResult {
            success: true,
            message: Some("Authenticated".to_string()),
            user_id: None,
        },
        ServerMessage::UploadRejected {
            reason: "File too large".to_string(),
        },
        ServerMessage::Pong,
    ];

    for msg in messages {
        let json = serde_json::to_string(&msg).unwrap();
        let deserialised: ServerMessage = serde_json::from_str(&json).unwrap();

        // Verify roundtrip
        let json2 = serde_json::to_string(&deserialised).unwrap();
        assert_eq!(json, json2);
    }
}

// Test removed: ClientCredentials and ClientPermissions structs are not used
// in the actual implementation, only in test support code

#[test]
fn test_config_merge() {
    let mut config = Config::default();
    let original_port = config.server.port;

    // Create args with different values
    let args = hecate_server::args::Args {
        config: None,
        generate_config: false,
        validate: false,
        store: Some(PathBuf::from("/custom/store")),
        port: Some(9999),
        verbose: true,
        auth_key: Some("test_key".to_string()),
        auth_config: None,
        tls_cert: Some(PathBuf::from("/path/to/cert.pem")),
        tls_key: Some(PathBuf::from("/path/to/key.pem")),
    };

    config.merge_with_args(&args);

    // Verify merge worked
    assert_eq!(config.server.port, 9999);
    assert_ne!(config.server.port, original_port);
    assert_eq!(config.server.storage_path, PathBuf::from("/custom/store"));
    assert_eq!(config.auth.auth_key, Some("test_key".to_string()));
    assert_eq!(
        config.tls.cert_path,
        Some(PathBuf::from("/path/to/cert.pem"))
    );
    assert_eq!(config.tls.key_path, Some(PathBuf::from("/path/to/key.pem")));
}

#[test]
fn test_binary_data_handling() {
    // Create binary data with all byte values
    let mut binary_data = Vec::new();
    for i in 0..=255 {
        binary_data.push(i as u8);
    }

    let msg = ClientMessage::DataChunk {
        data: binary_data.clone(),
        is_final: true,
    };

    let json = serde_json::to_string(&msg).unwrap();
    let deserialised: ClientMessage = serde_json::from_str(&json).unwrap();

    match deserialised {
        ClientMessage::DataChunk { data, is_final } => {
            assert_eq!(data.len(), 256);
            assert_eq!(data, binary_data);
            assert!(is_final);
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_large_chunk_handling() {
    // Test 1MB chunk (typical size)
    let large_data = vec![0x42; 1024 * 1024];

    let msg = ServerMessage::DataChunk {
        data: large_data.clone(),
        is_final: false,
    };

    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.len() > 1024 * 1024); // JSON encoding adds overhead

    let deserialised: ServerMessage = serde_json::from_str(&json).unwrap();

    match deserialised {
        ServerMessage::DataChunk { data, is_final } => {
            assert_eq!(data.len(), 1024 * 1024);
            assert!(!is_final);
            assert!(data.iter().all(|&b| b == 0x42));
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_filename_validation() {
    use hecate_server::protocol::validate_filename;

    // Valid filenames
    assert!(validate_filename("test.hecate").is_ok());
    assert!(validate_filename("my-backup-2024.hecate").is_ok());
    assert!(validate_filename("data_archive.hecate").is_ok());

    // Invalid filenames
    assert!(validate_filename("").is_err()); // Empty
    assert!(validate_filename("test.txt").is_err()); // Wrong extension
    assert!(validate_filename("../etc/passwd.hecate").is_err()); // Path traversal
    assert!(validate_filename("test/file.hecate").is_err()); // Contains slash
    assert!(validate_filename("test\\file.hecate").is_err()); // Contains backslash
    assert!(validate_filename("test\0file.hecate").is_err()); // Control character

    // Very long filename (over 255 chars)
    let long_name = format!("{}.hecate", "a".repeat(250));
    assert!(validate_filename(&long_name).is_err());
}

#[test]
fn test_file_size_validation() {
    use hecate_server::protocol::validate_file_size;

    // Valid sizes - no upper limit
    assert!(validate_file_size(1).is_ok());
    assert!(validate_file_size(1024).is_ok());
    assert!(validate_file_size(1024 * 1024 * 1024).is_ok()); // 1GB
    assert!(validate_file_size(10 * 1024 * 1024 * 1024).is_ok()); // 10GB
    assert!(validate_file_size(u64::MAX).is_ok()); // Maximum possible size

    // Invalid sizes
    assert!(validate_file_size(0).is_err()); // Zero size not allowed
}

#[test]
fn test_chunk_size_validation() {
    use hecate_server::protocol::{validate_chunk_size, MAX_CHUNK_SIZE};

    // Valid chunks
    assert!(validate_chunk_size(&vec![1]).is_ok());
    assert!(validate_chunk_size(&vec![0; 1024]).is_ok());
    assert!(validate_chunk_size(&vec![0; MAX_CHUNK_SIZE]).is_ok());

    // Invalid chunks
    assert!(validate_chunk_size(&vec![]).is_err()); // Empty
    assert!(validate_chunk_size(&vec![0; MAX_CHUNK_SIZE + 1]).is_err()); // Too large
}

#[test]
fn test_error_codes() {
    // Test all error codes serialize correctly
    let errors = vec![
        ErrorCode::AuthRequired,
        ErrorCode::AuthFailed,
        ErrorCode::InvalidRequest,
        ErrorCode::FileNotFound,
        ErrorCode::FileTooLarge,
        ErrorCode::QuotaExceeded,
        ErrorCode::ServerError,
    ];

    for error_code in errors {
        let msg = ServerMessage::Error {
            code: error_code,
            message: format!("Error: {}", error_code),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialised: ServerMessage = serde_json::from_str(&json).unwrap();

        match deserialised {
            ServerMessage::Error { code, .. } => {
                assert_eq!(code, error_code);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
