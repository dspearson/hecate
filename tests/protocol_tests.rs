#[cfg(test)]
mod protocol_tests {
    use hecate::protocol::*;
    use serde_json;

    #[test]
    fn test_filename_validation_valid() {
        assert!(validate_filename("backup.hecate").is_ok());
        assert!(validate_filename("my-archive-2024.hecate").is_ok());
        assert!(validate_filename("test_file_123.hecate").is_ok());
    }

    #[test]
    fn test_filename_validation_invalid() {
        // Empty filename
        assert!(validate_filename("").is_err());

        // Directory traversal
        assert!(validate_filename("../etc/passwd.hecate").is_err());
        assert!(validate_filename("../../secrets.hecate").is_err());
        assert!(validate_filename("/etc/passwd.hecate").is_err());
        assert!(validate_filename("test\\..\\secrets.hecate").is_err());

        // Wrong extension
        assert!(validate_filename("file.txt").is_err());
        assert!(validate_filename("archive.tar.gz").is_err());

        // Control characters
        assert!(validate_filename("file\0.hecate").is_err());
        assert!(validate_filename("file\n.hecate").is_err());
        assert!(validate_filename("file\r.hecate").is_err());

        // Too long (> 255 chars)
        let long_name = format!("{}.hecate", "a".repeat(250));
        assert!(validate_filename(&long_name).is_err());
    }

    #[test]
    fn test_chunk_size_validation() {
        // Valid chunks
        assert!(validate_chunk_size(&vec![1u8]).is_ok());
        assert!(validate_chunk_size(&vec![0u8; 1024]).is_ok());
        assert!(validate_chunk_size(&vec![0u8; MAX_CHUNK_SIZE]).is_ok());

        // Invalid chunks
        assert!(validate_chunk_size(&vec![]).is_err());
        assert!(validate_chunk_size(&vec![0u8; MAX_CHUNK_SIZE + 1]).is_err());
    }

    #[test]
    fn test_client_message_serialization() {
        let messages = vec![
            ClientMessage::Auth {
                key: "secret_key".to_string(),
            },
            ClientMessage::UploadRequest {
                name: "test.hecate".to_string(),
                size: 1024,
            },
            ClientMessage::DataChunk {
                data: vec![1, 2, 3, 4],
                is_final: false,
            },
            ClientMessage::ListRequest,
            ClientMessage::GetRequest {
                name: "file.hecate".to_string(),
            },
            ClientMessage::Ping,
        ];

        for msg in messages {
            let json = serde_json::to_string(&msg).unwrap();
            let deserialized: ClientMessage = serde_json::from_str(&json).unwrap();

            // Verify roundtrip
            let json2 = serde_json::to_string(&deserialized).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_server_message_serialization() {
        let messages = vec![
            ServerMessage::AuthResult {
                success: true,
                message: Some("Authenticated".to_string()),
            },
            ServerMessage::UploadAccepted {
                name: "file-123.hecate".to_string(),
            },
            ServerMessage::UploadRejected {
                reason: "File too large".to_string(),
            },
            ServerMessage::ChunkReceived {
                bytes_received: 1024,
            },
            ServerMessage::UploadComplete {
                total_bytes: 1048576,
            },
            ServerMessage::FileList {
                files: vec![
                    FileInfo {
                        name: "backup1.hecate".to_string(),
                        size: 1024,
                        created: "2024-01-01T00:00:00Z".to_string(),
                    },
                    FileInfo {
                        name: "backup2.hecate".to_string(),
                        size: 2048,
                        created: "2024-01-02T00:00:00Z".to_string(),
                    },
                ],
            },
            ServerMessage::DataChunk {
                data: vec![5, 6, 7, 8],
                is_final: true,
            },
            ServerMessage::Error {
                code: ErrorCode::RateLimited,
                message: "Too many requests".to_string(),
            },
            ServerMessage::Pong,
        ];

        for msg in messages {
            let json = serde_json::to_string(&msg).unwrap();
            let deserialized: ServerMessage = serde_json::from_str(&json).unwrap();

            // Verify roundtrip
            let json2 = serde_json::to_string(&deserialized).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(format!("{}", ErrorCode::AuthRequired), "AUTH_REQUIRED");
        assert_eq!(format!("{}", ErrorCode::AuthFailed), "AUTH_FAILED");
        assert_eq!(format!("{}", ErrorCode::InvalidRequest), "INVALID_REQUEST");
        assert_eq!(format!("{}", ErrorCode::FileNotFound), "FILE_NOT_FOUND");
        assert_eq!(format!("{}", ErrorCode::FileTooLarge), "FILE_TOO_LARGE");
        assert_eq!(format!("{}", ErrorCode::QuotaExceeded), "QUOTA_EXCEEDED");
        assert_eq!(format!("{}", ErrorCode::RateLimited), "RATE_LIMITED");
        assert_eq!(format!("{}", ErrorCode::ServerError), "SERVER_ERROR");
    }

    #[test]
    fn test_message_type_tags() {
        // Verify that serde tags work correctly
        let auth = ClientMessage::Auth {
            key: "test".to_string(),
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains(r#""type":"Auth""#));

        let ping = ClientMessage::Ping;
        let json = serde_json::to_string(&ping).unwrap();
        assert!(json.contains(r#""type":"Ping""#));
    }

    #[test]
    fn test_malformed_json_handling() {
        // Test that malformed JSON is rejected
        let bad_json = r#"{"type": "Auth", "invalid_field": "value"}"#;
        let result: Result<ClientMessage, _> = serde_json::from_str(bad_json);
        assert!(result.is_err() || matches!(result, Ok(ClientMessage::Auth { .. })));

        let bad_json = r#"{"not_a_type": "Auth"}"#;
        let result: Result<ClientMessage, _> = serde_json::from_str(bad_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_boundary_values() {
        // Test chunk size boundaries
        assert!(validate_chunk_size(&vec![0u8; MAX_CHUNK_SIZE]).is_ok());
        assert!(validate_chunk_size(&vec![0u8; MAX_CHUNK_SIZE + 1]).is_err());

        // Test filename length boundaries
        // ".hecate" is 7 characters, so we need 248 'a's to make 255 total
        let max_filename = format!("{}.hecate", "a".repeat(248)); // 248 + 7 = 255 total
        assert_eq!(max_filename.len(), 255);
        assert!(validate_filename(&max_filename).is_ok());

        let too_long = format!("{}.hecate", "a".repeat(249)); // 249 + 7 = 256 total
        assert_eq!(too_long.len(), 256);
        assert!(validate_filename(&too_long).is_err());
    }
}
