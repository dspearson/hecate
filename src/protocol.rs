use serde::{Deserialize, Serialize};
use std::fmt;

// Maximum chunk size: 1MB
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    Auth { key: String },
    UploadRequest { name: String, size: u64 },
    DataChunk { data: Vec<u8>, is_final: bool },
    ListRequest,
    GetRequest { name: String },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    AuthResult {
        success: bool,
        message: Option<String>,
    },
    UploadAccepted {
        name: String,
    },
    UploadRejected {
        reason: String,
    },
    ChunkReceived {
        bytes_received: u64,
    },
    UploadComplete {
        total_bytes: u64,
    },
    FileList {
        files: Vec<FileInfo>,
    },
    DataChunk {
        data: Vec<u8>,
        is_final: bool,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub created: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    AuthRequired,
    AuthFailed,
    InvalidRequest,
    FileNotFound,
    FileTooLarge,
    QuotaExceeded,
    RateLimited,
    ServerError,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::AuthRequired => write!(f, "AUTH_REQUIRED"),
            ErrorCode::AuthFailed => write!(f, "AUTH_FAILED"),
            ErrorCode::InvalidRequest => write!(f, "INVALID_REQUEST"),
            ErrorCode::FileNotFound => write!(f, "FILE_NOT_FOUND"),
            ErrorCode::FileTooLarge => write!(f, "FILE_TOO_LARGE"),
            ErrorCode::QuotaExceeded => write!(f, "QUOTA_EXCEEDED"),
            ErrorCode::RateLimited => write!(f, "RATE_LIMITED"),
            ErrorCode::ServerError => write!(f, "SERVER_ERROR"),
        }
    }
}

// Input validation functions
pub fn validate_filename(name: &str) -> Result<(), String> {
    // Check for empty name
    if name.is_empty() {
        return Err("Filename cannot be empty".to_string());
    }

    // Check length
    if name.len() > 255 {
        return Err("Filename too long (max 255 characters)".to_string());
    }

    // Check for directory traversal attempts
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err("Invalid characters in filename".to_string());
    }

    // Check for control characters
    if name.chars().any(|c| c.is_control()) {
        return Err("Control characters not allowed in filename".to_string());
    }

    // Ensure it ends with .hecate
    if !name.ends_with(".hecate") {
        return Err("Filename must end with .hecate".to_string());
    }

    Ok(())
}

pub fn validate_chunk_size(chunk: &[u8]) -> Result<(), String> {
    if chunk.is_empty() {
        return Err("Chunk cannot be empty".to_string());
    }

    if chunk.len() > MAX_CHUNK_SIZE {
        return Err(format!(
            "Chunk too large (max {} MB)",
            MAX_CHUNK_SIZE / (1024 * 1024)
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_filename() {
        assert!(validate_filename("test.hecate").is_ok());
        assert!(validate_filename("my-backup-2024.hecate").is_ok());

        assert!(validate_filename("").is_err());
        assert!(validate_filename("../etc/passwd.hecate").is_err());
        assert!(validate_filename("/etc/passwd.hecate").is_err());
        assert!(validate_filename("test\\file.hecate").is_err());
        assert!(validate_filename("test.txt").is_err());
        assert!(validate_filename("test\0.hecate").is_err());

        let long_name = format!("{}.hecate", "a".repeat(250));
        assert!(validate_filename(&long_name).is_err());
    }

    #[test]
    fn test_message_serialization() {
        let msg = ClientMessage::Auth {
            key: "secret".to_string(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: ClientMessage = serde_json::from_str(&json).unwrap();

        match decoded {
            ClientMessage::Auth { key } => assert_eq!(key, "secret"),
            _ => panic!("Wrong message type"),
        }
    }
}
