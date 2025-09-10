use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::protocol::MAX_CHUNK_SIZE;
use crate::storage::StorageManager;
use crate::users::UserManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub index: u32,
    pub offset: u64,
    pub size: usize,
    pub hash: String, // SHA256 of chunk for integrity
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadStatus {
    pub session_id: String,
    pub total_size: u64,
    pub bytes_received: u64,
    pub chunks_total: u32,
    pub chunks_received: Vec<u32>,
    pub is_complete: bool,
    pub percentage: f64,
}

pub struct ResumableUploadManager {
    storage: StorageManager,
    user_manager: UserManager,
}

impl ResumableUploadManager {
    pub fn new(storage: StorageManager, user_manager: UserManager) -> Self {
        Self {
            storage,
            user_manager,
        }
    }

    /// Initialize a new resumable upload session
    pub async fn init_upload(
        &self,
        user_id: i64,
        filename: &str,
        total_size: u64,
    ) -> Result<String> {
        // Check user quota first
        if !self
            .storage
            .check_user_quota(user_id, total_size as i64)
            .await?
        {
            anyhow::bail!("Insufficient quota for upload");
        }

        // Create temporary file
        let (temp_path, _) = self.storage.create_temp_file(Some(user_id)).await?;

        // Create upload session in database
        let session_id = self
            .user_manager
            .create_upload_session(
                user_id,
                filename,
                total_size as i64,
                temp_path.to_string_lossy().as_ref(),
            )
            .await?;

        Ok(session_id)
    }

    /// Get upload status for a session
    pub async fn get_status(&self, session_id: &str) -> Result<Option<UploadStatus>> {
        let session = self.user_manager.get_upload_session(session_id).await?;

        match session {
            Some(s) => {
                let chunks_received: Vec<u32> = serde_json::from_str(&s.chunks_received)?;
                let chunks_total =
                    ((s.total_size + MAX_CHUNK_SIZE as i64 - 1) / MAX_CHUNK_SIZE as i64) as u32;
                let percentage = if s.total_size > 0 {
                    (s.bytes_received as f64 / s.total_size as f64) * 100.0
                } else {
                    0.0
                };

                Ok(Some(UploadStatus {
                    session_id: s.id,
                    total_size: s.total_size as u64,
                    bytes_received: s.bytes_received as u64,
                    chunks_total,
                    chunks_received,
                    is_complete: s.bytes_received >= s.total_size,
                    percentage,
                }))
            }
            None => Ok(None),
        }
    }

    /// Write a chunk to the upload
    pub async fn write_chunk(
        &self,
        session_id: &str,
        chunk_index: u32,
        data: &[u8],
    ) -> Result<UploadStatus> {
        let session = self
            .user_manager
            .get_upload_session(session_id)
            .await?
            .context("Upload session not found")?;

        // Parse existing chunks
        let mut chunks_received: HashSet<u32> = serde_json::from_str(&session.chunks_received)?;

        // Check if chunk was already received
        if chunks_received.contains(&chunk_index) {
            return self
                .get_status(session_id)
                .await?
                .context("Failed to get status");
        }

        // Calculate chunk offset
        let offset = chunk_index as u64 * MAX_CHUNK_SIZE as u64;

        // Open temp file and seek to position
        let temp_path = PathBuf::from(&session.temp_path);
        let mut file = File::options()
            .write(true)
            .create(true)
            .open(&temp_path)
            .await
            .context("Failed to open temp file")?;

        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .context("Failed to seek in file")?;

        file.write_all(data)
            .await
            .context("Failed to write chunk")?;

        file.sync_all().await.context("Failed to sync file")?;

        // Update session
        chunks_received.insert(chunk_index);
        let chunks_vec: Vec<u32> = chunks_received.into_iter().collect();
        let new_bytes = session.bytes_received + data.len() as i64;

        self.user_manager
            .update_upload_progress(session_id, new_bytes, &chunks_vec)
            .await?;

        // Check if upload is complete
        let chunks_total =
            ((session.total_size + MAX_CHUNK_SIZE as i64 - 1) / MAX_CHUNK_SIZE as i64) as u32;
        let is_complete = chunks_vec.len() as u32 == chunks_total;

        if is_complete {
            self.finalize_upload(session_id).await?;
        }

        Ok(UploadStatus {
            session_id: session_id.to_string(),
            total_size: session.total_size as u64,
            bytes_received: new_bytes as u64,
            chunks_total,
            chunks_received: chunks_vec,
            is_complete,
            percentage: (new_bytes as f64 / session.total_size as f64) * 100.0,
        })
    }

    /// Get missing chunks for an upload
    pub async fn get_missing_chunks(&self, session_id: &str) -> Result<Vec<u32>> {
        let session = self
            .user_manager
            .get_upload_session(session_id)
            .await?
            .context("Upload session not found")?;

        let chunks_received: HashSet<u32> = serde_json::from_str(&session.chunks_received)?;
        let chunks_total =
            ((session.total_size + MAX_CHUNK_SIZE as i64 - 1) / MAX_CHUNK_SIZE as i64) as u32;

        let missing: Vec<u32> = (0..chunks_total)
            .filter(|i| !chunks_received.contains(i))
            .collect();

        Ok(missing)
    }

    /// Finalize a completed upload
    async fn finalize_upload(&self, session_id: &str) -> Result<()> {
        let session = self
            .user_manager
            .get_upload_session(session_id)
            .await?
            .context("Upload session not found")?;

        let temp_path = PathBuf::from(&session.temp_path);

        // Move file to final location
        let final_path = self
            .storage
            .finalize_upload(&temp_path, &session.filename, Some(session.user_id))
            .await?;

        // Calculate file hash for deduplication
        let file_hash = self.storage.calculate_file_hash(&final_path).await?;

        // Update user's used bytes
        self.storage
            .update_user_usage(session.user_id, session.total_size)
            .await?;

        // Mark session as complete
        self.user_manager
            .complete_upload_session(session_id)
            .await?;

        // Log audit
        self.user_manager
            .log_audit(
                Some(session.user_id),
                "file_upload_completed",
                Some(serde_json::json!({
                    "filename": session.filename,
                    "size": session.total_size,
                    "hash": file_hash,
                    "session_id": session_id,
                })),
                None,
            )
            .await?;

        Ok(())
    }

    /// Cancel an upload session
    pub async fn cancel_upload(&self, session_id: &str) -> Result<()> {
        let session = self
            .user_manager
            .get_upload_session(session_id)
            .await?
            .context("Upload session not found")?;

        let temp_path = PathBuf::from(&session.temp_path);

        // Clean up temp file
        self.storage.cleanup_temp_file(&temp_path).await?;

        // Mark session as complete (cancelled)
        self.user_manager
            .complete_upload_session(session_id)
            .await?;

        // Log audit
        self.user_manager
            .log_audit(
                Some(session.user_id),
                "file_upload_cancelled",
                Some(serde_json::json!({
                    "filename": session.filename,
                    "session_id": session_id,
                })),
                None,
            )
            .await?;

        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) -> Result<usize> {
        self.user_manager.cleanup_expired_sessions().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn setup_test_managers() -> (ResumableUploadManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = StorageManager::new(temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let db_path = temp_dir.path().join("test.db");
        // Create the database file first
        std::fs::File::create(&db_path).unwrap();
        let user_manager = UserManager::new(&format!("sqlite://{}?mode=rwc", db_path.display()))
            .await
            .unwrap();

        let manager = ResumableUploadManager::new(storage, user_manager);
        (manager, temp_dir)
    }

    #[tokio::test]
    async fn test_resumable_upload() {
        let (manager, _temp_dir) = setup_test_managers().await;

        // Create a test user
        let user = manager
            .user_manager
            .create_user("testuser", "test@example.com", "password123", None)
            .await
            .unwrap();

        // Initialize upload
        let session_id = manager
            .init_upload(user.id, "test.hecate", 3 * MAX_CHUNK_SIZE as u64)
            .await
            .unwrap();

        // Write chunks
        let chunk1 = vec![1u8; MAX_CHUNK_SIZE];
        let status1 = manager.write_chunk(&session_id, 0, &chunk1).await.unwrap();
        assert_eq!(status1.chunks_received.len(), 1);
        assert!(!status1.is_complete);

        let chunk2 = vec![2u8; MAX_CHUNK_SIZE];
        let status2 = manager.write_chunk(&session_id, 1, &chunk2).await.unwrap();
        assert_eq!(status2.chunks_received.len(), 2);
        assert!(!status2.is_complete);

        // Get missing chunks
        let missing = manager.get_missing_chunks(&session_id).await.unwrap();
        assert_eq!(missing, vec![2]);

        let chunk3 = vec![3u8; MAX_CHUNK_SIZE];
        let status3 = manager.write_chunk(&session_id, 2, &chunk3).await.unwrap();
        assert_eq!(status3.chunks_received.len(), 3);
        assert!(status3.is_complete);
    }

    #[tokio::test]
    async fn test_duplicate_chunk() {
        let (manager, _temp_dir) = setup_test_managers().await;

        let user = manager
            .user_manager
            .create_user("testuser2", "test2@example.com", "password123", None)
            .await
            .unwrap();

        // Use 2 chunks so the upload doesn't complete after first chunk
        let session_id = manager
            .init_upload(user.id, "test.hecate", 2 * MAX_CHUNK_SIZE as u64)
            .await
            .unwrap();

        let chunk = vec![1u8; MAX_CHUNK_SIZE];

        // Write chunk first time
        let status1 = manager.write_chunk(&session_id, 0, &chunk).await.unwrap();
        assert_eq!(status1.bytes_received, MAX_CHUNK_SIZE as u64);
        assert!(!status1.is_complete);

        // Write same chunk again - should be idempotent
        let status2 = manager.write_chunk(&session_id, 0, &chunk).await.unwrap();
        assert_eq!(status2.bytes_received, MAX_CHUNK_SIZE as u64);
        assert!(!status2.is_complete);
    }
}
