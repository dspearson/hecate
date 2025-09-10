use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use crate::protocol::FileInfo;
use crate::users::UserManager;

/// Storage manager for handling file operations with multi-user support
pub struct StorageManager {
    base_path: PathBuf,
    user_manager: Option<UserManager>,
}

impl StorageManager {
    /// Create a new storage manager
    pub async fn new(base_path: PathBuf) -> Result<Self> {
        // Ensure the storage directory exists
        fs::create_dir_all(&base_path)
            .await
            .with_context(|| format!("Failed to create storage directory {:?}", base_path))?;

        Ok(Self {
            base_path,
            user_manager: None,
        })
    }

    /// Create a new storage manager with user management support
    pub async fn new_with_users(base_path: PathBuf, user_manager: UserManager) -> Result<Self> {
        fs::create_dir_all(&base_path)
            .await
            .with_context(|| format!("Failed to create storage directory {:?}", base_path))?;

        Ok(Self {
            base_path,
            user_manager: Some(user_manager),
        })
    }

    /// Get the storage path for a specific user
    fn get_user_path(&self, user_id: Option<i64>) -> PathBuf {
        match user_id {
            Some(id) => self.base_path.join(format!("user_{}", id)),
            None => self.base_path.clone(),
        }
    }

    /// Ensure user directory exists
    async fn ensure_user_dir(&self, user_id: Option<i64>) -> Result<PathBuf> {
        let path = self.get_user_path(user_id);
        fs::create_dir_all(&path)
            .await
            .with_context(|| format!("Failed to create user directory {:?}", path))?;
        Ok(path)
    }

    /// Generate a unique filename for storage
    pub fn generate_filename(&self, requested_name: &str) -> String {
        // If the filename already ends with .hecate, use it as-is
        if requested_name.ends_with(".hecate") {
            requested_name.to_string()
        } else {
            // Append .hecate extension
            format!("{}.hecate", requested_name)
        }
    }

    /// Create a temporary file for uploading
    pub async fn create_temp_file(&self, user_id: Option<i64>) -> Result<(PathBuf, fs::File)> {
        let user_path = self.ensure_user_dir(user_id).await?;
        let temp_name = format!(".upload_{}.tmp", Uuid::new_v4());
        let temp_path = user_path.join(temp_name);

        let file = fs::File::create(&temp_path)
            .await
            .with_context(|| format!("Failed to create temporary file {:?}", temp_path))?;

        Ok((temp_path, file))
    }

    /// Finalize an upload by moving temp file to final location
    pub async fn finalize_upload(
        &self,
        temp_path: &Path,
        filename: &str,
        user_id: Option<i64>,
    ) -> Result<PathBuf> {
        let user_path = self.ensure_user_dir(user_id).await?;
        let mut final_path = user_path.join(filename);

        // Handle filename collisions
        if final_path.exists() {
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
            let uuid = Uuid::new_v4();

            // Extract base name and extension
            let base = filename.trim_end_matches(".hecate");
            final_path = user_path.join(format!("{}_{}_{}.hecate", base, timestamp, uuid));
        }

        fs::rename(temp_path, &final_path).await.with_context(|| {
            format!(
                "Failed to finalize upload from {:?} to {:?}",
                temp_path, final_path
            )
        })?;

        Ok(final_path)
    }

    /// Delete a temporary file (used for cleanup on error)
    pub async fn cleanup_temp_file(&self, temp_path: &Path) -> Result<()> {
        if temp_path.exists() {
            fs::remove_file(temp_path)
                .await
                .with_context(|| format!("Failed to cleanup temporary file {:?}", temp_path))?;
        }
        Ok(())
    }

    /// List all files in storage for a user
    pub async fn list_files(&self, user_id: Option<i64>) -> Result<Vec<FileInfo>> {
        let user_path = self.get_user_path(user_id);

        // If user directory doesn't exist, return empty list
        if !user_path.exists() {
            return Ok(Vec::new());
        }

        let mut entries = fs::read_dir(&user_path)
            .await
            .with_context(|| format!("Failed to read storage directory {:?}", user_path))?;

        let mut files = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;

            // Skip directories and hidden/temp files
            if metadata.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();

                // Skip temporary files
                if name.starts_with('.') || name.ends_with(".tmp") {
                    continue;
                }

                // Only list .hecate files
                if !name.ends_with(".hecate") {
                    continue;
                }

                let created = metadata
                    .created()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| {
                        chrono::DateTime::<Utc>::from_timestamp(d.as_secs() as i64, 0)
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_else(|| "unknown".to_string())
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                files.push(FileInfo {
                    name,
                    size: metadata.len(),
                    created,
                });
            }
        }

        // Sort by creation time (newest first)
        files.sort_by(|a, b| b.created.cmp(&a.created));

        Ok(files)
    }

    /// Get a file for download
    pub async fn get_file(&self, filename: &str, user_id: Option<i64>) -> Result<PathBuf> {
        let user_path = self.get_user_path(user_id);
        let file_path = user_path.join(filename);

        if !file_path.exists() {
            anyhow::bail!("File not found: {}", filename);
        }

        if !file_path.is_file() {
            anyhow::bail!("Path is not a file: {}", filename);
        }

        Ok(file_path)
    }

    /// Get storage statistics for a user
    pub async fn get_stats(&self, user_id: Option<i64>) -> Result<StorageStats> {
        let user_path = self.get_user_path(user_id);

        if !user_path.exists() {
            return Ok(StorageStats {
                total_size: 0,
                file_count: 0,
                temp_file_count: 0,
                storage_path: user_path.display().to_string(),
            });
        }

        let mut total_size = 0u64;
        let mut file_count = 0usize;
        let mut temp_file_count = 0usize;

        let mut entries = fs::read_dir(&user_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            if let Ok(metadata) = entry.metadata().await {
                if metadata.is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();

                    if name.starts_with('.') || name.ends_with(".tmp") {
                        temp_file_count += 1;
                    } else if name.ends_with(".hecate") {
                        file_count += 1;
                        total_size += metadata.len();
                    }
                }
            }
        }

        Ok(StorageStats {
            total_size,
            file_count,
            temp_file_count,
            storage_path: user_path.display().to_string(),
        })
    }

    /// Clean up old temporary files for a user
    pub async fn cleanup_old_temp_files(
        &self,
        max_age_hours: u64,
        user_id: Option<i64>,
    ) -> Result<usize> {
        let user_path = self.get_user_path(user_id);

        if !user_path.exists() {
            return Ok(0);
        }

        let mut cleaned = 0;
        let max_age = std::time::Duration::from_secs(max_age_hours * 3600);
        let now = std::time::SystemTime::now();

        let mut entries = fs::read_dir(&user_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();

            // Only clean up temp files
            if name.starts_with(".upload_") && name.ends_with(".tmp") {
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(age) = now.duration_since(modified) {
                            if age > max_age {
                                if fs::remove_file(entry.path()).await.is_ok() {
                                    cleaned += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(cleaned)
    }

    /// Calculate SHA256 hash of a file
    pub async fn calculate_file_hash(&self, path: &Path) -> Result<String> {
        let mut file = fs::File::open(path).await?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 8192];

        loop {
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Check if user has enough quota for a file
    pub async fn check_user_quota(&self, user_id: i64, size: i64) -> Result<bool> {
        if let Some(ref user_manager) = self.user_manager {
            user_manager.check_quota(user_id, size).await
        } else {
            Ok(true) // No quota management without user manager
        }
    }

    /// Update user's used bytes after successful upload
    pub async fn update_user_usage(&self, user_id: i64, delta: i64) -> Result<()> {
        if let Some(ref user_manager) = self.user_manager {
            user_manager.update_used_bytes(user_id, delta).await
        } else {
            Ok(())
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_size: u64,
    pub file_count: usize,
    pub temp_file_count: usize,
    pub storage_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_storage_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = StorageManager::new(temp_dir.path().to_path_buf())
            .await
            .unwrap();

        // Directory should exist
        assert!(temp_dir.path().exists());

        // Stats should be empty
        let stats = storage.get_stats(None).await.unwrap();
        assert_eq!(stats.file_count, 0);
        assert_eq!(stats.total_size, 0);
    }

    #[tokio::test]
    async fn test_filename_generation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = StorageManager::new(temp_dir.path().to_path_buf())
            .await
            .unwrap();

        // Should preserve .hecate extension
        assert_eq!(storage.generate_filename("test.hecate"), "test.hecate");

        // Should add .hecate extension
        assert_eq!(storage.generate_filename("test"), "test.hecate");
    }

    #[tokio::test]
    async fn test_temp_file_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = StorageManager::new(temp_dir.path().to_path_buf())
            .await
            .unwrap();

        let (temp_path, mut file) = storage.create_temp_file(None).await.unwrap();

        // Temp file should exist
        assert!(temp_path.exists());
        assert!(temp_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".upload_"));

        // Should be writable
        file.write_all(b"test data").await.unwrap();
        file.sync_all().await.unwrap();

        // Cleanup
        storage.cleanup_temp_file(&temp_path).await.unwrap();
        assert!(!temp_path.exists());
    }

    #[tokio::test]
    async fn test_user_isolation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = StorageManager::new(temp_dir.path().to_path_buf())
            .await
            .unwrap();

        // Create files for different users
        let (temp1, mut file1) = storage.create_temp_file(Some(1)).await.unwrap();
        file1.write_all(b"user1 data").await.unwrap();
        file1.sync_all().await.unwrap();
        drop(file1);

        let path1 = storage
            .finalize_upload(&temp1, "file1.hecate", Some(1))
            .await
            .unwrap();

        let (temp2, mut file2) = storage.create_temp_file(Some(2)).await.unwrap();
        file2.write_all(b"user2 data").await.unwrap();
        file2.sync_all().await.unwrap();
        drop(file2);

        let path2 = storage
            .finalize_upload(&temp2, "file2.hecate", Some(2))
            .await
            .unwrap();

        // Verify user directories are separate
        assert!(path1.to_string_lossy().contains("user_1"));
        assert!(path2.to_string_lossy().contains("user_2"));

        // Verify each user only sees their own files
        let user1_files = storage.list_files(Some(1)).await.unwrap();
        assert_eq!(user1_files.len(), 1);
        assert_eq!(user1_files[0].name, "file1.hecate");

        let user2_files = storage.list_files(Some(2)).await.unwrap();
        assert_eq!(user2_files.len(), 1);
        assert_eq!(user2_files[0].name, "file2.hecate");
    }
}
