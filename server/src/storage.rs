use anyhow::{Context, Result};
use chrono::Utc;
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

use crate::protocol::FileInfo;

/// Storage manager for handling file operations
pub struct StorageManager {
    base_path: PathBuf,
}

impl StorageManager {
    /// Create a new storage manager
    pub async fn new(base_path: PathBuf) -> Result<Self> {
        // Ensure the storage directory exists
        fs::create_dir_all(&base_path)
            .await
            .with_context(|| format!("Failed to create storage directory {:?}", base_path))?;

        Ok(Self { base_path })
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
    pub async fn create_temp_file(&self) -> Result<(PathBuf, fs::File)> {
        let temp_name = format!(".upload_{}.tmp", Uuid::new_v4());
        let temp_path = self.base_path.join(temp_name);

        let file = fs::File::create(&temp_path)
            .await
            .with_context(|| format!("Failed to create temporary file {:?}", temp_path))?;

        Ok((temp_path, file))
    }

    /// Finalize an upload by moving temp file to final location
    pub async fn finalize_upload(&self, temp_path: &Path, filename: &str) -> Result<PathBuf> {
        let mut final_path = self.base_path.join(filename);

        // Handle filename collisions
        if final_path.exists() {
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
            let uuid = Uuid::new_v4();

            // Extract base name and extension
            let base = filename.trim_end_matches(".hecate");
            final_path = self
                .base_path
                .join(format!("{}_{}_{}.hecate", base, timestamp, uuid));
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

    /// List all files in storage
    pub async fn list_files(&self) -> Result<Vec<FileInfo>> {
        let mut entries = fs::read_dir(&self.base_path)
            .await
            .with_context(|| format!("Failed to read storage directory {:?}", self.base_path))?;

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
    pub async fn get_file(&self, filename: &str) -> Result<PathBuf> {
        let file_path = self.base_path.join(filename);

        if !file_path.exists() {
            anyhow::bail!("File not found: {}", filename);
        }

        if !file_path.is_file() {
            anyhow::bail!("Path is not a file: {}", filename);
        }

        Ok(file_path)
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> Result<StorageStats> {
        let mut total_size = 0u64;
        let mut file_count = 0usize;
        let mut temp_file_count = 0usize;

        let mut entries = fs::read_dir(&self.base_path).await?;

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
            storage_path: self.base_path.display().to_string(),
        })
    }

    /// Clean up old temporary files
    pub async fn cleanup_old_temp_files(&self, max_age_hours: u64) -> Result<usize> {
        let mut cleaned = 0;
        let max_age = std::time::Duration::from_secs(max_age_hours * 3600);
        let now = std::time::SystemTime::now();

        let mut entries = fs::read_dir(&self.base_path).await?;

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
        let stats = storage.get_stats().await.unwrap();
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

        let (temp_path, mut file) = storage.create_temp_file().await.unwrap();

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
}
