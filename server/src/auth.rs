#[cfg(test)]
#[allow(dead_code)]
pub mod test_support {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClientCredentials {
        pub client_id: String,
        pub key_hash: String, // Argon2 hash
        pub permissions: ClientPermissions,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClientPermissions {
        pub can_upload: bool,
        pub can_download: bool,
        pub can_list: bool,
        pub max_file_size: Option<u64>,     // Per-file limit (enforced)
        pub max_total_storage: Option<u64>, // Total storage quota (not enforced)
    }

    impl Default for ClientPermissions {
        fn default() -> Self {
            Self {
                can_upload: true,
                can_download: true,
                can_list: true,
                max_file_size: None,
                max_total_storage: None,
            }
        }
    }
    use anyhow::{Context, Result};
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Arc;
    use tokio::fs;
    use tokio::sync::RwLock;

    pub struct AuthManager {
        clients: Arc<RwLock<HashMap<String, ClientCredentials>>>,
        config_path: Option<String>,
    }

    impl AuthManager {
        pub async fn new(config_path: Option<String>) -> Result<Self> {
            let manager = Self {
                clients: Arc::new(RwLock::new(HashMap::new())),
                config_path,
            };

            if let Some(ref path) = manager.config_path {
                manager.load_config(path).await?;
            }

            Ok(manager)
        }

        async fn load_config(&self, path: &str) -> Result<()> {
            if !Path::new(path).exists() {
                return Ok(());
            }

            let content = fs::read_to_string(path)
                .await
                .context("Failed to read auth config")?;

            let credentials: Vec<ClientCredentials> =
                serde_json::from_str(&content).context("Failed to parse auth config")?;

            let mut clients = self.clients.write().await;
            clients.clear();

            for cred in credentials {
                clients.insert(cred.client_id.clone(), cred);
            }

            Ok(())
        }

        pub async fn authenticate(
            &self,
            client_id: &str,
            key: &str,
        ) -> Result<Option<ClientPermissions>> {
            let clients = self.clients.read().await;

            // Authentication is always required - no exceptions
            if clients.is_empty() {
                // This should never happen as we validate config has auth
                anyhow::bail!("No authentication configured - server misconfiguration");
            }

            if let Some(cred) = clients.get(client_id) {
                if Self::verify_key(key, &cred.key_hash)? {
                    return Ok(Some(cred.permissions.clone()));
                }
            }

            Ok(None)
        }

        fn verify_key(key: &str, hash: &str) -> Result<bool> {
            let parsed_hash = PasswordHash::new(hash)
                .map_err(|e| anyhow::anyhow!("Invalid password hash: {}", e))?;

            let argon2 = Argon2::default();
            Ok(argon2.verify_password(key.as_bytes(), &parsed_hash).is_ok())
        }
    }
}
