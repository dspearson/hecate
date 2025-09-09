use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub defaults: DefaultSettings,

    #[serde(default)]
    pub servers: Vec<ServerConfig>,

    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DefaultSettings {
    #[serde(default = "default_shares_needed")]
    pub shares_needed: u8,

    #[serde(default = "default_total_shares")]
    pub total_shares: u8,

    #[serde(default = "default_server")]
    pub server: String,

    #[serde(default)]
    pub verbose: bool,

    #[serde(default)]
    pub output_dir: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub name: String,
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub auth_key: Option<String>,
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsConfig {
    /// Whether to verify the certificate (default: true)
    #[serde(default = "default_verify")]
    pub verify: bool,
    /// Optional certificate fingerprint to match (SHA256 hex)
    #[serde(default)]
    pub fingerprint: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify: true,
            fingerprint: None,
        }
    }
}

fn default_verify() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    /// Default preshared authentication key for servers that don't specify one
    #[serde(default)]
    pub default_key: Option<String>,
}

impl Default for DefaultSettings {
    fn default() -> Self {
        Self {
            shares_needed: default_shares_needed(),
            total_shares: default_total_shares(),
            server: default_server(),
            verbose: false,
            output_dir: None,
        }
    }
}

fn default_shares_needed() -> u8 {
    2
}
fn default_total_shares() -> u8 {
    5
}
fn default_server() -> String {
    "localhost:10112".to_string()
}

impl Config {
    /// Load config from the standard locations
    pub fn load() -> Result<Self> {
        // Try config locations in order of precedence
        let config_paths = Self::get_config_paths();

        for path in &config_paths {
            if path.exists() {
                return Self::load_from_file(path);
            }
        }

        // No config file found, use defaults
        Ok(Config::default())
    }

    /// Load config from a specific file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {path:?}"))?;

        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {path:?}"))?;

        Ok(config)
    }

    /// Save config to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self).context("Failed to serialise config")?;

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {parent:?}"))?;
        }

        fs::write(path, contents)
            .with_context(|| format!("Failed to write config file: {path:?}"))?;

        Ok(())
    }

    /// Get the list of config file paths to check, in order of precedence
    pub fn get_config_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // 1. Environment variable
        if let Ok(path) = std::env::var("HECATE_CONFIG") {
            paths.push(PathBuf::from(path));
        }

        // 2. Current directory
        paths.push(PathBuf::from(".hecate.toml"));

        // 3. User config directory (XDG_CONFIG_HOME or ~/.config)
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("hecate").join("config.toml"));
            paths.push(config_dir.join("hecate.toml"));
        }

        // 4. Home directory
        if let Some(home_dir) = dirs::home_dir() {
            paths.push(home_dir.join(".hecate.toml"));
        }

        // 5. System-wide config
        paths.push(PathBuf::from("/etc/hecate/config.toml"));

        paths
    }

    /// Get the default config file path for writing
    pub fn get_default_config_path() -> Result<PathBuf> {
        // Prefer XDG_CONFIG_HOME/hecate/config.toml
        if let Some(config_dir) = dirs::config_dir() {
            Ok(config_dir.join("hecate").join("config.toml"))
        } else if let Some(home_dir) = dirs::home_dir() {
            Ok(home_dir.join(".hecate.toml"))
        } else {
            anyhow::bail!("Could not determine config file location")
        }
    }

    /// Find a server configuration by name
    pub fn find_server(&self, name: &str) -> Option<&ServerConfig> {
        self.servers.iter().find(|s| s.name == name)
    }

    /// Get authentication key for a server
    pub fn get_auth_key(&self, server: &str) -> Option<String> {
        // First check if this is a named server with its own key
        if let Some(server_config) = self.find_server(server) {
            if let Some(ref key) = server_config.auth_key {
                return Some(key.clone());
            }
        }

        // Fall back to default auth key
        self.auth.default_key.clone()
    }

    /// Get the default server from config
    pub fn get_default_server(&self) -> String {
        // First check if any server is marked as default
        for server in &self.servers {
            if server.default {
                return format!("{}:{}", server.address, server.port);
            }
        }

        // Otherwise use the defaults.server value
        self.defaults.server.clone()
    }
}

/// Create a sample config file
pub fn create_sample_config() -> Config {
    Config {
        defaults: DefaultSettings {
            shares_needed: 2,
            total_shares: 5,
            server: "localhost:10112".to_string(),
            verbose: false,
            output_dir: None,
        },
        servers: vec![
            ServerConfig {
                name: "local".to_string(),
                address: "localhost".to_string(),
                port: 10112,
                default: true,
                auth_key: None,
                tls: TlsConfig {
                    verify: false, // Allow self-signed for localhost
                    fingerprint: None,
                },
            },
            ServerConfig {
                name: "backup".to_string(),
                address: "backup.example.com".to_string(),
                port: 10112,
                default: false,
                auth_key: Some("your-secret-key-here".to_string()),
                tls: TlsConfig::default(), // Full verification for production
            },
        ],
        auth: AuthConfig {
            default_key: Some("your-preshared-key-here".to_string()),
        },
    }
}
