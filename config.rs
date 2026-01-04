//! Configuration management with environment variable support.
//!
//! This module provides [`Config`] for loading and validating SecureFS settings
//! from JSON files and environment variables.
//!
//! ## Environment Variables
//!
//! - `SECUREFS_KEY_PATH`: Override encryption key file path
//! - `SECUREFS_STORAGE_DIR`: Override storage directory path
//! - `SECUREFS_CONFIG`: Override config file path

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

/// Environment variable names for configuration overrides
pub const ENV_KEY_PATH: &str = "SECUREFS_KEY_PATH";
pub const ENV_STORAGE_DIR: &str = "SECUREFS_STORAGE_DIR";
pub const ENV_CONFIG_PATH: &str = "SECUREFS_CONFIG";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub key_path: String,
    pub storage_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_path: "./securefs.key".to_string(),
            storage_dir: "./storage".to_string(),
        }
    }
}

impl Config {
    /// Load config from file path
    pub fn load(path: &str) -> Result<Self> {
        let s =
            fs::read_to_string(path).with_context(|| format!("reading config file {}", path))?;
        let mut config: Config = serde_json::from_str(&s)?;
        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    /// Load config with environment variable overrides
    /// Priority: ENV vars > config file > defaults
    pub fn load_with_env(path: Option<&str>) -> Result<Self> {
        // Check for config path from environment
        let config_path = path
            .map(String::from)
            .or_else(|| env::var(ENV_CONFIG_PATH).ok());

        let mut config = match config_path {
            Some(ref p) if Path::new(p).exists() => {
                info!(path = p, "loading config from file");
                let s = fs::read_to_string(p)
                    .with_context(|| format!("reading config file {}", p))?;
                serde_json::from_str(&s)?
            }
            _ => {
                debug!("using default configuration");
                Config::default()
            }
        };

        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    /// Apply environment variable overrides to config
    fn apply_env_overrides(&mut self) {
        if let Ok(key_path) = env::var(ENV_KEY_PATH) {
            debug!(key_path = %key_path, "overriding key_path from environment");
            self.key_path = key_path;
        }

        if let Ok(storage_dir) = env::var(ENV_STORAGE_DIR) {
            debug!(storage_dir = %storage_dir, "overriding storage_dir from environment");
            self.storage_dir = storage_dir;
        }
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        // Validate key_path is not empty
        if self.key_path.trim().is_empty() {
            anyhow::bail!("key_path cannot be empty");
        }

        // Validate storage_dir is not empty
        if self.storage_dir.trim().is_empty() {
            anyhow::bail!("storage_dir cannot be empty");
        }

        // Warn if key path looks like it might be in a public directory
        let key_path = Path::new(&self.key_path);
        if let Some(parent) = key_path.parent() {
            let parent_str = parent.to_string_lossy().to_lowercase();
            if parent_str.contains("public")
                || parent_str.contains("www")
                || parent_str.contains("htdocs")
            {
                warn!(
                    path = %self.key_path,
                    "key file path appears to be in a public directory - this is a security risk"
                );
            }
        }

        // Warn if paths contain potentially sensitive patterns
        if self.key_path.contains("..") {
            warn!("key_path contains '..' - consider using absolute paths");
        }

        Ok(())
    }

    /// Create a new config with explicit values
    pub fn new(key_path: impl Into<String>, storage_dir: impl Into<String>) -> Self {
        Self {
            key_path: key_path.into(),
            storage_dir: storage_dir.into(),
        }
    }
}
