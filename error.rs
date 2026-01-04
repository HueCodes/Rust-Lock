use thiserror::Error;

/// Custom error types for SecureFS operations
#[derive(Debug, Error)]
pub enum SecureFsError {
    /// Key-related errors (loading, generation, validation)
    #[error("Key error: {0}")]
    Key(String),

    /// Encryption operation failures
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption operation failures (includes authentication failures)
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// File storage and I/O errors
    #[error("Storage error: {0}")]
    Storage(String),

    /// File format errors (version mismatch, corrupted headers)
    #[error("Format error: {0}")]
    Format(String),

    /// Configuration errors
    #[error("Config error: {0}")]
    Config(String),
}

impl SecureFsError {
    pub fn key(msg: impl Into<String>) -> Self {
        Self::Key(msg.into())
    }

    pub fn encryption(msg: impl Into<String>) -> Self {
        Self::Encryption(msg.into())
    }

    pub fn decryption(msg: impl Into<String>) -> Self {
        Self::Decryption(msg.into())
    }

    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }

    pub fn format(msg: impl Into<String>) -> Self {
        Self::Format(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}

impl From<std::io::Error> for SecureFsError {
    fn from(err: std::io::Error) -> Self {
        Self::Storage(err.to_string())
    }
}
