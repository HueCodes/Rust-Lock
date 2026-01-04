//! # SecureFS - Encrypted File Storage Library
//!
//! SecureFS provides military-grade file encryption using XChaCha20-Poly1305 AEAD
//! with optional gzip compression and streaming support for large files.
//!
//! ## Features
//!
//! - **XChaCha20-Poly1305**: Extended-nonce authenticated encryption
//! - **Streaming API**: Process large files without loading into memory
//! - **Compression**: Optional gzip compression before encryption
//! - **Secure Key Management**: Automatic zeroization and Unix permissions
//! - **Format Detection**: Auto-detect V1 (buffer) and V2 (streaming) formats
//!
//! ## Quick Start
//!
//! ```no_run
//! use securefs::{config::Config, key_manager::KeyManager, storagefile_ops::SecureFileOps};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let cfg = Config::new("./key.bin", "./storage");
//!     let km = KeyManager::new(&cfg).await?;
//!     let ops = SecureFileOps::new(km, &cfg.storage_dir);
//!
//!     // Encrypt data
//!     ops.write_encrypted("secret.txt", b"sensitive data").await?;
//!
//!     // Decrypt data
//!     let data = ops.read_encrypted("secret.txt").await?;
//!     Ok(())
//! }
//! ```
//!
//! ## File Format Versions
//!
//! - **V1 (Legacy)**: Single-buffer encryption with nonce prefix
//! - **V2 (Streaming)**: Chunked encryption with version header

pub mod config;
pub mod encryptor;
pub mod error;
pub mod key_manager;
pub mod metadata;
pub mod storagefile_ops;
pub mod streaming;
pub mod util;

// Re-export common types for convenience
pub use error::SecureFsError;
