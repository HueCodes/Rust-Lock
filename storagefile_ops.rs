//! High-level secure file operations.
//!
//! This module provides [`SecureFileOps`], the primary interface for encrypting,
//! decrypting, and managing files in the secure storage.
//!
//! ## Features
//!
//! - Buffer and streaming encryption modes
//! - Optional compression
//! - Auto-format detection for reading files
//! - File metadata tracking
//! - Concurrent operation support

use crate::encryptor::Encryptor;
use crate::key_manager::KeyManager;
use crate::metadata::FileMetadata;
use crate::streaming::{FormatFlags, StreamEncryptor, VERSION_V2_STREAM};
use anyhow::{Context, Result};
use std::io::Cursor;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, info, warn};

pub struct SecureFileOps {
    encryptor: Encryptor,
    stream_encryptor: StreamEncryptor,
    root: PathBuf,
    compress: bool,
}

impl SecureFileOps {
    pub fn new(km: KeyManager, root: impl Into<PathBuf>) -> Self {
        Self {
            encryptor: Encryptor::new(km.cipher()),
            stream_encryptor: StreamEncryptor::new(km.cipher()),
            root: root.into(),
            compress: false,
        }
    }

    pub fn with_compression(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    pub async fn write_encrypted(&self, name: &str, data: &[u8]) -> Result<()> {
        debug!(file = name, size = data.len(), compress = self.compress, "encrypting file (buffer mode)");
        fs::create_dir_all(&self.root).await?;
        let path = self.root.join(name);
        let enc = if self.compress {
            self.encryptor.encrypt_compressed(data, None)?
        } else {
            self.encryptor.encrypt(data, None)?
        };
        fs::write(&path, &enc).await?;
        FileMetadata::record(&path, data.len() as u64).await?;
        info!(file = name, original_size = data.len(), encrypted_size = enc.len(), "file encrypted successfully");
        Ok(())
    }

    pub async fn read_encrypted(&self, name: &str) -> Result<Vec<u8>> {
        debug!(file = name, "decrypting file (buffer mode)");
        let path = self.root.join(name);
        let data = fs::read(&path)
            .await
            .with_context(|| format!("reading {:?}", &path))?;
        let result = if self.compress {
            self.encryptor.decrypt_compressed(&data, None)
        } else {
            self.encryptor.decrypt(&data, None)
        };
        match &result {
            Ok(plaintext) => info!(file = name, encrypted_size = data.len(), decrypted_size = plaintext.len(), "file decrypted successfully"),
            Err(e) => error!(file = name, error = %e, "decryption failed"),
        }
        result
    }

    /// Write encrypted data from a stream source (for large files)
    /// Uses chunked encryption to avoid loading entire file into memory
    /// Recommended for files > 10MB
    pub async fn write_encrypted_stream<R>(
        &self,
        name: &str,
        reader: &mut R,
    ) -> Result<u64>
    where
        R: AsyncRead + Unpin,
    {
        debug!(file = name, compress = self.compress, "encrypting file (streaming mode)");
        fs::create_dir_all(&self.root).await?;
        let path = self.root.join(name);

        let mut file = fs::File::create(&path).await
            .with_context(|| format!("creating {:?}", &path))?;

        let flags = FormatFlags {
            compressed: self.compress,
        };

        // Use filename as AAD for tamper detection
        let aad = name.as_bytes();

        let bytes_written = self.stream_encryptor
            .encrypt_stream(reader, &mut file, flags, Some(aad))
            .await?;

        // Record metadata
        FileMetadata::record(&path, bytes_written).await?;

        info!(file = name, bytes = bytes_written, "file encrypted successfully (streaming)");
        Ok(bytes_written)
    }

    /// Read and decrypt data to a stream destination (for large files)
    /// Uses chunked decryption to avoid loading entire file into memory
    /// Returns number of plaintext bytes written and compression flag
    pub async fn read_encrypted_stream<W>(
        &self,
        name: &str,
        writer: &mut W,
    ) -> Result<(u64, bool)>
    where
        W: AsyncWrite + Unpin,
    {
        debug!(file = name, "decrypting file (streaming mode)");
        let path = self.root.join(name);
        let mut file = fs::File::open(&path).await
            .with_context(|| format!("opening {:?}", &path))?;

        // Use filename as AAD for tamper detection
        let aad = name.as_bytes();

        let (bytes_read, flags) = self.stream_encryptor
            .decrypt_stream(&mut file, writer, Some(aad))
            .await?;

        info!(file = name, bytes = bytes_read, compressed = flags.compressed, "file decrypted successfully (streaming)");
        Ok((bytes_read, flags.compressed))
    }

    /// Auto-detecting read: determines format (V1 buffer or V2 streaming) and decrypts accordingly.
    /// Returns decrypted data and whether the file was compressed.
    pub async fn read_encrypted_auto(&self, name: &str) -> Result<(Vec<u8>, bool)> {
        let path = self.root.join(name);
        let data = fs::read(&path)
            .await
            .with_context(|| format!("reading {:?}", &path))?;

        if data.is_empty() {
            anyhow::bail!("encrypted file is empty");
        }

        // Check first byte to detect format
        let format_version = data[0];
        debug!(file = name, format_version, "auto-detecting file format");

        if format_version == VERSION_V2_STREAM {
            // V2 streaming format - use streaming decryptor
            info!(file = name, "detected V2 streaming format");
            let mut reader = Cursor::new(data);
            let mut output = Vec::new();

            // Use filename as AAD for tamper detection (matches streaming write)
            let aad = name.as_bytes();

            let (bytes_read, flags) = self.stream_encryptor
                .decrypt_stream(&mut reader, &mut output, Some(aad))
                .await?;

            info!(file = name, bytes = bytes_read, compressed = flags.compressed, "V2 file decrypted successfully");
            Ok((output, flags.compressed))
        } else {
            // V1 legacy buffer format - first 24 bytes are nonce
            info!(file = name, "detected V1 legacy format");
            let result = if self.compress {
                self.encryptor.decrypt_compressed(&data, None)?
            } else {
                self.encryptor.decrypt(&data, None)?
            };
            info!(file = name, encrypted_size = data.len(), decrypted_size = result.len(), "V1 file decrypted successfully");
            Ok((result, self.compress))
        }
    }

    /// Auto-detecting stream read: determines format and streams decrypted output.
    /// Returns bytes written and compression flag.
    pub async fn read_encrypted_stream_auto<W>(
        &self,
        name: &str,
        writer: &mut W,
    ) -> Result<(u64, bool)>
    where
        W: AsyncWrite + Unpin,
    {
        let path = self.root.join(name);
        let data = fs::read(&path)
            .await
            .with_context(|| format!("reading {:?}", &path))?;

        if data.is_empty() {
            anyhow::bail!("encrypted file is empty");
        }

        // Check first byte to detect format
        let format_version = data[0];
        debug!(file = name, format_version, "auto-detecting file format for stream read");

        if format_version == VERSION_V2_STREAM {
            // V2 streaming format
            info!(file = name, "detected V2 streaming format");
            let mut reader = Cursor::new(data);
            let aad = name.as_bytes();

            let (bytes_read, flags) = self.stream_encryptor
                .decrypt_stream(&mut reader, writer, Some(aad))
                .await?;

            info!(file = name, bytes = bytes_read, compressed = flags.compressed, "V2 file decrypted to stream");
            Ok((bytes_read, flags.compressed))
        } else {
            // V1 legacy buffer format
            info!(file = name, "detected V1 legacy format");
            let result = if self.compress {
                self.encryptor.decrypt_compressed(&data, None)?
            } else {
                self.encryptor.decrypt(&data, None)?
            };

            writer.write_all(&result).await?;
            writer.flush().await?;

            info!(file = name, bytes = result.len(), "V1 file decrypted to stream");
            Ok((result.len() as u64, self.compress))
        }
    }

    /// Check if an encrypted file exists
    pub async fn exists(&self, name: &str) -> bool {
        let path = self.root.join(name);
        fs::try_exists(&path).await.unwrap_or(false)
    }

    /// Delete an encrypted file and its metadata
    pub async fn delete_file(&self, name: &str) -> Result<()> {
        info!(file = name, "deleting encrypted file");
        let path = self.root.join(name);
        let meta_path = path.with_extension("meta.json");

        // Delete encrypted file
        if fs::try_exists(&path).await.unwrap_or(false) {
            fs::remove_file(&path).await
                .with_context(|| format!("deleting {:?}", &path))?;
            debug!(file = name, "encrypted file deleted");
        } else {
            warn!(file = name, "file not found during delete");
        }

        // Delete metadata file if it exists
        if fs::try_exists(&meta_path).await.unwrap_or(false) {
            fs::remove_file(&meta_path).await.ok(); // Best effort, don't fail if missing
            debug!(file = name, "metadata file deleted");
        }

        info!(file = name, "file deletion complete");
        Ok(())
    }

    /// List all encrypted files in storage
    /// Returns a vector of (filename, size_bytes, has_metadata) tuples
    pub async fn list_files(&self) -> Result<Vec<(String, u64, bool)>> {
        let mut files = Vec::new();

        // Check if storage directory exists
        if !fs::try_exists(&self.root).await.unwrap_or(false) {
            return Ok(files);
        }

        let mut dir = fs::read_dir(&self.root).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();

            // Skip directories and metadata files
            if path.is_dir() || path.extension().and_then(|e| e.to_str()) == Some("json") {
                continue;
            }

            // Get filename
            let filename = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };

            // Get file size
            let metadata = entry.metadata().await?;
            let size = metadata.len();

            // Check if metadata file exists
            let meta_path = path.with_extension("meta.json");
            let has_metadata = fs::try_exists(&meta_path).await.unwrap_or(false);

            files.push((filename, size, has_metadata));
        }

        // Sort by filename for consistent ordering
        files.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(files)
    }

    /// Read metadata for an encrypted file
    pub async fn get_metadata(&self, name: &str) -> Result<FileMetadata> {
        let path = self.root.join(name);
        let meta_path = path.with_extension("meta.json");

        let content = fs::read_to_string(&meta_path).await
            .with_context(|| format!("reading metadata from {:?}", &meta_path))?;

        let metadata: FileMetadata = serde_json::from_str(&content)
            .with_context(|| format!("parsing metadata from {:?}", &meta_path))?;

        Ok(metadata)
    }
}
