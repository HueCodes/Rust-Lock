use crate::encryptor::Encryptor;
use crate::key_manager::KeyManager;
use crate::metadata::FileMetadata;
use crate::streaming::{FormatFlags, StreamEncryptor};
use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite};

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
        fs::create_dir_all(&self.root).await?;
        let path = self.root.join(name);
        let enc = if self.compress {
            self.encryptor.encrypt_compressed(data, None)?
        } else {
            self.encryptor.encrypt(data, None)?
        };
        fs::write(&path, &enc).await?;
        FileMetadata::record(&path, data.len() as u64).await?;
        Ok(())
    }

    pub async fn read_encrypted(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.root.join(name);
        let data = fs::read(&path)
            .await
            .with_context(|| format!("reading {:?}", &path))?;
        if self.compress {
            self.encryptor.decrypt_compressed(&data, None)
        } else {
            self.encryptor.decrypt(&data, None)
        }
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
        let path = self.root.join(name);
        let mut file = fs::File::open(&path).await
            .with_context(|| format!("opening {:?}", &path))?;

        // Use filename as AAD for tamper detection
        let aad = name.as_bytes();

        let (bytes_read, flags) = self.stream_encryptor
            .decrypt_stream(&mut file, writer, Some(aad))
            .await?;

        Ok((bytes_read, flags.compressed))
    }

    /// Check if an encrypted file exists
    pub async fn exists(&self, name: &str) -> bool {
        let path = self.root.join(name);
        fs::try_exists(&path).await.unwrap_or(false)
    }

    /// Delete an encrypted file and its metadata
    pub async fn delete_file(&self, name: &str) -> Result<()> {
        let path = self.root.join(name);
        let meta_path = path.with_extension("meta.json");

        // Delete encrypted file
        if fs::try_exists(&path).await.unwrap_or(false) {
            fs::remove_file(&path).await
                .with_context(|| format!("deleting {:?}", &path))?;
        }

        // Delete metadata file if it exists
        if fs::try_exists(&meta_path).await.unwrap_or(false) {
            fs::remove_file(&meta_path).await.ok(); // Best effort, don't fail if missing
        }

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
