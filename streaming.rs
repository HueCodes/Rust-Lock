//! Streaming encryption and decryption for large files.
//!
//! This module provides [`StreamEncryptor`] for processing large files in chunks
//! without loading them entirely into memory.
//!
//! ## V2 File Format
//!
//! ```text
//! [version:1][flags:1][chunk1][chunk2]...
//!
//! Each chunk:
//! [nonce:24][length:4][encrypted_data]
//! ```
//!
//! ## Chunk Size
//!
//! Files are processed in 64KB chunks, balancing memory usage against
//! per-chunk cryptographic overhead.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, AeadCore, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Chunk size for streaming encryption (64KB)
/// Balances memory usage vs. overhead from per-chunk nonces and tags
const CHUNK_SIZE: usize = 64 * 1024;

/// File format version for streaming encrypted files
pub const VERSION_V2_STREAM: u8 = 2;

/// Flags for file format options
#[derive(Debug, Clone, Copy)]
pub struct FormatFlags {
    pub compressed: bool,
}

impl FormatFlags {
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.compressed {
            flags |= 0x01; // Bit 0: compression enabled
        }
        flags
    }

    pub fn from_byte(byte: u8) -> Self {
        Self {
            compressed: (byte & 0x01) != 0,
        }
    }
}

/// StreamEncryptor handles streaming encryption/decryption for large files
/// Uses chunked AEAD to maintain authentication while processing incrementally
pub struct StreamEncryptor {
    cipher: XChaCha20Poly1305,
}

impl StreamEncryptor {
    pub fn new(cipher: XChaCha20Poly1305) -> Self {
        Self { cipher }
    }

    /// Encrypts data from reader in chunks, writing to writer
    /// Format per chunk: \[nonce:24\]\[chunk_len:4\]\[encrypted_data:chunk_len\]
    /// File format: \[version:1\]\[flags:1\]\[chunks...\]
    pub async fn encrypt_stream<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        flags: FormatFlags,
        aad: Option<&[u8]>,
    ) -> Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        // Write file format header
        writer.write_u8(VERSION_V2_STREAM).await?;
        writer.write_u8(flags.to_byte()).await?;

        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut total_bytes = 0u64;

        loop {
            // Read chunk from source
            let n = reader.read(&mut buffer).await?;
            if n == 0 {
                break; // EOF
            }

            let plaintext = &buffer[..n];

            // Generate unique nonce for this chunk
            let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

            // Encrypt chunk with optional AAD
            let ciphertext = match aad {
                Some(a) => self.cipher.encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad: a,
                    },
                )
                .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?,
                None => self.cipher
                    .encrypt(&nonce, plaintext)
                    .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?,
            };

            // Write chunk: nonce + length + ciphertext
            writer.write_all(&nonce).await?;
            writer.write_u32(ciphertext.len() as u32).await?;
            writer.write_all(&ciphertext).await?;

            total_bytes += n as u64;
        }

        writer.flush().await?;
        Ok(total_bytes)
    }

    /// Decrypts streaming format from reader, writing plaintext to writer
    /// Reads file header and processes chunks sequentially
    pub async fn decrypt_stream<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        aad: Option<&[u8]>,
    ) -> Result<(u64, FormatFlags)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        // Read and validate version
        let version = reader.read_u8().await
            .context("reading version byte")?;
        if version != VERSION_V2_STREAM {
            anyhow::bail!("unsupported file format version: {}", version);
        }

        // Read flags
        let flags_byte = reader.read_u8().await
            .context("reading flags byte")?;
        let flags = FormatFlags::from_byte(flags_byte);

        let mut total_bytes = 0u64;
        let mut nonce_buf = [0u8; 24];

        loop {
            // Try to read nonce (24 bytes)
            match reader.read_exact(&mut nonce_buf).await {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // End of file reached
                    break;
                },
                Err(e) => return Err(e.into()),
            }

            #[allow(deprecated)]
            let nonce = XNonce::from_slice(&nonce_buf);

            // Read chunk length
            let chunk_len = reader.read_u32().await
                .context("reading chunk length")? as usize;

            // Read encrypted chunk
            let mut ciphertext = vec![0u8; chunk_len];
            reader.read_exact(&mut ciphertext).await
                .context("reading encrypted chunk")?;

            // Decrypt chunk
            let plaintext = match aad {
                Some(a) => self.cipher.decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: a,
                    },
                )
                .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))?,
                None => self.cipher
                    .decrypt(nonce, ciphertext.as_slice())
                    .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))?,
            };

            // Write decrypted chunk
            writer.write_all(&plaintext).await?;
            total_bytes += plaintext.len() as u64;
        }

        writer.flush().await?;
        Ok((total_bytes, flags))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::KeyInit;
    use std::io::Cursor;

    fn make_cipher() -> XChaCha20Poly1305 {
        let key = [0x42u8; 32];
        XChaCha20Poly1305::new_from_slice(&key).expect("valid key")
    }

    #[tokio::test]
    async fn test_stream_round_trip_small() {
        let cipher = make_cipher();
        let encryptor = StreamEncryptor::new(cipher);

        let plaintext = b"hello world, this is a test message";
        let mut reader = Cursor::new(plaintext.to_vec());
        let mut encrypted = Vec::new();

        let flags = FormatFlags { compressed: false };
        encryptor
            .encrypt_stream(&mut reader, &mut encrypted, flags, None)
            .await
            .expect("encryption failed");

        // Decrypt
        let mut decrypt_reader = Cursor::new(encrypted);
        let mut decrypted = Vec::new();
        let (bytes, _flags) = encryptor
            .decrypt_stream(&mut decrypt_reader, &mut decrypted, None)
            .await
            .expect("decryption failed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(bytes, plaintext.len() as u64);
    }

    #[tokio::test]
    async fn test_stream_round_trip_large() {
        let cipher = make_cipher();
        let encryptor = StreamEncryptor::new(cipher);

        // Create data larger than CHUNK_SIZE to test multiple chunks
        let plaintext = vec![0x42u8; CHUNK_SIZE * 3 + 1000];
        let mut reader = Cursor::new(plaintext.clone());
        let mut encrypted = Vec::new();

        let flags = FormatFlags { compressed: false };
        encryptor
            .encrypt_stream(&mut reader, &mut encrypted, flags, None)
            .await
            .expect("encryption failed");

        // Decrypt
        let mut decrypt_reader = Cursor::new(encrypted);
        let mut decrypted = Vec::new();
        let (bytes, _flags) = encryptor
            .decrypt_stream(&mut decrypt_reader, &mut decrypted, None)
            .await
            .expect("decryption failed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(bytes, plaintext.len() as u64);
    }

    #[tokio::test]
    async fn test_stream_with_aad() {
        let cipher = make_cipher();
        let encryptor = StreamEncryptor::new(cipher);

        let plaintext = b"secret data";
        let aad = b"filename:secret.txt";
        let mut reader = Cursor::new(plaintext.to_vec());
        let mut encrypted = Vec::new();

        let flags = FormatFlags { compressed: false };
        encryptor
            .encrypt_stream(&mut reader, &mut encrypted, flags, Some(aad))
            .await
            .expect("encryption failed");

        // Decrypt with correct AAD
        let mut decrypt_reader = Cursor::new(encrypted.clone());
        let mut decrypted = Vec::new();
        encryptor
            .decrypt_stream(&mut decrypt_reader, &mut decrypted, Some(aad))
            .await
            .expect("decryption should succeed with correct AAD");

        assert_eq!(decrypted, plaintext);

        // Decrypt with wrong AAD should fail
        let mut decrypt_reader = Cursor::new(encrypted);
        let mut decrypted = Vec::new();
        let result = encryptor
            .decrypt_stream(&mut decrypt_reader, &mut decrypted, Some(b"wrong-aad"))
            .await;

        assert!(result.is_err(), "decryption should fail with wrong AAD");
    }

    #[tokio::test]
    async fn test_flags_round_trip() {
        let flags = FormatFlags { compressed: true };
        let byte = flags.to_byte();
        let parsed = FormatFlags::from_byte(byte);
        assert!(parsed.compressed);

        let flags = FormatFlags { compressed: false };
        let byte = flags.to_byte();
        let parsed = FormatFlags::from_byte(byte);
        assert!(!parsed.compressed);
    }
}
