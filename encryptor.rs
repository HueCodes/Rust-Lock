//! Buffer-based encryption and decryption using XChaCha20-Poly1305.
//!
//! This module provides the [`Encryptor`] struct for encrypting and decrypting
//! data buffers with optional gzip compression.
//!
//! ## Format
//!
//! Encrypted data format: `[nonce:24][ciphertext]`
//!
//! - 24-byte nonce (generated randomly per encryption)
//! - Ciphertext with 16-byte Poly1305 authentication tag

use anyhow::{bail, Result};
use chacha20poly1305::aead::{Aead, AeadCore, OsRng, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use flate2::write::{GzDecoder, GzEncoder};
use flate2::Compression;
use std::io::Write;

/// Encrypt and decrypt data buffers using XChaCha20-Poly1305 (extended nonce)
/// - Uses a 24-byte nonce (practically impossible to collide when using OsRng)
/// - Supports additional authenticated data (AAD) so you can bind metadata
#[derive(Clone)]
pub struct Encryptor {
    cipher: XChaCha20Poly1305,
}

impl Encryptor {
    pub fn new(cipher: XChaCha20Poly1305) -> Self {
        Self { cipher }
    }

    /// Encrypts `plaintext`, prepending the 24-byte nonce to the ciphertext.
    /// `aad` is optional associated data (e.g. filename or metadata) that will be
    /// authenticated but not encrypted.
    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 24-byte
        let ct = match aad {
            Some(a) => self
                .cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad: a,
                    },
                )
                .map_err(|e| anyhow::anyhow!(e))?,
            None => self
                .cipher
                .encrypt(&nonce, plaintext)
                .map_err(|e| anyhow::anyhow!(e))?,
        };
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypts a buffer produced by `encrypt`. Expects the first 24 bytes to be the nonce.
    pub fn decrypt(&self, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if ciphertext.len() < 24 {
            bail!("ciphertext too short: expected nonce prefix");
        }
        let (nonce_bytes, data) = ciphertext.split_at(24);
        #[allow(deprecated)]
        let nonce = XNonce::from_slice(nonce_bytes);
        let pt = match aad {
            Some(a) => self
                .cipher
                .decrypt(nonce, Payload { msg: data, aad: a })
                .map_err(|e| anyhow::anyhow!(e))?,
            None => self
                .cipher
                .decrypt(nonce, data)
                .map_err(|e| anyhow::anyhow!(e))?,
        };
        Ok(pt)
    }

    /// Compresses plaintext with gzip, then encrypts. Prepends nonce to output.
    pub fn encrypt_compressed(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plaintext)?;
        let compressed = encoder.finish()?;
        self.encrypt(&compressed, aad)
    }

    /// Decrypts ciphertext, then decompresses with gzip.
    pub fn decrypt_compressed(&self, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let compressed = self.decrypt(ciphertext, aad)?;
        let mut decoder = GzDecoder::new(Vec::new());
        decoder.write_all(&compressed)?;
        Ok(decoder.finish()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::KeyInit;

    fn make_encryptor() -> Encryptor {
        // deterministic key for tests
        let key = [0x42u8; 32];
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("valid key");
        Encryptor::new(cipher)
    }

    #[test]
    fn round_trip_no_aad() {
        let e = make_encryptor();
        let pt = b"hello world";
        let ct = e.encrypt(pt, None).expect("encrypt");
        let out = e.decrypt(&ct, None).expect("decrypt");
        assert_eq!(out, pt);
    }

    #[test]
    fn round_trip_with_aad() {
        let e = make_encryptor();
        let pt = b"secret";
        let aad = b"filename:foo.txt";
        let ct = e.encrypt(pt, Some(aad)).expect("encrypt");
        let out = e.decrypt(&ct, Some(aad)).expect("decrypt");
        assert_eq!(out, pt);
    }

    #[test]
    fn fail_on_bad_aad() {
        let e = make_encryptor();
        let pt = b"secret";
        let ct = e.encrypt(pt, Some(b"good-aad")).expect("encrypt");
        let res = e.decrypt(&ct, Some(b"bad-aad"));
        assert!(res.is_err());
    }

    #[test]
    fn round_trip_compressed() {
        let e = make_encryptor();
        let pt = b"hello world hello world hello world"; // repeating for compression
        let ct = e.encrypt_compressed(pt, None).expect("encrypt_compressed");
        let out = e.decrypt_compressed(&ct, None).expect("decrypt_compressed");
        assert_eq!(out, pt);
    }

    #[test]
    fn compressed_smaller_than_uncompressed() {
        let e = make_encryptor();
        let pt = b"test test test test test test test test test test"; // repeating
        let ct_uncompressed = e.encrypt(pt, None).expect("encrypt");
        let ct_compressed = e.encrypt_compressed(pt, None).expect("encrypt_compressed");
        // compressed should be smaller (plaintext has repetition)
        assert!(ct_compressed.len() < ct_uncompressed.len());
    }
}
