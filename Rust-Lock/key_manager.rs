use anyhow::{bail, Context, Result};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand_core::OsRng;
use rand_core::RngCore;
use std::path::Path;
use tokio::fs;
use zeroize::Zeroize;

/// Handles key generation and persistence.
/// In production: prefer a hardware key store or OS keyring.
pub struct KeyManager {
    key_bytes: [u8; 32],
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

impl KeyManager {
    pub async fn new(cfg: &crate::config::Config) -> Result<Self> {
        let path = Path::new(&cfg.key_path);

        // Check if file exists using tokio::fs
        let key_bytes = if fs::try_exists(path).await
            .with_context(|| format!("checking existence of {}", path.display()))?
        {
            // Read existing key
            let data = fs::read(path).await
                .with_context(|| format!("reading key from {}", path.display()))?;
            if data.len() != 32 {
                bail!(
                    "expected 32-byte key at {} but found {} bytes",
                    path.display(),
                    data.len()
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&data);
            arr
        } else {
            // Generate new key
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);

            // Write with restrictive permissions using spawn_blocking for Unix
            #[cfg(unix)]
            {
                let path_buf = path.to_path_buf();
                let key_clone = key;
                tokio::task::spawn_blocking(move || {
                    use std::fs::OpenOptions;
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;

                    let mut f = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&path_buf)?;
                    f.write_all(&key_clone)?;
                    Ok::<(), anyhow::Error>(())
                }).await??;
            }
            #[cfg(not(unix))]
            {
                fs::write(path, &key).await?;
            }

            key
        };

        Ok(Self { key_bytes })
    }

    pub fn cipher(&self) -> XChaCha20Poly1305 {
        // This is safe because key_bytes is always exactly 32 bytes
        debug_assert_eq!(self.key_bytes.len(), 32);
        XChaCha20Poly1305::new_from_slice(&self.key_bytes)
            .expect("BUG: key_bytes is always 32 bytes, this should never fail")
    }
}
