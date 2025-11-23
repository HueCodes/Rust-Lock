# Rust-Lock

A production-ready, secure file storage system in Rust with military-grade encryption, optional compression, and zero-copy operations.

## Features

- **XChaCha20-Poly1305 AEAD Encryption** - Extended nonces, authenticated encryption for maximum security
- **Optional Gzip Compression** - Reduce storage footprint before encryption
- **Secure Key Management** - Cryptographically secure random key generation with OS-level RNG
- **Zero Memory Leaks** - Automatic key zeroization on drop using `zeroize`
- **Async I/O** - Built on Tokio for high-performance file operations
- **Configurable Storage** - Flexible storage directory and key file paths
- **Metadata Tracking** - Built-in file metadata support

## Quick Start

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
securefs = { git = "https://github.com/HueCodes/Rust-Lock.git" }
tokio = { version = "1", features = ["full"] }
```

### Basic Usage

```rust
use anyhow::Result;
use securefs::{config::Config, key_manager::KeyManager, storagefile_ops::SecureFileOps};

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let cfg = Config::load("config.json")?;
    
    // Initialize key manager and file operations
    let km = KeyManager::new(&cfg)?;
    let fs = SecureFileOps::new(km, cfg.storage_dir.clone())
        .with_compression(true);  // Enable compression

    // Write encrypted data
    fs.write_encrypted("secret.txt", b"Top secret data").await?;
    
    // Read and decrypt
    let data = fs.read_encrypted("secret.txt").await?;
    println!("Decrypted: {}", String::from_utf8_lossy(&data));
    
    Ok(())
}
```

### Configuration

Create a `config.json` file:

```json
{
  "key_path": "./securefs.key",
  "storage_dir": "./storage"
}
```

## Key Management

The `KeyManager` handles secure key generation and storage:

- **Automatic Generation** - Creates a 256-bit key if none exists
- **Secure Storage** - Keys stored with restrictive file permissions (0600)
- **Memory Safety** - Keys automatically zeroized when dropped
- **Validation** - Ensures key file integrity on load

```rust
let km = KeyManager::new(&config)?;
// Key is securely loaded and ready for encryption operations
// Automatically cleaned from memory when km goes out of scope
```

## Encryption

Uses **XChaCha20-Poly1305** for authenticated encryption:

- **24-byte nonces** - Extended nonce space prevents reuse
- **AEAD** - Authenticated Encryption with Associated Data
- **Tag verification** - Prevents tampering and corruption

### With Compression

```rust
let fs = SecureFileOps::new(km, storage_dir).with_compression(true);
fs.write_encrypted("large_file.txt", &large_data).await?;
```

Data flow: `plaintext → gzip → encrypt → storage`

### Without Compression

```rust
let fs = SecureFileOps::new(km, storage_dir);
fs.write_encrypted("file.txt", &data).await?;
```

Data flow: `plaintext → encrypt → storage`

## Architecture

```
┌─────────────────────────────────────────┐
│            SecureFileOps                │
│  - write_encrypted()                    │
│  - read_encrypted()                     │
│  - with_compression()                   │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│           Encryptor                     │
│  - XChaCha20-Poly1305 cipher            │
│  - Nonce generation                     │
│  - AEAD operations                      │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│          KeyManager                     │
│  - Secure key generation (OsRng)        │
│  - Key loading/validation               │
│  - Automatic zeroization                │
└─────────────────────────────────────────┘
```

## Testing

Run the test suite:

```bash
cargo test
```

Integration tests verify:
- Full encrypt/decrypt roundtrip
- Compression functionality
- Key management
- File operations

## 📊 Performance

- **Encryption overhead**: ~microseconds per operation
- **Compression ratio**: Varies by data (text: ~60-70% reduction)
- **Memory footprint**: Minimal, keys are only 32 bytes
- **Async I/O**: Non-blocking file operations scale with workload

## Security

- **No encryption key in memory longer than needed**
- **Nonces never reused** (24-byte XChaCha20 nonces)
- **Authenticated encryption** prevents tampering
- **Secure key generation** using OS entropy (`OsRng`)
- **Restrictive permissions** on key files (Unix: 0600)

## Configuration Options

```rust
pub struct Config {
    pub key_path: String,      // Path to encryption key file
    pub storage_dir: String,   // Directory for encrypted files
}
```

Load from JSON:
```rust
let cfg = Config::load("config.json")?;
```

## 📝 Building

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run example
cargo run --bin securefs
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

## Links

- **Repository**: https://github.com/HueCodes/Rust-Lock
- **Issues**: https://github.com/HueCodes/Rust-Lock/issues

## Disclaimer

This is cryptographic software. While it uses industry-standard algorithms and best practices, it has not been independently audited. Use in production at your own risk.

---

Built with 🦀 Rust
