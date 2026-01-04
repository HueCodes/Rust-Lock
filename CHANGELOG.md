# Changelog

All notable changes to SecureFS (Rust-Lock) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-04

### Quality & Developer Experience Release

This release focuses on code quality, developer experience, and production readiness with **10 completed improvements**.

### Added

#### Structured Logging
- **Tracing integration** (`tracing` + `tracing-subscriber`)
  - Structured logging with `info!`, `warn!`, `error!`, `debug!` macros
  - Log all operations: encrypt, decrypt, delete, key generation
  - Environment-based log levels via `RUST_LOG`
  - Example: `RUST_LOG=info,securefs=debug ./securefs encrypt file.txt`

#### Auto-Format Detection
- **Transparent V1/V2 file handling**
  - `read_encrypted_auto()` - Auto-detects and decrypts any format
  - `read_encrypted_stream_auto()` - Streaming version
  - Reads first byte to determine: V1 (nonce prefix) or V2 (version 0x02)
  - Maintains backward compatibility with all existing encrypted files

#### Custom Error Types
- **New `error.rs` module** with `SecureFsError` enum
  - `Key`, `Encryption`, `Decryption`, `Storage`, `Format`, `Config` variants
  - Implements `thiserror::Error` for clean error messages
  - Helper constructors: `SecureFsError::key("message")`
  - `From<std::io::Error>` implementation

#### Secure Configuration
- **Environment variable support**
  - `SECUREFS_KEY_PATH` - Override key file path
  - `SECUREFS_STORAGE_DIR` - Override storage directory
  - `SECUREFS_CONFIG` - Override config file path
  - `Config::load_with_env()` for automatic env merging
  - Security warnings for public directory paths

#### Progress Indicators
- **CLI progress bars** (`indicatif` crate)
  - Styled progress bar for encryption with bytes/percentage
  - Spinner for decryption operations
  - Clean finish messages with operation summary

#### Documentation
- **Module-level documentation** (`//!` comments)
  - `lib.rs` - Library overview with quick start example
  - `encryptor.rs` - Buffer encryption format docs
  - `streaming.rs` - V2 file format specification
  - `storagefile_ops.rs` - High-level API overview
  - `key_manager.rs` - Security features docs
  - `config.rs` - Environment variable docs
  - Clean `cargo doc` output with no warnings

### Changed

#### Test Coverage Expanded
- **7 new integration tests** (9 total)
  - `test_delete_file` - File removal and metadata cleanup
  - `test_list_files` - Directory listing accuracy
  - `test_metadata_persistence` - `.meta.json` storage verification
  - `test_nonexistent_file_handling` - Error case validation
  - `test_concurrent_operations` - Multi-file async safety
  - `test_streaming_roundtrip` - Stream encrypt/decrypt cycle
  - `test_auto_format_detection` - V1/V2 format detection

#### Code Quality
- **Fixed all Clippy warnings**
  - Replaced `assert_eq!` with `assert!` for boolean tests
  - Removed unnecessary borrows in `fs::write()`
  - Escaped brackets in doc comments
- **Removed orphaned files**
  - Deleted `mod.rs` (duplicated lib.rs)
  - Deleted `storagemod.rs` (referenced non-existent modules)

### Dependencies
- **Added**: `tracing = "0.1"` - Structured logging
- **Added**: `tracing-subscriber = "0.3"` with env-filter feature
- **Added**: `indicatif = "0.17"` - CLI progress bars

### Testing
- All 19 tests passing (9 unit + 9 integration + 1 doc test)
- Cargo clippy clean (with standard lints)
- Cargo doc builds without warnings
- Cargo audit: No critical vulnerabilities

### Security Notes
- Environment variable configuration follows 12-factor app principles
- Config validation warns about insecure key paths
- No `unwrap()` in critical production code paths

---

## [0.2.0] - 2025-11-23

### Major Release - Performance, Security, and CLI

This release represents a significant upgrade with **10 completed improvements** focused on performance, security, and usability.

### Added

#### Performance & Scalability
- **Streaming Encryption/Decryption API** (`streaming.rs`) - 295 lines
  - New `StreamEncryptor` for chunked AEAD encryption (64KB chunks)
  - `write_encrypted_stream()` and `read_encrypted_stream()` methods
  - Can handle multi-GB files without loading into memory
  - Format: `[version:1][flags:1][nonce:24][chunk_len:4][encrypted_data]...`
  - 4 comprehensive tests for streaming functionality

- **File Format Versioning**
  - Version 2 streaming format with header
  - `FormatFlags` struct to track per-file options (compression, etc.)
  - Backward compatible with existing files
  - Compression flag now stored in file, not instance

#### CLI Interface (406 lines)
- **Complete command-line tool** (`cli/main.rs`)
  - `securefs init` - Initialize config and generate encryption key
  - `securefs encrypt` - Encrypt files (with `--stream` and `--compress` options)
  - `securefs decrypt` - Decrypt files (output to file or stdout)
  - `securefs list` - List encrypted files (with `--verbose` table view)
  - `securefs remove` - Delete encrypted files (with confirmation)
  - `securefs status` - Show storage statistics and health check
  - Supports large file streaming mode

#### Library APIs
- `exists(name)` - Check if encrypted file exists
- `delete_file(name)` - Remove encrypted file + metadata
- `list_files()` - Enumerate all encrypted files with metadata
- `get_metadata(name)` - Read file metadata from storage

#### Security Enhancements
- **AAD (Additional Authenticated Data) Support**
  - Filename used as AAD in encryption
  - Prevents file swapping attacks in storage
  - Integrated into both streaming and standard APIs
  - Backward compatible (v1 files work, v2 files use AAD)

### Changed

#### Breaking Changes
- **KeyManager.key_bytes is now private** (security fix)
  - Prevents accidental key exposure/logging
  - Only `cipher()` method provides controlled access
  - **Migration**: Use `km.cipher()` instead of accessing `key_bytes` directly

- **KeyManager::new() is now async**
  - Changed from sync to async for non-blocking I/O
  - **Migration**: Add `.await` to all `KeyManager::new()` calls
  - Example: `let km = KeyManager::new(&cfg).await?;`

#### Performance Improvements
- **Fixed Blocking I/O in KeyManager**
  - Converted to `tokio::fs` for async file operations
  - Unix permission setting uses `spawn_blocking`
  - No longer blocks tokio runtime executor threads

- **Optimized Dependencies**
  - Replaced `tokio = "full"` with minimal features:
    `["fs", "io-util", "io-std", "macros", "rt-multi-thread"]`
  - **Result**: ~20-30% reduction in binary size

#### Code Quality
- **Improved Error Handling**
  - Removed `unwrap()` from `metadata.rs` (path.file_name())
  - Better error messages with context
  - Proper error propagation throughout

### Dependencies
- **Added**: `clap = "4"` with derive features (CLI argument parsing)
- **Added**: `tokio` feature `io-std` (for stdin/stdout support)
- **Optimized**: Reduced tokio feature set for smaller binaries

### Testing
- All 11 tests passing (9 unit tests + 2 integration tests)
- CLI manually tested with full workflow:
  - init → encrypt (standard & streaming) → list → decrypt → remove → status
  - 5MB file streaming with compression verified
  - File integrity confirmed (decrypted = original)

### Security Notes
- **AAD prevents tampering**: Encrypted files now bind filename to ciphertext
- **Private key field**: Reduces risk of accidental key exposure
- **Async I/O**: Improves concurrency safety in tokio runtime

### Performance Notes
- **Memory efficiency**: 5MB file encrypted without loading fully into memory
- **Streaming mode**: Recommended for files > 10MB
- **Compression**: Works seamlessly with streaming (auto-detected on decrypt)

---

## [0.1.0] - Initial Release

### Added
- XChaCha20-Poly1305 AEAD encryption
- Optional Gzip compression
- Secure key generation with OsRng
- Automatic key zeroization on drop
- Async I/O with Tokio
- Basic file operations (read/write encrypted)
- Configuration via JSON
- Unit and integration tests

[0.3.0]: https://github.com/HueCodes/Rust-Lock/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/HueCodes/Rust-Lock/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/HueCodes/Rust-Lock/releases/tag/v0.1.0
