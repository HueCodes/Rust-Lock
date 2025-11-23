# Migration Guide: v0.1.0 → v0.2.0

This guide helps you upgrade your code from SecureFS 0.1.0 to 0.2.0.

## Breaking Changes

### 1. KeyManager::new() is now async ⚠️

**Before (0.1.0):**
```rust
let cfg = Config::load("config.json")?;
let km = KeyManager::new(&cfg)?;
```

**After (0.2.0):**
```rust
let cfg = Config::load("config.json")?;
let km = KeyManager::new(&cfg).await?;  // ← Add .await
```

**Why**: Improved performance by using async I/O (tokio::fs) instead of blocking operations.

**Impact**: You must add `.await` to all `KeyManager::new()` calls. Your function must be `async`.

---

### 2. KeyManager.key_bytes is now private 🔒

**Before (0.1.0):**
```rust
let km = KeyManager::new(&cfg)?;
let key = km.key_bytes;  // ❌ No longer works
println!("{:?}", km.key_bytes);  // ❌ Compilation error
```

**After (0.2.0):**
```rust
let km = KeyManager::new(&cfg).await?;
let cipher = km.cipher();  // ✅ Get cipher instance instead
```

**Why**: Security fix - prevents accidental key exposure, logging, or copying.

**Impact**: You cannot directly access raw key bytes. Use `km.cipher()` to get a cipher instance for encryption operations.

**Note**: If you absolutely need the raw key bytes (not recommended), you'll need to modify the library or implement your own key management.

---

## New Features (Non-Breaking)

### 3. Streaming API for Large Files

**New in 0.2.0** - Handle files larger than available RAM:

```rust
use tokio::fs::File;

let km = KeyManager::new(&cfg).await?;
let ops = SecureFileOps::new(km, "./storage");

// Encrypt large file (streaming mode)
let mut reader = File::open("large_file.bin").await?;
let bytes_written = ops.write_encrypted_stream("large_file.bin", &mut reader).await?;

// Decrypt large file (streaming mode)
let mut writer = File::create("decrypted.bin").await?;
let (bytes_read, was_compressed) = ops.read_encrypted_stream("large_file.bin", &mut writer).await?;
```

**Recommended for**: Files > 10MB

---

### 4. File Management APIs

**New in 0.2.0** - List, delete, and check file existence:

```rust
// Check if file exists
if ops.exists("secret.txt").await {
    println!("File found!");
}

// List all encrypted files
let files = ops.list_files().await?;
for (name, size, has_metadata) in files {
    println!("{}: {} bytes", name, size);
}

// Delete encrypted file
ops.delete_file("old_secret.txt").await?;

// Get file metadata
let metadata = ops.get_metadata("secret.txt").await?;
println!("Original size: {} bytes", metadata.size);
```

---

### 5. CLI Tool

**New in 0.2.0** - Complete command-line interface:

```bash
# Initialize SecureFS
securefs init

# Encrypt a file
securefs encrypt myfile.txt --compress

# Encrypt large file with streaming
securefs encrypt bigfile.bin --stream --compress

# Decrypt to file
securefs decrypt myfile.txt -o decrypted.txt

# Decrypt to stdout
securefs decrypt myfile.txt

# List all files
securefs list --verbose

# Remove file
securefs remove myfile.txt

# Show storage status
securefs status
```

---

## File Format Compatibility

### Reading Old Files (v0.1.0 format)

**Good news**: v0.2.0 can still read files encrypted with v0.1.0!

- Old format files (without version header) are automatically detected
- They will be read using the legacy decryption path
- No re-encryption needed

### Writing New Files (v0.2.0 format)

Files encrypted with v0.2.0 use a new format:

```
[version:1][flags:1][data...]
```

**Standard API** (write_encrypted/read_encrypted):
- Still uses old format for backward compatibility
- No version header added

**Streaming API** (write_encrypted_stream/read_encrypted_stream):
- Uses new v2 format with version header
- Supports per-file flags (compression state)
- Includes AAD (filename) for tamper detection

**Recommendation**: Use streaming API for new files when possible.

---

## Dependency Updates

Update your `Cargo.toml`:

```toml
[dependencies]
securefs = { git = "https://github.com/HueCodes/Rust-Lock.git", tag = "v0.2.0" }
tokio = { version = "1", features = ["full"] }
```

**If you're also using tokio**: We've optimized our tokio features. If you want minimal dependencies:

```toml
tokio = { version = "1", features = ["fs", "io-util", "macros", "rt-multi-thread"] }
```

---

## Example: Complete Migration

**Before (0.1.0):**
```rust
use securefs::{config::Config, key_manager::KeyManager, storagefile_ops::SecureFileOps};

fn main() -> anyhow::Result<()> {
    let cfg = Config::load("config.json")?;
    let km = KeyManager::new(&cfg)?;
    let ops = SecureFileOps::new(km, cfg.storage_dir).with_compression(true);

    // Access key directly (bad practice, but possible)
    println!("Key: {:?}", km.key_bytes);

    tokio::runtime::Runtime::new()?.block_on(async {
        ops.write_encrypted("secret.txt", b"data").await?;
        let data = ops.read_encrypted("secret.txt").await?;
        Ok(())
    })
}
```

**After (0.2.0):**
```rust
use securefs::{config::Config, key_manager::KeyManager, storagefile_ops::SecureFileOps};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::load("config.json")?;
    let km = KeyManager::new(&cfg).await?;  // ← Added .await
    let ops = SecureFileOps::new(km, cfg.storage_dir).with_compression(true);

    // Key is now private (cannot access directly)
    // Use cipher() if needed: let cipher = km.cipher();

    // Standard API (backward compatible)
    ops.write_encrypted("secret.txt", b"data").await?;
    let data = ops.read_encrypted("secret.txt").await?;

    // New: List files
    let files = ops.list_files().await?;
    println!("Encrypted files: {}", files.len());

    // New: Streaming for large files
    use tokio::fs::File;
    let mut reader = File::open("large.bin").await?;
    ops.write_encrypted_stream("large.bin", &mut reader).await?;

    Ok(())
}
```

---

## Testing Your Migration

1. **Update dependencies**: `cargo update`
2. **Fix compilation errors**: Add `.await` to `KeyManager::new()` calls
3. **Remove key_bytes access**: Replace with `cipher()` calls if needed
4. **Run tests**: `cargo test`
5. **Verify existing files**: Ensure you can still decrypt old files

---

## Getting Help

- **Issues**: https://github.com/HueCodes/Rust-Lock/issues
- **Discussions**: https://github.com/HueCodes/Rust-Lock/discussions
- **Changelog**: See [CHANGELOG.md](CHANGELOG.md) for full details

---

## Rollback Instructions

If you need to rollback to v0.1.0:

```toml
[dependencies]
securefs = { git = "https://github.com/HueCodes/Rust-Lock.git", tag = "v0.1.0" }
```

**Note**: Files encrypted with v0.2.0 streaming API may not be readable by v0.1.0.
