use anyhow::Result;
use std::fs;
use tempfile::TempDir;

use securefs::{config, key_manager, storagefile_ops};

#[tokio::test]
async fn securefileops_roundtrip() -> Result<()> {
    // setup temp dirs
    let tmp = TempDir::new()?;
    let storage_dir = tmp.path().join("storage");
    let key_path = tmp.path().join("testkey.bin");

    // write deterministic key (32 bytes)
    let key = [0x42u8; 32];
    fs::write(&key_path, &key)?;

    // create a minimal config pointing at our temp files
    let cfg = config::Config {
        key_path: key_path.to_string_lossy().to_string(),
        storage_dir: storage_dir.to_string_lossy().to_string(),
    };

    // use KeyManager and SecureFileOps
    let km = key_manager::KeyManager::new(&cfg).await?;
    let ops = storagefile_ops::SecureFileOps::new(km, cfg.storage_dir.clone());

    let name = "it.txt";
    let data = b"integration secret";

    // write and read back
    ops.write_encrypted(name, data).await?;
    let out = ops.read_encrypted(name).await?;

    assert_eq!(out, data);
    Ok(())
}

#[tokio::test]
async fn securefileops_roundtrip_compressed() -> Result<()> {
    // setup temp dirs
    let tmp = TempDir::new()?;
    let storage_dir = tmp.path().join("storage");
    let key_path = tmp.path().join("testkey.bin");

    // write deterministic key (32 bytes)
    let key = [0x42u8; 32];
    fs::write(&key_path, &key)?;

    // create a minimal config pointing at our temp files
    let cfg = config::Config {
        key_path: key_path.to_string_lossy().to_string(),
        storage_dir: storage_dir.to_string_lossy().to_string(),
    };

    // use KeyManager and SecureFileOps with compression enabled
    let km = key_manager::KeyManager::new(&cfg).await?;
    let ops =
        storagefile_ops::SecureFileOps::new(km, cfg.storage_dir.clone()).with_compression(true);

    let name = "compressed.txt";
    let data = b"integration secret with compression enabled for testing";

    // write and read back with compression
    ops.write_encrypted(name, data).await?;
    let out = ops.read_encrypted(name).await?;

    assert_eq!(out, data);
    Ok(())
}
