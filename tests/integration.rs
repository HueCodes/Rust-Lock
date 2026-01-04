use anyhow::Result;
use std::fs;
use std::io::Cursor;
use tempfile::TempDir;

use securefs::{config, key_manager, storagefile_ops, streaming};

#[tokio::test]
async fn securefileops_roundtrip() -> Result<()> {
    // setup temp dirs
    let tmp = TempDir::new()?;
    let storage_dir = tmp.path().join("storage");
    let key_path = tmp.path().join("testkey.bin");

    // write deterministic key (32 bytes)
    let key = [0x42u8; 32];
    fs::write(&key_path, key)?;

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
    fs::write(&key_path, key)?;

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

/// Helper to create a test environment with KeyManager and SecureFileOps
async fn setup_test_env() -> Result<(TempDir, storagefile_ops::SecureFileOps)> {
    let tmp = TempDir::new()?;
    let storage_dir = tmp.path().join("storage");
    let key_path = tmp.path().join("testkey.bin");

    let key = [0x42u8; 32];
    fs::write(&key_path, key)?;

    let cfg = config::Config {
        key_path: key_path.to_string_lossy().to_string(),
        storage_dir: storage_dir.to_string_lossy().to_string(),
    };

    let km = key_manager::KeyManager::new(&cfg).await?;
    let ops = storagefile_ops::SecureFileOps::new(km, cfg.storage_dir.clone());

    Ok((tmp, ops))
}

#[tokio::test]
async fn test_delete_file() -> Result<()> {
    let (tmp, ops) = setup_test_env().await?;

    let name = "to_delete.txt";
    let data = b"this file will be deleted";

    // Write file
    ops.write_encrypted(name, data).await?;
    assert!(ops.exists(name).await);

    // Verify metadata file exists
    let meta_path = tmp.path().join("storage").join("to_delete.meta.json");
    assert!(meta_path.exists());

    // Delete file
    ops.delete_file(name).await?;

    // Verify file and metadata are gone
    assert!(!ops.exists(name).await);
    assert!(!meta_path.exists());

    Ok(())
}

#[tokio::test]
async fn test_list_files() -> Result<()> {
    let (_tmp, ops) = setup_test_env().await?;

    // Initially empty
    let files = ops.list_files().await?;
    assert!(files.is_empty());

    // Add some files
    ops.write_encrypted("file1.txt", b"content1").await?;
    ops.write_encrypted("file2.txt", b"content2").await?;
    ops.write_encrypted("file3.txt", b"content3 longer").await?;

    // List should show 3 files
    let files = ops.list_files().await?;
    assert_eq!(files.len(), 3);

    // Files should be sorted alphabetically
    assert_eq!(files[0].0, "file1.txt");
    assert_eq!(files[1].0, "file2.txt");
    assert_eq!(files[2].0, "file3.txt");

    // All should have metadata
    assert!(files.iter().all(|(_, _, has_meta)| *has_meta));

    Ok(())
}

#[tokio::test]
async fn test_metadata_persistence() -> Result<()> {
    let (tmp, ops) = setup_test_env().await?;

    let name = "meta_test.txt";
    let data = b"test data for metadata persistence";

    // Write file
    ops.write_encrypted(name, data).await?;

    // Read metadata
    let metadata = ops.get_metadata(name).await?;
    assert_eq!(metadata.filename, "meta_test.txt");
    assert_eq!(metadata.size, data.len() as u64);

    // Verify metadata file content directly
    let meta_path = tmp.path().join("storage").join("meta_test.meta.json");
    let content = fs::read_to_string(meta_path)?;
    assert!(content.contains("meta_test.txt"));
    assert!(content.contains(&data.len().to_string()));

    Ok(())
}

#[tokio::test]
async fn test_nonexistent_file_handling() -> Result<()> {
    let (_tmp, ops) = setup_test_env().await?;

    // Reading non-existent file should fail
    let result = ops.read_encrypted("does_not_exist.txt").await;
    assert!(result.is_err());

    // exists() should return false
    assert!(!ops.exists("does_not_exist.txt").await);

    // Deleting non-existent file should succeed (idempotent)
    ops.delete_file("does_not_exist.txt").await?;

    // Getting metadata for non-existent file should fail
    let result = ops.get_metadata("does_not_exist.txt").await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    let (_tmp, ops) = setup_test_env().await?;
    let ops = std::sync::Arc::new(ops);

    // Spawn multiple concurrent writes
    let mut handles = Vec::new();
    for i in 0..5 {
        let ops_clone = ops.clone();
        let handle = tokio::spawn(async move {
            let name = format!("concurrent_{}.txt", i);
            let data = format!("content for file {}", i);
            ops_clone.write_encrypted(&name, data.as_bytes()).await
        });
        handles.push(handle);
    }

    // Wait for all writes to complete
    for handle in handles {
        handle.await??;
    }

    // Verify all files exist
    let files = ops.list_files().await?;
    assert_eq!(files.len(), 5);

    // Read back all files concurrently
    let mut read_handles = Vec::new();
    for i in 0..5 {
        let ops_clone = ops.clone();
        let handle = tokio::spawn(async move {
            let name = format!("concurrent_{}.txt", i);
            ops_clone.read_encrypted(&name).await
        });
        read_handles.push((i, handle));
    }

    // Verify all reads succeed with correct content
    for (i, handle) in read_handles {
        let data = handle.await??;
        let expected = format!("content for file {}", i);
        assert_eq!(data, expected.as_bytes());
    }

    Ok(())
}

#[tokio::test]
async fn test_streaming_roundtrip() -> Result<()> {
    let (_tmp, ops) = setup_test_env().await?;

    let name = "stream_test.txt";
    let data = b"streaming encryption test data that spans multiple chunks when large enough";

    // Write using streaming
    let mut reader = Cursor::new(data.to_vec());
    let bytes_written = ops.write_encrypted_stream(name, &mut reader).await?;
    assert_eq!(bytes_written, data.len() as u64);

    // Read using streaming
    let mut output = Vec::new();
    let (bytes_read, compressed) = ops.read_encrypted_stream(name, &mut output).await?;
    assert_eq!(bytes_read, data.len() as u64);
    assert!(!compressed);
    assert_eq!(output, data);

    Ok(())
}

#[tokio::test]
async fn test_auto_format_detection() -> Result<()> {
    let tmp = TempDir::new()?;
    let storage_dir = tmp.path().join("storage");
    let key_path = tmp.path().join("testkey.bin");

    let key = [0x42u8; 32];
    fs::write(&key_path, key)?;

    let cfg = config::Config {
        key_path: key_path.to_string_lossy().to_string(),
        storage_dir: storage_dir.to_string_lossy().to_string(),
    };

    let km = key_manager::KeyManager::new(&cfg).await?;
    let ops = storagefile_ops::SecureFileOps::new(km, cfg.storage_dir.clone());

    // Write V1 format (buffer mode)
    let v1_name = "v1_file.txt";
    let v1_data = b"V1 buffer mode data";
    ops.write_encrypted(v1_name, v1_data).await?;

    // Write V2 format (streaming mode)
    let v2_name = "v2_file.txt";
    let v2_data = b"V2 streaming mode data";
    let mut reader = Cursor::new(v2_data.to_vec());
    ops.write_encrypted_stream(v2_name, &mut reader).await?;

    // Auto-detect and read V1 file
    let (v1_result, _) = ops.read_encrypted_auto(v1_name).await?;
    assert_eq!(v1_result, v1_data);

    // Auto-detect and read V2 file
    let (v2_result, _) = ops.read_encrypted_auto(v2_name).await?;
    assert_eq!(v2_result, v2_data);

    // Verify V2 file starts with version byte
    let v2_path = storage_dir.join(v2_name);
    let raw_v2 = fs::read(v2_path)?;
    assert_eq!(raw_v2[0], streaming::VERSION_V2_STREAM);

    Ok(())
}
