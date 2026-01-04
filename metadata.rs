use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct FileMetadata {
    pub filename: String,
    pub size: u64,
}

impl FileMetadata {
    pub async fn record(path: &Path, size: u64) -> Result<()> {
        let filename = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("path has no filename: {}", path.display()))?
            .to_string_lossy()
            .into_owned();

        let meta = Self { filename, size };
        let json = serde_json::to_string_pretty(&meta)?;
        let meta_path = path.with_extension("meta.json");
        fs::write(meta_path, json).await?;
        Ok(())
    }
}
