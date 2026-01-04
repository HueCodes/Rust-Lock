use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use securefs::{config, key_manager::KeyManager, storagefile_ops::SecureFileOps};
use std::io::{self, Write};
use std::path::PathBuf;
use tokio::fs;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

/// SecureFS - Military-grade encrypted file storage with XChaCha20-Poly1305
#[derive(Parser)]
#[command(name = "securefs")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.json")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize SecureFS (generate config and encryption key)
    Init {
        /// Storage directory path
        #[arg(short, long, default_value = "./storage")]
        storage_dir: String,

        /// Encryption key file path
        #[arg(short, long, default_value = "./securefs.key")]
        key_path: String,
    },

    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        input: PathBuf,

        /// Encrypted filename in storage (defaults to input filename)
        #[arg(short, long)]
        output: Option<String>,

        /// Enable compression before encryption
        #[arg(short, long)]
        compress: bool,

        /// Use streaming mode for large files (>10MB recommended)
        #[arg(short, long)]
        stream: bool,
    },

    /// Decrypt a file
    Decrypt {
        /// Encrypted filename in storage
        name: String,

        /// Output file path (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Use streaming mode for large files
        #[arg(short, long)]
        stream: bool,
    },

    /// List all encrypted files
    List {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
    },

    /// Remove an encrypted file
    Remove {
        /// Encrypted filename to remove
        name: String,

        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Show storage status and statistics
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging
    // Use RUST_LOG environment variable to control log level (e.g., RUST_LOG=info,securefs=debug)
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .with_thread_ids(false)
        .init();

    let cli = Cli::parse();
    info!(command = ?cli.command, "SecureFS starting");

    match cli.command {
        Commands::Init {
            storage_dir,
            key_path,
        } => cmd_init(&cli.config, &storage_dir, &key_path).await,

        Commands::Encrypt {
            input,
            output,
            compress,
            stream,
        } => cmd_encrypt(&cli.config, &input, output.as_deref(), compress, stream).await,

        Commands::Decrypt {
            name,
            output,
            stream,
        } => cmd_decrypt(&cli.config, &name, output.as_ref(), stream).await,

        Commands::List { verbose } => cmd_list(&cli.config, verbose).await,

        Commands::Remove { name, yes } => cmd_remove(&cli.config, &name, yes).await,

        Commands::Status => cmd_status(&cli.config).await,
    }
}

/// Create a styled progress bar for file operations
fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Create a spinner for indeterminate operations
fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}

/// Initialize SecureFS configuration and generate encryption key
async fn cmd_init(config_path: &str, storage_dir: &str, key_path: &str) -> Result<()> {
    println!("Initializing SecureFS...");

    // Create config
    let cfg = config::Config {
        key_path: key_path.to_string(),
        storage_dir: storage_dir.to_string(),
    };

    // Check if config already exists
    if fs::try_exists(config_path).await.unwrap_or(false) {
        anyhow::bail!(
            "Configuration file '{}' already exists. Remove it first or use a different path.",
            config_path
        );
    }

    // Check if key already exists
    if fs::try_exists(key_path).await.unwrap_or(false) {
        anyhow::bail!(
            "Key file '{}' already exists. Remove it first or use a different path.",
            key_path
        );
    }

    // Create storage directory
    fs::create_dir_all(storage_dir)
        .await
        .with_context(|| format!("creating storage directory '{}'", storage_dir))?;

    // Generate encryption key (KeyManager will create it)
    let _km = KeyManager::new(&cfg).await?;

    // Write config file
    let config_json = serde_json::to_string_pretty(&cfg)?;
    fs::write(config_path, config_json)
        .await
        .with_context(|| format!("writing config to '{}'", config_path))?;

    println!("Initialization complete!");
    println!("Config:  {}", config_path);
    println!("Key:     {}", key_path);
    println!("Storage: {}", storage_dir);
    println!();
    println!("IMPORTANT: Keep your key file secure and backed up!");
    println!("Without it, your encrypted files cannot be recovered.");

    Ok(())
}

/// Encrypt a file
async fn cmd_encrypt(
    config_path: &str,
    input: &PathBuf,
    output: Option<&str>,
    compress: bool,
    stream: bool,
) -> Result<()> {
    let cfg = config::Config::load(config_path)?;
    let km = KeyManager::new(&cfg).await?;
    let ops = SecureFileOps::new(km, cfg.storage_dir).with_compression(compress);

    // Determine output name
    let output_name = match output {
        Some(name) => name.to_string(),
        None => input
            .file_name()
            .context("input file has no filename")?
            .to_string_lossy()
            .to_string(),
    };

    let input_size = fs::metadata(input)
        .await
        .with_context(|| format!("reading metadata for {:?}", input))?
        .len();

    let mode_str = if stream { "streaming" } else { "buffer" };
    let compress_str = if compress { " (compressed)" } else { "" };

    // Create progress bar
    let pb = create_progress_bar(input_size, &format!("Encrypting{}", compress_str));

    if stream {
        // Streaming mode for large files
        let mut file = fs::File::open(input)
            .await
            .with_context(|| format!("opening {:?}", input))?;

        let bytes = ops
            .write_encrypted_stream(&output_name, &mut file)
            .await?;

        pb.set_position(bytes);
        pb.finish_with_message(format!("Encrypted {} bytes ({})", bytes, mode_str));
    } else {
        // In-memory mode for smaller files
        let data = fs::read(input)
            .await
            .with_context(|| format!("reading {:?}", input))?;

        pb.set_position(data.len() as u64 / 2); // Show reading progress
        ops.write_encrypted(&output_name, &data).await?;
        pb.set_position(input_size);
        pb.finish_with_message(format!("Encrypted {} bytes ({})", data.len(), mode_str));
    }

    println!("  {} -> {}", input.display(), output_name);
    Ok(())
}

/// Decrypt a file
async fn cmd_decrypt(
    config_path: &str,
    name: &str,
    output: Option<&PathBuf>,
    stream: bool,
) -> Result<()> {
    let cfg = config::Config::load(config_path)?;
    let km = KeyManager::new(&cfg).await?;
    let ops = SecureFileOps::new(km, cfg.storage_dir);

    // Use spinner since we don't know the decrypted size ahead of time
    let spinner = create_spinner(&format!("Decrypting {}...", name));

    if stream {
        // Streaming mode
        match output {
            Some(output_path) => {
                let mut file = fs::File::create(output_path)
                    .await
                    .with_context(|| format!("creating {:?}", output_path))?;

                let (bytes, compressed) = ops.read_encrypted_stream(name, &mut file).await?;

                let compress_note = if compressed { " (was compressed)" } else { "" };
                spinner.finish_with_message(format!(
                    "Decrypted {} bytes{} -> {:?}",
                    bytes, compress_note, output_path
                ));
            }
            None => {
                spinner.finish_and_clear();
                let mut stdout = tokio::io::stdout();
                let (bytes, compressed) = ops.read_encrypted_stream(name, &mut stdout).await?;

                let compress_note = if compressed { " (was compressed)" } else { "" };
                eprintln!("Decrypted {} bytes{} to stdout", bytes, compress_note);
            }
        }
    } else {
        // In-memory mode
        let data = ops.read_encrypted(name).await?;

        match output {
            Some(output_path) => {
                fs::write(output_path, &data)
                    .await
                    .with_context(|| format!("writing to {:?}", output_path))?;

                spinner.finish_with_message(format!(
                    "Decrypted {} bytes -> {:?}",
                    data.len(), output_path
                ));
            }
            None => {
                spinner.finish_and_clear();
                // Write to stdout
                io::stdout().write_all(&data)?;
                eprintln!("Decrypted {} bytes to stdout", data.len());
            }
        }
    }

    Ok(())
}

/// List all encrypted files
async fn cmd_list(config_path: &str, verbose: bool) -> Result<()> {
    let cfg = config::Config::load(config_path)?;
    let km = KeyManager::new(&cfg).await?;
    let ops = SecureFileOps::new(km, cfg.storage_dir);

    let files = ops.list_files().await?;

    if files.is_empty() {
        println!("No encrypted files found");
        return Ok(());
    }

    println!("Encrypted files ({} total):", files.len());
    println!();

    if verbose {
        println!("{:<40} {:>12} {:>10}", "FILENAME", "SIZE (bytes)", "METADATA");
        println!("{}", "─".repeat(64));

        for (name, size, has_meta) in files {
            let meta_status = if has_meta { "yes" } else { "no" };
            println!("{:<40} {:>12} {:>10}", name, size, meta_status);
        }
    } else {
        for (name, size, _) in files {
            println!("  {} ({} bytes)", name, size);
        }
    }

    Ok(())
}

/// Remove an encrypted file
async fn cmd_remove(config_path: &str, name: &str, yes: bool) -> Result<()> {
    let cfg = config::Config::load(config_path)?;
    let km = KeyManager::new(&cfg).await?;
    let ops = SecureFileOps::new(km, cfg.storage_dir);

    // Check if file exists
    if !ops.exists(name).await {
        anyhow::bail!("File '{}' not found in storage", name);
    }

    // Confirm deletion unless --yes flag is set
    if !yes {
        print!("Delete '{}'? This cannot be undone. [y/N]: ", name);
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;

        if !response.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    ops.delete_file(name).await?;

    println!("Deleted '{}'", name);

    Ok(())
}

/// Show storage status and statistics
async fn cmd_status(config_path: &str) -> Result<()> {
    let cfg = config::Config::load(config_path)?;
    let km = KeyManager::new(&cfg).await?;
    let ops = SecureFileOps::new(km, cfg.storage_dir.clone());

    println!("SecureFS Status");
    println!();

    // Config info
    println!("Configuration:");
    println!("  Config file:   {}", config_path);
    println!("  Key file:      {}", cfg.key_path);
    println!("  Storage dir:   {}", cfg.storage_dir);
    println!();

    // Check if key exists
    let key_exists = fs::try_exists(&cfg.key_path).await.unwrap_or(false);
    println!("Key Status:      {}", if key_exists { "Present" } else { "Missing" });
    println!();

    // File statistics
    let files = ops.list_files().await?;

    let total_files = files.len();
    let total_size: u64 = files.iter().map(|(_, size, _)| size).sum();
    let files_with_meta = files.iter().filter(|(_, _, has_meta)| *has_meta).count();

    println!("Storage Statistics:");
    println!("  Total files:       {}", total_files);
    println!("  Total size:        {} bytes ({:.2} MB)", total_size, total_size as f64 / 1_048_576.0);
    println!("  With metadata:     {}/{}", files_with_meta, total_files);

    // Check for files without metadata
    let orphaned = files.iter().filter(|(_, _, has_meta)| !*has_meta).count();
    if orphaned > 0 {
        println!();
        println!("WARNING: {} file(s) missing metadata", orphaned);
    }

    Ok(())
}
