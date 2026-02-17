use anyhow::{Context, Result};
use clap::Parser;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use umbra_indexer::{Indexer, IndexerConfig};
use umbra_rs::storage::{JsonFileStorage, Network};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// RPC URL for Solana connection
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,

    /// Program ID to index
    #[arg(long)]
    program_id: String,

    /// Start slot for indexing
    #[arg(long, default_value_t = 0)]
    start_slot: u64,

    /// Path to storage file (JSON)
    #[arg(long, default_value = "umbra_db/indexer_state.json")]
    storage_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let program_id = Pubkey::from_str(&args.program_id)
        .context("Invalid program ID")?;

    let config = IndexerConfig {
        rpc_url: args.rpc_url,
        program_id,
        start_slot: args.start_slot,
        commitment: CommitmentConfig::confirmed(),
    };

    // Initialize Storage
    let storage = JsonFileStorage::load_or_init(&args.storage_path, Network::Local)?;
    let storage = Arc::new(storage);

    let indexer = Indexer::new(config, storage);

    indexer.run().await?;

    Ok(())
}
