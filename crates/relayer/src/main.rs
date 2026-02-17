use anyhow::{Context, Result};
use clap::Parser;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::read_keypair_file;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use umbra_relayer::{run_server, RelayerConfig};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// RPC URL for Solana connection
    #[arg(long, default_value = "http://127.0.0.1:8899")]
    rpc_url: String,

    /// Relayer Keypair file path
    #[arg(long)]
    keypair: PathBuf,

    /// Listening Address
    #[arg(long, default_value = "0.0.0.0:3000")]
    listen: String,

    /// Umbra Program ID
    #[arg(long)]
    program_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let program_id = Pubkey::from_str(&args.program_id)
        .context("Invalid program ID")?;

    let keypair = read_keypair_file(&args.keypair)
        .map_err(|e| anyhow::anyhow!("Failed to read keypair: {}", e))?;

    let listen_addr = SocketAddr::from_str(&args.listen)
        .context("Invalid listen address")?;

    let config = RelayerConfig {
        rpc_url: args.rpc_url,
        relayer_keypair: Arc::new(keypair),
        listen_addr,
        program_id,
    };

    run_server(config).await?;

    Ok(())
}
