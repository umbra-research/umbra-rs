use anyhow::{Context, Result};
use axum::{
    extract::{State, Json},
    routing::post,
    Router, http::{StatusCode, Request},
    middleware::{self, Next},
    response::Response,
};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
    instruction::Instruction,
};
use std::sync::Arc;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::{info, error, instrument};

// Import umbra-core types if needed, or define local request types.
// We need to construct umbra-program instructions.
// Since umbra-program is an anchor program, we can use codegen or manual instruction construction.
// Ideally, we'd use the generated client code, but we don't have it in rust easily without generating it.
// We can manually construct the instruction data for 'withdraw_with_relayer'.
// But wait, the IDL generation failed, so we don't have safe Rust bindings yet.
// We have to emulate `anchor-lang` instruction data layout (Discriminator + Args).

#[derive(Clone)]
pub struct RelayerConfig {
    pub rpc_url: String,
    pub relayer_keypair: Arc<Keypair>,
    pub listen_addr: SocketAddr,
    pub program_id: Pubkey,
}

struct AppState {
    client: RpcClient,
    keypair: Arc<Keypair>,
    program_id: Pubkey,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RelayRequest {
    pub stealth_pubkey: String,
    pub recipient_pubkey: String,
    pub amount: u64,
    pub relayer_fee: u64,
    pub signature: String, // Base64 or Hex encoded Ed25519 signature
}

#[derive(Debug, Serialize)]
pub struct RelayResponse {
    pub tx_signature: String,
}

pub async fn run_server(config: RelayerConfig) -> Result<()> {
    let client = RpcClient::new_with_commitment(config.rpc_url.clone(), CommitmentConfig::confirmed());
    let state = Arc::new(AppState {
        client,
        keypair: config.relayer_keypair,
        program_id: config.program_id,
    });

    let app = Router::new()
        .route("/relay", post(handle_relay))
        .layer(middleware::from_fn(remove_ip_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!("Relayer listening on {}", config.listen_addr);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    axum::serve(listener, app).await.context("Server failed")
}

async fn remove_ip_headers(req: Request<axum::body::Body>, next: Next) -> Response {
    let mut req = req;
    let headers = req.headers_mut();
    
    // Strip common IP-tracking headers
    headers.remove("X-Forwarded-For");
    headers.remove("X-Real-IP");
    headers.remove("CF-Connecting-IP");
    headers.remove("True-Client-IP");
    
    next.run(req).await
}

#[instrument(skip(state))]
async fn handle_relay(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RelayRequest>,
) ->  std::result::Result<Json<RelayResponse>, StatusCode> {
    info!("Received relay request for stealth pubkey: {}", payload.stealth_pubkey);

    // 1. Parsing Input
    let stealth_pubkey = Pubkey::try_from(payload.stealth_pubkey.as_str())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let recipient_pubkey = Pubkey::try_from(payload.recipient_pubkey.as_str())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // Decode signature
    use base64::{engine::general_purpose, Engine as _};
    let signature_bytes = general_purpose::STANDARD.decode(&payload.signature)
        .or_else(|_| hex::decode(&payload.signature))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // 2. Construct Ed25519 Instruction
    // The message signed should match what the program expects.
    // Usually: [stealth_pubkey, recipient_pubkey, amount, fee]
    // The program implementation of `withdraw_with_relayer` checks Ed25519 program.
    // We assume the user signed the correct message.
    
    // We need to create the `new_ed25519_instruction` that verifies this signature against the message.
    // The message is implicitly constructed by the client. We must reconstruct it here to verify?
    // Or just pass it to the Ed25519 instruction.
    // The Ed25519 instruction takes (Pubkey, Signature, Message).
    // If we pass the wrong message, it will fail on-chain (or simulation).
    // We should construct the expected message:
    // Message = stealth_pubkey (32) || recipient_pubkey (32) || amount (8) || fee (8) ?
    // We need to agree on the message format.
    // Let's assume standard serialization:
    let mut message = Vec::new();
    message.extend_from_slice(stealth_pubkey.as_ref());
    message.extend_from_slice(recipient_pubkey.as_ref());
    message.extend_from_slice(&payload.amount.to_le_bytes()); // u64
    message.extend_from_slice(&payload.relayer_fee.to_le_bytes()); // u64
    
    // Manual Ed25519 Instruction Construction
    // Layout:
    // count (1) | padding (1) 
    // sig_offset (2) | sig_ix (2) | pk_offset (2) | pk_ix (2) | msg_offset (2) | msg_size (2) | msg_ix (2)
    // data...
    
    let mut ix_data = Vec::new();
    let num_signatures: u8 = 1;
    let padding: u8 = 0;
    
    // Header size = 1 + 1 + 14 = 16 bytes.
    // offsets relative to start of instruction data.
    let header_size = 16;
    let pubkey_offset = header_size;
    let signature_offset = pubkey_offset + 32;
    let message_offset = signature_offset + 64;
    
    ix_data.push(num_signatures);
    ix_data.push(padding);
    ix_data.extend_from_slice(&(signature_offset as u16).to_le_bytes()); // sig_offset
    ix_data.extend_from_slice(&u16::MAX.to_le_bytes());                  // sig_ix (current instruction)
    ix_data.extend_from_slice(&(pubkey_offset as u16).to_le_bytes());    // pk_offset
    ix_data.extend_from_slice(&u16::MAX.to_le_bytes());                  // pk_ix (current instruction)
    ix_data.extend_from_slice(&(message_offset as u16).to_le_bytes());   // msg_offset
    ix_data.extend_from_slice(&(message.len() as u16).to_le_bytes());    // msg_size
    ix_data.extend_from_slice(&u16::MAX.to_le_bytes());                  // msg_ix (current instruction)

    // Append data
    ix_data.extend_from_slice(stealth_pubkey.as_ref());
    ix_data.extend_from_slice(&signature_bytes);
    ix_data.extend_from_slice(&message);

    let ed25519_ix = Instruction {
        program_id: solana_sdk::ed25519_program::id(),
        accounts: vec![],
        data: ix_data,
    };
    
    // Rename to avoid confusion with umbra_ix data
    let umbra_ix_data_content = {
        // 3. Construct Umbra Program Instruction
        // Discriminator for "withdraw_with_relayer"
        // Anchor discriminators are Sha256("global:withdraw_with_relayer")[..8]
        let discriminator = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"global:withdraw_with_relayer");
            let hash = hasher.finalize();
            let mut d = [0u8; 8];
            d.copy_from_slice(&hash[..8]);
            d
        };
        
        let mut d = Vec::new();
        d.extend_from_slice(&discriminator);
        d.extend_from_slice(&payload.amount.to_le_bytes());
        d.extend_from_slice(&payload.relayer_fee.to_le_bytes());
        d
    };

    // Accounts:
    // 1. stealth_pda (mut)
    // 2. relayer (mut, signer)
    // 3. recipient (mut)
    // 4. system_program
    // 5. instructions_sysvar
    
    use solana_sdk::instruction::AccountMeta;
    let accounts = vec![
        AccountMeta::new(stealth_pubkey, false), // PDA is not signer (program signs)
        AccountMeta::new(state.keypair.pubkey(), true), // Relayer signs
        AccountMeta::new(recipient_pubkey, false), 
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::instructions::id(), false),
    ];

    let umbra_ix = Instruction {
        program_id: state.program_id,
        accounts,
        data: umbra_ix_data_content,
    };

    // 4. Build and Sign Transaction
    let latest_blockhash = state.client.get_latest_blockhash()
        .map_err(|e| {
            error!("Failed to get blockhash: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let tx = Transaction::new_signed_with_payer(
        &[ed25519_ix, umbra_ix],
        Some(&state.keypair.pubkey()),
        &[&*state.keypair],
        latest_blockhash,
    );
    
    // 5. Simulate Check (Optional but recommended)
    // let sim = state.client.simulate_transaction(&tx).map_err(...)?;
    
    // 6. Send
    let signature = state.client.send_and_confirm_transaction(&tx)
        .map_err(|e| {
            error!("Transaction failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    info!("Relay success! Sig: {}", signature);

    Ok(Json(RelayResponse {
        tx_signature: signature.to_string(),
    }))
}
