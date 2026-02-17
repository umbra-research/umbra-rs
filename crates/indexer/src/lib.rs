use anyhow::{Result};
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
// Make sure this trait is visible for `try_from_slice`
use borsh::BorshDeserialize; 
use tracing::{debug, info, instrument, warn};
use umbra_rs::storage::{CandidateRecord, UmbraStorage};

const ANCHOR_DISCRIMINATOR_SIZE: usize = 8;

pub struct IndexerConfig {
    pub rpc_url: String,
    pub program_id: Pubkey,
    pub start_slot: u64,
    pub commitment: CommitmentConfig,
}

pub struct Indexer {
    client: RpcClient,
    storage: Arc<dyn UmbraStorage>,
    config: IndexerConfig,
    announcement_discriminator: [u8; 8],
}

impl Indexer {
    pub fn new(config: IndexerConfig, storage: Arc<dyn UmbraStorage>) -> Self {
        let client = RpcClient::new_with_commitment(config.rpc_url.clone(), config.commitment);
        
        // Calculate "event:StealthAnnouncement" discriminator
        let mut hasher = Sha256::new();
        hasher.update(b"event:StealthAnnouncement");
        let hash = hasher.finalize();
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&hash[..8]);

        Self {
            client,
            storage,
            config,
            announcement_discriminator: disc,
        }
    }

    #[instrument(skip(self))]
    pub async fn run(&self) -> Result<()> {
        info!("Starting Umbra Indexer...");
        
        // 1. Initialize State
        let mut state = self.storage.load_state();
        let mut current_slot = if state.scan.last_scanned_slot > 0 {
            state.scan.last_scanned_slot
        } else {
            self.config.start_slot
        };
        
        let mut last_blockhash = state.scan.params.get("last_blockhash").cloned();

        info!("Resuming indexing from slot {}", current_slot);

        loop {
            // 2. Poll for Next Block
            let latest_slot = match self.client.get_slot() {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to get latest slot: {}. Retrying...", e);
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            
            if current_slot >= latest_slot {
                sleep(Duration::from_millis(500)).await;
                continue;
            }

            let process_slot = current_slot + 1;
            
            // 3. Fetch Block
            match self.client.get_block(process_slot) {
                Ok(block) => {
                    let blockhash = block.blockhash.clone();
                    
                    // 4. Re-org Check
                    if let Some(prev_hash) = &last_blockhash {
                         if block.previous_blockhash != *prev_hash {
                             warn!("RE-ORG DETECTED at slot {}. Parent {} != Expected {}. Rolling back...", 
                                process_slot, block.previous_blockhash, prev_hash);
                             
                             // Simple rollback strategy: Go back 1 slot.
                             current_slot = current_slot.saturating_sub(1);
                             
                             if let Ok(prev_block) = self.client.get_block(current_slot) {
                                 last_blockhash = Some(prev_block.blockhash);
                                 let mut params = state.scan.params.clone();
                                 if let Some(h) = &last_blockhash {
                                     params.insert("last_blockhash".to_string(), h.clone());
                                 }
                                 self.storage.update_scan_state(current_slot, Some(params))?;
                             } else {
                                 warn!("Could not fetch rollback slot {}. Resetting safety check.", current_slot);
                                 last_blockhash = None; 
                             }
                             continue;
                         }
                    }

                    // 5. Process Transactions
                    // block.transactions is Vec (in this version of solana-client?)
                    // Error said: expression has type Vec...
                    if let Some(txs) = Some(block.transactions) { // Hack to keep logic structure if needed, or just iterate.
                       // Just iterate directly:
                       for tx_status in txs {
                            // Extract signature
                            let signature = if let Some(transaction) = &tx_status.transaction.decode() {
                                transaction.signatures.get(0).map(|s| s.to_string()).unwrap_or_default()
                            } else {
                                "unknown".to_string()
                            };

                            if let Some(meta) = tx_status.meta {
                                if let Some(err) = meta.err {
                                    continue; // Skip failed txs
                                }
                                use solana_transaction_status::option_serializer::OptionSerializer;
                                if let OptionSerializer::Some(logs) = meta.log_messages {
                                    self.process_logs(process_slot, &logs, &signature).await?;
                                }
                            }
                       }
                    }
                    
                    // 6. Commit State
                    current_slot = process_slot;
                    last_blockhash = Some(blockhash.clone());
                    
                    let mut params = state.scan.params.clone();
                    params.insert("last_blockhash".to_string(), blockhash);
                    
                    self.storage.update_scan_state(current_slot, Some(params))?;
                    
                    if current_slot % 10 == 0 {
                        info!("Indexed slot {}", current_slot);
                    }
                }
                Err(err) => {
                    debug!("Could not fetch slot {}: {}. Skipping...", process_slot, err);
                    current_slot = process_slot;
                    last_blockhash = None; 
                     self.storage.update_scan_state(current_slot, None)?;
                }
            }
        }
    }

    async fn process_logs(&self, slot: u64, logs: &[String], signature: &str) -> Result<()> {
        for log in logs {
            if let Some(data_str) = log.strip_prefix("Program data: ") {
                if let Ok(data) = general_purpose::STANDARD.decode(data_str) {
                    if data.len() < ANCHOR_DISCRIMINATOR_SIZE {
                        continue;
                    }
                    
                    let (discriminator, content) = data.split_at(ANCHOR_DISCRIMINATOR_SIZE);
                    
                    if discriminator == self.announcement_discriminator {
                         info!("Found StealthAnnouncement at slot {} in tx {}", slot, signature);
                         
                         // We use a custom struct to match the event exactly including Token-2022 support
                         use borsh::BorshDeserialize;
                         
                         #[derive(BorshDeserialize)]
                         struct StealthAnnouncementEvent {
                             pub ephemeral_pubkey: [u8; 32],
                             pub hashed_tag: [u8; 32],
                             pub ciphertext: Vec<u8>,
                             pub token_mint: Option<Pubkey>,
                         }

                         if let Ok(event) = StealthAnnouncementEvent::try_from_slice(content) {
                            let candidate = CandidateRecord {
                                slot,
                                signature: signature.to_string(),
                                recipient: "unknown".to_string(), 
                                amount: 0, 
                                memo: event.ciphertext, 
                            };
                            
                            self.storage.save_candidate_output(candidate)?;
                         } else {
                             // Falback for legacy events without token_mint?
                             if let Ok(legacy) = umbra_rs::core::protocol::Announcement::try_from_slice(content) {
                                 warn!("Parsed legacy StealthAnnouncement (no token_mint)");
                                 let candidate = CandidateRecord {
                                    slot,
                                    signature: signature.to_string(),
                                    recipient: "unknown".to_string(),
                                    amount: 0,
                                    memo: legacy.ciphertext,
                                };
                                self.storage.save_candidate_output(candidate)?;
                             }
                         }
                    }
                }
            }
        }
        Ok(())
    }
}
