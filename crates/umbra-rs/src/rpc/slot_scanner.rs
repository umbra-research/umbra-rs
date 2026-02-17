use solana_client::client_error::ClientError;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcBlockConfig;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_transaction_status::{
    EncodedTransaction, EncodedTransactionWithStatusMeta, TransactionDetails, UiTransaction,
    UiTransactionEncoding,
};
use thiserror::Error;

use crate::rpc::scanner::{extract_candidate_from_ui_transaction, ScannerError};
use crate::rpc::types::CandidateOutput;

/// Errors that can occur while scanning blocks/slots for Umbra candidates.
#[derive(Debug, Error)]
pub enum SlotScanError {
    #[error("RPC error while fetching block: {0}")]
    Rpc(#[from] ClientError),

    #[error("scanner error while decoding Umbra memo: {0}")]
    Scanner(#[from] ScannerError),
}

/// Scan a single slot for Umbra candidate outputs.
///
/// This:
/// - fetches the block for `slot` with `Json` transaction encoding
/// - iterates all transactions
/// - runs `extract_candidate_from_ui_transaction` on each
/// - returns all `CandidateOutput` found in this slot.
pub fn scan_slot_for_candidates(
    rpc: &RpcClient,
    slot: u64,
) -> Result<Vec<CandidateOutput>, SlotScanError> {
    let block_config = RpcBlockConfig {
        encoding: Some(UiTransactionEncoding::Json),
        transaction_details: Some(TransactionDetails::Full),
        rewards: Some(false),
        commitment: Some(CommitmentConfig::finalized()),
        ..RpcBlockConfig::default()
    };

    let block = rpc.get_block_with_config(slot, block_config)?;

    let mut candidates = Vec::new();

    // In 3.x, `block.transactions` is `Option<Vec<EncodedTransactionWithStatusMeta>>`.
    let txs: Vec<EncodedTransactionWithStatusMeta> = match block.transactions {
        Some(txs) => txs,
        None => return Ok(candidates),
    };

    for tx_with_meta in txs {
        // We only care about `Json`-encoded transactions → `UiTransaction`.
        let ui_tx: UiTransaction = match tx_with_meta.transaction {
            EncodedTransaction::Json(ui) => ui,
            _ => continue,
        };

        // Best-effort signature extraction (first signature or empty string).
        let signature = ui_tx.signatures.get(0).cloned().unwrap_or_default();

        // Delegate Umbra-specific logic to the pure scanner.
        if let Some(candidate) = extract_candidate_from_ui_transaction(slot, signature, &ui_tx)? {
            candidates.push(candidate);
        }
    }

    Ok(candidates)
}

/// Scan an inclusive slot range `[start_slot, end_slot]` for Umbra candidates.
///
/// - Skips slots that fail RPC (logs via `tracing::warn!`)
/// - Aggregates all `CandidateOutput` from all successfully fetched slots.
pub fn scan_slot_range_for_candidates(
    rpc: &RpcClient,
    start_slot: u64,
    end_slot: u64,
) -> Result<Vec<CandidateOutput>, SlotScanError> {
    let mut all_candidates = Vec::new();

    for slot in start_slot..=end_slot {
        match scan_slot_for_candidates(rpc, slot) {
            Ok(mut slot_candidates) => {
                all_candidates.append(&mut slot_candidates);
            }
            Err(err) => {
                return Err(err);
                #[cfg(feature = "logging")]
                // Network / RPC noise shouldn't bring down the whole scan.
                tracing::warn!(%slot, %err, "failed to scan slot for Umbra candidates");
            }
        }
    }

    Ok(all_candidates)
}
