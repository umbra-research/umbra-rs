use solana_client::client_error::ClientError;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::RpcBlockConfig;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_transaction_status::{
    EncodedTransaction, EncodedTransactionWithStatusMeta, TransactionDetails, UiTransaction,
    UiTransactionEncoding,
};

/// A raw transaction reference from a slot.
/// This is the correct input for Phase-2 ownership logic.
#[derive(Debug, Clone)]
pub struct SlotTransaction {
    pub slot: u64,
    pub signature: String,
    pub ui_transaction: UiTransaction,
}

/// Fetch raw UiTransactions from a single slot.
pub fn fetch_ui_transactions_for_slot(
    rpc: &RpcClient,
    slot: u64,
) -> Result<Vec<SlotTransaction>, ClientError> {
    let block_config = RpcBlockConfig {
        encoding: Some(UiTransactionEncoding::Json),
        transaction_details: Some(TransactionDetails::Full),
        rewards: Some(false),
        commitment: Some(CommitmentConfig::confirmed()),
        ..RpcBlockConfig::default()
    };

    let block = rpc.get_block_with_config(slot, block_config)?;

    let mut result = Vec::new();

    let txs: Vec<EncodedTransactionWithStatusMeta> = match block.transactions {
        Some(t) => t,
        None => return Ok(result),
    };

    for tx_with_meta in txs {
        let ui_tx = match tx_with_meta.transaction {
            EncodedTransaction::Json(ui) => ui,
            _ => continue,
        };

        let signature = ui_tx.signatures.get(0).cloned().unwrap_or_default();

        result.push(SlotTransaction {
            slot,
            signature,
            ui_transaction: ui_tx,
        });
    }

    Ok(result)
}

/// Fetch UiTransactions from a slot range.
pub fn fetch_ui_transactions_for_slot_range(
    rpc: &RpcClient,
    start_slot: u64,
    end_slot: u64,
) -> Result<Vec<SlotTransaction>, ClientError> {
    let mut out = Vec::new();

    for slot in start_slot..=end_slot {
        match fetch_ui_transactions_for_slot(rpc, slot) {
            Ok(mut txs) => out.append(&mut txs),
            Err(err) => {
                return Err(ClientError::from(err));
                #[cfg(feature = "logging")]
                tracing::warn!(%slot, %err, "failed to fetch UiTransactions for slot");
            }
        }
    }

    Ok(out)
}
