use solana_sdk::{
    instruction::Instruction, message::Message, pubkey::Pubkey, transaction::Transaction,
};

use solana_system_interface::instruction::transfer;

use crate::{derivation::ScalarSigner, SweepSolError};

pub const MIN_REMAINING_LAMPORTS: u64 = 1_000_000;

/// Parameters required to build a SOL sweep transaction.
pub struct SweepSolParams<'a> {
    /// Ephemeral private-key signer derived from scalar
    pub signer: &'a ScalarSigner,
    /// Recipient of the swept funds
    pub to: Pubkey,
    /// Amount of lamports to sweep
    pub amount: u64,
    /// Recent blockhash to sign transaction with
    pub recent_blockhash: solana_sdk::hash::Hash,
}

/// Build and sign sweep transaction using scalar-based Ed25519 signer.
pub fn build_and_sign_sweep_sol_transaction(
    params: &SweepSolParams<'_>,
) -> Result<Transaction, SweepSolError> {
    if params.amount == 0 {
        return Err(SweepSolError::ZeroAmount);
    }

    let from = params.signer.pubkey();
    let to = params.to;

    let ix: Instruction = transfer(&from, &to, params.amount);

    let mut message = Message::new(&[ix], Some(&from));
    message.recent_blockhash = params.recent_blockhash;

    let msg_bytes = message.serialize();
    let sig = params.signer.sign_message(&msg_bytes);

    Ok(Transaction {
        signatures: vec![sig.into()],
        message,
    })
}
