use solana_sdk::{
    instruction::{AccountMeta, Instruction}, message::Message, pubkey::Pubkey, transaction::Transaction,
};
use crate::program::instruction::UmbraInstruction;
use borsh::to_vec;

use crate::sweep::{derivation::ScalarSigner, SweepSolError};

pub const MIN_REMAINING_LAMPORTS: u64 = 1_000_000;

/// Parameters required to build a SOL sweep transaction.
pub struct SweepSolParams<'a> {
    /// Ephemeral private-key signer derived from scalar
    pub signer: &'a ScalarSigner,
    /// Recipient of the swept funds
    pub to: Pubkey,
    /// Amount of lamports to sweep (Ignored for Program Withdraw, it sweeps all)
    pub amount: u64,
    /// Recent blockhash to sign transaction with
    pub recent_blockhash: solana_sdk::hash::Hash,
}

/// Build and sign sweep transaction using scalar-based Ed25519 signer.
pub fn build_and_sign_sweep_sol_transaction(
    params: &SweepSolParams<'_>,
) -> Result<Transaction, SweepSolError> {
    
    let program_id = crate::program::ID;
    let (stealth_pda, _bump) = Pubkey::find_program_address(
        &[b"stealth", params.signer.pubkey().as_ref()], 
        &program_id
    );

    let instruction = UmbraInstruction::Withdraw;
    let data = to_vec(&instruction).map_err(|_| SweepSolError::ZeroAmount)?; // Map error appropriately or add new var

    let accounts = vec![
        AccountMeta::new(stealth_pda, false),
        AccountMeta::new(params.signer.pubkey(), true),
        AccountMeta::new(params.to, false),
    ];

    let ix = Instruction {
        program_id,
        accounts,
        data,
    };

    let mut message = Message::new(&[ix], Some(&params.signer.pubkey()));
    message.recent_blockhash = params.recent_blockhash;

    let msg_bytes = message.serialize();
    let sig = params.signer.sign_message(&msg_bytes);

    Ok(Transaction {
        signatures: vec![sig.into()],
        message,
    })
}
