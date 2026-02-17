use std::str::FromStr;

use bs58;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::{UiCompiledInstruction, UiMessage, UiTransaction};
use thiserror::Error;

use crate::rpc::memo::{parse_umbra_memo, MemoDecodeError};
use crate::rpc::types::{CandidateOutput, UmbraMemo};

/// Memo program ID on Solana mainnet/devnet.
const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// System program ID for SOL transfers.
const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// Errors occurring while extracting Umbra candidates.
#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("encoded transaction must be Json")]
    NotJsonEncoded,

    #[error("transaction message must be Raw")]
    NotRawMessage,

    #[error("memo decode error: {0}")]
    MemoDecode(#[from] MemoDecodeError),

    #[error("base58 decode error: {0}")]
    Base58(#[from] bs58::decode::Error),

    #[error("invalid account index in instruction")]
    InvalidAccountIndex,

    #[error("invalid program id index in instruction")]
    InvalidProgramIdIndex,

    #[error("unexpected system transfer layout")]
    InvalidSystemTransferLayout,
}

/// Extract the first Umbra candidate output from a UiTransaction.
///
/// Returns:
/// - `Ok(Some(...))` if this is an Umbra transaction,
/// - `Ok(None)` if no Umbra memo is present,
/// - `Err(...)` for malformed or inconsistent transaction structures.
pub fn extract_candidate_from_ui_transaction(
    slot: u64,
    signature: String,
    ui_tx: &UiTransaction,
) -> Result<Option<CandidateOutput>, ScannerError> {
    // Access the message field of the UiTransaction.
    // This drastically reduces nesting compared to older versions.
    let raw = match &ui_tx.message {
        UiMessage::Raw(raw_message) => raw_message,
        _ => return Err(ScannerError::NotRawMessage),
    };

    let account_keys = &raw.account_keys;
    let instructions = &raw.instructions;

    // 1) Locate Umbra memo instruction
    let (memo_inst, _) = match find_memo_inst(account_keys, instructions)? {
        Some(x) => x,
        None => return Ok(None),
    };

    let memo_bytes = bs58::decode(&memo_inst.data).into_vec()?;

    let memo: UmbraMemo = match parse_umbra_memo(&memo_bytes) {
        Ok(m) => m,
        Err(MemoDecodeError::InvalidMagic) => return Ok(None),
        Err(e) => return Err(ScannerError::MemoDecode(e)),
    };

    // 2) Locate SystemProgram::Transfer
    let (recipient, amount) = match find_system_transfer(account_keys, instructions)? {
        Some(v) => v,
        None => (Pubkey::default(), 0),
    };

    Ok(Some(CandidateOutput {
        slot,
        signature,
        recipient,
        amount,
        memo,
    }))
}

/// Find the first memo instruction targeting the Memo program.
fn find_memo_inst<'a>(
    account_keys: &'a [String],
    instructions: &'a [UiCompiledInstruction],
) -> Result<Option<(&'a UiCompiledInstruction, Pubkey)>, ScannerError> {
    let memo_pid = Pubkey::from_str(MEMO_PROGRAM_ID).unwrap();

    for inst in instructions {
        let pid_index = inst.program_id_index as usize;

        let key_str = account_keys
            .get(pid_index)
            .ok_or(ScannerError::InvalidProgramIdIndex)?;

        let pid = Pubkey::from_str(key_str).map_err(|_| ScannerError::InvalidProgramIdIndex)?;

        if pid == memo_pid {
            return Ok(Some((inst, pid)));
        }
    }
    Ok(None)
}

/// Find the first SOL transfer instruction (SystemProgram::Transfer).
fn find_system_transfer(
    account_keys: &[String],
    instructions: &[UiCompiledInstruction],
) -> Result<Option<(Pubkey, u64)>, ScannerError> {
    let system_pid = Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap();

    for inst in instructions {
        let pid_index = inst.program_id_index as usize;

        let key_str = account_keys
            .get(pid_index)
            .ok_or(ScannerError::InvalidProgramIdIndex)?;

        let pid = Pubkey::from_str(key_str).map_err(|_| ScannerError::InvalidProgramIdIndex)?;

        if pid != system_pid {
            continue;
        }

        // Layout:
        //   4 bytes: discriminant (u32 LE), transfer = 2
        //   8 bytes: amount (u64 LE)
        let data = bs58::decode(&inst.data).into_vec()?;

        if data.len() < 4 + 8 {
            return Err(ScannerError::InvalidSystemTransferLayout);
        }

        let disc = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if disc != 2 {
            continue;
        }

        let amount = u64::from_le_bytes(data[4..12].try_into().unwrap());

        let dst_index = *inst
            .accounts
            .get(1)
            .ok_or(ScannerError::InvalidAccountIndex)? as usize;

        let dst_str = account_keys
            .get(dst_index)
            .ok_or(ScannerError::InvalidAccountIndex)?;

        let recipient = Pubkey::from_str(dst_str).map_err(|_| ScannerError::InvalidAccountIndex)?;

        return Ok(Some((recipient, amount)));
    }

    Ok(None)
}
