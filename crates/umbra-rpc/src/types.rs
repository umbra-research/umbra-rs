use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use umbra_core::PointWrapper;

/// Parsed Umbra memo payload.
///
/// The memo encodes protocol metadata and the ephemeral public key `R`
/// used by the initiator when generating a one-time output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UmbraMemo {
    /// Umbra memo protocol version.
    pub version: u8,

    /// Ephemeral public key R encoded in compressed Edwards-Y format.
    pub ephemeral_pubkey: PointWrapper,
}

/// A single Umbra candidate output discovered on-chain.
///
/// This contains enough metadata for a caller to check whether the output
/// belongs to a given Umbra identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateOutput {
    /// Slot where the transaction was included.
    pub slot: u64,

    /// Base58 transaction signature.
    pub signature: String,

    /// Recipient public key of the transfer.
    pub recipient: Pubkey,

    /// Amount in lamports (for SOL transfers).
    pub amount: u64,

    /// Parsed Umbra memo payload.
    pub memo: UmbraMemo,
}
