use crate::core::PointWrapper;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
/// The structure emitted as an event (or logged) to announce a stealth payment.
/// This matches the on-chain event structure.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Announcement {
    /// The ephemeral public key (R) needed for ECDH.
    pub ephemeral_pubkey: PointWrapper,
    /// The view tag (H(shared_secret)[..]) to help scanning.
    pub hashed_tag: [u8; 32],
    /// Encrypted metadata (e.g. amount, memo) if any.
    pub ciphertext: Vec<u8>,
}

/// Helper struct for additional metadata if needed in the future.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Metadata {
    pub version: u8,
    pub data: Vec<u8>,
}

/// The request payload sent to the Relayer to execute a meta-transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerRequest {
    /// The public key of the stealth address (the PDA that holds funds).
    pub stealth_pubkey: String,
    /// The recipient's public key (where funds goes, or the relayer's fee payer).
    /// Actually, in `withdraw_with_relayer`, the relayer pays fees, but this might be the destination of the token?
    /// Let's keep it generic: The transaction likely transfers to this.
    pub recipient_pubkey: String,
    /// The amount to withdraw/transfer.
    pub amount: u64,
    /// The fee paid to the relayer.
    pub relayer_fee: u64,
    /// The signature of the message (Base64 or Hex).
    /// Message = stealth_pubkey || recipient_pubkey || amount || relayer_fee (serialized)
    pub signature: String,
}
