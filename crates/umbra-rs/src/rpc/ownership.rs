use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint};

use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiTransaction;
use thiserror::Error;
use crate::core::{PointWrapper, ScalarWrapper};

use crate::rpc::scanner::extract_candidate_from_ui_transaction;
use crate::rpc::types::{CandidateOutput, UmbraMemo};

/// Claimant key material needed to test ownership of a candidate output.
///
/// This is intentionally minimal:
/// - `view_scalar` is the claimant's view secret (used to derive the shared secret)
/// - `spend_pubkey` is the claimant's long-term public key (base of all one-time keys P)
#[derive(Debug, Clone)]
pub struct ClaimantKeyMaterial {
    pub view_scalar: ScalarWrapper,
    pub spend_pubkey: PointWrapper,
}

impl ClaimantKeyMaterial {
    /// Construct from full Identity.
    pub fn from_identity(identity: &crate::core::Identity) -> Self {
        Self {
            view_scalar: identity.initiator_view_sk.clone(),
            spend_pubkey: identity.initiator_spend_pk.clone(),
        }
    }
}

/// A fully verified output that belongs to the claimant.
#[derive(Debug, Clone)]
pub struct OwnedOutput {
    pub slot: u64,
    pub signature: String,
    pub one_time_pubkey: Pubkey,
    pub amount: u64,
    pub memo: UmbraMemo,
}

#[derive(Debug, Error)]
pub enum OwnershipError {
    #[error("invalid ephemeral public key in memo")]
    InvalidEphemeralPubkey,

    #[error("point decompression failed")]
    PointDecompressionFailed,
}



/// Try to determine whether a `CandidateOutput` belongs to a claimant.
///
/// Returns:
/// - `Ok(Some(OwnedOutput))` if the candidate is owned by this claimant,
/// - `Ok(None)` if it does not match,
/// - `Err(OwnershipError)` if the memo / point data is structurally invalid.
pub fn match_candidate_output(
    candidate: &CandidateOutput,
    claimant: &ClaimantKeyMaterial,
) -> Result<Option<OwnedOutput>, OwnershipError> {
    // 1. Get ephemeral pubkey
    let ephem_point: EdwardsPoint = candidate.memo.ephemeral_pubkey.0;
    
    // 2. Derive shared secret hash (tweak) using core primitive
    // This replaces manual ECDH and Hashing
    use crate::core::derive_shared_secret_view_only;
    use crate::core::PointWrapper;
    
    // derive_shared_secret_view_only takes PointWrapper and ScalarWrapper references
    let output_tweak = derive_shared_secret_view_only(
        &PointWrapper(ephem_point), 
        &claimant.view_scalar
    );
    
    // 3. Derive expected one-time public key P:
    // P = spend_pubkey + tweak * G
    let spend_point: EdwardsPoint = claimant.spend_pubkey.0;
    let tweak_scalar = output_tweak.0;
    let tweak_point = &tweak_scalar * &ED25519_BASEPOINT_POINT;
    
    let derived_point = spend_point + tweak_point;
    let derived_bytes = derived_point.compress().to_bytes();
    
    // 4. Compare
    let recipient_pk: Pubkey = candidate.recipient;
    let recipient_bytes = recipient_pk.to_bytes();
    
    if derived_bytes != recipient_bytes {
        return Ok(None);
    }
    
    Ok(Some(OwnedOutput {
        slot: candidate.slot,
        signature: candidate.signature.clone(),
        one_time_pubkey: recipient_pk,
        amount: candidate.amount,
        memo: candidate.memo.clone(),
    }))
}

/// Represents a non-fatal issue encountered while scanning a transaction.
///
/// We keep this lightweight so callers can choose to log it or ignore it.
#[derive(Debug)]
pub struct ScanIssue {
    pub slot: u64,
    pub signature: String,
    pub error: String,
}

/// Scan a sequence of UiTransactions, extract Umbra candidates and filter
/// those that belong to the given claimant.
///
/// This glues together:
/// - Phase 2A: `extract_candidate_from_ui_transaction`
/// - Phase 2B: `match_candidate_output`
///
/// Notes:
/// - This function is *best-effort*: any malformed transaction, memo, or
///   ownership error will be recorded in `issues` but will not abort the scan.
/// - This makes it safe to run over large chunks of history without panicking.
pub fn scan_ui_transactions_for_owned_outputs<'a, I>(
    claimant: &ClaimantKeyMaterial,
    txs: I,
) -> (Vec<OwnedOutput>, Vec<ScanIssue>)
where
    I: IntoIterator<Item = (u64, String, &'a UiTransaction)>,
{
    let mut owned = Vec::new();
    let mut issues = Vec::new();

    for (slot, signature, ui_tx) in txs {
        // 1) Phase 2A: attempt to extract a candidate output
        let candidate_res = extract_candidate_from_ui_transaction(slot, signature.clone(), ui_tx);

        let candidate_opt = match candidate_res {
            Ok(opt) => opt,
            Err(e) => {
                // Malformed transaction / unexpected structure:
                // record and continue with the next transaction.
                issues.push(ScanIssue {
                    slot,
                    signature: signature.clone(),
                    error: format!("scanner error: {e}"),
                });
                continue;
            }
        };

        // No Umbra memo present → skip silently.
        let candidate = match candidate_opt {
            Some(c) => c,
            None => continue,
        };

        // 2) Phase 2B: check if this candidate belongs to the claimant
        match match_candidate_output(&candidate, claimant) {
            Ok(Some(owned_output)) => {
                owned.push(owned_output);
            }
            Ok(None) => {
                // Valid Umbra candidate, but not owned by this claimant → ignore.
            }
            Err(e) => {
                // Structural issues (e.g. invalid points) should be recorded.
                issues.push(ScanIssue {
                    slot,
                    signature: candidate.signature.clone(),
                    error: format!("ownership check error: {e}"),
                });
            }
        }
    }

    (owned, issues)
}
