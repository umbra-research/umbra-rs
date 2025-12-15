use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar};
use sha2::{Digest, Sha512};
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiTransaction;
use thiserror::Error;
use umbra_core::{PointWrapper, ScalarWrapper};

use crate::scanner::extract_candidate_from_ui_transaction;
use crate::types::{CandidateOutput, UmbraMemo};

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
    pub fn from_identity(identity: &umbra_core::Identity) -> Self {
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

const SHARED_SECRET_DOMAIN: &[u8] = b"umbra.v0.shared_secret";

/// Domain separated hash-to-scalar for shared secrets.
fn hash_shared_secret(shared: &EdwardsPoint) -> Scalar {
    let compressed = shared.compress().to_bytes();

    let mut h = Sha512::new();
    h.update(SHARED_SECRET_DOMAIN);
    h.update(compressed);

    let digest = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest[..32]);

    Scalar::from_bytes_mod_order(bytes)
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
    // ---------------------------------------------------------------------
    // 1. Get ephemeral pubkey from Umbra memo
    // ---------------------------------------------------------------------

    // NOTE: This assumes `UmbraMemo` exposes an EdwardsPoint or PointWrapper
    // for the ephemeral key. Adjust this line to match your actual type:
    //
    //   - If UmbraMemo has `ephemeral_pubkey: PointWrapper`:
    //         let ephem_point: EdwardsPoint = candidate.memo.ephemeral_pubkey.0;
    //
    //   - If UmbraMemo stores `[u8; 32]`:
    //         let ephem_point = EdwardsPoint::decompress(
    //             curve25519_dalek::edwards::CompressedEdwardsY(candidate.memo.ephemeral_bytes)
    //         ).ok_or(OwnershipError::PointDecompressionFailed)?;
    //
    // Adjust below as needed.
    let ephem_point: EdwardsPoint = candidate.memo.ephemeral_pubkey.0;

    // ---------------------------------------------------------------------
    // 2. Derive shared secret: view_scalar * ephemeral_pubkey
    // ---------------------------------------------------------------------
    let view_scalar: Scalar = claimant.view_scalar.0;
    let shared_point: EdwardsPoint = &view_scalar * &ephem_point;

    // ---------------------------------------------------------------------
    // 3. Hash shared secret → tweak scalar (domain-separated)
    // ---------------------------------------------------------------------
    let tweak: Scalar = hash_shared_secret(&shared_point);

    // ---------------------------------------------------------------------
    // 4. Derive expected one-time public key P:
    //
    //     P_expected = spend_pubkey + tweak * G
    //
    // where `G` is the Ed25519 basepoint.
    // ---------------------------------------------------------------------
    let spend_point: EdwardsPoint = claimant.spend_pubkey.0;
    let tweak_point: EdwardsPoint = &tweak * &ED25519_BASEPOINT_POINT;
    let derived_point: EdwardsPoint = spend_point + tweak_point;

    let derived_bytes: [u8; 32] = derived_point.compress().to_bytes();

    // ---------------------------------------------------------------------
    // 5. Compare with on-chain recipient pubkey
    // ---------------------------------------------------------------------
    let recipient_pk: Pubkey = candidate.recipient;
    let recipient_bytes = recipient_pk.to_bytes();

    if derived_bytes != recipient_bytes {
        // This candidate does not belong to this claimant.
        return Ok(None);
    }

    // ---------------------------------------------------------------------
    // 6. Build OwnedOutput
    // ---------------------------------------------------------------------
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
