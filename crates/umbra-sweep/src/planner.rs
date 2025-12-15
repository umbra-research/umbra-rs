use curve25519_dalek::edwards::CompressedEdwardsY;
use solana_sdk::pubkey::Pubkey;

use umbra_core::derive::derive_for_claimant;
use umbra_core::{Identity, PointWrapper};

use umbra_rpc::ownership::OwnedOutput;

use crate::derivation::ScalarSigner;

#[derive(Debug, Clone)]
pub struct SweepPlan {
    pub one_time_pubkey: Pubkey,
    pub amount: u64,
    pub destination: Pubkey,
    pub signer: ScalarSigner,
}

#[derive(Debug, Clone)]
pub struct PlanIssue {
    pub slot: u64,
    pub signature: String,
    pub error: String,
}

pub fn build_sweep_plan(
    owned_outputs: &[OwnedOutput],
    claimant_identity: &Identity,
    sweep_destination: Pubkey,
) -> (Vec<SweepPlan>, Vec<PlanIssue>) {
    let mut plans = Vec::new();
    let mut issues = Vec::new();

    for out in owned_outputs {
        // 1) Solana Pubkey → EdwardsPoint
        let compressed = CompressedEdwardsY(out.one_time_pubkey.to_bytes());
        let one_time_point = match compressed.decompress() {
            Some(p) => p,
            None => {
                issues.push(PlanIssue {
                    slot: out.slot,
                    signature: out.signature.clone(),
                    error: "failed to decompress one-time pubkey into EdwardsPoint".into(),
                });
                continue;
            }
        };
        // 2) ECC derive (Phase 1)
        let recovery = match derive_for_claimant(
            claimant_identity,
            &PointWrapper(one_time_point),
            &out.memo.ephemeral_pubkey,
        ) {
            Some(r) => r,
            None => {
                issues.push(PlanIssue {
                    slot: out.slot,
                    signature: out.signature.clone(),
                    error: "derive_for_claimant returned None (mismatch or invalid)".into(),
                });
                continue;
            }
        };

        // 3) Build signer
        let signer = ScalarSigner::new(recovery.derived_spend_scalar.clone());

        // 4) Final plan
        plans.push(SweepPlan {
            one_time_pubkey: out.one_time_pubkey,
            amount: out.amount,
            destination: sweep_destination,
            signer,
        });
    }

    (plans, issues)
}
