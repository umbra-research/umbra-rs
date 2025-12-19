use rand_core::OsRng;

use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use umbra::ownership::OwnedOutput;
use umbra::planner::build_sweep_plan;
use umbra::{build_and_sign_sweep_sol_transaction, SweepSolParams, UmbraMemo};
use umbra::{derive::derive_for_initiator, Identity};

#[test]
fn test_full_local_umbra_flow() {
    let mut rng = OsRng;

    let sweep_destination = Pubkey::new_unique();

    // Step 1: identity
    let id = Identity::new_random(&mut rng);

    // Step 2: initiator output
    let out = derive_for_initiator(&id, &mut rng);

    // Step 3: RPC-style candidate output
    // Construct OwnedOutput manually (local testing)
    let owned = OwnedOutput {
        slot: 0,
        signature: "local_sig".into(),
        one_time_pubkey: Pubkey::new_from_array(out.one_time_pubkey.to_bytes()),
        amount: 1_000_000,
        memo: UmbraMemo {
            version: 1,
            ephemeral_pubkey: out.ephemeral_pubkey.clone(),
        },
    };

    // Step 5: planner
    let (plans, issues) = build_sweep_plan(&[owned], &id, sweep_destination);

    assert!(issues.is_empty());
    assert_eq!(plans.len(), 1);

    let plan = &plans[0];

    // Step 6: sweep builder
    let bh = Hash::new_unique();
    let params = SweepSolParams {
        signer: &plan.signer,
        to: sweep_destination,
        amount: plan.amount,
        recent_blockhash: bh,
    };

    let tx = build_and_sign_sweep_sol_transaction(&params).expect("sweep transaction must build");

    assert!(tx.signatures.len() > 0);
}
