use rand_core::OsRng;
use solana_sdk::pubkey::Pubkey;
use umbra::{
    derive_for_claimant, derive_for_initiator, ownership::OwnedOutput, planner::build_sweep_plan,
    Identity, UmbraMemo,
};

#[test]
fn test_planner_builds_plan() {
    let mut rng = OsRng;
    let id = Identity::new_random(&mut rng);

    // Initiator produces candidate
    let out = derive_for_initiator(&id, &mut rng);

    // Claimant recovers spend authority
    let _rec = derive_for_claimant(&id, &out.one_time_pubkey, &out.ephemeral_pubkey)
        .expect("claimant must recover");

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

    // Now call planner
    let (plans, issues) = build_sweep_plan(&[owned], &id, Pubkey::new_unique());

    assert!(issues.is_empty(), "no issues expected");
    assert_eq!(plans.len(), 1);
}
