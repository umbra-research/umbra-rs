use rand_core::OsRng;
use solana_sdk::hash::Hash;

use umbra::derivation::ScalarSigner;
use umbra::ScalarWrapper;
use umbra::{build_and_sign_sweep_sol_transaction, SweepSolParams};

#[test]
fn test_sweep_transaction_builds() {
    let mut rng = OsRng;

    let signer = ScalarSigner::new(ScalarWrapper::random(&mut rng));

    // Fake blockhash + fake destination
    let bh = Hash::new_unique();
    let dest = solana_sdk::pubkey::Pubkey::new_unique();

    let params = SweepSolParams {
        signer: &signer,
        to: dest,
        amount: 10_000,
        recent_blockhash: bh,
    };

    let tx = build_and_sign_sweep_sol_transaction(&params).expect("build sweep should work");

    assert_eq!(tx.message.account_keys.len(), 3);
    assert!(tx.signatures.len() > 0);
}
