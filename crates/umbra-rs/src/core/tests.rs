use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

use super::*;

#[test]
fn initiator_claimant_roundtrip() {
    let mut rng = OsRng;

    let identity = Identity::new_random(&mut rng);
    let output = derive_for_initiator(&identity, &mut rng);

    let claimant =
        derive_for_claimant(&identity, &output.one_time_pubkey, &output.ephemeral_pubkey)
            .expect("claimant should successfully recover output");

    assert!(claimant.derived_spend_scalar.0 != Scalar::ZERO);
}
