use rand_core::OsRng;
use umbra::{
    derive::{derive_for_claimant, derive_for_initiator},
    Identity,
};

#[test]
fn test_initiator_claimant_roundtrip() {
    // Generate identity
    let mut rng = OsRng;
    let id = Identity::new_random(&mut rng);

    // Initiator → produce output
    let out = derive_for_initiator(&id, &mut rng);

    // Claimant → recover
    let rec = derive_for_claimant(&id, &out.one_time_pubkey, &out.ephemeral_pubkey);

    assert!(rec.is_some(), "claimant should recover output");
}
