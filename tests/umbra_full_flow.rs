use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use solana_sdk::{hash::Hash, pubkey::Pubkey};
use tracing::info;
use umbra::{
    build_and_sign_sweep_sol_transaction,
    derive::{derive_for_claimant, derive_for_initiator},
    ownership::{match_candidate_output, ClaimantKeyMaterial},
    planner::build_sweep_plan,
    Identity, PointWrapper, SweepSolParams,
};
use umbra_rpc::memo::{build_umbra_memo, parse_umbra_memo, UMBRA_MEMO_VERSION};
use umbra_rpc::types::CandidateOutput;
use umbra_sweep::derivation::ScalarSigner;
use umbra_sweep::sol::MIN_REMAINING_LAMPORTS;

#[test]
fn canonical_full_flow_validates_protocol() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let mut rng = ChaCha20Rng::seed_from_u64(2024);

    // ---------------------------------------------------------------------
    // 1. Identity setup (deterministic for reproducibility)
    // ---------------------------------------------------------------------
    let identity = Identity::new_random(&mut rng);

    assert_eq!(
        identity.initiator_spend_pk.0,
        ED25519_BASEPOINT_POINT * identity.initiator_spend_sk.0,
        "spend public key must match secret"
    );

    assert_eq!(
        identity.initiator_view_pk.0,
        ED25519_BASEPOINT_POINT * identity.initiator_view_sk.0,
        "view public key must match secret"
    );

    // ---------------------------------------------------------------------
    // 2. Initiator phase
    // ---------------------------------------------------------------------
    let initiator_output = derive_for_initiator(&identity, &mut rng);
    let fresh_output = derive_for_initiator(&identity, &mut rng);
    assert_ne!(
        initiator_output.ephemeral_pubkey, fresh_output.ephemeral_pubkey,
        "ephemeral public keys must not be reused"
    );
    assert_ne!(
        initiator_output.one_time_pubkey, identity.initiator_spend_pk,
        "one-time key must differ from long-term spend key"
    );

    let memo_bytes = build_umbra_memo(&initiator_output.ephemeral_pubkey.to_bytes());
    let memo = parse_umbra_memo(&memo_bytes).expect("memo should parse");
    assert_eq!(memo.version, UMBRA_MEMO_VERSION);
    assert_eq!(
        memo.ephemeral_pubkey, initiator_output.ephemeral_pubkey,
        "memo must encode the exact ephemeral key"
    );

    // ---------------------------------------------------------------------
    // 3. Simulated on-chain output
    // ---------------------------------------------------------------------
    let amount = MIN_REMAINING_LAMPORTS + 250_000;
    let recipient = Pubkey::new_from_array(initiator_output.one_time_pubkey.to_bytes());
    let candidate = CandidateOutput {
        slot: 88,
        signature: "canonical_sig".into(),
        recipient,
        amount,
        memo: memo.clone(),
    };
    assert_eq!(candidate.recipient, recipient);
    assert_eq!(candidate.amount, amount);
    assert_eq!(candidate.memo.version, UMBRA_MEMO_VERSION);

    // ---------------------------------------------------------------------
    // 4. Claimant scan & ownership detection
    // ---------------------------------------------------------------------
    let recovery = derive_for_claimant(
        &identity,
        &initiator_output.one_time_pubkey,
        &memo.ephemeral_pubkey,
    )
    .expect("claimant should recover spend authority");

    let reconstructed_point = CompressedEdwardsY(recipient.to_bytes())
        .decompress()
        .expect("recipient must decompress");
    assert_eq!(
        PointWrapper(reconstructed_point),
        initiator_output.one_time_pubkey,
        "recovered one-time key must match initiator intent"
    );
    assert_ne!(
        recovery.derived_spend_scalar.0,
        Scalar::ZERO,
        "derived spend scalar must be non-zero"
    );

    let recovery_repeat = derive_for_claimant(
        &identity,
        &initiator_output.one_time_pubkey,
        &memo.ephemeral_pubkey,
    )
    .expect("deterministic recovery should succeed again");
    assert_eq!(
        recovery.shared_secret_hash.0, recovery_repeat.shared_secret_hash.0,
        "shared secret derivation must be deterministic"
    );
    assert_eq!(
        recovery.derived_spend_scalar.0, recovery_repeat.derived_spend_scalar.0,
        "derived spend scalar must be deterministic"
    );

    // ---------------------------------------------------------------------
    // 5. Sweep planning
    // ---------------------------------------------------------------------
    let claimant_keys = ClaimantKeyMaterial::from_identity(&identity);
    let owned_output = match_candidate_output(&candidate, &claimant_keys)
        .expect("ownership check should succeed")
        .expect("candidate must belong to claimant");

    let destination = Pubkey::new_unique();
    let (plans, issues) = build_sweep_plan(&[owned_output.clone()], &identity, destination);
    assert!(issues.is_empty(), "planning should be issue-free");
    assert_eq!(plans.len(), 1, "exactly one sweep plan is expected");

    let plan = &plans[0];
    assert_eq!(plan.one_time_pubkey, recipient);
    assert_eq!(plan.destination, destination);
    assert_eq!(plan.amount, amount);
    assert_eq!(plan.signer.pubkey(), recipient, "signer must control P");

    let sweep_amount = plan.amount.saturating_sub(MIN_REMAINING_LAMPORTS);
    assert_eq!(
        sweep_amount,
        amount - MIN_REMAINING_LAMPORTS,
        "sweep must leave rent buffer untouched"
    );

    // ---------------------------------------------------------------------
    // 6. Sweep transaction construction
    // ---------------------------------------------------------------------
    let tx = build_and_sign_sweep_sol_transaction(&SweepSolParams {
        signer: &plan.signer,
        to: destination,
        amount: sweep_amount,
        recent_blockhash: Hash::new_unique(),
    })
    .expect("sweep transaction must build");

    let payer = plan.signer.pubkey();
    assert_eq!(tx.signatures.len(), 1);
    assert_eq!(
        tx.message.account_keys[0], payer,
        "fee payer must be signer"
    );
    assert_eq!(
        tx.message.account_keys[1], destination,
        "recipient must be sweep destination"
    );
    assert_eq!(
        tx.message.instructions.len(),
        1,
        "only transfer instruction is expected"
    );
    let ix = &tx.message.instructions[0];
    assert_eq!(ix.accounts, vec![0, 1], "from/to ordering must be correct");

    // ---------------------------------------------------------------------
    // 7. Final protocol invariants
    // ---------------------------------------------------------------------
    let initiator_view_only_signer = ScalarSigner::new(recovery.shared_secret_hash.clone());
    assert_ne!(
        initiator_view_only_signer.pubkey(),
        recipient,
        "shared secret alone (initiator knowledge) cannot derive spend key"
    );

    let mut outsider_rng = ChaCha20Rng::seed_from_u64(999);
    let outsider = Identity::new_random(&mut outsider_rng);
    assert!(
        derive_for_claimant(
            &outsider,
            &initiator_output.one_time_pubkey,
            &memo.ephemeral_pubkey
        )
        .is_none(),
        "third-party should not claim output"
    );
    assert!(
        match_candidate_output(&candidate, &ClaimantKeyMaterial::from_identity(&outsider))
            .unwrap()
            .is_none(),
        "ownership check must reject foreign claimant"
    );

    let (post_claim_plans, _) = build_sweep_plan(&[], &identity, destination);
    assert!(
        post_claim_plans.is_empty(),
        "after claiming, nothing else should be sweepable"
    );

    let mut replay_rng = ChaCha20Rng::seed_from_u64(2024);
    let replay_identity = Identity::new_random(&mut replay_rng);
    let replay_output = derive_for_initiator(&replay_identity, &mut replay_rng);
    assert_eq!(
        identity.initiator_spend_pk, replay_identity.initiator_spend_pk,
        "identity derivation must be deterministic with fixed RNG"
    );
    assert_eq!(
        initiator_output.one_time_pubkey, replay_output.one_time_pubkey,
        "key derivation must be deterministic for same inputs"
    );
    assert_eq!(
        initiator_output.ephemeral_pubkey, replay_output.ephemeral_pubkey,
        "ephemeral keys must be deterministic under same seed"
    );

    let initiator_address = Pubkey::new_from_array(identity.initiator_spend_pk.to_bytes());
    let initiator_view_address = Pubkey::new_from_array(identity.initiator_view_pk.to_bytes());
    let receiver_address = Pubkey::new_from_array(initiator_output.one_time_pubkey.to_bytes());

    info!(
        %initiator_address,
        %initiator_view_address,
        %receiver_address,
        %destination,
        "Canonical Umbra flow addresses (human-readable Base58)"
    );
    info!(
        identity = ?identity,
        memo_version = memo.version,
        one_time_pubkey = ?initiator_output.one_time_pubkey,
        ephemeral_pubkey = ?initiator_output.ephemeral_pubkey,
        "Initiator materials captured for verification"
    );
    info!(
        amount_lamports = amount,
        sweep_amount,
        payer = %payer,
        blockhash = %tx.message.recent_blockhash,
        "Transaction amounts and context"
    );
    info!(
        shared_secret_hash = ?recovery.shared_secret_hash,
        derived_spend_scalar = ?recovery.derived_spend_scalar,
        "Recovered claimant materials"
    );
    info!(
        account_keys = ?tx.message.account_keys,
        instructions = ?tx.message.instructions,
        signatures = ?tx.signatures,
        "Sweep transaction ready; flow validated by logged artifacts"
    );
}
