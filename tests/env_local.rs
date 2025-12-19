// Entry point for all local environment tests.
// This pulls in the `local` module tree from `tests/local/mod.rs`.

// mod local;

use curve25519_dalek::edwards::CompressedEdwardsY;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};
use solana_sdk::{hash::Hash, message::MessageHeader, pubkey::Pubkey};
use solana_transaction_status::{UiCompiledInstruction, UiMessage, UiRawMessage, UiTransaction};
use umbra::{
    build_and_sign_sweep_sol_transaction, derive::derive_for_initiator,
    extract_candidate_from_ui_transaction, planner::build_sweep_plan, Identity, SweepSolParams,
};
use umbra_rpc::memo::build_umbra_memo;
use umbra_rpc::ownership::{
    match_candidate_output, scan_ui_transactions_for_owned_outputs, ClaimantKeyMaterial,
};

const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const SYSTEM_TRANSFER_DISCRIMINANT: u32 = 2;
const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

use tracing::info;

#[test]
fn full_local_end_to_end_flow() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Emulates a real user flow: initiator emits a claimant output plus a decoy (plus a bad memo and plain transfer),
    // claimant scans the ledger, matches the owned output, plans and builds the sweep transaction, and verifies no re-plan after claiming.
    // 1) Deterministic identities for initiator/claimant + a decoy identity.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    info!("Generating identities with rng seed 42 {:?}", rng);

    let claimant_identity = Identity::new_random(&mut rng);
    // info!("Claimant identity: {:?}", claimant_identity);
    let foreign_identity = Identity::new_random(&mut rng);
    // info!("Foreign identity: {:?}", foreign_identity);

    let sweep_destination = Pubkey::new_unique();
    info!("Sweep destination: {:?}", sweep_destination);
    let payer = Pubkey::new_unique();
    info!("Payer: {:?}", payer);

    // 2) Initiator side: produce Umbra outputs for claimant and for a decoy.
    let (owned_tx, owned_p) =
        build_umbra_transaction(&mut rng, &claimant_identity, payer, "owned_sig", 2_500_000);

    info!("TX built for claimant {:?}", owned_tx);

    info!(
        "Owned transaction built with one-time pubkey: {:?}",
        owned_p
    );

    let (foreign_tx, _) =
        build_umbra_transaction(&mut rng, &foreign_identity, payer, "foreign_sig", 1_111_000);

    info!("Foreign transaction built.");
    info!("Owned Tx: {:?}", owned_tx);

    // Corrupted memo (unsupported version) to validate rejection/safety.
    let mut bad_memo = build_umbra_memo(
        &derive_for_initiator(&claimant_identity, &mut rng)
            .ephemeral_pubkey
            .to_bytes(),
    );
    bad_memo[4] = 99; // unsupported version
    let bad_tx = build_transaction(
        payer,
        Pubkey::new_unique(),
        "bad_sig",
        500_000,
        Some(bad_memo),
    );

    // Non-Umbra transfer (no memo)
    let plain_tx = build_transaction(payer, Pubkey::new_unique(), "plain_sig", 750_000, None);
    info!("Plain transaction built. {:?}", plain_tx);

    // 3) Publish in mocked ledger (Vec of UiTransactions with slots + signatures).
    let ledger = vec![
        (10_u64, "owned_sig".to_string(), owned_tx),
        (11_u64, "foreign_sig".to_string(), foreign_tx),
        (12_u64, "bad_sig".to_string(), bad_tx),
        (13_u64, "plain_sig".to_string(), plain_tx),
    ];

    // Quick sanity: owned transaction must round-trip through scanner + matcher.
    let candidate = extract_candidate_from_ui_transaction(10, "owned_sig".into(), &ledger[0].2)
        .expect("candidate extraction should not error")
        .expect("Umbra memo must produce candidate");

    info!("Candidate extracted: {:?}", candidate);

    assert_eq!(candidate.memo.version, 1);
    assert_eq!(
        candidate.recipient, owned_p,
        "candidate recipient should match derived P"
    );
    assert_eq!(candidate.amount, 2_500_000);

    let recipient_point = CompressedEdwardsY(candidate.recipient.to_bytes())
        .decompress()
        .expect("recipient pubkey must decompress");

    info!("Recipient point decompressed: {:?}", recipient_point);

    assert!(
        umbra::derive::derive_for_claimant(
            &claimant_identity,
            &umbra::PointWrapper(recipient_point),
            &candidate.memo.ephemeral_pubkey
        )
        .is_some(),
        "direct derivation should match before RPC-like path"
    );

    let owned_match = match_candidate_output(
        &candidate,
        &ClaimantKeyMaterial::from_identity(&claimant_identity),
    )
    .expect("matching should not error");
    info!("Owned match: {:?}", owned_match);
    assert!(
        owned_match.is_some(),
        "ownership check should succeed for claimant"
    );

    // 4) Claimant scans ledger for owned outputs.
    let claimant_keys = ClaimantKeyMaterial::from_identity(&claimant_identity);
    let (owned_outputs, scan_issues) = scan_ui_transactions_for_owned_outputs(
        &claimant_keys,
        ledger
            .iter()
            .map(|(slot, sig, tx)| (*slot, sig.clone(), tx)),
    );

    assert_eq!(owned_outputs.len(), 1, "only claimant-owned output is kept");
    assert_eq!(
        owned_outputs[0].one_time_pubkey, owned_p,
        "derived recipient must match expected one-time key"
    );
    assert_eq!(owned_outputs[0].amount, 2_500_000);
    assert_eq!(
        owned_outputs[0].memo.version, 1,
        "accepted memo version should be forwarded"
    );

    assert_eq!(
        scan_issues.len(),
        1,
        "unsupported memo version should be recorded as issue"
    );

    assert!(
        scan_issues[0].error.contains("unsupported memo version"),
        "issue should reflect bad memo handling"
    );

    // 5) Planner derives spend authority and sweep plan.
    let (plans, plan_issues) =
        build_sweep_plan(&owned_outputs, &claimant_identity, sweep_destination);

    info!("Sweep plans built: {:?}", plans);
    assert!(
        plan_issues.is_empty(),
        "derivation and decompression must succeed"
    );
    assert_eq!(plans.len(), 1, "exactly one sweep plan is produced");

    let plan = &plans[0];
    assert_eq!(plan.one_time_pubkey, owned_p);
    assert_eq!(plan.destination, sweep_destination);
    assert_eq!(plan.amount, 2_500_000);

    // 6) Build sweep transaction (claim) with derived signer.
    let sweep_tx = build_and_sign_sweep_sol_transaction(&SweepSolParams {
        signer: &plan.signer,
        to: plan.destination,
        amount: plan.amount,
        recent_blockhash: Hash::new_unique(),
    })
    .expect("sweep transaction must build");

    info!("Sweep transaction built: {:?}", sweep_tx);

    assert_eq!(sweep_tx.signatures.len(), 1);
    assert_eq!(sweep_tx.message.account_keys.len(), 3);

    // 7) Post-claim: mark as claimed and ensure no double-claim on restart.
    let mut pending = owned_outputs.clone();
    pending.retain(|out| out.signature != "owned_sig");
    let (post_claim_plans, post_claim_issues) =
        build_sweep_plan(&pending, &claimant_identity, sweep_destination);
    assert!(post_claim_issues.is_empty());
    assert!(
        post_claim_plans.is_empty(),
        "claimed outputs must not be re-planned"
    );

    // 8) Persistence safety: reload persisted outputs should reproduce same plan.
    let (replayed_plans, replayed_issues) =
        build_sweep_plan(&owned_outputs, &claimant_identity, sweep_destination);
    assert!(replayed_issues.is_empty());
    assert_eq!(replayed_plans.len(), 1);
}

fn build_umbra_transaction<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient_identity: &Identity,
    payer: Pubkey,
    signature: &str,
    amount: u64,
) -> (UiTransaction, Pubkey) {
    let initiator_output = derive_for_initiator(recipient_identity, rng);
    let memo_bytes = build_umbra_memo(&initiator_output.ephemeral_pubkey.to_bytes());
    let recipient_pk = Pubkey::new_from_array(initiator_output.one_time_pubkey.to_bytes());

    (
        build_transaction(payer, recipient_pk, signature, amount, Some(memo_bytes)),
        recipient_pk,
    )
}

fn build_transaction(
    payer: Pubkey,
    recipient: Pubkey,
    signature: &str,
    amount: u64,
    memo_bytes: Option<Vec<u8>>,
) -> UiTransaction {
    let account_keys = vec![
        payer.to_string(),
        recipient.to_string(),
        SYSTEM_PROGRAM_ID.to_string(),
        MEMO_PROGRAM_ID.to_string(),
    ];

    let mut instructions = Vec::new();

    if let Some(bytes) = memo_bytes {
        instructions.push(UiCompiledInstruction {
            program_id_index: 3,
            accounts: vec![0],
            data: bs58::encode(bytes).into_string(),
            stack_height: None,
        });
    }

    instructions.push(UiCompiledInstruction {
        program_id_index: 2,
        accounts: vec![0, 1],
        data: bs58::encode(system_transfer_bytes(amount)).into_string(),
        stack_height: None,
    });

    let raw = UiRawMessage {
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        },
        account_keys,
        recent_blockhash: Hash::new_unique().to_string(),
        instructions,
        address_table_lookups: None,
    };

    UiTransaction {
        signatures: vec![signature.to_string()],
        message: UiMessage::Raw(raw),
    }
}

fn system_transfer_bytes(amount: u64) -> [u8; 12] {
    let mut data = [0u8; 12];
    data[..4].copy_from_slice(&SYSTEM_TRANSFER_DISCRIMINANT.to_le_bytes());
    data[4..].copy_from_slice(&amount.to_le_bytes());
    data
}
