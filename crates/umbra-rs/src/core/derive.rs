use crate::core::{Identity, PointWrapper, ScalarWrapper};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

const SHARED_SECRET_DOMAIN: &[u8] = b"umbra.v0.shared_secret";

fn hash_to_scalar(domain: &[u8], input: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(input);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest[..32]);
    Scalar::from_bytes_mod_order(bytes)
}
#[derive(Clone, Debug)]
pub struct InitiatorOutput {
    pub one_time_pubkey: PointWrapper,
    pub ephemeral_pubkey: PointWrapper,
    pub shared_secret_hash: ScalarWrapper,
}

#[derive(Clone, Debug)]
pub struct ClaimantRecovery {
    /// H(S') domain-separated
    pub shared_secret_hash: ScalarWrapper,
    /// a + H(S')
    pub derived_spend_scalar: ScalarWrapper,
}

impl Zeroize for ClaimantRecovery {
    fn zeroize(&mut self) {
        self.shared_secret_hash.zeroize();
        self.derived_spend_scalar.zeroize();
    }
}

impl Drop for ClaimantRecovery {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Initiator generates output (one-time address)
pub fn derive_for_initiator<R: RngCore + CryptoRng>(
    identity: &Identity,
    rng: &mut R,
) -> InitiatorOutput {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    let ephemeral_scalar = Scalar::from_bytes_mod_order_wide(&bytes);
    
    let ephemeral_pubkey = ED25519_BASEPOINT_POINT * ephemeral_scalar;

    let shared_secret_point = identity.initiator_view_pk.0 * ephemeral_scalar;
    let shared_secret_bytes = shared_secret_point.compress().to_bytes();

    let shared_secret_hash = hash_to_scalar(SHARED_SECRET_DOMAIN, &shared_secret_bytes);

    let one_time_pubkey =
        identity.initiator_spend_pk.0 + (ED25519_BASEPOINT_POINT * shared_secret_hash);

    InitiatorOutput {
        one_time_pubkey: PointWrapper(one_time_pubkey),
        ephemeral_pubkey: PointWrapper(ephemeral_pubkey),
        shared_secret_hash: ScalarWrapper(shared_secret_hash),
    }
}

/// Claimant scans & recovers spend authority
pub fn derive_for_claimant(
    identity: &Identity,
    one_time_pubkey: &PointWrapper,
    ephemeral_pubkey: &PointWrapper,
) -> Option<ClaimantRecovery> {
    let recovered_shared_point = ephemeral_pubkey.0 * identity.initiator_view_sk.0;
    let recovered_shared_bytes = recovered_shared_point.compress().to_bytes();

    let recovered_shared_hash = hash_to_scalar(SHARED_SECRET_DOMAIN, &recovered_shared_bytes);

    let reconstructed_pubkey =
        identity.initiator_spend_pk.0 + (ED25519_BASEPOINT_POINT * recovered_shared_hash);

    if reconstructed_pubkey == one_time_pubkey.0 {
        let derived_scalar = identity.initiator_spend_sk.0 + recovered_shared_hash;
        Some(ClaimantRecovery {
            shared_secret_hash: ScalarWrapper(recovered_shared_hash),
            derived_spend_scalar: ScalarWrapper(derived_scalar),
        })
    } else {
        None
    }
}

/// Derives the shared secret hash from the ephemeral public key and view secret key.
/// Useful for view-only wallets or when the stealth address is not verified (e.g. simple memo decryption).
pub fn derive_shared_secret_view_only(
    ephemeral_pubkey: &PointWrapper,
    view_secret_key: &ScalarWrapper,
) -> ScalarWrapper {
    let recovered_shared_point = ephemeral_pubkey.0 * view_secret_key.0;
    let recovered_shared_bytes = recovered_shared_point.compress().to_bytes();

    let recovered_shared_hash = hash_to_scalar(SHARED_SECRET_DOMAIN, &recovered_shared_bytes);
    ScalarWrapper(recovered_shared_hash)
}

/// Derives the stealth private key from view secret, spend secret, and ephemeral public key.
/// This is used to sign withdrawal requests.
pub fn derive_stealth_key(
    view_secret_key: &ScalarWrapper,
    spend_secret_key: &ScalarWrapper,
    ephemeral_pubkey: &PointWrapper,
) -> ScalarWrapper {
    let recovered_shared_point = ephemeral_pubkey.0 * view_secret_key.0;
    let recovered_shared_bytes = recovered_shared_point.compress().to_bytes();

    let recovered_shared_hash = hash_to_scalar(SHARED_SECRET_DOMAIN, &recovered_shared_bytes);
    
    // stealth_priv = spend_priv + H(shared_secret)
    ScalarWrapper(spend_secret_key.0 + recovered_shared_hash)
}
