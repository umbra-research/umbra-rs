use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar};
use sha2::{Digest, Sha512};
use solana_sdk::{pubkey::Pubkey, signature::Signature};

use crate::core::ScalarWrapper;

/// Allows deriving an Ed25519 keypair deterministically from a scalar.
/// Used to sign sweep transactions in Umbra.
#[derive(Clone, Debug)]
pub struct ScalarSigner {
    secret: Scalar,
    public: EdwardsPoint,
}

impl ScalarSigner {
    pub fn new(wrapper: ScalarWrapper) -> Self {
        let secret = wrapper.0;
        let public = &secret * &ED25519_BASEPOINT_POINT;
        Self { secret, public }
    }

    pub fn pubkey(&self) -> Pubkey {
        let bytes = self.public.compress().to_bytes();
        Pubkey::new_from_array(bytes)
    }

    /// Ed25519 signature using RFC8032-style hashing.
    /// Compatible with Solana's ed25519 verification.
    pub fn sign_message(&self, msg: &[u8]) -> Signature {
        let mut h = Sha512::new();
        h.update(msg);
        let r = Scalar::from_hash(h);

        let r_point = &r * &ED25519_BASEPOINT_POINT;
        let r_comp = r_point.compress().to_bytes();

        let mut h2 = Sha512::new();
        h2.update(&r_comp);
        h2.update(&self.public.compress().to_bytes());
        h2.update(msg);

        let k = Scalar::from_hash(h2);

        let s = r + k * self.secret;

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r_comp);
        sig_bytes[32..].copy_from_slice(&s.to_bytes());

        Signature::from(sig_bytes)
    }
}
