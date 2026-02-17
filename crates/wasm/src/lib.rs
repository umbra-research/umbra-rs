use wasm_bindgen::prelude::*;
use umbra_rs::core::{
    encrypt_memo as core_encrypt, decrypt_memo as core_decrypt,
    derive_for_initiator, Identity, PointWrapper, ScalarWrapper,
};


// We need a PRNG that works in WASM.
// Since we are in a WASM environment, we can use `getrandom` crate behavior
// (which delegates to browser crypto.getRandomValues via rand_core features usually)
// OR we can implement a simple wrapper around `js_sys::Math::random` or better `window.crypto`.
// 
// For `rand 0.8` (which uses `rand_core 0.6` and `getrandom`), enabling "js" feature on getrandom
// handles this automatically.
// In our root Cargo.toml, we have `rand_core` features = ["getrandom"].
// We need to ensure `getrandom` has "js" feature enabled if compiling for wasm32-unknown-unknown.
// Usually `getrandom` enables "js" automatically on wasm32-unknown-unknown if configured.

#[wasm_bindgen]
pub fn setup() {
    // Optional: Init logging/panic hook
    console_error_panic_hook::set_once();
}

#[derive(Serialize)]
#[allow(non_snake_case)]
pub struct WasmKeypair {
    pub spendPrivateKey: String, // hex encoded for UI display or storage
    pub viewPrivateKey: String,
    pub spendPublicKey: String,
    pub viewPublicKey: String,
    pub pubkey: String, // Full solana address string of spend_pk (simplified) or view?
                        // Actually Umbra Identity is NOT a simple Solana keypair. 
                        // It's (spend_sk, view_sk).
                        // Let's just return hex strings for keys.
}

#[wasm_bindgen]
pub struct UmbraIdentity {
    inner: Identity,
}

#[wasm_bindgen]
impl UmbraIdentity {
    /// Generate a new random Identity (Spend Key + View Key).
    pub fn generate() -> UmbraIdentity {
        let mut rng = rand::rngs::OsRng;
        let identity = Identity::new_random(&mut rng);
        UmbraIdentity { inner: identity }
    }

    /// Reconstruct from private key scalars (hex strings).
    pub fn from_secret_keys(spend_sk_hex: &str, view_sk_hex: &str) -> Result<UmbraIdentity, JsError> {
        let spend_bytes = hex_decode(spend_sk_hex)?;
        let view_bytes = hex_decode(view_sk_hex)?;
        
        let spend_sk = ScalarWrapper::from_bytes(spend_bytes);
        let view_sk = ScalarWrapper::from_bytes(view_bytes);

        // Recompute public keys
        // We need internal logic from Identity to rebuild PKs from SKs?
        // Identity::new_random does it. We should assume we can rebuild it.
        // But Identity struct fields are public in umbra-core.
        
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let spend_pk = PointWrapper(ED25519_BASEPOINT_POINT * spend_sk.0);
        let view_pk = PointWrapper(ED25519_BASEPOINT_POINT * view_sk.0);

        Ok(UmbraIdentity {
            inner: Identity {
                initiator_spend_sk: spend_sk,
                initiator_view_sk: view_sk,
                initiator_spend_pk: spend_pk,
                initiator_view_pk: view_pk,
            }
        })
    }

    pub fn to_json(&self) -> String {
        // Return JSON representation
        let spend_sk = hex::encode(self.inner.initiator_spend_sk.to_bytes());
        let view_sk = hex::encode(self.inner.initiator_view_sk.to_bytes());
        let spend_pk = hex::encode(self.inner.initiator_spend_pk.to_bytes()); // Compressed
        let view_pk = hex::encode(self.inner.initiator_view_pk.to_bytes());

        format!(
            r#"{{"spendSecret":"{}","viewSecret":"{}","spendPub":"{}","viewPub":"{}"}}"#,
            spend_sk, view_sk, spend_pk, view_pk
        )
    }
    
    pub fn get_public_keys(&self) -> JsValue {
         // Return object { spendPub: "hex", viewPub: "hex" }
         // For now just return string JSON is easiest
         JsValue::from_str(&self.to_json())
    }
}

// Helper
fn hex_decode(h: &str) -> Result<[u8; 32], JsError> {
    let v = hex::decode(h).map_err(|e| JsError::new(&e.to_string()))?;
    if v.len() != 32 {
        return Err(JsError::new("Invalid key length (expected 32 bytes)"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}

// Imports for serialization
use serde::{Serialize};
use sha2::{Sha256, Digest};


#[wasm_bindgen]
pub fn encrypt_memo_wasm(
    recipient_view_pubkey_hex: &str,
    recipient_spend_pubkey_hex: &str,
    memo: &str,
) -> Result<String, JsError> {
    
    // 1. Reconstruct Recipient Identity (PKs only)
    let view_pk_bytes = hex_decode(recipient_view_pubkey_hex)?;
    let spend_pk_bytes = hex_decode(recipient_spend_pubkey_hex)?;
    
    use curve25519_dalek::edwards::CompressedEdwardsY;
    
    let view_pt = CompressedEdwardsY(view_pk_bytes).decompress()
        .ok_or_else(|| JsError::new("Invalid view pubkey point"))?;
    let spend_pt = CompressedEdwardsY(spend_pk_bytes).decompress()
        .ok_or_else(|| JsError::new("Invalid spend pubkey point"))?;
        
    let dummy_sk = ScalarWrapper(curve25519_dalek::scalar::Scalar::ZERO); // Placeholder, we only need PKs here.
    
    let recipient_identity = Identity {
        initiator_spend_sk: dummy_sk.clone(),
        initiator_view_sk: dummy_sk,
        initiator_spend_pk: PointWrapper(spend_pt),
        initiator_view_pk: PointWrapper(view_pt),
    };
    
    // 2. Derive Ephemeral, Stealth Address, and Shared Secret
    let mut rng = rand::rngs::OsRng;
    let output = derive_for_initiator(&recipient_identity, &mut rng);
    
    // 3. Encrypt Memo
    let encrypted = core_encrypt(&mut rng, &output.shared_secret_hash, memo).map_err(|e| JsError::new(&e))?;
    
    // 4. Return JSON struct
    let ephemeral_pk_hex = hex::encode(output.ephemeral_pubkey.0.compress().to_bytes());
    let stealth_pk_hex = hex::encode(output.one_time_pubkey.0.compress().to_bytes());
    
    // Compute Hashed Tag used for scanning (H(SharedSecret))
    // We use the shared_secret_hash (Scalar) bytes as input
    let ss_bytes = output.shared_secret_hash.to_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&ss_bytes);
    let hashed_tag = hasher.finalize();
    let hashed_tag_hex = hex::encode(hashed_tag);

    Ok(format!(
        r#"{{"encryptedMemo":"{}","ephemeralPubkey":"{}","stealthPubkey":"{}","hashedTag":"{}"}}"#,
        encrypted, ephemeral_pk_hex, stealth_pk_hex, hashed_tag_hex
    ))
}

#[wasm_bindgen]
pub fn decrypt_memo_wasm(
    view_secret_key_hex: &str,
    ephemeral_pubkey_hex: &str,
    encrypted_memo: &str,
) -> Result<String, JsError> {
    // 1. Reconstruct View Secret
    let view_bytes = hex_decode(view_secret_key_hex)?;
    let view_sk = ScalarWrapper::from_bytes(view_bytes);
    
    // 2. Reconstruct Ephemeral Public
    let eph_bytes = hex_decode(ephemeral_pubkey_hex)?;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let eph_pt = CompressedEdwardsY(eph_bytes).decompress()
        .ok_or_else(|| JsError::new("Invalid ephemeral pubkey"))?;
    let eph_pk = PointWrapper(eph_pt);
        
    // 3. Derive Shared Secret (View-only)
    // We added this to core!
    use umbra_rs::core::derive_shared_secret_view_only;
    let shared_secret = derive_shared_secret_view_only(&eph_pk, &view_sk);
    
    // 4. Decrypt
    core_decrypt(&shared_secret, encrypted_memo).map_err(|e| JsError::new(&e))
}

#[wasm_bindgen]
pub fn recover_stealth_secret_wasm(
    view_secret_key_hex: &str,
    spend_secret_key_hex: &str,
    ephemeral_pubkey_hex: &str,
) -> Result<String, JsError> {
    // 1. Reconstruct Keys
    let view_bytes = hex_decode(view_secret_key_hex)?;
    let view_sk = ScalarWrapper::from_bytes(view_bytes);
    
    let spend_bytes = hex_decode(spend_secret_key_hex)?;
    let spend_sk = ScalarWrapper::from_bytes(spend_bytes);

    let eph_bytes = hex_decode(ephemeral_pubkey_hex)?;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let eph_pt = CompressedEdwardsY(eph_bytes).decompress()
        .ok_or_else(|| JsError::new("Invalid ephemeral pubkey"))?;
    let eph_pk = PointWrapper(eph_pt);

    // 2. Derive Stealth Secret
    use umbra_rs::core::derive_stealth_key;
    let stealth_sk = derive_stealth_key(&view_sk, &spend_sk, &eph_pk);
    
    // 3. Derive Public Key
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    let stealth_pk_point = ED25519_BASEPOINT_POINT * stealth_sk.0;
    let stealth_pk_bytes = stealth_pk_point.compress().to_bytes();
    
    let secret_hex = hex::encode(stealth_sk.to_bytes());
    let pub_hex = hex::encode(stealth_pk_bytes);

    // 4. Return JSON
    Ok(format!(r#"{{"secret":"{}","pubkey":"{}"}}"#, secret_hex, pub_hex))
}

#[wasm_bindgen]
pub fn sign_message_wasm(
    secret_key_hex: &str,
    message_hex: &str,
) -> Result<String, JsError> {
    // 1. Reconstruct Secret Key (Scalar)
    let sk_bytes = hex_decode(secret_key_hex)?;
    let sk_scalar = ScalarWrapper::from_bytes(sk_bytes);
    
    // 2. Derive Ed25519 Keypair from Scalar
    // Umbra uses Ristretto/Curve25519 scalars. 
    // Ed25519 signing expects a specific Keypair structure usually derived from a Seed or Expanded Secret.
    // The stealth key logic in `core` produces a Scalar.
    // We need to treat this Scalar as the secret key for Ed25519 signing.
    // Does the `ed25519-dalek` crate support signing with a raw scalar?
    // Usually `Keypair::from_bytes` takes 32 bytes (seed) or 64 bytes (expanded).
    // If our `stealth_sk` is a Scalar, it corresponds to the private key `d` in `P = d * B`.
    // Ed25519 standard `Keypair` usually stores the 32-byte SEED, from which `d` is derived via SHA512.
    // However, we are doing "stealth address" which computes `d` directly (Spend + Hash(Shared) * View).
    // So `d` IS the scalar.
    // We need to sign using this scalar directly.
    // `ed25519-dalek` has `SigningKey` (v2) or `Keypair` (v1).
    // We can construct a signer from the scalar bytes IF the library allows it.
    // `ed25519_dalek::SigningKey::from_bytes(bytes)` interprets bytes as the SEED usually.
    // BUT checking docs: "The private key is a 32-byte seed".
    // Wait. If we just pass the scalar bytes as the seed, then `d` will be `hash(scalar)`. That changes the private key!
    // We need to perform "Raw Ed25519 Signing" where we provide `a` (the scalar) directly.
    // Most high-level libraries (including `ed25519-dalek` default) enforce the standard (Seed -> Hash -> Scalar).
    // BUT `solana-sdk` uses `ed25519-dalek`. 
    // We might need to use `curve25519-dalek` (or internal logic) to sign manually if standard libraries enforce the seed model.
    // OR we use a library that supports "ExpandedSecretKey".
    // 
    // Let's check `umbra-rs::core`. It likely has signing utils?
    // If not, we implement simplified signing: R = rB, S = r + H(R, P, M) * a.
    // `ed25519-dalek` has `hazmat` feature or `ExpandedSecretKey`.
    
    // Let's assume standard `Keypair::from_bytes` works if our scalar IS the seed? 
    // No, that's not how stealth addresses work. Stealth address math operates on the scalar `a`.
    // `stealth_priv = spend_priv + hash(shared_secret)`. This is a scalar addition.
    // So `stealth_priv` is a scalar.
    // If we feed this scalar into `Keypair::from_bytes`, it will hash it again => wrong key.
    
    // We need: `ed25519_dalek::ExpandedSecretKey` (if using v1) or equivalent.
    // `umbra-rs` likely depends on `ed25519-dalek`.
    
    // Alternative: Use `solana_sdk::signature::Keypair::from_bytes`? 
    // No, Solana Keypair also assumes Seed.
    
    // WE NEED Manual Signing using the Scalar.
    // This is often called "signing with a private scalar".
    // I will use `ed25519_dalek::SigningKey` but I need to be careful.
    // Re-check `crates/core` to see if we already solved this. 
    // If not, I will use `curve25519-dalek` directly to implement `sign`.
    // Or I check if `ed25519_dalek` was compiled with `features = ["batch", "fast", "serde"]` etc.
    
    // Let's defer to a helper likely in `umbra-rs::core`? 
    // I'll check `umbra-rs/src/core/mod.rs` or `encryption.rs`.
    // If not found, I will implement it here using `ed25519-dalek` if possible or manually.
    
    // For now, I'll attempt to use `ed25519_dalek::SigningKey::from_scalar_bytes` (if it exists) or `ExpandedSecretKey`.
    
    // Checking dependency `cargo.toml` for `ed25519-dalek`.
    
    // Let's look for `umbra_rs::core::sign` first?
    // I'll assume I need to implement it.
    
    // Implementation of Ed25519 Sign with Scalar `sk`:
    // 1. We need a nonce `r`. Standard: `r = hash(hash(seed)_prefix || message)`.
    // But we don't have a seed. We have `sk`.
    // We can generate random `r` (Ed25519-ph?) or deterministic `r` from `hash(sk || message)`.
    // Let's use random `r` for safety if we can't reproduce the standard nonce derivation.
    // But Ed25519 is deterministic.
    // We can use `Sha512(sk_bytes || message)` as source for `r`?
    
    // Actually, `ed25519-dalek` has `SecretKey` type which IS the seed.
    // It has `ExpandedSecretKey` which is `(scalar, prefix)`.
    // If we construct `ExpandedSecretKey` with `(stealth_sk, dummy_prefix)`...
    // The prefix is used for nonce generation.
    // Does the prefix matter for validity?
    // Verification checks `GS == R + H(R,A,M)A`. Nothing to do with prefix.
    // So ANY nonce `r` is valid as long as we don't reuse it for different messages (leaks key).
    // So `ExpandedSecretKey` with a pseudo-random prefix (or hash of scalar) works.
    
    // I'll try to find `sign_with_scalar` helper or implement it.
    // Since I can't browse crates.io, I will implement a basic `sign_with_scalar` function here using `curve25519-dalek`.
    
    // IMPORTANT: Message can be any length, not fixed 32 bytes!
    // Withdrawal message is 80 bytes: stealth_pk(32) + recipient(32) + amount(8) + fee(8)
    let message_bytes = hex::decode(message_hex)
        .map_err(|e| JsError::new(&format!("Invalid message hex: {}", e)))?;
    
    // Using umbra-rs core helper if available? 
    // Let's try to verify if `umbra-rs` has signing.
    // If not, I'll add a minimal signer here.
    
    // Minimal Ed25519 Signer (using curve25519-dalek constants):
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Sha512, Digest};
    
    let a_scalar = sk_scalar.0;
    let pubkey_point = ED25519_BASEPOINT_POINT * a_scalar;
    let pubkey_bytes = pubkey_point.compress().to_bytes();
    
    // Nonce `r`: Deterministic usually.
    // Let's use Sha512(sk_bytes || h(message))? 
    // Or just `Sha512(sk_bytes || message)`.
    let mut h = Sha512::new();
    h.update(&sk_bytes);
    h.update(&message_bytes);
    let r_bytes = h.finalize(); // 64 bytes
    
    // Reduce r to scalar
    let r_scalar = Scalar::from_bytes_mod_order_wide(&r_bytes.into());
    let R_point = ED25519_BASEPOINT_POINT * r_scalar;
    let R_bytes = R_point.compress().to_bytes();
    
    // Checksum H(R || A || M)
    let mut h_ram = Sha512::new();
    h_ram.update(&R_bytes);
    h_ram.update(&pubkey_bytes);
    h_ram.update(&message_bytes);
    let k_bytes = h_ram.finalize();
    let k_scalar = Scalar::from_bytes_mod_order_wide(&k_bytes.into());
    
    // S = r + k * a
    let S_scalar = r_scalar + (k_scalar * a_scalar);
    let S_bytes = S_scalar.to_bytes();
    
    // Signature = R || S
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&R_bytes);
    sig_bytes[32..].copy_from_slice(&S_bytes);
    
    Ok(hex::encode(sig_bytes))
}
