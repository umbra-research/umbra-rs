use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::{CryptoRng, RngCore};
use crate::core::ScalarWrapper;
use sha2::{Digest, Sha256};

/// Encrypts a memo string using a key derived from the Shared Secret.
///
/// Output Format: [Nonce (12B) || Ciphertext (N) || Tag (16B)] (Base64 Encoded)
pub fn encrypt_memo<R: RngCore + CryptoRng>(
    rng: &mut R,
    shared_secret: &ScalarWrapper,
    memo: &str,
) -> Result<String, String> {
    // 1. Derive Encryption Key: Sha256(shared_secret || "memo")
    let key = derive_key(shared_secret);
    let cipher = ChaCha20Poly1305::new(&key);

    // 2. Generate Random Nonce (96-bit)
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 3. Encrypt
    let ciphertext = cipher
        .encrypt(nonce, Payload {
            msg: memo.as_bytes(),
            aad: &[],
        })
        .map_err(|e| format!("Encryption failure: {}", e))?;

    // 4. Pack: Nonce + Ciphertext (Tag is included in ciphertext by crate usually? 
    // Wait, ChaCha20Poly1305 crate `encrypt` returns Vec<u8> containing ciphertext + tag appended.
    // So we just need to prepend Nonce.
    
    let mut packed = Vec::with_capacity(12 + ciphertext.len());
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ciphertext);

    // 5. Hex Encode (consistent with decrypt_memo and backend storage)
    Ok(hex::encode(packed))
}

/// Decrypts a memo string using the Shared Secret.
/// Input is hex-encoded: [Nonce (12B) || Ciphertext (N) || Tag (16B)]
pub fn decrypt_memo(
    shared_secret: &ScalarWrapper,
    encrypted_memo_hex: &str,
) -> Result<String, String> {
    // 1. Decode Hex
    let packed = hex::decode(encrypted_memo_hex)
        .map_err(|e| format!("Hex decode error: {}", e))?;

    if packed.len() < 12 + 16 { // Nonce + Tag minimum
        return Err("Ciphertext too short".to_string());
    }

    // 2. Extract Nonce
    let (nonce_bytes, ciphertext_with_tag) = packed.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // 3. Derive Key
    let key = derive_key(shared_secret);
    let cipher = ChaCha20Poly1305::new(&key);

    // 4. Decrypt
    let plaintext_bytes = cipher
        .decrypt(nonce, Payload {
            msg: ciphertext_with_tag,
            aad: &[],
        })
        .map_err(|e| format!("Decryption failure (mac mismatch?): {}", e))?;

    // 5. UTF-8 Decode
    String::from_utf8(plaintext_bytes).map_err(|e| format!("Invalid UTF-8: {}", e))
}

fn derive_key(shared_secret: &ScalarWrapper) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.0.as_bytes());
    hasher.update(b"umbra.v0.memo_key");
    let result = hasher.finalize();
    *Key::from_slice(&result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn test_memo_encryption_roundtrip() {
        let mut rng = OsRng;
        let shared_secret = ScalarWrapper::random(&mut rng);
        let memo = "Meeting at midnight under the bridge. 🌑";

        // Encrypt
        let encrypted = encrypt_memo(&mut rng, &shared_secret, memo).expect("Encrypt failed");
        
        // Decrypt
        let decrypted = decrypt_memo(&shared_secret, &encrypted).expect("Decrypt failed");

        assert_eq!(memo, decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut rng = OsRng;
        let shared_secret = ScalarWrapper::random(&mut rng);
        let wrong_secret = ScalarWrapper::random(&mut rng);
        let memo = "Top Secret";

        let encrypted = encrypt_memo(&mut rng, &shared_secret, memo).unwrap();
        
        // Try decrypt with wrong key
        let result = decrypt_memo(&wrong_secret, &encrypted);
        assert!(result.is_err());
    }
}
