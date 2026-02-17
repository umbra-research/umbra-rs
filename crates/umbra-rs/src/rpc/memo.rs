use thiserror::Error;
use crate::core::PointWrapper;

use crate::rpc::types::UmbraMemo;

/// 4-byte prefix used to identify Umbra memos.
///
/// Public part of the protocol specification.
/// Do not change without a migration plan.
pub const UMBRA_MEMO_MAGIC: &[u8; 4] = b"UMBR";

/// Umbra memo format version.
///
/// Placed immediately after the magic header.
pub const UMBRA_MEMO_VERSION: u8 = 1;

/// Errors that may occur while decoding Umbra memo payloads.
#[derive(Debug, Error)]
pub enum MemoDecodeError {
    #[error("memo too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("invalid magic header: not an Umbra memo")]
    InvalidMagic,

    #[error("unsupported memo version: {0}")]
    UnsupportedVersion(u8),

    #[error("ephemeral pubkey bytes are invalid")]
    InvalidEphemeralPubkey,
}

use base64::{Engine as _, engine::general_purpose};

/// Decode raw memo bytes (Base64 encoded) into an `UmbraMemo`.
///
/// Expected layout (version 1) AFTER Base64 decoding:
///
/// +------------+---------+--------------------------+
/// | 0..4       | 4       | 5..37                    |
/// +------------+---------+--------------------------+
/// | magic      | version | R (32 bytes)             |
/// +------------+---------+--------------------------+
///
pub fn parse_umbra_memo(raw_utf8: &[u8]) -> Result<UmbraMemo, MemoDecodeError> {
    // 1. Decode Base64 first
    let decoded = general_purpose::STANDARD
        .decode(raw_utf8)
        .map_err(|_| MemoDecodeError::InvalidMagic)?; // Generic error or add new one

    const HEADER: usize = 4 + 1; // magic + version
    const R_LEN: usize = 32;
    const MIN: usize = HEADER + R_LEN;

    if decoded.len() < MIN {
        return Err(MemoDecodeError::TooShort {
            expected: MIN,
            actual: decoded.len(),
        });
    }

    let (magic, rest) = decoded.split_at(4);
    if magic != UMBRA_MEMO_MAGIC {
        return Err(MemoDecodeError::InvalidMagic);
    }

    let (&version, rest) = rest.split_first().unwrap(); // length guaranteed

    if version != UMBRA_MEMO_VERSION {
        return Err(MemoDecodeError::UnsupportedVersion(version));
    }

    let (r_bytes, _) = rest.split_at(R_LEN);

    let mut arr = [0u8; 32];
    arr.copy_from_slice(r_bytes);

    let r = PointWrapper::from_bytes(arr).ok_or(MemoDecodeError::InvalidEphemeralPubkey)?;

    Ok(UmbraMemo {
        version,
        ephemeral_pubkey: r,
    })
}

/// Encode an Umbra memo according to the official protocol specification.
///
/// Layout (version 1) BEFORE Base64 encoding:
/// +------------+---------+--------------------------+
/// | magic (4)  | v (1)   | R (32 bytes)             |
/// +------------+---------+--------------------------+
///
/// The result is a Base64 encoded UTF-8 string bytes.
pub fn build_umbra_memo(ephemeral_y: &[u8; 32]) -> Vec<u8> {
    const HEADER_LEN: usize = 4 + 1;
    const R_LEN: usize = 32;

    let mut buf = Vec::with_capacity(HEADER_LEN + R_LEN);

    // 1) Magic
    buf.extend_from_slice(UMBRA_MEMO_MAGIC);

    // 2) Version
    buf.push(UMBRA_MEMO_VERSION);

    // 3) Ephemeral pubkey (compressed Y)
    buf.extend_from_slice(ephemeral_y);

    // 4) Base64 Encode
    general_purpose::STANDARD.encode(buf).into_bytes()
}
