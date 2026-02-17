//! Umbra RPC utilities for scanning and decoding Umbra outputs on Solana.
//!
//! This crate is intentionally "view-only":
//! - It does NOT perform RPC calls.
//! - It only parses UiTransaction structures already retrieved by the user.
//!
//! Responsibilities:
//! - Parse Umbra memo payloads.
//! - Extract candidate Umbra outputs (R, P, amount, signature, slot).
//!
//! Higher layers can:
//! - feed in UiTransactions,
//! - match candidates to Umbra identities (umbra-core),
//! - sweep funds if ownership is proven.

pub mod memo;
pub mod ownership;
pub mod scanner;
pub mod slot_scanner;
pub mod slot_scanner_ui;
pub mod types;

pub use memo::{parse_umbra_memo, MemoDecodeError};
pub use scanner::{extract_candidate_from_ui_transaction, ScannerError};
pub use slot_scanner::{scan_slot_for_candidates, SlotScanError};
pub use slot_scanner_ui::{fetch_ui_transactions_for_slot_range, SlotTransaction};
pub use types::{CandidateOutput, UmbraMemo};
