//!
//! This crate provides the **unified public interface** for the entire Umbra protocol.
//! Application developers should depend **only on this `umbra` crate**, which aggregates:
//!
//! - `umbra-core`   — key material, cryptographic primitives, initiator/claimant flow  
//! - `umbra-rpc`    — on-chain scanning, memo decoding, slot-range scanners  
//! - `umbra-sweep`  — SOL sweeping & scalar-based signer  
//! - `umbra-client` — high-level end-to-end Umbra SDK  
//!
//! The goal: provide a **stable, clean API surface** while allowing internal crates
//! to evolve independently. All public types and functions flow through this facade.
//!
//! ---

// -----------------------------------------------------------------------------
// These give users access to all protocol components via a single dependency:
// `use umbra::umbra_client::UmbraClient`
// `use umbra::umbra_core::Identity`
// etc.

pub mod umbra_client {
    pub use ::umbra_client::*;
}

pub mod umbra_core {
    pub use ::umbra_core::*;
}

pub mod umbra_rpc {
    pub use ::umbra_rpc::*;
}

pub mod umbra_sweep {
    pub use ::umbra_sweep::*;
}

pub mod umbra_api {
    pub use ::umbra_api::*;
}

pub mod umbra_storage {
    pub use ::umbra_storage::*;
}

pub use umbra_api::*;
pub use umbra_client::*;
pub use umbra_core::*;
pub use umbra_rpc::*;
pub use umbra_storage::*;
pub use umbra_sweep::*;

// -----------------------------------------------------------------------------
// Version Macro
// -----------------------------------------------------------------------------

/// Returns `"Umbra vX.Y.Z"` using this crate's package version.
///
/// Useful for logging, telemetry, analytics, RPC metadata, or client banners.
///
/// # Example
/// ```
/// println!("{}", umbra::umbra_version!());
/// ```
#[macro_export]
macro_rules! umbra_version {
    () => {
        concat!("Umbra v", env!("CARGO_PKG_VERSION"))
    };
}
