pub mod core;

#[cfg(feature = "full")]
pub mod client;
#[cfg(feature = "full")]
pub mod api;
#[cfg(feature = "full")]
pub mod rpc;
#[cfg(feature = "full")]
pub mod storage;
#[cfg(feature = "full")]
pub mod sweep;

// Local program definitions to avoid dependency conflicts
#[cfg(feature = "full")]
pub mod program;
