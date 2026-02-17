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
