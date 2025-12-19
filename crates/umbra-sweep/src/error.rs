use thiserror::Error;

#[derive(Debug, Error)]
pub enum SweepSolError {
    #[error("sweep amount cannot be zero")]
    ZeroAmount,

    #[error("failed to sign transaction")]
    SigningFailed,

    #[error("failed to build SOL sweep transaction")]
    BuildFailed,
}
