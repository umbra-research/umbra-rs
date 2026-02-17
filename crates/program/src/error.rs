use solana_program::program_error::ProgramError;
use thiserror::Error;

#[derive(Error, Debug, Copy, Clone)]
pub enum UmbraError {
    #[error("Invalid Instruction")]
    InvalidInstruction,
    #[error("Incorrect Program ID")]
    IncorrectProgramId,
    #[error("Insufficient Funds")]
    InsufficientFunds,
    #[error("Invalid Authority")]
    InvalidAuthority,
}

impl From<UmbraError> for ProgramError {
    fn from(e: UmbraError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
