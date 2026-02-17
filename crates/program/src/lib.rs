pub mod error;
pub mod instruction;
pub mod processor;

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, pubkey::Pubkey,
};

use processor::Processor;

solana_program::declare_id!("2L2TivMpeKJotzaHuQPUHDgfKaPwrvL5uGuhRw6dju96");

// Declare the entrypoint
entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    Processor::process(program_id, accounts, instruction_data)
}
