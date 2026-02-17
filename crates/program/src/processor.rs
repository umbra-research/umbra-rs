use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
    sysvar::instructions,
    log::sol_log_data,
};
use borsh::BorshSerialize;

use crate::{instruction::{Announcement, UmbraInstruction}, error::UmbraError};

pub struct Processor;

impl Processor {
    pub fn process(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let instruction = borsh::from_slice::<UmbraInstruction>(instruction_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        match instruction {
            UmbraInstruction::SendStealth { amount, announcement } => {
                Self::process_send_stealth(program_id, accounts, amount, announcement)
            }
            UmbraInstruction::SendStealthSpl { amount, announcement } => {
                Self::process_send_stealth_spl(program_id, accounts, amount, announcement)
            }
            UmbraInstruction::Withdraw => {
                Self::process_withdraw(program_id, accounts)
            }
            UmbraInstruction::WithdrawWithRelayer { fee } => {
                Self::process_withdraw_with_relayer(program_id, accounts, fee)
            }
        }
    }

    fn process_send_stealth(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        amount: u64,
        announcement: Announcement,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let sender = next_account_info(account_info_iter)?;
        let stealth_pda = next_account_info(account_info_iter)?;
        let stealth_pubkey = next_account_info(account_info_iter)?;
        let system_program = next_account_info(account_info_iter)?;

        if !sender.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Verify seeds
        let (pda, bump) = Pubkey::find_program_address(
            &[b"stealth", stealth_pubkey.key.as_ref()],
            program_id,
        );

        if pda != *stealth_pda.key {
             return Err(ProgramError::InvalidSeeds);
        }

        // Create PDA if not exists (transfer to it automatically creates it, but we want to assign it?)
        // Actually, just transferring to it is enough to make it exist with lamports.
        // But if we want it to be "owned" by the program to control withdrawal, we MUST assign it or create it.
        // System Program Transfer -> Address. account owner is System Program logic?
        // No, to control withdrawal we must be the owner.
        // So we must `system_instruction::create_account` or `assign`.
        // Since we are using a simplified flow:
        // 1. Transfer Lamports.
        // 2. If valid PDA, we can sign for it later?
        // Wait, only the owner can decrement lamports (except for cleanup).
        // If system program owns it, ANYONE with the private key can spend it.
        // But the PDA has NO private key.
        // So only the Program (if it owns it) or System Program (if seed derived??)
        // PDAs can only be signed for by the Program.
        // If the account has no data and is owned by System Program, only System Program can sign?
        // BUT System Program allows "signing checks" via seeds? No.
        // We MUST Create the account and assign it to our Program ID so WE can debit it later.
        
        // However, Anchor `init` does `create_account`.
        // We should do the same.
        // But we can't create_account if we don't have signer privileges for it?
        // We do via invoke_signed.
        
        if stealth_pda.data_is_empty() {
             invoke_signed(
                &system_instruction::create_account(
                    sender.key,
                    stealth_pda.key,
                    amount, // Initial Rent/Balance
                    0, // Space (no data needed)
                    program_id, // Owner
                ),
                &[sender.clone(), stealth_pda.clone(), system_program.clone()],
                &[&[b"stealth", stealth_pubkey.key.as_ref(), &[bump]]],
            )?;
        } else {
             // Just transfer
             invoke(
                &system_instruction::transfer(sender.key, stealth_pda.key, amount),
                &[sender.clone(), stealth_pda.clone(), system_program.clone()],
            )?;
        }
        
        Self::emit_announcement(announcement, None);
        Ok(())
    }

    fn process_send_stealth_spl(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        amount: u64,
        announcement: Announcement,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let sender = next_account_info(account_info_iter)?;
        let mint = next_account_info(account_info_iter)?;
        let sender_token = next_account_info(account_info_iter)?;
        let stealth_pda = next_account_info(account_info_iter)?;
        let stealth_token = next_account_info(account_info_iter)?;
        let stealth_pubkey = next_account_info(account_info_iter)?;
        let system_program = next_account_info(account_info_iter)?;
        let token_program = next_account_info(account_info_iter)?;

        if !sender.is_signer { return Err(ProgramError::MissingRequiredSignature); }

        let (pda, bump) = Pubkey::find_program_address(
            &[b"stealth", stealth_pubkey.key.as_ref()],
            program_id,
        );
        if pda != *stealth_pda.key { return Err(ProgramError::InvalidSeeds); }

        // Create PDA if empty
        if stealth_pda.data_is_empty() {
            invoke_signed(
                &system_instruction::create_account(
                    sender.key,
                    stealth_pda.key,
                    1000000, 
                    0,
                    program_id
                ),
                &[sender.clone(), stealth_pda.clone(), system_program.clone()],
                &[&[b"stealth", stealth_pubkey.key.as_ref(), &[bump]]],
            )?;
        }

        // Unpack mint decimals
        let mint_data = mint.try_borrow_data()?;
        if mint_data.len() < 82 { 
             // ... 
        }
        let decimals = mint_data[44]; 
        drop(mint_data);

        // Transfer Checked
        let ix = spl_token_2022::instruction::transfer_checked(
            token_program.key,
            sender_token.key,
            mint.key,
            stealth_token.key,
            sender.key,
            &[],
            amount,
            decimals,
        )?;

        invoke(
            &ix,
            &[
                sender_token.clone(),
                mint.clone(),
                stealth_token.clone(),
                sender.clone(),
                token_program.clone()
            ],
        )?;

        Self::emit_announcement(announcement, Some(*mint.key));
        Ok(())
    }

    fn process_withdraw(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let stealth_pda = next_account_info(account_info_iter)?;
        let authority = next_account_info(account_info_iter)?;
        let recipient = next_account_info(account_info_iter)?;

        if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }

        // Verify PDA
        let (pda, _bump) = Pubkey::find_program_address(
            &[b"stealth", authority.key.as_ref()],
            program_id,
        );
        if pda != *stealth_pda.key { return Err(ProgramError::InvalidSeeds); }

        // Transfer all lamports
        let lamports = stealth_pda.lamports();
        **stealth_pda.try_borrow_mut_lamports()? = 0;
        **recipient.try_borrow_mut_lamports()? += lamports;
        
        Ok(())
    }

    fn process_withdraw_with_relayer(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        fee: u64,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let stealth_pda = next_account_info(account_info_iter)?;
        let relayer = next_account_info(account_info_iter)?;
        let recipient = next_account_info(account_info_iter)?;
        let instructions_sysvar = next_account_info(account_info_iter)?;

        if !relayer.is_signer { return Err(ProgramError::MissingRequiredSignature); }

        // Verify Ed25519 Signature
        let index = instructions::load_current_index_checked(instructions_sysvar)?;
        if index == 0 { return Err(ProgramError::InvalidInstructionData); }
        
        let ix = instructions::load_instruction_at_checked((index - 1) as usize, instructions_sysvar)?;
        
        if ix.program_id != solana_program::ed25519_program::id() {
            return Err(UmbraError::IncorrectProgramId.into());
        }

        if ix.data.len() < 16 { return Err(ProgramError::InvalidInstructionData); }
        let pubkey_offset = u16::from_le_bytes([ix.data[6], ix.data[7]]) as usize;
        
        if ix.data.len() < pubkey_offset + 32 { return Err(ProgramError::InvalidInstructionData); }
        let signer_pubkey_bytes = &ix.data[pubkey_offset..pubkey_offset+32];
        let signer_pubkey = Pubkey::new_from_array(signer_pubkey_bytes.try_into().unwrap());

        // Verify PDA derivation
        let (pda, _bump) = Pubkey::find_program_address(
            &[b"stealth", signer_pubkey.as_ref()],
            program_id,
        );
        if pda != *stealth_pda.key { return Err(ProgramError::InvalidSeeds); }

        // Pay Fee & Withdraw
        if stealth_pda.lamports() < fee { return Err(UmbraError::InsufficientFunds.into()); }

        **stealth_pda.try_borrow_mut_lamports()? -= fee;
        **relayer.try_borrow_mut_lamports()? += fee;
        
        let remaining_lamports = stealth_pda.lamports();
        **stealth_pda.try_borrow_mut_lamports()? = 0;
        **recipient.try_borrow_mut_lamports()? += remaining_lamports;
        
        Ok(())
    }

    fn emit_announcement(announcement: Announcement, token_mint: Option<Pubkey>) {
        let discriminator = [0x6eu8, 0x51, 0x93, 0x07, 0x22, 0x1f, 0x05, 0x1b];
        
        let event = StealthAnnouncementEvent {
             ephemeral_pubkey: announcement.ephemeral_pubkey,
             hashed_tag: announcement.hashed_tag,
             ciphertext: announcement.ciphertext,
             token_mint,
        };

        if let Ok(data) = borsh::to_vec(&event) {
             let mut log_data = Vec::with_capacity(8 + data.len());
             log_data.extend_from_slice(&discriminator);
             log_data.extend_from_slice(&data);
             sol_log_data(&[&log_data]);
        }
    }
}

#[derive(borsh::BorshSerialize)]
struct StealthAnnouncementEvent {
    ephemeral_pubkey: [u8; 32],
    hashed_tag: [u8; 32],
    ciphertext: Vec<u8>,
    token_mint: Option<Pubkey>,
}
