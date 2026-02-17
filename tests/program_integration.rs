use solana_program_test::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use umbra_program::{self, instruction::{UmbraInstruction, Announcement}};
use spl_token_2022;
use borsh::BorshSerialize;

#[tokio::test]
async fn test_send_stealth_spl_manual_logic() {
    let program_id = Pubkey::new_unique();
    // Actually, ProgramTest::new takes a name and ID.
    // We can use any ID.
    
    let mut pt = ProgramTest::new(
        "umbra_program",
        program_id,
        processor!(umbra_program::process_instruction),
    );
    
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    // 1. Create a Token-2022 Mint
    let mint = Keypair::new();
    let mint_authority = Keypair::new();
    let rent = banks_client.get_rent().await.unwrap();
    let mint_len = 82; 
    
    let create_mint_ix = solana_sdk::system_instruction::create_account(
        &payer.pubkey(),
        &mint.pubkey(),
        rent.minimum_balance(mint_len),
        mint_len as u64,
        &spl_token_2022::id(),
    );
    
    let init_mint_ix = spl_token_2022::instruction::initialize_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &mint_authority.pubkey(),
        Some(&mint_authority.pubkey()),
        6, 
    ).unwrap();
    
    let tx = Transaction::new_signed_with_payer(
        &[create_mint_ix, init_mint_ix],
        Some(&payer.pubkey()),
        &[&payer, &mint],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();
    
    // 2. Create Sender Token Account and Mint to it
    let sender_token = Keypair::new();
    let create_sender_token_ix = solana_sdk::system_instruction::create_account(
        &payer.pubkey(),
        &sender_token.pubkey(),
        rent.minimum_balance(165),
        165,
        &spl_token_2022::id(),
    );
    
    let init_sender_token_ix = spl_token_2022::instruction::initialize_account(
        &spl_token_2022::id(),
        &sender_token.pubkey(),
        &mint.pubkey(),
        &payer.pubkey(),
    ).unwrap();
    
    let mint_to_ix = spl_token_2022::instruction::mint_to(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &sender_token.pubkey(),
        &mint_authority.pubkey(),
        &[&mint_authority.pubkey()],
        1000,
    ).unwrap();
    
    let tx = Transaction::new_signed_with_payer(
        &[create_sender_token_ix, init_sender_token_ix, mint_to_ix],
        Some(&payer.pubkey()),
        &[&payer, &sender_token, &mint_authority],
        recent_blockhash,
    );
    banks_client.process_transaction(tx).await.unwrap();

    // 3. Setup Stealth Destination
    let stealth_keypair_seed = Keypair::new();
    let (stealth_pda, bump) = Pubkey::find_program_address(
        &[b"stealth", stealth_keypair_seed.pubkey().as_ref()],
        &program_id
    );
    
    // Create ATA for Stealth PDA (must be done by payer as stealth_pda can't sign yet)
    let stealth_ata = spl_associated_token_account::get_associated_token_address_with_program_id(
        &stealth_pda,
        &mint.pubkey(),
        &spl_token_2022::id(),
    );
    
    let create_ata_ix = spl_associated_token_account::instruction::create_associated_token_account_idempotent(
        &payer.pubkey(),
        &stealth_pda,
        &mint.pubkey(),
        &spl_token_2022::id(),
    );
    
    let tx = Transaction::new_signed_with_payer(
        &[create_ata_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash
    );
    banks_client.process_transaction(tx).await.unwrap();

    // 4. Invoke SendStealthSpl
    let ephemeral_pubkey = [1u8; 32];
    let hashed_tag = [2u8; 32];
    let ciphertext = vec![3u8; 10];
    let amount = 500u64;
    
    let announcement = Announcement {
        ephemeral_pubkey,
        hashed_tag,
        ciphertext,
    };
    
    let instruction = UmbraInstruction::SendStealthSpl {
        amount,
        announcement,
    };
    
    let data = borsh::to_vec(&instruction).unwrap();
    
    let mut accounts = vec![
        AccountMeta::new(payer.pubkey(), true), // Sender
        AccountMeta::new_readonly(mint.pubkey(), false), // Mint
        AccountMeta::new(sender_token.pubkey(), false), // Sender Token
        AccountMeta::new(stealth_pda, false), // Stealth PDA
        AccountMeta::new(stealth_ata, false), // Stealth Token Account
        AccountMeta::new_readonly(stealth_keypair_seed.pubkey(), false), // Stealth Pubkey
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false), // System Program
        AccountMeta::new_readonly(spl_token_2022::id(), false), // Token Program
    ];
    
    let ix = Instruction {
        program_id,
        accounts,
        data,
    };
    
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash
    );
    
    banks_client.process_transaction(tx).await.unwrap();
    
    // 5. Verify Balance
    let account = banks_client.get_account(stealth_ata).await.unwrap().unwrap();
    use spl_token_2022::extension::StateWithExtensions;
    let state = StateWithExtensions::<spl_token_2022::state::Account>::unpack(&account.data).unwrap();
    assert_eq!(state.base.amount, 500);
}
