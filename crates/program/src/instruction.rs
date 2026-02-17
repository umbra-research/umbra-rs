use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Announcement {
    pub ephemeral_pubkey: [u8; 32],
    pub hashed_tag: [u8; 32],
    pub ciphertext: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum UmbraInstruction {
    /// Announces a stealth payment.
    /// Accounts:
    /// 0. `[signer]` Sender
    /// 1. `[writeable]` Stealth PDA (seeds=[b"stealth", stealth_pubkey])
    /// 2. `[]` Stealth Pubkey (seed resource)
    /// 3. `[]` System Program
    SendStealth {
        amount: u64,
        announcement: Announcement,
    },

    /// Announces a stealth SPL token payment.
    /// Accounts:
    /// 0. `[signer]` Sender
    /// 1. `[]` Mint
    /// 2. `[writeable]` Sender Token Account
    /// 3. `[writeable]` Stealth PDA
    /// 4. `[writeable]` Stealth Token Account
    /// 5. `[]` Stealth Pubkey
    /// 6. `[]` System Program
    /// 7. `[]` Token Program
    SendStealthSpl {
        amount: u64,
        announcement: Announcement,
    },

    /// Withdraws SOL from the Stealth PDA.
    /// Accounts:
    /// 0. `[writeable]` Stealth PDA (seeds=[b"stealth", authority])
    /// 1. `[signer]` Authority
    /// 2. `[writeable]` Recipient
    Withdraw,

    /// Withdraws SOL from the Stealth PDA via a Relayer, paying a fee.
    /// Accounts:
    /// 0. `[writeable]` Stealth PDA
    /// 1. `[signer]` Relayer
    /// 2. `[writeable]` Recipient
    /// 3. `[]` Instructions Sysvar (to verify Ed25519 signature)
    WithdrawWithRelayer {
        fee: u64,
    },
}
