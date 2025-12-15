use rand_core::{CryptoRng, RngCore};
use solana_client::client_error::ClientError;
use solana_client::rpc_client::RpcClient;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::Transaction;
use solana_system_interface::instruction::transfer;
use thiserror::Error;

use umbra_client::{UmbraBatchSummary, UmbraClient, UmbraClientConfig};
use umbra_core::derive::derive_for_initiator;
use umbra_rpc::memo::{build_umbra_memo, UMBRA_MEMO_VERSION};
use umbra_sweep::executor::execute_sweep_plans;
use umbra_sweep::planner::build_sweep_plan;
use umbra_sweep::sol::{build_and_sign_sweep_sol_transaction, SweepSolParams, MIN_REMAINING_LAMPORTS};

pub use umbra_client::UmbraClientError;
pub use umbra_core::{Identity, InitiatorOutput, PointWrapper, ScalarWrapper};
pub use umbra_rpc::ownership::{OwnedOutput, ScanIssue};
pub use umbra_sweep::executor::SweepExecutorError;
pub use umbra_sweep::planner::{PlanIssue, SweepPlan};
pub use umbra_sweep::SweepSolError;

#[cfg(feature = "logging")]
pub use umbra_client::init_logging;

const MEMO_PROGRAM_ID: Pubkey = solana_sdk::pubkey!("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

/// Network options for Umbra API.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub rpc_url: String,
}

/// Protocol-level toggles that impact transaction construction.
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Supported memo version for Umbra transfers.
    pub memo_version: u8,
    /// Rent buffer left behind when sweeping lamports.
    pub min_remaining_lamports: u64,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            memo_version: UMBRA_MEMO_VERSION,
            min_remaining_lamports: MIN_REMAINING_LAMPORTS,
        }
    }
}

/// High-level configuration for Umbra public API.
#[derive(Debug, Clone)]
pub struct UmbraApiConfig {
    pub network: NetworkConfig,
    pub sweep_destination: Pubkey,
    pub protocol: ProtocolConfig,
}

impl UmbraApiConfig {
    pub fn new(rpc_url: impl Into<String>, sweep_destination: Pubkey) -> Self {
        Self {
            network: NetworkConfig {
                rpc_url: rpc_url.into(),
            },
            sweep_destination,
            protocol: ProtocolConfig::default(),
        }
    }
}

/// Public error surface exposed by the API layer.
#[derive(Debug, Error)]
pub enum UmbraApiError {
    #[error("unsupported memo version requested: {requested}, supported: {supported}")]
    UnsupportedMemoVersion { requested: u8, supported: u8 },

    #[error("umbra client error: {0}")]
    Client(#[from] UmbraClientError),

    #[error("rpc error: {0}")]
    Rpc(#[from] ClientError),
}

/// Ready-to-submit instructions for an Umbra transfer.
#[derive(Debug, Clone)]
pub struct InitiatorTransfer {
    pub one_time_pubkey: Pubkey,
    pub memo: Vec<u8>,
    pub instructions: Vec<Instruction>,
    pub output: InitiatorOutput,
}

/// Umbra Public API facade that wraps lower-level crates.
pub struct UmbraApi {
    protocol: ProtocolConfig,
    sweep_destination: Pubkey,
    client: UmbraClient,
}

impl UmbraApi {
    /// Create a new API instance with the provided configuration.
    pub fn new(config: UmbraApiConfig) -> Self {
        let client_config = UmbraClientConfig {
            sweep_destination: config.sweep_destination,
        };

        let client = UmbraClient::new(&config.network.rpc_url, client_config);

        Self {
            protocol: config.protocol,
            sweep_destination: config.sweep_destination,
            client,
        }
    }

    /// Build a memo payload for initiator-side transfers.
    pub fn build_umbra_memo(&self, ephemeral_pubkey: &PointWrapper) -> Result<Vec<u8>, UmbraApiError> {
        if self.protocol.memo_version != UMBRA_MEMO_VERSION {
            return Err(UmbraApiError::UnsupportedMemoVersion {
                requested: self.protocol.memo_version,
                supported: UMBRA_MEMO_VERSION,
            });
        }

        Ok(build_umbra_memo(&ephemeral_pubkey.to_bytes()))
    }

    /// Build transfer instructions (memo + system transfer) targeting a one-time key.
    pub fn build_transfer_instructions(
        &self,
        payer: Pubkey,
        one_time_pubkey: Pubkey,
        amount: u64,
        memo: Option<&[u8]>,
    ) -> Vec<Instruction> {
        let mut instructions = Vec::with_capacity(if memo.is_some() { 2 } else { 1 });

        if let Some(bytes) = memo {
            instructions.push(memo_instruction(bytes, &payer));
        }

        instructions.push(transfer(&payer, &one_time_pubkey, amount));

        instructions
    }

    /// Initiator flow: derive one-time keys, build memo, and produce transfer instructions.
    pub fn build_initiator_transfer<R: RngCore + CryptoRng>(
        &self,
        recipient_identity: &Identity,
        rng: &mut R,
        payer: Pubkey,
        amount: u64,
    ) -> Result<InitiatorTransfer, UmbraApiError> {
        let output = derive_for_initiator(recipient_identity, rng);
        let memo = self.build_umbra_memo(&output.ephemeral_pubkey)?;
        let one_time_pubkey = Pubkey::new_from_array(output.one_time_pubkey.to_bytes());

        let instructions = self.build_transfer_instructions(payer, one_time_pubkey, amount, Some(&memo));

        Ok(InitiatorTransfer {
            one_time_pubkey,
            memo,
            instructions,
            output,
        })
    }

    /// Claimant flow: scan a slot range for owned outputs.
    pub fn scan_slot_range(
        &self,
        claimant_identity: &Identity,
        start_slot: u64,
        end_slot: u64,
    ) -> Result<(Vec<OwnedOutput>, Vec<ScanIssue>), UmbraApiError> {
        self.client
            .scan_slot_range_for_owned_outputs(claimant_identity, start_slot, end_slot)
            .map_err(UmbraApiError::Rpc)
    }

    /// Async-friendly wrapper around [`scan_slot_range`].
    pub async fn scan_slot_range_async(
        &self,
        claimant_identity: &Identity,
        start_slot: u64,
        end_slot: u64,
    ) -> Result<(Vec<OwnedOutput>, Vec<ScanIssue>), UmbraApiError> {
        self.scan_slot_range(claimant_identity, start_slot, end_slot)
    }

    /// Sweep planning: derive spend authority and destination transfers.
    pub fn plan_sweep(
        &self,
        owned_outputs: &[OwnedOutput],
        claimant_identity: &Identity,
    ) -> (Vec<SweepPlan>, Vec<PlanIssue>) {
        build_sweep_plan(owned_outputs, claimant_identity, self.sweep_destination)
    }

    /// Build sweep transactions for a batch of plans using a provided blockhash.
    pub fn build_sweep_transactions(
        &self,
        plans: &[SweepPlan],
        recent_blockhash: Hash,
    ) -> Vec<Result<Transaction, SweepSolError>> {
        plans
            .iter()
            .map(|plan| {
                let params = SweepSolParams {
                    signer: &plan.signer,
                    to: plan.destination,
                    amount: plan.amount.saturating_sub(self.protocol.min_remaining_lamports),
                    recent_blockhash,
                };

                build_and_sign_sweep_sol_transaction(&params)
            })
            .collect()
    }

    /// Submit and confirm sweep transactions via the configured RPC client.
    pub fn submit_sweep_plans(
        &self,
        plans: &[SweepPlan],
    ) -> Vec<(SweepPlan, Result<Signature, SweepExecutorError>)> {
        execute_sweep_plans(self.client.rpc(), plans)
    }

    /// One-shot pipeline over a slot range: scan → plan → sweep.
    pub fn scan_plan_and_sweep_slot_range(
        &self,
        claimant_identity: &Identity,
        start_slot: u64,
        end_slot: u64,
    ) -> Result<UmbraBatchSummary, UmbraApiError> {
        self.client
            .scan_plan_and_sweep_slot_range(claimant_identity, start_slot, end_slot)
            .map_err(UmbraApiError::from)
    }

    /// Async-friendly wrapper around [`scan_plan_and_sweep_slot_range`].
    pub async fn scan_plan_and_sweep_slot_range_async(
        &self,
        claimant_identity: &Identity,
        start_slot: u64,
        end_slot: u64,
    ) -> Result<UmbraBatchSummary, UmbraApiError> {
        self.scan_plan_and_sweep_slot_range(claimant_identity, start_slot, end_slot)
    }

    /// Accessor for the underlying RPC client.
    pub fn rpc(&self) -> &RpcClient {
        self.client.rpc()
    }
}

fn memo_instruction(memo: &[u8], payer: &Pubkey) -> Instruction {
    Instruction {
        program_id: MEMO_PROGRAM_ID,
        accounts: vec![AccountMeta::new_readonly(*payer, true)],
        data: memo.to_vec(),
    }
}
