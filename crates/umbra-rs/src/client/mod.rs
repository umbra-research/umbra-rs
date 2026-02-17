use solana_client::client_error::ClientError;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, signature::Signature};
use solana_transaction_status::UiTransaction;
use thiserror::Error;

use crate::core::Identity;
use crate::rpc::fetch_ui_transactions_for_slot_range;
use crate::rpc::ownership::{
    scan_ui_transactions_for_owned_outputs, ClaimantKeyMaterial, OwnedOutput, ScanIssue,
};
use crate::sweep::executor::{execute_sweep_plans, SweepExecutorError};
use crate::sweep::planner::{build_sweep_plan, PlanIssue, SweepPlan};

pub mod confidential;

#[cfg(feature = "logging")]
pub fn init_logging() {
    use tracing_subscriber::fmt::Subscriber;
    let subscriber = Subscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// High-level configuration for the Umbra client.
/// For now we only need a sweep destination, but this is a good place
/// to add tuning knobs later (e.g. max batch size, timeouts, etc.).
#[derive(Debug, Clone)]
pub struct UmbraClientConfig {
    /// Destination address where recovered funds will be swept.
    pub sweep_destination: Pubkey,
}

/// Public error type for high-level Umbra client operations.
///
/// Note that most pipeline issues (scanner, planning, execution)
/// are captured inside `UmbraBatchSummary` as non-fatal issues.
/// This error is reserved for *top-level* fatal problems, such as
/// a completely unreachable RPC endpoint.
#[derive(Debug, Error)]
pub enum UmbraClientError {
    #[error("RPC error: {0}")]
    Rpc(#[from] solana_client::client_error::ClientError),
}

/// Summary of a full scan → plan → sweep pipeline over a batch of
/// transactions provided by the caller.
///
/// Everything is reported in a structured way:
/// - which outputs are owned
/// - which plans were created
/// - which sweeps succeeded or failed
/// - non-fatal issues at each stage
#[derive(Debug)]
pub struct UmbraBatchSummary {
    /// Outputs that were determined to belong to the given identity.
    pub owned_outputs: Vec<OwnedOutput>,

    /// Sweep plans constructed from the owned outputs.
    pub sweep_plans: Vec<SweepPlan>,

    /// Successful sweeps: each plan with the resulting on-chain signature.
    pub successful_sweeps: Vec<(SweepPlan, Signature)>,

    /// Failed sweeps: each plan with its execution error.
    pub failed_sweeps: Vec<(SweepPlan, SweepExecutorError)>,

    /// Non-fatal scanner issues (e.g. malformed memo, invalid tx layout).
    pub scan_issues: Vec<ScanIssue>,

    /// Non-fatal planner issues (e.g. point decompression failed, mismatch).
    pub plan_issues: Vec<PlanIssue>,
}

/// High-level Umbra client orchestrating the full flow:
///
/// UiTransaction(s) → OwnedOutput(s) → SweepPlan(s) → on-chain sweep.
pub struct UmbraClient {
    rpc: RpcClient,
    config: UmbraClientConfig,
}

impl UmbraClient {
    /// Create a new UmbraClient from an RPC URL and configuration.
    pub fn new(rpc_url: impl AsRef<str>, config: UmbraClientConfig) -> Self {
        let rpc = RpcClient::new(rpc_url.as_ref().to_string());
        Self { rpc, config }
    }

    /// Access the underlying RpcClient if callers need lower-level queries.
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// Run the full Umbra pipeline on a batch of UiTransactions:
    ///
    /// 1. Scan → find Umbra candidate outputs + check ownership.
    /// 2. Plan → derive spend scalar & build per-output sweep plans.
    /// 3. Execute → sign and submit sweep transactions on-chain.
    ///
    /// This function does not fetch transactions itself; callers are
    /// responsible for providing `(slot, signature, UiTransaction)` tuples.
    pub fn scan_plan_and_sweep_batch<'a, I>(
        &self,
        identity: &Identity,
        txs: I,
    ) -> Result<UmbraBatchSummary, UmbraClientError>
    where
        I: IntoIterator<Item = (u64, String, &'a UiTransaction)>,
    {
        // -----------------------------------------------------------------
        // Phase 2: Scan & ownership
        // -----------------------------------------------------------------
        let claimant_keys = ClaimantKeyMaterial::from_identity(identity);

        let (owned_outputs, scan_issues) =
            scan_ui_transactions_for_owned_outputs(&claimant_keys, txs);

        // -----------------------------------------------------------------
        // Phase 3.5: Planner
        // -----------------------------------------------------------------
        let (sweep_plans, plan_issues) =
            build_sweep_plan(&owned_outputs, identity, self.config.sweep_destination);

        // -----------------------------------------------------------------
        // Phase 4: Executor
        // -----------------------------------------------------------------
        let executed = execute_sweep_plans(&self.rpc, &sweep_plans);

        let mut successful_sweeps = Vec::new();
        let mut failed_sweeps = Vec::new();

        for (plan, res) in executed {
            match res {
                Ok(sig) => successful_sweeps.push((plan, sig)),
                Err(err) => failed_sweeps.push((plan, err)),
            }
        }

        Ok(UmbraBatchSummary {
            owned_outputs,
            sweep_plans,
            successful_sweeps,
            failed_sweeps,
            scan_issues,
            plan_issues,
        })
    }

    /// Scan a slot range [start_slot, end_slot] for Umbra-owned outputs
    /// belonging to the given claimant `Identity`.
    ///
    /// This is a **read-only / discovery** operation:
    /// - Fetches all blocks in the slot range
    /// - Decodes `UiTransaction` (JSON)
    /// - Runs Phase-2 ownership scanner to determine which outputs belong
    ///   to the provided claimant keys
    ///
    /// Returns:
    /// - `OwnedOutput` list: candidates that claimant can sweep
    /// - `ScanIssue` list: malformed / inconsistent transactions encountered
    ///
    /// RPC failures (network / node) are surfaced as `ClientError`.
    pub fn scan_slot_range_for_owned_outputs(
        &self,
        identity: &Identity,
        start_slot: u64,
        end_slot: u64,
    ) -> Result<(Vec<OwnedOutput>, Vec<ScanIssue>), ClientError> {
        let slot_txs = fetch_ui_transactions_for_slot_range(&self.rpc, start_slot, end_slot)?;

        let iter = slot_txs
            .iter()
            .map(|stx| (stx.slot, stx.signature.clone(), &stx.ui_transaction));

        let claimant_keys = ClaimantKeyMaterial::from_identity(identity);

        let (owned_outputs, scan_issues) =
            scan_ui_transactions_for_owned_outputs(&claimant_keys, iter);

        Ok((owned_outputs, scan_issues))
    }

    /// Full pipeline over a slot range:
    ///
    /// 1. Fetch UiTransactions for [start_slot, end_slot]
    /// 2. Phase 2: Determine owned outputs for the claimant
    /// 3. Phase 3: Build sweep plans
    /// 4. Phase 4: Execute sweeps on-chain
    ///
    /// Returns a structured UmbraBatchSummary with all intermediate
    /// results and non-fatal issues.
    pub fn scan_plan_and_sweep_slot_range(
        &self,
        identity: &Identity,
        start_slot: u64,
        end_slot: u64,
    ) -> Result<UmbraBatchSummary, UmbraClientError> {
        // ------------------------------------------------------------
        // Step 1: Fetch all UiTransactions in slot range
        // ------------------------------------------------------------
        let slot_txs = fetch_ui_transactions_for_slot_range(&self.rpc, start_slot, end_slot)?;

        let iter = slot_txs
            .iter()
            .map(|stx| (stx.slot, stx.signature.clone(), &stx.ui_transaction));

        // ------------------------------------------------------------
        // Step 2: Phase 2 — ownership scanner
        // ------------------------------------------------------------
        let claimant_keys = ClaimantKeyMaterial::from_identity(identity);

        let (owned_outputs, scan_issues) =
            scan_ui_transactions_for_owned_outputs(&claimant_keys, iter);

        // ------------------------------------------------------------
        // Step 3: Phase 3 — planner
        // ------------------------------------------------------------
        let (sweep_plans, plan_issues) =
            build_sweep_plan(&owned_outputs, identity, self.config.sweep_destination);

        // ------------------------------------------------------------
        // Step 4: Phase 4 — executor
        // ------------------------------------------------------------
        let executed = execute_sweep_plans(&self.rpc, &sweep_plans);

        let mut successful_sweeps = Vec::new();
        let mut failed_sweeps = Vec::new();

        for (plan, res) in executed {
            match res {
                Ok(sig) => successful_sweeps.push((plan, sig)),
                Err(err) => failed_sweeps.push((plan, err)),
            }
        }

        Ok(UmbraBatchSummary {
            owned_outputs,
            sweep_plans,
            successful_sweeps,
            failed_sweeps,
            scan_issues,
            plan_issues,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_init() {
        let pk = Pubkey::new_unique();
        let config = UmbraClientConfig { sweep_destination: pk };
        let client = UmbraClient::new("http://localhost:8899", config.clone());
        // Verify we can access the RPC client URL (sanity check)
        assert_eq!(client.rpc().url(), "http://localhost:8899");
    }
}

