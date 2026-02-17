use solana_client::client_error::ClientError;
use solana_client::rpc_client::RpcClient;
use solana_sdk::signature::Signature;
use thiserror::Error;

use crate::sweep::error::SweepSolError;
use crate::sweep::planner::SweepPlan;
use crate::sweep::sol::{build_and_sign_sweep_sol_transaction, SweepSolParams, MIN_REMAINING_LAMPORTS};

/// High-level errors that can occur while executing a sweep plan.
#[derive(Debug, Error)]
pub enum SweepExecutorError {
    #[error("RPC error: {0}")]
    Rpc(#[from] ClientError),

    #[error("failed to build sweep transaction: {0}")]
    Build(#[from] SweepSolError),

    #[error(
        "nothing to sweep for {one_time_pubkey}: balance={balance}, min_remaining={min_remaining}"
    )]
    NothingToSweep {
        one_time_pubkey: String,
        balance: u64,
        min_remaining: u64,
    },
}

/// Execute a single sweep plan:
/// - fetch current balance of the one-time account
/// - compute sweep amount (leaving rent buffer)
/// - fetch recent blockhash
/// - build and sign the sweep transaction
/// - send and confirm on-chain
///
/// This function is synchronous and best-effort:
/// callers can decide whether to retry on certain errors.
pub fn execute_sweep_plan(
    rpc: &RpcClient,
    plan: &SweepPlan,
) -> Result<Signature, SweepExecutorError> {
    // ---------------------------------------------------------------------
    // 1) Fetch the *current* on-chain balance of Stealth PDA.
    // ---------------------------------------------------------------------
    let program_id = crate::program::ID;
    let (stealth_pda, _bump) = solana_sdk::pubkey::Pubkey::find_program_address(
        &[b"stealth", plan.one_time_pubkey.as_ref()], 
        &program_id
    );

    let balance = rpc.get_balance(&stealth_pda)?;

    if balance == 0 {
        return Err(SweepExecutorError::NothingToSweep {
            one_time_pubkey: plan.one_time_pubkey.to_string(), // Report the signer key for reference
            balance,
            min_remaining: 0,
        });
    }

    let sweep_amount = balance; // Withdraw all

    // ---------------------------------------------------------------------
    // 2) Fetch a recent blockhash for transaction signing.
    // ---------------------------------------------------------------------
    let recent_blockhash = rpc.get_latest_blockhash()?;

    // ---------------------------------------------------------------------
    // 3) Build & sign the sweep transaction using Phase-3 primitive.
    // ---------------------------------------------------------------------
    let params = SweepSolParams {
        signer: &plan.signer,
        to: plan.destination,
        amount: sweep_amount,
        recent_blockhash,
    };

    let tx = build_and_sign_sweep_sol_transaction(&params)?;

    // ---------------------------------------------------------------------
    // 4) Send and confirm transaction.
    // ---------------------------------------------------------------------
    let sig = rpc.send_and_confirm_transaction(&tx)?;

    Ok(sig)
}

/// Execute a batch of sweep plans.
/// Returns a vector of (plan, result) so callers can log / retry selectively.
pub fn execute_sweep_plans(
    rpc: &RpcClient,
    plans: &[SweepPlan],
) -> Vec<(SweepPlan, Result<Signature, SweepExecutorError>)> {
    plans
        .iter()
        .cloned()
        .map(|plan| {
            let res = execute_sweep_plan(rpc, &plan);
            (plan, res)
        })
        .collect()
}
