use std::{env, fs, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Args, Parser, Subcommand, ValueEnum};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey, signature::read_keypair_file, signer::Signer, transaction::Transaction,
};
use umbra_api::{Identity, OwnedOutput, PlanIssue, SweepPlan, UmbraApi, UmbraApiConfig};
use umbra_client::UmbraBatchSummary;
use umbra_core::{PointWrapper, ScalarWrapper};
use umbra_rpc::memo::UMBRA_MEMO_VERSION;
use umbra_rpc::ownership::{match_candidate_output, ClaimantKeyMaterial, ScanIssue};
use umbra_rpc::types::{CandidateOutput, UmbraMemo};
use zeroize::Zeroize;

const IDENTITY_FILE_VERSION: u8 = 1;
const DEFAULT_LOCAL_RPC_URL: &str = "http://127.0.0.1:8899";
const DEFAULT_DEVNET_RPC_URL: &str = "https://api.devnet.solana.com";
const DEFAULT_SWEEP_DEST_ENV: &str = "UMBRA_SWEEP_DESTINATION";
const DEFAULT_LOCAL_SWEEP_DESTINATION: &str = "11111111111111111111111111111111";

#[derive(Parser)]
#[command(name = "umbra", about = "Umbra operator & debugging CLI", version)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = Network::Local)]
    network: Network,

    #[arg(long, global = true)]
    rpc_url: Option<String>,

    #[arg(long, global = true)]
    sweep_destination: Option<String>,

    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Identity(IdentityCommand),
    #[command(subcommand)]
    Send(SendCommand),
    #[command(subcommand)]
    Scan(ScanCommand),
    #[command(subcommand)]
    Claim(ClaimCommand),
    #[command(subcommand)]
    Sweep(SweepCommand),
    #[command(subcommand)]
    Flow(FlowCommand),
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Generate a fresh Umbra identity (view + spend keys).
    Generate(GenerateArgs),
    /// Display public information about an identity file.
    Inspect {
        #[arg(long)]
        identity: PathBuf,
    },
    /// Import an identity file (format validation enforced).
    Import {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
        /// Overwrite destination file if it already exists.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args)]
struct GenerateArgs {
    #[arg(long)]
    export: Option<PathBuf>,
}

#[derive(Subcommand)]
enum SendCommand {
    /// Build an Umbra transfer (initiator flow).
    Build {
        #[arg(long)]
        recipient: PathBuf,
        #[arg(long)]
        payer: String,
        #[arg(long)]
        amount: u64,
    },
    /// Build and submit an Umbra transfer.
    Submit {
        #[arg(long)]
        recipient: PathBuf,
        #[arg(long)]
        payer_keypair: PathBuf,
        #[arg(long)]
        amount: u64,
        /// Require an explicit confirmation before submitting.
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
enum ScanCommand {
    /// Scan a single slot for Umbra candidates.
    Slot {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        slot: u64,
    },
    /// Scan an inclusive slot range.
    Range {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        start: u64,
        #[arg(long)]
        end: u64,
    },
}

#[derive(Subcommand)]
enum ClaimCommand {
    /// Test whether an identity owns a candidate output.
    Check {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        slot: u64,
        #[arg(long)]
        signature: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        ephemeral: String,
        /// Umbra memo version for the candidate (defaults to current).
        #[arg(long, default_value_t = UMBRA_MEMO_VERSION)]
        memo_version: u8,
    },
    /// Derive spend authority for an owned output (no secrets printed).
    Derive {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        one_time_pubkey: String,
        #[arg(long)]
        ephemeral: String,
    },
}

#[derive(Subcommand)]
enum SweepCommand {
    /// Build sweep plans from owned outputs over a slot range.
    Plan {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        start: u64,
        #[arg(long)]
        end: u64,
    },
    /// Execute sweep plans (confirmation required unless dry-run).
    Execute {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        start: u64,
        #[arg(long)]
        end: u64,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum FlowCommand {
    /// Full scan → claim → plan → sweep pipeline.
    Run {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        start: u64,
        #[arg(long)]
        end: u64,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    #[serde(default = "identity_file_version")]
    version: u8,
    initiator_spend_sk: [u8; 32],
    initiator_view_sk: [u8; 32],
}

#[derive(Serialize)]
struct IdentitySummary {
    spend_pubkey: String,
    view_pubkey: String,
    exported: bool,
}

#[derive(Serialize)]
struct BuiltTransfer {
    amount: u64,
    one_time_pubkey: String,
    ephemeral_pubkey: String,
    memo_base64: String,
    instruction_count: usize,
}

#[derive(Serialize)]
struct ScanSummary {
    owned: Vec<OwnedOutputSummary>,
    scan_issues: Vec<IssueSummary>,
}

#[derive(Serialize)]
struct OwnedOutputSummary {
    slot: u64,
    signature: String,
    one_time_pubkey: String,
    amount: u64,
    ephemeral_pubkey: String,
}

#[derive(Serialize)]
struct IssueSummary {
    slot: u64,
    signature: String,
    error: String,
}

#[derive(Serialize)]
struct PlanSummary {
    plans: Vec<PlanRow>,
    plan_issues: Vec<IssueSummary>,
    scan_issues: Vec<IssueSummary>,
}

#[derive(Serialize)]
struct PlanRow {
    one_time_pubkey: String,
    destination: String,
    amount: u64,
}

#[derive(Serialize)]
struct SweepExecutionSummary {
    submitted: Vec<SubmittedSweep>,
    failed: Vec<FailedSweep>,
    plan_issues: Vec<IssueSummary>,
    scan_issues: Vec<IssueSummary>,
}

#[derive(Serialize)]
struct SubmittedSweep {
    one_time_pubkey: String,
    signature: String,
    amount: u64,
}

#[derive(Serialize)]
struct FailedSweep {
    one_time_pubkey: String,
    error: String,
    amount: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Network {
    Local,
    Devnet,
    Custom,
}

#[derive(Clone)]
struct ResolvedCliConfig {
    rpc_url: String,
    sweep_destination: Pubkey,
    network: Network,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Identity(cmd) => handle_identity(&cli, cmd),
        Command::Send(cmd) => handle_send(&cli, cmd),
        Command::Scan(cmd) => handle_scan(&cli, cmd),
        Command::Claim(cmd) => handle_claim(&cli, cmd),
        Command::Sweep(cmd) => handle_sweep(&cli, cmd),
        Command::Flow(cmd) => handle_flow(&cli, cmd),
    }
}

fn handle_identity(cli: &Cli, cmd: &IdentityCommand) -> Result<()> {
    match cmd {
        IdentityCommand::Generate(args) => {
            let mut rng = OsRng;
            let identity = Identity::new_random(&mut rng);

            if let Some(path) = args.export.as_ref() {
                save_identity(path, &identity)?;
            }

            let summary = IdentitySummary {
                spend_pubkey: encode_point(&identity.initiator_spend_pk),
                view_pubkey: encode_point(&identity.initiator_view_pk),
                exported: args.export.is_some(),
            };

            render(cli, summary, |s| {
                println!("Spend pubkey   : {}", s.spend_pubkey);
                println!("View pubkey    : {}", s.view_pubkey);
                if s.exported {
                    if let Some(path) = args.export.as_ref() {
                        println!("Identity saved : {}", path.display());
                    }
                }
            });
        }
        IdentityCommand::Inspect { identity } => {
            let identity = load_identity(identity)?;
            let summary = IdentitySummary {
                spend_pubkey: encode_point(&identity.initiator_spend_pk),
                view_pubkey: encode_point(&identity.initiator_view_pk),
                exported: true,
            };
            render(cli, summary, |s| {
                println!("Spend pubkey: {}", s.spend_pubkey);
                println!("View pubkey : {}", s.view_pubkey);
            });
        }
        IdentityCommand::Import { from, to, force } => {
            let identity = load_identity(from)?;
            if to.exists() && !force {
                bail!(
                    "destination {} already exists; pass --force to overwrite",
                    to.display()
                );
            }
            save_identity(to, &identity)?;
            let summary = IdentitySummary {
                spend_pubkey: encode_point(&identity.initiator_spend_pk),
                view_pubkey: encode_point(&identity.initiator_view_pk),
                exported: true,
            };
            render(cli, summary, |s| {
                println!("Imported identity with spend pubkey {}", s.spend_pubkey);
                println!("Saved to {}", to.display());
            });
        }
    }

    Ok(())
}

fn handle_send(cli: &Cli, cmd: &SendCommand) -> Result<()> {
    match cmd {
        SendCommand::Build {
            recipient,
            payer,
            amount,
        } => {
            let api = build_api(cli, false)?;
            let recipient_identity = load_identity(recipient)?;
            let payer_pubkey = parse_pubkey(payer)?;
            let mut rng = OsRng;
            let transfer =
                api.build_initiator_transfer(&recipient_identity, &mut rng, payer_pubkey, *amount)?;

            let summary = BuiltTransfer {
                amount: *amount,
                one_time_pubkey: transfer.one_time_pubkey.to_string(),
                ephemeral_pubkey: encode_point(&transfer.output.ephemeral_pubkey),
                memo_base64: STANDARD.encode(&transfer.memo),
                instruction_count: transfer.instructions.len(),
            };

            render(cli, summary, |s| {
                println!("One-time pubkey : {}", s.one_time_pubkey);
                println!("Ephemeral pubkey: {}", s.ephemeral_pubkey);
                println!("Memo (base64)   : {}", s.memo_base64);
                println!("Instructions    : {}", s.instruction_count);
            });
        }
        SendCommand::Submit {
            recipient,
            payer_keypair,
            amount,
            confirm,
        } => {
            if !*confirm {
                bail!("Submission requested without --confirm");
            }

            let api = build_api(cli, true)?;
            let recipient_identity = load_identity(recipient)?;
            let payer = read_keypair_file(payer_keypair)
                .map_err(|e| anyhow!("failed to read keypair {}: {e}", payer_keypair.display()))?;

            let payer_pubkey = payer.pubkey();
            let mut rng = OsRng;
            let transfer =
                api.build_initiator_transfer(&recipient_identity, &mut rng, payer_pubkey, *amount)?;
            let recent_blockhash = api.rpc().get_latest_blockhash()?;

            let tx = Transaction::new_signed_with_payer(
                &transfer.instructions,
                Some(&payer_pubkey),
                &[&payer],
                recent_blockhash,
            );

            let sig = api.rpc().send_and_confirm_transaction(&tx)?;
            render(cli, sig.to_string(), |s| {
                println!("Submitted transaction: {}", s);
            });
        }
    }

    Ok(())
}

fn handle_scan(cli: &Cli, cmd: &ScanCommand) -> Result<()> {
    match cmd {
        ScanCommand::Slot { identity, slot } => run_scan(cli, identity, *slot, *slot),
        ScanCommand::Range {
            identity,
            start,
            end,
        } => run_scan(cli, identity, *start, *end),
    }
}

fn handle_claim(cli: &Cli, cmd: &ClaimCommand) -> Result<()> {
    match cmd {
        ClaimCommand::Check {
            identity,
            slot,
            signature,
            recipient,
            amount,
            ephemeral,
            memo_version,
        } => {
            let identity = load_identity(identity)?;
            let claimant = ClaimantKeyMaterial::from_identity(&identity);
            let recipient_pk = parse_pubkey(&recipient)?;
            let ephemeral_pk = decode_point(&ephemeral)?;
            let candidate = CandidateOutput {
                slot: *slot,
                signature: signature.clone(),
                recipient: recipient_pk,
                amount: *amount,
                memo: UmbraMemo {
                    version: *memo_version,
                    ephemeral_pubkey: ephemeral_pk,
                },
            };

            let res = match_candidate_output(&candidate, &claimant)?;
            let owned = res.is_some();

            render(cli, owned, |owned| {
                if *owned {
                    println!("Output is owned by the provided identity.");
                } else {
                    println!("Output does NOT belong to the provided identity.");
                }
            });
            Ok(())
        }
        ClaimCommand::Derive {
            identity,
            one_time_pubkey,
            ephemeral,
        } => {
            let identity = load_identity(identity)?;
            let ot_pk = parse_pubkey(&one_time_pubkey)?;
            let ot_point = CompressedEdwardsY(ot_pk.to_bytes())
                .decompress()
                .ok_or_else(|| {
                    anyhow!("failed to decompress one-time pubkey into Edwards point")
                })?;
            let ephemeral_point = decode_point(&ephemeral)?;

            let recovered = umbra_core::derive::derive_for_claimant(
                &identity,
                &PointWrapper(ot_point),
                &ephemeral_point,
            );
            render(cli, recovered.is_some(), |ok| {
                if *ok {
                    println!("Spend authority derived; secrets are not displayed.");
                } else {
                    println!("Unable to derive spend authority for this output.");
                }
            });
            Ok(())
        }
    }
}

fn handle_sweep(cli: &Cli, cmd: &SweepCommand) -> Result<()> {
    match cmd {
        SweepCommand::Plan {
            identity,
            start,
            end,
        } => {
            let api = build_api(cli, true)?;
            let identity = load_identity(identity)?;
            let (owned, scan_issues) = api.scan_slot_range(&identity, *start, *end)?;
            let (plans, plan_issues) = api.plan_sweep(&owned, &identity);

            let summary = PlanSummary {
                plans: plans.iter().map(plan_row).collect(),
                plan_issues: plan_issues.iter().map(issue_from_plan).collect(),
                scan_issues: scan_issues.iter().map(issue_from_scan).collect(),
            };

            render(cli, summary, |s| {
                println!("{} sweep plan(s) built", s.plans.len());
                for plan in &s.plans {
                    println!(
                        "- {} → {} ({} lamports)",
                        plan.one_time_pubkey, plan.destination, plan.amount
                    );
                }
                if !s.plan_issues.is_empty() {
                    println!("Plan issues: {}", s.plan_issues.len());
                }
                if !s.scan_issues.is_empty() {
                    println!("Scan issues: {}", s.scan_issues.len());
                }
            });
        }
        SweepCommand::Execute {
            identity,
            start,
            end,
            confirm,
            dry_run,
        } => {
            let api = build_api(cli, true)?;
            let identity = load_identity(identity)?;
            let (owned, scan_issues) = api.scan_slot_range(&identity, *start, *end)?;
            let (plans, plan_issues) = api.plan_sweep(&owned, &identity);

            if *dry_run {
                let summary = PlanSummary {
                    plans: plans.iter().map(plan_row).collect(),
                    plan_issues: plan_issues.iter().map(issue_from_plan).collect(),
                    scan_issues: scan_issues.iter().map(issue_from_scan).collect(),
                };
                render(cli, summary, |s| {
                    println!("Dry-run: {} plan(s) ready", s.plans.len());
                });
                return Ok(());
            }

            if !*confirm {
                bail!("Sweep execution requires --confirm");
            }

            let executed = api.submit_sweep_plans(&plans);
            let mut submitted = Vec::new();
            let mut failed = Vec::new();

            for (plan, res) in executed {
                match res {
                    Ok(sig) => submitted.push(SubmittedSweep {
                        one_time_pubkey: plan.one_time_pubkey.to_string(),
                        signature: sig.to_string(),
                        amount: plan.amount,
                    }),
                    Err(err) => failed.push(FailedSweep {
                        one_time_pubkey: plan.one_time_pubkey.to_string(),
                        error: err.to_string(),
                        amount: plan.amount,
                    }),
                }
            }

            let summary = SweepExecutionSummary {
                submitted,
                failed,
                plan_issues: plan_issues.iter().map(issue_from_plan).collect(),
                scan_issues: scan_issues.iter().map(issue_from_scan).collect(),
            };

            render(cli, summary, |s| {
                println!("Submitted sweeps: {}", s.submitted.len());
                for sweep in &s.submitted {
                    println!(
                        "- {} ({} lamports) → {}",
                        sweep.one_time_pubkey, sweep.amount, sweep.signature
                    );
                }
                if !s.failed.is_empty() {
                    println!("Failed sweeps: {}", s.failed.len());
                    for sweep in &s.failed {
                        println!("- {} failed: {}", sweep.one_time_pubkey, sweep.error);
                    }
                }
            });
        }
    }

    Ok(())
}

fn handle_flow(cli: &Cli, cmd: &FlowCommand) -> Result<()> {
    match cmd {
        FlowCommand::Run {
            identity,
            start,
            end,
            confirm,
            dry_run,
        } => {
            let api = build_api(cli, true)?;
            let identity = load_identity(identity)?;

            if *dry_run {
                let (owned, scan_issues) = api.scan_slot_range(&identity, *start, *end)?;
                let (plans, plan_issues) = api.plan_sweep(&owned, &identity);
                let summary = PlanSummary {
                    plans: plans.iter().map(plan_row).collect(),
                    plan_issues: plan_issues.iter().map(issue_from_plan).collect(),
                    scan_issues: scan_issues.iter().map(issue_from_scan).collect(),
                };
                render(cli, summary, |s| {
                    println!("Dry-run flow summary: {} plan(s)", s.plans.len());
                });
                return Ok(());
            }

            if !*confirm {
                bail!("Flow execution requires --confirm");
            }

            let batch = api.scan_plan_and_sweep_slot_range(&identity, *start, *end)?;
            render(cli, summarize_batch(batch), |s| {
                println!("Owned outputs : {}", s.owned);
                println!("Sweep plans   : {}", s.plans);
                println!("Successful tx : {}", s.successful);
                println!("Failed tx     : {}", s.failed);
                if s.scan_issues + s.plan_issues > 0 {
                    println!("Issues: scan {}, plan {}", s.scan_issues, s.plan_issues);
                }
            });
        }
    }

    Ok(())
}

fn summarize_batch(batch: UmbraBatchSummary) -> FlowSummary {
    FlowSummary {
        owned: batch.owned_outputs.len(),
        plans: batch.sweep_plans.len(),
        successful: batch.successful_sweeps.len(),
        failed: batch.failed_sweeps.len(),
        scan_issues: batch.scan_issues.len(),
        plan_issues: batch.plan_issues.len(),
    }
}

#[derive(Serialize)]
struct FlowSummary {
    owned: usize,
    plans: usize,
    successful: usize,
    failed: usize,
    scan_issues: usize,
    plan_issues: usize,
}

fn run_scan(cli: &Cli, identity_path: &PathBuf, start: u64, end: u64) -> Result<()> {
    let api = build_api(cli, true)?;
    let identity = load_identity(identity_path)?;
    let (owned, scan_issues) = api.scan_slot_range(&identity, start, end)?;
    let summary = ScanSummary {
        owned: owned.iter().map(owned_output_summary).collect(),
        scan_issues: scan_issues.iter().map(issue_from_scan).collect(),
    };

    render(cli, summary, |s| {
        println!("Owned outputs: {}", s.owned.len());
        for out in &s.owned {
            println!(
                "- slot {} sig {} amount {} P {}",
                out.slot, out.signature, out.amount, out.one_time_pubkey
            );
        }
        if !s.scan_issues.is_empty() {
            println!("Scan issues: {}", s.scan_issues.len());
        }
    });
    Ok(())
}

fn build_api(cli: &Cli, require_local_validator: bool) -> Result<UmbraApi> {
    let resolved = resolve_cli_config(cli)?;

    if require_local_validator {
        enforce_localnet(&resolved)?;
    }

    Ok(UmbraApi::new(UmbraApiConfig::new(
        resolved.rpc_url,
        resolved.sweep_destination,
    )))
}

fn identity_file_version() -> u8 {
    IDENTITY_FILE_VERSION
}

impl IdentityFile {
    fn from_identity(identity: &Identity) -> Self {
        Self {
            version: IDENTITY_FILE_VERSION,
            initiator_spend_sk: identity.initiator_spend_sk.to_bytes(),
            initiator_view_sk: identity.initiator_view_sk.to_bytes(),
        }
    }

    fn into_identity(mut self) -> Result<Identity> {
        if self.version != IDENTITY_FILE_VERSION {
            bail!(
                "identity version mismatch: found {}, expected {}",
                self.version,
                IDENTITY_FILE_VERSION
            );
        }

        let spend_bytes = self.initiator_spend_sk;
        let view_bytes = self.initiator_view_sk;

        let spend_scalar = ScalarWrapper::from_bytes(spend_bytes);
        let view_scalar = ScalarWrapper::from_bytes(view_bytes);

        let spend_pubkey = PointWrapper(ED25519_BASEPOINT_POINT * spend_scalar.0);
        let view_pubkey = PointWrapper(ED25519_BASEPOINT_POINT * view_scalar.0);

        self.initiator_spend_sk.zeroize();
        self.initiator_view_sk.zeroize();

        Ok(Identity {
            initiator_spend_sk: spend_scalar,
            initiator_view_sk: view_scalar,
            initiator_spend_pk: spend_pubkey,
            initiator_view_pk: view_pubkey,
        })
    }
}

fn save_identity(path: &PathBuf, identity: &Identity) -> Result<()> {
    let disk = IdentityFile::from_identity(identity);
    let bytes = serde_json::to_vec_pretty(&disk)?;
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn load_identity(path: &PathBuf) -> Result<Identity> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let disk: IdentityFile = serde_json::from_slice(&bytes)?;
    disk.into_identity()
}

fn parse_pubkey(input: &str) -> Result<Pubkey> {
    Pubkey::from_str(input).with_context(|| format!("invalid pubkey: {input}"))
}

fn decode_point(input: &str) -> Result<PointWrapper> {
    let bytes = bs58::decode(input)
        .into_vec()
        .with_context(|| format!("invalid base58 point: {input}"))?;
    if bytes.len() != 32 {
        bail!("expected 32-byte point, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    PointWrapper::from_bytes(arr).ok_or_else(|| anyhow!("point decompression failed"))
}

fn encode_point(point: &PointWrapper) -> String {
    bs58::encode(point.to_bytes()).into_string()
}

fn owned_output_summary(out: &OwnedOutput) -> OwnedOutputSummary {
    OwnedOutputSummary {
        slot: out.slot,
        signature: out.signature.clone(),
        one_time_pubkey: out.one_time_pubkey.to_string(),
        amount: out.amount,
        ephemeral_pubkey: encode_point(&out.memo.ephemeral_pubkey),
    }
}

fn issue_from_scan(issue: &ScanIssue) -> IssueSummary {
    IssueSummary {
        slot: issue.slot,
        signature: issue.signature.clone(),
        error: issue.error.clone(),
    }
}

fn issue_from_plan(issue: &PlanIssue) -> IssueSummary {
    IssueSummary {
        slot: issue.slot,
        signature: issue.signature.clone(),
        error: issue.error.clone(),
    }
}

fn plan_row(plan: &SweepPlan) -> PlanRow {
    PlanRow {
        one_time_pubkey: plan.one_time_pubkey.to_string(),
        destination: plan.destination.to_string(),
        amount: plan.amount,
    }
}

fn render<T, F>(cli: &Cli, value: T, printer: F)
where
    T: Serialize,
    F: FnOnce(&T),
{
    if cli.json {
        if let Ok(out) = serde_json::to_string_pretty(&value) {
            println!("{out}");
            return;
        }
    }
    printer(&value);
}

fn resolve_cli_config(cli: &Cli) -> Result<ResolvedCliConfig> {
    let rpc_url = cli
        .rpc_url
        .clone()
        .or_else(|| default_rpc_url(cli.network))
        .ok_or_else(|| anyhow!("--rpc-url is required for custom network"))?;

    let sweep_destination = cli
        .sweep_destination
        .as_ref()
        .map(|s| parse_pubkey(s))
        .transpose()?
        .or_else(|| default_sweep_destination(cli.network))
        .ok_or_else(|| anyhow!("--sweep-destination is required for this network"))?;

    Ok(ResolvedCliConfig {
        rpc_url,
        sweep_destination,
        network: cli.network,
    })
}

fn default_rpc_url(network: Network) -> Option<String> {
    match network {
        Network::Local => Some(DEFAULT_LOCAL_RPC_URL.to_string()),
        Network::Devnet => Some(DEFAULT_DEVNET_RPC_URL.to_string()),
        Network::Custom => None,
    }
}

fn default_sweep_destination(network: Network) -> Option<Pubkey> {
    match network {
        Network::Local => env::var(DEFAULT_SWEEP_DEST_ENV)
            .ok()
            .map(|v| parse_pubkey(&v))
            .transpose()
            .unwrap_or_else(|_| parse_pubkey(DEFAULT_LOCAL_SWEEP_DESTINATION).ok()),
        Network::Devnet | Network::Custom => None,
    }
}

fn enforce_localnet(config: &ResolvedCliConfig) -> Result<()> {
    if !is_localnet(config) {
        return Ok(());
    }

    let client = RpcClient::new_with_timeout(config.rpc_url.clone(), Duration::from_millis(500));

    // 1. RPC must respond
    client.get_version().map_err(|_| {
        anyhow!(
            "Local Solana validator not detected at {}\nHint: run `solana-test-validator`",
            config.rpc_url
        )
    })?;

    // 2. Must be fresh-ish localnet (slot sanity check)
    let first_slot = client
        .get_first_available_block()
        .map_err(|_| anyhow!("Unable to query first available block"))?;

    if first_slot > 10 {
        bail!(
            "Local Solana validator detected, but ledger is not fresh (first slot = {}).\n\
             Hint: restart with `solana-test-validator --reset`",
            first_slot
        );
    }

    Ok(())
}

fn is_localnet(config: &ResolvedCliConfig) -> bool {
    match config.network {
        Network::Local => true,
        Network::Devnet | Network::Custom => {
            config.rpc_url.contains("127.0.0.1") || config.rpc_url.contains("localhost")
        }
    }
}
