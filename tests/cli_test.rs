use std::{
    env,
    path::PathBuf,
    process::Command,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use solana_sdk::pubkey::Pubkey;

const DEFAULT_SWEEP_DESTINATION: &str = "11111111111111111111111111111111";

static CLI_BIN: OnceLock<PathBuf> = OnceLock::new();

use tracing::info;
#[test]
fn send_build_works_with_default_localnet_flags() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let binary = cli_binary();
    let recipient = temp_path("recipient");
    generate_identity(&binary, &recipient);

    let payer = Pubkey::new_unique().to_string();

    info!("Using payer: {}", payer);

    let output = Command::new(&binary)
        .env("UMBRA_SWEEP_DESTINATION", DEFAULT_SWEEP_DESTINATION)
        .args([
            "send",
            "build",
            "--recipient",
            recipient.to_str().unwrap(),
            "--payer",
            &payer,
            "--amount",
            "5",
            "--json",
        ])
        .output()
        .expect("failed to run send build");

    info!("output: {:?}", output);

    assert!(
        output.status.success(),
        "send build should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout).expect("valid JSON output");

    assert!(
        parsed.get("one_time_pubkey").is_some(),
        "one_time_pubkey missing from JSON"
    );
    assert!(
        parsed.get("memo_base64").is_some(),
        "memo_base64 missing from JSON"
    );
}

#[test]
fn sweep_plan_fails_fast_when_localnet_unavailable() {
    let binary = cli_binary();
    let identity = temp_path("sweep-identity");
    generate_identity(&binary, &identity);

    let output = Command::new(&binary)
        .env("UMBRA_SWEEP_DESTINATION", DEFAULT_SWEEP_DESTINATION)
        .args([
            "sweep",
            "plan",
            "--identity",
            identity.to_str().unwrap(),
            "--start",
            "0",
            "--end",
            "0",
        ])
        .output()
        .expect("failed to run sweep plan");

    info!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    assert!(
        !output.status.success(),
        "sweep plan should fail without local validator"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Local Solana validator not detected"),
        "expected local validator error, got: {stderr}"
    );
}

fn cli_binary() -> PathBuf {
    CLI_BIN
        .get_or_init(|| {
            let status = Command::new("cargo")
                .args(["build", "-p", "umbra-cli"])
                .status()
                .expect("failed to build umbra-cli");
            assert!(status.success(), "cargo build -p umbra-cli failed");

            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path.push("target");
            path.push("debug");
            path.push("umbra-cli");
            path
        })
        .clone()
}

fn generate_identity(binary: &PathBuf, path: &PathBuf) {
    let output = Command::new(binary)
        .args(["identity", "generate", "--export", path.to_str().unwrap()])
        .output()
        .expect("failed to generate identity");

    assert!(
        output.status.success(),
        "identity generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn temp_path(label: &str) -> PathBuf {
    let mut path = env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    path.push(format!(
        "umbra-cli-test-{label}-{}-{nanos}.json",
        std::process::id()
    ));
    path
}
