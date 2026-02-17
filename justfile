# ============================================================
# Umbra Development Commands
# ============================================================

set shell := ["bash", "-cu"]

# -------------------------------
# Format + Lint
# -------------------------------
format:
    cargo fmt --all

clippy:
    cargo clippy --workspace --all-targets -- -D warnings


# -------------------------------
# Unit Tests (all crates)
# -------------------------------
test-unit:
    cargo test --workspace --lib -- --nocapture


# -------------------------------
# Local Integration Tests
# (tests/env_local.rs + tests/local/*)
# -------------------------------
test-local:
    cargo test -p umbra --test env_local -- --nocapture

# -------------------------------
# Full Integration Tests
# umbra_full_flow.rs
# -------------------------------
test-full:
    cargo test -p umbra --test umbra_full_flow -- --nocapture

# -------------------------------
# Devnet Integration Tests
# (tests/env_devnet.rs + tests/devnet/*)
# -------------------------------
test-devnet:
    cargo test -p umbra --test env_devnet -- --nocapture

# -------------------------------
# Test cli commands
# -------------------------------
test-cli:
    cargo test -p umbra --test cli_test -- --nocapture


# -------------------------------
# Run all tests (unit + local)
# -------------------------------
test:
    just test-unit
    just test-local


# -------------------------------
# Full CI
# -------------------------------
ci:
    just test
# -------------------------------
# Backend Services
# -------------------------------
run-system:
    cd ../umbra-system && cargo run
# -------------------------------
# Program Commands
# -------------------------------
build-program:
    cd crates/program && cargo build-sbf

deploy-program:
    # Requires solana-test-validator running
    cd crates/program && solana program-v4 deploy --keypair ../../wallet.json --program-keypair target/sbf/deploy/umbra_program-keypair.json target/deploy/umbra_program.so

# -------------------------------
# WASM Commands
# -------------------------------
build-wasm:
    cd crates/wasm && wasm-pack build --target web