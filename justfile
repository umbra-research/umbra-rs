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
# Run all tests (unit + local)
# -------------------------------
test:
    just test-unit
    just test-local


# -------------------------------
# Full CI
# -------------------------------
ci:
    just format
    just clippy
    just test