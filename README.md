# Umbra-RS — Stealth Payments on Solana

**Umbra** is a privacy-preserving payment protocol on Solana. It enables senders to transfer SOL and SPL Tokens (including Token-2022 Confidential Transfers) to recipients without revealing their real wallet address / identity on-chain.

> ⚠️ **Beta Software**: This software is in active development (v0.1.0) and has not yet been audited. Use at your own risk.

## 🚀 Key Features

*   **Stealth Addresses**: Cryptographically derived one-time addresses using ECDH (Elliptic Curve Diffie-Hellman) ensures linkability is broken between sender and receiver.
*   **SPL Token Support**: Full support for standard SPL Tokens and **Token-2022** (including Confidential Transfers).
*   **Gasless Withdrawals**: Integrated Relayer service allows recipients to withdraw funds without needing SOL in their stealth wallet (Relayer pays fees in exchange for a cut).
*   **Modular Architecture**:
    *   **Core**: Pure Rust cryptography library (`umbra-core`).
    *   **Program**: Anchor-based on-chain program (`umbra-program`).
    *   **Services**: Dockerized Indexer and Relayer for high-availability deployments.

## 🏗️ Architecture

The workspace is organized into the following crates:

| Crate | Description |
|-------|-------------|
| `crates/umbra-core` | Core cryptographic primitives (Curve25519, hashing, address derivation). |
| `crates/umbra-program` | Solana Program (Anchor) handling on-chain transfers and withdrawals. |
| `crates/umbra-client` | Rust SDK for client-side integration (scanning, sweeping, transaction building). |
| `crates/umbra-rpc` | RPC wrappers and type definitions logic for safe Solana interaction. |
| `crates/umbra-indexer` | Service that listens for `StealthAnnouncement` events and indexes them. |
| `crates/umbra-relayer` | HTTP service enabling gasless withdrawals via signature verification. |
| `bins/umbra-cli` | Command-line interface for managing identities and operations. |

## 🛠️ Getting Started

### Prerequisites

*   **Rust**: 1.79+ (Stable)
*   **Solana Toolchain**: 1.18.x or later
*   **Docker**: (Optional, for running services)

### Installation (CLI)

Install the CLI tool locally:

```bash
cargo install --path bins/umbra-cli
```

### Usage (CLI)

1.  **Generate Identity**:
    ```bash
    umbra identity generate --export my_identity.json
    ```

2.  **Send Stealth Payment**:
    ```bash
    # Sends 1.5 SOL to the recipient's identity file path
    umbra send build --recipient recipient_identity.json --payer <PAYER_KEYPAIR> --amount 1500000000
    ```

3.  **Scan for Funds**:
    ```bash
    umbra scan range --identity my_identity.json --start 0 --end 1000
    ```

4.  **Sweep Funds**:
    ```bash
    umbra sweep execute --identity my_identity.json --start 0 --end 1000 --confirm
    ```

## 🐳 Docker Deployment

The system infrastructure (`indexer` and `relayer`) is fully Dockerized.

### Build the Image

```bash
docker build -t umbra-system .
```

### Run Indexer

```bash
docker run -d --name umbra-indexer \
  -v $(pwd)/umbra_db:/usr/local/bin/umbra_db \
  umbra-system:indexer \
  /usr/local/bin/umbra-indexer \
  --rpc-url https://api.devnet.solana.com \
  --program-id <PROGRAM_ID>
```

### Run Relayer

```bash
docker run -d --name umbra-relayer \
  -p 3000:3000 \
  -v $(pwd)/relayer-keypair.json:/usr/local/bin/keypair.json \
  umbra-system:relayer \
  /usr/local/bin/umbra-relayer \
  --rpc-url https://api.devnet.solana.com \
  --keypair /usr/local/bin/keypair.json \
  --program-id <PROGRAM_ID>
```

## 🧪 Development

### Build Workspace

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Build Anchor Program

```bash
anchor build -p umbra-program
```

## 📄 License

MIT License. See `LICENSE` for details.
