Umbra (Solana) — Project Documentation (Brief)

Status: v0.1.0 Release Candidate. This document outlines the core architecture.

# Umbra Protocol Library

## Overview

This directory contains the core Rust implementation of the Umbra protocol. It is designed as a standalone workspace providing all necessary components to build privacy-preserving applications on Solana.

## Crates Overview

The workspace is modular, consisting of the following crates:

| Crate | Purpose | Dependencies |
|-------|---------|--------------|
| **`umbra-core`** | Pure cryptography & logic | None (Pure Rust) |
| **`umbra-rpc`** | Solana RPC interaction | `solana-sdk` |
| **`umbra-api`** | Common types & interfaces | `umbra-core` |
| **`umbra-client`** | High-level wallet/SDK | `umbra-rpc`, `umbra-storage` |
| **`umbra-storage`** | Local key/state management | `serde` |
| **`umbra-sweep`** | Logic for sweeping funds | `umbra-rpc` |

---

## 1. `umbra-core`
**The Cryptographic Heart.**  
Contains all pure logic for key derivation and identity management. Zero network dependencies, suitable for WASM/Embedded.
- **Features**: Elliptic curve math (Ristretto), stealth address derivation, shared secret computation.

## 2. `umbra-rpc`
**The Blockchain Connector.**
Handles low-level interaction with Solana nodes.
- **Features**: Memo parsing (`UMBR` protocol), efficient block scanning, transaction instruction building.

## 3. `umbra-api`
**The Interface Layer.**
Defines the common data structures and traits used across the ecosystem.
- **Features**: `SendRequest`, `InboxItem` types, and trait definitions for custom implementations.

## 4. `umbra-storage`
**Secure Persistence.**
Manages the local storage of user identities and transaction history.
- **Features**: Encrypted key storage (file-based or custom backend), scanning cursor state management.

## 5. `umbra-sweep`
**The Claim Executor.**
Dedicated logic for moving funds from stealth addresses to a destination wallet.
- **Features**: Robust sweeping algorithm, handles rent exemption, multiple output sweeping.

## 6. `umbra-client`
**The High-Level SDK.**
Combines all above crates into a simple, developer-friendly client.
- **Features**:
    - `scan_and_cache()`: Background scanning logic.
    - `send_stealth()`: One-line function to send privacy transfers.
    - `sweep_all()`: One-line function to claim all funds.

### Usage Example (Client)
```rust
use umbra_client::UmbraClient;

let client = UmbraClient::new("https://api.devnet.solana.com", storage_provider);

// Send
client.send_stealth(&recipient_id, 1.5).await?;

// Scan & Claim
let balance = client.sync().await?;
if balance > 0.0 {
    client.sweep_to_wallet(&my_main_wallet).await?;
}
```
