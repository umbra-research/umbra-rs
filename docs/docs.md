# Umbra (Solana) — System Architecture

**Status**: v0.1.0 Release.

## Overview

The Umbra system is designed modularly to separate cryptographic logic, blockchain interaction, and user-facing applications. This ensures auditability and maintainability.

## Component Stack

### 1. Core Layer (`crates/umbra-core` & `crates/umbra-program`)
*   **`umbra-core`**: The source of truth for all cryptography.
    *   **Implements**: Ristretto Group Operations (using `curve25519-dalek`), Stealth Address Derivation (ECDH), Shared Secret Hashing.
    *   **Usage**: Used by Client, Relayer, and WASM bindings.
*   **`umbra-program`**: The on-chain Anchor program.
    *   **Implements**: `send_stealth` (SOL/SPL), `withdraw`, `withdraw_with_relayer`.
    *   **Safety**: Verifies Ed25519 signatures for gasless withdrawals and ensures strict PDA derivations.

### 2. Interaction Layer (`crates/umbra-client` & `crates/umbra-rpc`)
*   **`umbra-rpc`**: Handles Solana RPC transport.
    *   **Features**: Block fetching, Transaction serialization, Log parsing.
*   **`umbra-client`**: The High-Level SDK.
    *   **Features**:
        *   **Scanning**: efficiently scans blocks for `StealthAnnouncement` events.
        *   **Output Management**: Decrypts announcements to check ownership.
        *   **Sweeping**: Builds transactions to move funds from stealth PDAs to real wallets.

### 3. Service Layer (`crates/umbra-indexer` & `crates/umbra-relayer`)
*   **`umbra-indexer`**:
    *   **Role**: Persistent observer. Listens to the chain and stores potential outputs in a local DB (JSON/Postgres) to prevent re-scanning from genesis.
    *   **Resiliency**: Handles basic chain re-orgs/rollbacks.
*   **`umbra-relayer`**:
    *   **Role**: Privacy Proxy. Allows users to submit "Withdraw Requests" (signed off-chain) to this service.
    *   **Mechanism**: The relayer submits the transaction on-chain, paying the gas fees. The program deducts a `fee` from the withdrawal amount and reimburses the relayer in the same atomic transaction.

## Data Flow

1.  **Sender** generates `Ephemeral Secret` and derives `Stealth Pubkey` (via `umbra-core`).
2.  **Sender** invokes `umbra-program::send_stealth` (via `umbra-client`).
3.  **Program** transfers funds to PDA and emits `StealthAnnouncement` event.
4.  **Indexer** (or Client) sees event.
5.  **Recipient**'s Client derives `Shared Secret` from event data.
6.  **Recipient** checks if `H(Shared Secret) == Tag`. If yes, they own it.
7.  **Recipient** sweeps funds (directly or via Relayer).

## Security Model

*   **Non-Custodial**: The protocol never holds keys. Stealth PDAs are program-derived addresses that only the holder of the recipient's private view key can derive the spend key for.
*   **Linkability**: Observers see a transfer to a unique, random address. Only the sender and receiver know the link.
*   **Relayer Privacy**: The Relayer knows the IP address of the claimant unless Tor/VPN is used, but the on-chain link remains broken.
