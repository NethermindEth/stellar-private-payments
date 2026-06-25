# ZK Vote Proof Generator

Off-chain proof generation service for the Social Prediction Market.

## Overview

This tool generates zero-knowledge proofs for vote submissions without revealing:
- The actual vote value
- The voter's identity
- The mapping between voter and vote

## Prerequisites

1. Node.js 18+
2. Circuit artifacts (run `make setup && make zkey` in project root)

## Installation

```bash
cd tools/prover
npm install
```

## Usage

### Generate a Vote Proof

```bash
node src/index.js prove <vote> [nonce] [voterSecret] [nullifierRoot]

Arguments:
  vote          - 0 (no) or 1 (yes)
  nonce         - Random value to hide the vote (optional, auto-generated)
  voterSecret   - Secret to generate nullifier (optional, auto-generated)
  nullifierRoot - Merkle root of nullifier tree (optional)
```

Example:
```bash
node src/index.js prove 1 12345 67890
```

### Verify a Proof

```bash
node src/index.js verify '<proof>' '<publicSignals>'
```

## How It Works

1. **Vote Commitment**: `H(vote, nonce)` hides the vote value
2. **Nullifier**: `H(voterSecret)` creates a unique identifier to prevent double-voting
3. **Merkle Proof**: Proves the nullifier is in the nullifier set
4. **ZK Proof**: Proves all constraints without revealing inputs

## Circuit Details

- **Constraints**: 2910 non-linear
- **Public inputs**: nullifier_root, vote_commitment
- **Private inputs**: nonce, vote, nullifier_path_elements, nullifier_path_indices, nullifier
- **Tree depth**: 10 levels

## Flow

```
Voter                    Prover                    Contract
  │                         │                          │
  │── vote=1, nonce ───────>│                          │
  │                         │                          │
  │                    Generate proof                  │
  │                    (off-chain)                    │
  │                         │                          │
  │<── proof, commitment ───│                          │
  │                         │                          │
  │────────────────────────────────────────> submit_vote()
  │                         │                          │
  │                         │                     Store commitment
  │                         │                     Increment counter
```
