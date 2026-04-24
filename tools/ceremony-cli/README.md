# ceremony-cli

`ceremony-cli` is a Rust wrapper around [`snarkjs`](https://github.com/iden3/snarkjs) focused on a Groth16 BN254 trusted setup workflow for Stellar deployments.

It abstracts ceremony complexity into three commands:

- `init`
- `contribute`
- `finalize`

The tool logs every executed `snarkjs` command, validates input/output paths, refuses overwrites unless `--force` is set, and redacts sensitive parameters in logs.

For full app compatibility after a ceremony, this package also includes a separate helper binary:

- `zkey_to_deployment`

## Security model and guarantees

- Contribution entropy is generated automatically from OS CSPRNG (`getrandom`) inside the CLI.
- Entropy is never printed to the console.
- Logged commands redact sensitive entropy arguments (`-e=[REDACTED]`).
- Entropy buffer is wrapped with `zeroize` and wiped from Rust-managed memory after contribution command execution.

> Note: no software can guarantee removal of all transient copies made by external processes/OS internals. This tool performs best-effort in-process secret hygiene.

## Prerequisites

- `snarkjs` installed and available in `PATH` (e.g. `npm install -g snarkjs`).
- Compiled circuit (`.r1cs`). If `--circuit` is omitted the CLI auto-discovers the compiled `policy_tx_2_2.r1cs` from `target/*/build/circuits-*/out/circuits/` (release profile preferred). Run `cargo build -p circuits --release` to compile.
- A compatible Powers of Tau (`.ptau`) file (see below).

## Powers of Tau

The ceremony requires a Phase 1 Powers of Tau file large enough for the circuit's constraint count.

**Current circuit (`policy_tx_2_2`):** 37,616 constraints → requires **ptau power ≥ 16** (2^16 = 65,536).

Pick the right power: `ceil(log2(num_constraints))`. If unsure, run `npx snarkjs r1cs info $PATH.r1cs` to check.

**Download** from the [Hermez ceremony](https://github.com/iden3/snarkjs#7-prepare-phase-2) (54 contributions + beacon, recommended by snarkjs):

```bash
curl -L -o powersOfTau28_hez_final_16.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau
```

Other powers are available at `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_<POWER>.ptau` (powers 8–28). There are original sources hosted by `iden3`, the creator of snarkjs as well as the official Hermez ceremony artifacts.

Alternative source: [PSE Perpetual Powers of Tau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau) (80 contributions).

---

## Coordinator runbook

The coordinator initializes the ceremony and finalizes outputs.

### 1) Build and prepare

```bash
cargo build -p circuits --release           # compile circuit → produces .r1cs
cargo install --path tools/ceremony-cli    # install CLI to ~/.cargo/bin/

# Download ptau (~72 MB)
curl -L -o powersOfTau28_hez_final_16.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau
```

### 2) Initialize the ceremony

```bash
ceremony-cli init \
  --ptau powersOfTau28_hez_final_16.ptau \
  --output circuit_0000.zkey
```

The CLI auto-discovers the compiled `.r1cs` from the build output. You can override with `--circuit <path>` if needed.

This executes:

- `snarkjs groth16 setup ...`
- `snarkjs zkey verify ...`

Share `circuit_0000.zkey` and the `.ptau` file (or its download URL) with the first contributor.

### 3) Collect contributions

Each contributor returns a new `.zkey` to pass to the next contributor.

### 4) Finalize ceremony artifacts

```bash
ceremony-cli finalize \
  --zkey circuit_final_contrib.zkey \
  --beacon-hash $BEACON_HASH \
  --beacon-power 10 \
  --out-dir ./artifacts \
  --basename circuit
```

This executes:

- `snarkjs zkey beacon ...`
- `snarkjs zkey export verificationkey ...`

Outputs:

- `artifacts/circuit_final.zkey`
- `artifacts/circuit_verification_key.json`

Publish these with the ceremony transcript and beacon parameters.

### 5) Generate repo deployment artifacts

If you want the web prover and deployment files to use the final ceremony key material, convert the final `.zkey` into the repo-specific formats:

```bash
cargo run -p ceremony-cli --bin zkey_to_deployment -- \
  --zkey ./artifacts/circuit_final.zkey \
  --out-dir ./deployments/testnet/circuit_keys \
  --basename policy_tx_2_2 \
  --force
```

This generates:

- `deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin`
- `deployments/testnet/circuit_keys/policy_tx_2_2_vk.json`
- `deployments/testnet/circuit_keys/policy_tx_2_2_vk_soroban.bin`
- `deployments/testnet/circuit_keys/policy_tx_2_2_vk_const.rs`

Why this step exists:

- `artifacts/circuit_verification_key.json` is enough to redeploy the verifier contract.
- the app prover also needs `policy_tx_2_2_proving_key.bin`, which is an arkworks-serialized `ProvingKey<Bn254>`, not a `snarkjs` `.zkey`
- `vk_soroban.bin` and `vk_const.rs` are alternate verifier encodings used by this repo

Internally, the helper exports the `.zkey` to JSON with `snarkjs`, reconstructs the arkworks proving key, writes `proving_key.bin`, and emits the verifier artifacts in the same formats as `circuits/build.rs`.

---

## Contributor runbook

Each contributor receives an input `.zkey` and produces a new `.zkey`.

### Quick start

```bash
# One-time setup
cargo build -p circuits --release           # compile circuit (for verification)
cargo install --path tools/ceremony-cli    # install CLI to ~/.cargo/bin/

# Download ptau (~72 MB, if not provided by coordinator)
curl -L -o powersOfTau28_hez_final_16.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau

# Contribute (only 3 required args)
ceremony-cli contribute \
  --zkey circuit_0000.zkey \
  --ptau powersOfTau28_hez_final_16.ptau \
  --output circuit_0001.zkey \
  --name "$NAME"
```

The CLI auto-discovers the compiled `.r1cs` from the build output. No need to locate it manually.

This executes:

- `snarkjs zkey verify ...` (pre-verifies the input zkey before contribution)
- `snarkjs zkey contribute ... -e=[generated entropy]`
- `snarkjs zkey verify ...` (verifies your output zkey)

What to share with coordinator:

- only your output `.zkey` (for example `circuit_0001.zkey`)

What not to share:

- any local environment details, shell history snapshots, recordings, or logs beyond normal CLI output.

The CLI already keeps entropy internal, redacted, and zeroized after use.

## Force overwrite

Add `--force` to overwrite existing output files if needed.
