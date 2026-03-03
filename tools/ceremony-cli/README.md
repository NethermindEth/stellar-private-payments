# ceremony-cli

`ceremony-cli` is a Rust wrapper around [`snarkjs`](https://github.com/iden3/snarkjs) focused on a Groth16 BN254 trusted setup workflow for Stellar deployments.

It abstracts ceremony complexity into three commands:

- `init`
- `contribute`
- `finalize`

The tool logs every executed `snarkjs` command, validates input/output paths, refuses overwrites unless `--force` is set, and redacts sensitive parameters in logs.

## Security model and guarantees

- Contribution entropy is generated automatically from OS CSPRNG (`getrandom`) inside the CLI.
- Entropy is never printed to the console.
- Logged commands redact sensitive entropy arguments (`-e [REDACTED]`).
- Entropy buffer is wrapped with `zeroize` and wiped from Rust-managed memory after contribution command execution.

> Note: no software can guarantee removal of all transient copies made by external processes/OS internals. This tool performs best-effort in-process secret hygiene.

## Prerequisites

- `snarkjs` installed and available in `PATH`.
- circuit file(s). If omitted, CLI defaults to `circuits/src/policyTransaction.circom` and resolves it to the corresponding `.r1cs`.
- compatible `.ptau` file.

---

## Coordinator runbook

The coordinator initializes the ceremony and finalizes outputs.

### 1) Initialize the ceremony

```bash
ceremony-cli init \
  --ptau powersOfTau28_hez_final_10.ptau \
  --output circuit_0000.zkey
```

(You can still override with `--circuits <path>`.)

This executes:

- `snarkjs groth16 setup ...`
- `snarkjs zkey verify ...`

Share `circuit_0000.zkey` with the first contributor.

### 2) Collect contributions

Each contributor returns a new `.zkey` to pass to the next contributor.

### 3) Finalize ceremony artifacts

```bash
ceremony-cli finalize \
  --zkey circuit_final_contrib.zkey \
  --beacon-hash 0123456789abcdef0123456789abcdef \
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

---

## Contributor runbook

Each contributor receives an input `.zkey` and produces a new `.zkey`.

```bash
ceremony-cli contribute \
  --zkey circuit_0000.zkey \
  --ptau powersOfTau28_hez_final_10.ptau \
  --output circuit_0001.zkey \
  --name "contributor-1"
```

This executes:

- `snarkjs zkey verify ...` (pre-verifies the input zkey before contribution)
- `snarkjs zkey contribute ... -e [generated entropy]`
- `snarkjs zkey verify ...` (verifies your output zkey)

What to share with coordinator:

- only your output `.zkey` (for example `circuit_0001.zkey`)

What not to share:

- any local environment details, shell history snapshots, recordings, or logs beyond normal CLI output.

The CLI already keeps entropy internal, redacted, and zeroized after use.
By default, it uses `circuits/src/policyTransaction.circom` (resolved to `.r1cs`) unless `--circuits` is provided.

## Force overwrite

Add `--force` to overwrite existing output files if needed.
