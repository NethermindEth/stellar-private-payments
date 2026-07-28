//! Local witness + Groth16 bench for a deposit into `policy_tx_2_2_B`.
//!
//! No RPC. Times only:
//!   1. `WitnessCalculator::compute_witness` (circom-witness-rs graph)
//!   2. `Prover::prove_bytes`
//!
//! Usage (repo root, release circuits + graphs already built):
//! ```text
//! cargo run -p sdk-tests --release --bin prove_bench
//! cargo run -p sdk-tests --release --bin prove_bench -- 20
//! ```
//!
//! Env overrides:
//! - `CIRCUITS_DIR` — r1cs dir (default: `target/circuits-artifacts/release`)
//! - `KEYS_DIR` — proving key dir (default: `deployments/testnet/circuit_keys`)
//! - `GRAPH_DIR` — graph dir (default: `KEYS_DIR`, then committed
//!   `circuit_keys`)
//! - `BENCH_WARMUP` — discarded runs (default: 1)

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use stellar_private_payments_sdk::{
    chain::hash_ext_data_offchain,
    proving::{Prover, WitnessCalculator},
    tx::{
        encryption::derive_encryption_and_note_keypairs,
        flows::{DepositParams, TransactOutput, deposit},
    },
};
use types::{
    AspNonMembershipProof, ExtAmount, Field, KeyDerivationSignature, NoteAmount, PolicyFlags,
    SMT_DEPTH,
};

const STEM: &str = "policy_tx_2_2_B";
const TREE_DEPTH: u32 = 10;

fn main() -> Result<()> {
    let iters: usize = env::args()
        .nth(1)
        .map(|s| s.parse())
        .transpose()
        .context("iters must be a positive integer")?
        .unwrap_or(10);
    ensure!(iters > 0, "iters must be > 0");
    let warmup: usize = env::var("BENCH_WARMUP")
        .ok()
        .map(|s| s.parse())
        .transpose()
        .context("BENCH_WARMUP must be an integer")?
        .unwrap_or(1);

    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let circuits_dir = env::var_os("CIRCUITS_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("CARGO_TARGET_DIR")
                .map(|td| PathBuf::from(td).join("circuits-artifacts").join("release"))
        })
        .unwrap_or_else(|| repo.join("target/circuits-artifacts/release"));
    let keys_dir = env::var_os("KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join("deployments/testnet/circuit_keys"));
    let committed_keys = repo.join("deployments/testnet/circuit_keys");
    let graph_dir = env::var_os("GRAPH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| keys_dir.clone());

    let pk = fs::read(keys_dir.join(format!("{STEM}_proving_key.bin")))
        .with_context(|| format!("read proving key under {}", keys_dir.display()))?;
    let graph_path = {
        let primary = graph_dir.join(format!("{STEM}.graph.bin"));
        if primary.is_file() {
            primary
        } else {
            committed_keys.join(format!("{STEM}.graph.bin"))
        }
    };
    let graph =
        fs::read(&graph_path).with_context(|| format!("read graph at {}", graph_path.display()))?;
    let r1cs = fs::read(circuits_dir.join(format!("{STEM}.r1cs")))
        .with_context(|| format!("read r1cs under {}", circuits_dir.display()))?;

    println!("stem={STEM}");
    println!("circuits_dir={}", circuits_dir.display());
    println!("keys_dir={}", keys_dir.display());
    println!("graph={}", graph_path.display());
    println!("warmup={warmup} iters={iters}");
    println!(
        "artifact sizes: pk={} graph={} r1cs={}",
        pk.len(),
        graph.len(),
        r1cs.len()
    );

    let witness_calc = WitnessCalculator::from_graph(&graph).context("init WitnessCalculator")?;
    let prover = Prover::new(&pk, &r1cs).context("init Groth16 Prover")?;

    let inputs_json = build_deposit_inputs_json()?;
    println!("circuit_inputs_json_bytes={}", inputs_json.len());

    // Correctness check once (not timed).
    let witness_bytes = witness_calc
        .compute_witness(&inputs_json)
        .context("warmup witness")?;
    let proof = prover.prove_bytes(&witness_bytes).context("warmup prove")?;
    let public_inputs = prover.extract_public_inputs(&witness_bytes)?;
    ensure!(
        prover.verify(&proof, &public_inputs)?,
        "proof verification failed — aborting bench"
    );
    println!(
        "check ok: witness_elems={} proof_bytes={}",
        witness_bytes.len() / 32,
        proof.len()
    );

    for _ in 0..warmup {
        let w = witness_calc.compute_witness(&inputs_json)?;
        let _ = prover.prove_bytes(&w)?;
    }

    let mut witness_total = Duration::ZERO;
    let mut prove_total = Duration::ZERO;
    for i in 1..=iters {
        let t0 = Instant::now();
        let w = witness_calc.compute_witness(&inputs_json)?;
        let witness_dt = t0.elapsed();

        let t1 = Instant::now();
        let _ = prover.prove_bytes(&w)?;
        let prove_dt = t1.elapsed();

        witness_total += witness_dt;
        prove_total += prove_dt;
        println!(
            "run {i:>2}: witness={:.3}s  groth16={:.3}s  total={:.3}s",
            witness_dt.as_secs_f64(),
            prove_dt.as_secs_f64(),
            (witness_dt + prove_dt).as_secs_f64()
        );
    }

    let n = iters as f64;
    let w_avg = witness_total.as_secs_f64() / n;
    let p_avg = prove_total.as_secs_f64() / n;
    println!("---");
    println!("avg witness:  {w_avg:.3}s");
    println!("avg groth16:  {p_avg:.3}s");
    println!("avg total:    {:.3}s", w_avg + p_avg);

    Ok(())
}

fn build_deposit_inputs_json() -> Result<String> {
    let signature = KeyDerivationSignature(vec![42u8; 64]);
    let (note_keypair, encryption_keypair) = derive_encryption_and_note_keypairs(signature)?;
    let key = Field::try_from_le_bytes(*note_keypair.public.as_ref())?;
    let smt_depth = usize::try_from(SMT_DEPTH).context("SMT_DEPTH")?;

    let artifacts = deposit(
        DepositParams {
            priv_key: note_keypair.private,
            encryption_pubkey: encryption_keypair.public,
            pool_root: Field::ZERO,
            pool_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
            amount: ExtAmount::from(1),
            outputs: vec![TransactOutput {
                amount: NoteAmount::from(1u128),
                blinding: Field::try_from_le_bytes({
                    let mut b = [0u8; 32];
                    b[0] = 7;
                    b
                })?,
                recipient_note_pubkey: None,
                recipient_encryption_pubkey: None,
            }],
            membership_proof: None,
            non_membership_proof: Some(AspNonMembershipProof {
                key,
                old_key: Field::ZERO,
                old_value: Field::ZERO,
                is_old0: true,
                siblings: vec![Field::ZERO; smt_depth],
                root: Field::ZERO,
            }),
            tree_depth: TREE_DEPTH,
            smt_depth: SMT_DEPTH,
            policy_flags: PolicyFlags::BLOCKLIST,
        },
        hash_ext_data_offchain,
    )
    .context("build deposit circuit inputs")?;

    serde_json::to_string(&artifacts.circuit_inputs).context("serialize circuit inputs")
}
