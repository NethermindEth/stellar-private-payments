use super::{
    circom_tester::{InputValue, prove_and_verify},
    keypair::{derive_public_key, sign},
    merkle_tree::{merkle_proof, merkle_root},
    transaction::{commitment, nullifier, prepopulated_leaves},
};
use crate::test::utils::general::scalar_to_bigint;

use anyhow::{Context, Result};
use num_bigint::BigInt;
use std::panic::AssertUnwindSafe;
use std::{collections::HashMap, env, panic, path::PathBuf};
use zkhash::ark_ff::Zero;
use zkhash::fields::bn256::FpBN256 as Scalar;

const LEVELS: usize = 5;

#[derive(Clone, Debug)]
struct InputNote {
    priv_key: Scalar,
    blinding: Scalar,
    amount: Scalar,
}

#[derive(Clone, Debug)]
struct OutputNote {
    pub_key: Scalar,
    blinding: Scalar,
    amount: Scalar,
}

struct TxCase {
    real_idx: usize,
    in0: InputNote,
    in1: InputNote,
    out0: OutputNote,
    out1: OutputNote,
}

#[allow(clippy::too_many_arguments)]
impl TxCase {
    fn new(
        real_idx: usize,
        in0: InputNote,
        in1: InputNote,
        out0: OutputNote,
        out1: OutputNote,
    ) -> Self {
        Self {
            real_idx,
            in0,
            in1,
            out0,
            out1,
        }
    }
}

/// Runs one Transaction(5,2,2) case
#[allow(clippy::arithmetic_side_effects)]
fn run_case(
    wasm: &PathBuf,
    r1cs: &PathBuf,
    case: &TxCase,
    mut leaves: Vec<Scalar>,
    public_amount: Scalar,
) -> Result<()> {
    // === INPUT UTXOs ===
    let in0_pub = derive_public_key(case.in0.priv_key);
    let in1_pub = derive_public_key(case.in1.priv_key);

    let in0_commit = commitment(case.in0.amount, in0_pub, case.in0.blinding);
    let in1_commit = commitment(case.in1.amount, in1_pub, case.in1.blinding);

    // === MERKLE TREE ===
    leaves[0] = in0_commit;
    leaves[case.real_idx] = in1_commit;

    let root_scalar = merkle_root(leaves.clone());
    let (pe0, path_idx0_u64, depth0) = merkle_proof(&leaves, 0);
    let (pe1, path_idx1_u64, depth1) = merkle_proof(&leaves, case.real_idx);

    // Sanity check: both paths must match the circuit depth
    assert_eq!(depth0, LEVELS, "unexpected depth for input 0");
    assert_eq!(depth1, LEVELS, "unexpected depth for input 1");

    // === PATH CONVERSION ===
    let path_elems0: Vec<BigInt> = pe0.into_iter().map(scalar_to_bigint).collect();
    let path_elems1: Vec<BigInt> = pe1.into_iter().map(scalar_to_bigint).collect();
    let path_idx0 = Scalar::from(path_idx0_u64);
    let path_idx1 = Scalar::from(path_idx1_u64);

    // === SIGNATURES & NULLIFIERS ===
    let in0_sig = sign(case.in0.priv_key, in0_commit, path_idx0);
    let in1_sig = sign(case.in1.priv_key, in1_commit, path_idx1);
    let in0_null = nullifier(in0_commit, path_idx0, in0_sig);
    let in1_null = nullifier(in1_commit, path_idx1, in1_sig);

    // === OUTPUTS ===
    let out0_commit = commitment(case.out0.amount, case.out0.pub_key, case.out0.blinding);
    let out1_commit = commitment(case.out1.amount, case.out1.pub_key, case.out1.blinding);

    // === WITNESS MAP ===
    let mut inputs: HashMap<String, InputValue> = HashMap::new();

    // === Public signals ===
    inputs.insert(
        "root".into(),
        InputValue::Single(scalar_to_bigint(root_scalar)),
    );
    inputs.insert(
        "publicAmount".into(),
        InputValue::Single(scalar_to_bigint(public_amount)),
    );
    inputs.insert("extDataHash".into(), InputValue::Single(BigInt::from(0u32)));

    // === Private signals ===
    inputs.insert(
        "inputNullifier".into(),
        InputValue::Array(vec![scalar_to_bigint(in0_null), scalar_to_bigint(in1_null)]),
    );
    inputs.insert(
        "inAmount".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.in0.amount),
            scalar_to_bigint(case.in1.amount),
        ]),
    );
    inputs.insert(
        "inPrivateKey".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.in0.priv_key),
            scalar_to_bigint(case.in1.priv_key),
        ]),
    );
    inputs.insert(
        "inBlinding".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.in0.blinding),
            scalar_to_bigint(case.in1.blinding),
        ]),
    );
    inputs.insert(
        "inPathIndices".into(),
        InputValue::Array(vec![
            scalar_to_bigint(path_idx0),
            scalar_to_bigint(path_idx1),
        ]),
    );

    // Flattened path elements
    let mut in_path_elements_flat = Vec::with_capacity(path_elems0.len() + path_elems1.len());
    in_path_elements_flat.extend(path_elems0);
    in_path_elements_flat.extend(path_elems1);
    inputs.insert(
        "inPathElements".into(),
        InputValue::Array(in_path_elements_flat),
    );

    inputs.insert(
        "outputCommitment".into(),
        InputValue::Array(vec![
            scalar_to_bigint(out0_commit),
            scalar_to_bigint(out1_commit),
        ]),
    );
    inputs.insert(
        "outAmount".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.out0.amount),
            scalar_to_bigint(case.out1.amount),
        ]),
    );
    inputs.insert(
        "outPubkey".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.out0.pub_key),
            scalar_to_bigint(case.out1.pub_key),
        ]),
    );
    inputs.insert(
        "outBlinding".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.out0.blinding),
            scalar_to_bigint(case.out1.blinding),
        ]),
    );

    // === PROVE & VERIFY ===
    let prove_result =
        panic::catch_unwind(AssertUnwindSafe(|| prove_and_verify(wasm, r1cs, &inputs)));

    match prove_result {
        // Successful call to prove_and_verify
        Ok(Ok(res)) => {
            if res.verified {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "Proof failed to verify (res.verified=false)"
                ))
            }
        }

        // prove_and_verify returned an Err, most likely build failure
        Ok(Err(e)) => Err(anyhow::anyhow!("Prover error: {e:?}")),

        // prove_and_verify panicked (unsatisfied constraint, etc.), Used for test that should fail
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            Err(anyhow::anyhow!(
                "Prover panicked (expected on invalid proof): {msg}"
            ))
        }
    }
}

fn load_artifacts() -> Result<(PathBuf, PathBuf)> {
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/transaction2_js/transaction2.wasm");
    let r1cs = out_dir.join("transaction2.r1cs");
    anyhow::ensure!(wasm.exists(), "WASM not found at {}", wasm.display());
    anyhow::ensure!(r1cs.exists(), "R1CS not found at {}", r1cs.display());
    Ok((wasm, r1cs))
}

#[tokio::test]
async fn test_tx_1in_1out() -> Result<()> {
    // One real input (in1), one dummy input (in0.amount = 0).
    // One real output (out0 = in1.amount), one dummy output (out1.amount = 0).
    let (wasm, r1cs) = load_artifacts()?;

    let case = TxCase::new(
        7,
        InputNote {
            priv_key: Scalar::from(101u64),
            blinding: Scalar::from(201u64),
            amount: Scalar::from(0u64),
        }, // dummy
        InputNote {
            priv_key: Scalar::from(111u64),
            blinding: Scalar::from(211u64),
            amount: Scalar::from(13u64),
        }, // real
        OutputNote {
            pub_key: Scalar::from(501u64),
            blinding: Scalar::from(601u64),
            amount: Scalar::from(13u64),
        }, // real
        OutputNote {
            pub_key: Scalar::from(502u64),
            blinding: Scalar::from(602u64),
            amount: Scalar::from(0u64),
        }, // dummy
    );

    let leaves = prepopulated_leaves(LEVELS, 0xDEAD_BEEFu64, &[0, case.real_idx], 24);

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64))
}

#[tokio::test]
async fn test_tx_2in_1out() -> Result<()> {
    // Two real inputs; single real output equal to sum; one dummy output.
    let (wasm, r1cs) = load_artifacts()?;

    let a = Scalar::from(9u64);
    let b = Scalar::from(4u64);
    let sum = a + b;

    let case = TxCase::new(
        19,
        InputNote {
            priv_key: Scalar::from(201u64),
            blinding: Scalar::from(301u64),
            amount: a,
        },
        InputNote {
            priv_key: Scalar::from(211u64),
            blinding: Scalar::from(311u64),
            amount: b,
        },
        OutputNote {
            pub_key: Scalar::from(701u64),
            blinding: Scalar::from(801u64),
            amount: sum,
        }, // real
        OutputNote {
            pub_key: Scalar::from(702u64),
            blinding: Scalar::from(802u64),
            amount: Scalar::from(0u64),
        }, // dummy
    );

    let leaves = prepopulated_leaves(LEVELS, 0xFACEu64, &[0, case.real_idx], 24);

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64))
}

#[tokio::test]
async fn test_tx_1in_2out_split() -> Result<()> {
    // One real input (in1); two real outputs that split the amount; in0 is dummy.
    let (wasm, r1cs) = load_artifacts()?;

    let total = Scalar::from(20u64);
    let a0 = Scalar::from(6u64);
    let a1 = total - a0;

    let case = TxCase::new(
        23,
        InputNote {
            priv_key: Scalar::from(301u64),
            blinding: Scalar::from(401u64),
            amount: Scalar::from(0u64),
        }, // dummy
        InputNote {
            priv_key: Scalar::from(311u64),
            blinding: Scalar::from(411u64),
            amount: total,
        }, // real
        OutputNote {
            pub_key: Scalar::from(901u64),
            blinding: Scalar::from(1001u64),
            amount: a0,
        },
        OutputNote {
            pub_key: Scalar::from(902u64),
            blinding: Scalar::from(1002u64),
            amount: a1,
        },
    );

    let leaves = prepopulated_leaves(LEVELS, 0xC0FFEEu64, &[0, case.real_idx], 24);

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64))
}

#[tokio::test]
async fn test_tx_2in_2out_split() -> Result<()> {
    // Two real inputs; two outputs splitting the sum.
    let (wasm, r1cs) = load_artifacts()?;

    let a = Scalar::from(15u64);
    let b = Scalar::from(8u64);
    let sum = a + b;

    let out_a = Scalar::from(10u64);
    let out_b = sum - out_a;

    let case = TxCase::new(
        30,
        InputNote {
            priv_key: Scalar::from(401u64),
            blinding: Scalar::from(501u64),
            amount: a,
        },
        InputNote {
            priv_key: Scalar::from(411u64),
            blinding: Scalar::from(511u64),
            amount: b,
        },
        OutputNote {
            pub_key: Scalar::from(1101u64),
            blinding: Scalar::from(1201u64),
            amount: out_a,
        },
        OutputNote {
            pub_key: Scalar::from(1102u64),
            blinding: Scalar::from(1202u64),
            amount: out_b,
        },
    );

    let leaves = prepopulated_leaves(LEVELS, 0xBEEFu64, &[0, case.real_idx], 24);

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64))
}

#[tokio::test]
async fn test_tx_chained_spend() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    // We'll spend the output of Tx1 in Tx2
    let chain_priv = Scalar::from(777u64);
    let chain_pub = derive_public_key(chain_priv);
    let chain_blind = Scalar::from(2024u64);
    let chain_amount = Scalar::from(17u64); // this is Tx1.out0 and Tx2.in1

    // Indices
    let tx1_real_idx = 9usize;
    let chain_idx = 13usize;

    let mut leaves = prepopulated_leaves(LEVELS, 0xC0DEC0DEu64, &[0, tx1_real_idx, chain_idx], 24);

    // ----------------------------
    // TX1:  one real input -> two outputs (one becomes the chained note)
    // ----------------------------
    let tx1_input_real = InputNote {
        priv_key: Scalar::from(4242u64),
        blinding: Scalar::from(5151u64),
        amount: Scalar::from(25u64),
    };

    let tx1_out0 = OutputNote {
        pub_key: chain_pub,
        blinding: chain_blind,
        amount: chain_amount,
    };
    let tx1_out1 = OutputNote {
        pub_key: Scalar::from(3333u64),
        blinding: Scalar::from(4444u64),
        amount: tx1_input_real.amount - chain_amount,
    };

    // dummy in0 to disable its root check
    let tx1_in0_dummy = InputNote {
        priv_key: Scalar::from(11u64),
        blinding: Scalar::from(22u64),
        amount: Scalar::from(0u64),
    };

    // Run Tx1
    let tx1 = TxCase::new(
        tx1_real_idx,
        tx1_in0_dummy,
        tx1_input_real.clone(),
        tx1_out0.clone(),
        tx1_out1.clone(),
    );
    run_case(&wasm, &r1cs, &tx1, leaves.clone(), Scalar::from(0u64))?;

    // Compute Tx1.out0 commitment and insert it into the tree as if it was appended to the on-chain tree
    let out0_commit = commitment(tx1_out0.amount, tx1_out0.pub_key, tx1_out0.blinding);
    leaves[chain_idx] = out0_commit;

    // ----------------------------
    // TX2: spend Tx1.out0
    // ----------------------------
    // in1 matches Tx1.out0 (priv -> pub matches; amount & blinding match too)
    let tx2_in1 = InputNote {
        priv_key: chain_priv,
        blinding: chain_blind,
        amount: chain_amount,
    };
    // in0 remains a dummy
    let tx2_in0_dummy = InputNote {
        priv_key: Scalar::from(99u64),
        blinding: Scalar::from(100u64),
        amount: Scalar::from(0u64),
    };

    // Spend to a single real output (same value), plus one dummy output
    let tx2_out_real = OutputNote {
        pub_key: Scalar::from(8080u64),
        blinding: Scalar::from(9090u64),
        amount: chain_amount,
    };
    let tx2_out_dummy = OutputNote {
        pub_key: Scalar::from(0u64),
        blinding: Scalar::from(0u64),
        amount: Scalar::from(0u64),
    };

    let tx2 = TxCase::new(
        chain_idx,
        tx2_in0_dummy,
        tx2_in1,
        tx2_out_real,
        tx2_out_dummy,
    );

    // Now Tx2 should verify because the tree contains Tx1.out0 at `chain_idx`
    run_case(&wasm, &r1cs, &tx2, leaves, Scalar::from(0u64))
}
use ark_std::rand::{
    RngCore, SeedableRng,
    distributions::{Distribution, Uniform},
    rngs::StdRng,
};

use ark_ff::UniformRand; // for Scalar::rand

#[tokio::test]
async fn test_tx_randomized_stress() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    const N_ITERS: usize = 100;
    const TREE_LEVELS: usize = LEVELS; // 5
    const N: usize = 1 << TREE_LEVELS;
    let mut rng = StdRng::seed_from_u64(0x5EED_1337_D3AD_B33Fu64);

    for _ in 0..N_ITERS {
        // Scenarios:
        // 0: 1 real in, 1 real out (other out dummy)
        // 1: 1 real in, 2 real outs (split)
        // 2: 2 real ins, 1 real out (sum), 1 dummy out
        // 3: 2 real ins, 2 real outs (split)
        // let scenario = (next_u64(&mut rng) % 4) as u8;
        let scenario: u8 = Uniform::new_inclusive(0u8, 3u8).sample(&mut rng);

        // Choose real_idx != 0
        let real_idx = Uniform::new(1usize, N).sample(&mut rng);

        let leaves_seed: u64 = rng.next_u64();
        let leaves = prepopulated_leaves(TREE_LEVELS, leaves_seed, &[0, real_idx], 24);

        // Input 0 dummy (disables root check for in0)
        let in0_dummy = InputNote {
            priv_key: Scalar::rand(&mut rng),
            blinding: Scalar::rand(&mut rng),
            amount: Scalar::from(0u64),
        };

        // Real input 1
        let in1_amt_u64 = Uniform::new_inclusive(1, 1_000).sample(&mut rng);
        let in1_real = InputNote {
            priv_key: Scalar::rand(&mut rng),
            blinding: Scalar::rand(&mut rng),
            amount: Scalar::from(in1_amt_u64),
        };
        // Optional second real input
        let in0_alt_amt_u64 = Uniform::new_inclusive(1, 1_000).sample(&mut rng);
        let in0_real_alt = InputNote {
            priv_key: Scalar::rand(&mut rng),
            blinding: Scalar::rand(&mut rng),
            amount: Scalar::from(in0_alt_amt_u64),
        };

        // Decide amounts/out structure in u64-space, then convert to Scalar
        let (in0_used, in1_used, out0_amt_u64, out1_amt_u64) = match scenario {
            0 => {
                // 1 real in, 1 real out, 1 dummy out
                (in0_dummy.clone(), in1_real.clone(), in1_amt_u64, 0u64)
            }
            1 => {
                // 1 real in, split to 2 outs
                let x = Uniform::new_inclusive(0, in1_amt_u64).sample(&mut rng);
                let y = in1_amt_u64 - x;
                (in0_dummy.clone(), in1_real.clone(), x, y)
            }
            2 => {
                // 2 real ins, 1 real out (sum), 1 dummy out
                let sum = in0_alt_amt_u64 + in1_amt_u64;
                (in0_real_alt.clone(), in1_real.clone(), sum, 0u64)
            }
            _ => {
                // 2 real ins, 2 real outs (split)
                let sum = in0_alt_amt_u64 + in1_amt_u64;
                let x = Uniform::new_inclusive(0, sum).sample(&mut rng);
                let y = sum - x;
                (in0_real_alt.clone(), in1_real.clone(), x, y)
            }
        };

        let out0 = OutputNote {
            pub_key: Scalar::rand(&mut rng),
            blinding: Scalar::rand(&mut rng),
            amount: Scalar::from(out0_amt_u64),
        };
        let out1 = OutputNote {
            pub_key: Scalar::rand(&mut rng),
            blinding: Scalar::rand(&mut rng),
            amount: Scalar::from(out1_amt_u64),
        };
        let case = TxCase::new(real_idx, in0_used, in1_used, out0, out1);

        run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64)).with_context(|| {
            format!(
                "randomized iteration failed (seed=0x{leaves_seed:x}, scenario={scenario}, real_idx={real_idx})",
            )
        })?;
    }

    Ok(())
}

#[tokio::test]
async fn test_tx_only_adds_notes_deposit() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    // both inputs dummy -> Merkle check gated off by amount=0
    let case = TxCase::new(
        5,
        InputNote {
            priv_key: Scalar::from(11u64),
            blinding: Scalar::from(21u64),
            amount: Scalar::from(0u64),
        },
        InputNote {
            priv_key: Scalar::from(12u64),
            blinding: Scalar::from(22u64),
            amount: Scalar::from(0u64),
        },
        OutputNote {
            pub_key: Scalar::from(101u64),
            blinding: Scalar::from(201u64),
            amount: Scalar::from(7u64),
        },
        OutputNote {
            pub_key: Scalar::from(102u64),
            blinding: Scalar::from(202u64),
            amount: Scalar::from(5u64),
        },
    );

    let deposit = Scalar::from(12u64);
    let leaves = prepopulated_leaves(LEVELS, 0xD3AD0517u64, &[0, case.real_idx], 24);

    run_case(&wasm, &r1cs, &case, leaves, deposit)
}

#[tokio::test]
async fn test_tx_only_spends_notes_withdraw_one_real() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let spend = Scalar::from(9u64);
    let case = TxCase::new(
        7,
        InputNote {
            priv_key: Scalar::from(1u64),
            blinding: Scalar::from(2u64),
            amount: Scalar::from(0u64),
        },
        InputNote {
            priv_key: Scalar::from(111u64),
            blinding: Scalar::from(211u64),
            amount: spend,
        },
        OutputNote {
            pub_key: Scalar::from(0u64),
            blinding: Scalar::from(0u64),
            amount: Scalar::from(0u64),
        },
        OutputNote {
            pub_key: Scalar::from(0u64),
            blinding: Scalar::from(0u64),
            amount: Scalar::from(0u64),
        },
    );

    let leaves = prepopulated_leaves(LEVELS, 0xC0FFEEu64, &[0, case.real_idx], 24);
    let neg_spend = Scalar::zero() - spend;

    run_case(&wasm, &r1cs, &case, leaves, neg_spend)
}

#[tokio::test]
async fn test_tx_only_spends_notes_withdraw_two_real() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let a = Scalar::from(5u64);
    let b = Scalar::from(11u64);
    let sum_in = a + b;

    let case = TxCase::new(
        13,
        InputNote {
            priv_key: Scalar::from(401u64),
            blinding: Scalar::from(501u64),
            amount: a,
        },
        InputNote {
            priv_key: Scalar::from(411u64),
            blinding: Scalar::from(511u64),
            amount: b,
        },
        OutputNote {
            pub_key: Scalar::from(0u64),
            blinding: Scalar::from(0u64),
            amount: Scalar::from(0u64),
        },
        OutputNote {
            pub_key: Scalar::from(0u64),
            blinding: Scalar::from(0u64),
            amount: Scalar::from(0u64),
        },
    );

    let leaves = prepopulated_leaves(LEVELS, 0xC0FFEEu64, &[0, case.real_idx], 24);
    let neg_sum = Scalar::zero() - sum_in;

    run_case(&wasm, &r1cs, &case, leaves, neg_sum)
}

#[tokio::test]
async fn test_tx_same_nullifier_should_fail() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    // Make one real note and reuse it for BOTH inputs -> identical commitments, signatures, and nullifiers
    let privk = Scalar::from(7777u64);
    let blind = Scalar::from(4242u64);
    let amount = Scalar::from(33u64);

    let same_note = InputNote {
        priv_key: privk,
        blinding: blind,
        amount,
    };

    let out_real = OutputNote {
        pub_key: Scalar::from(9001u64),
        blinding: Scalar::from(8001u64),
        amount,
    };
    let out_dummy = OutputNote {
        pub_key: Scalar::from(0u64),
        blinding: Scalar::from(0u64),
        amount: Scalar::from(0u64),
    };

    let real_idx = 5usize;
    let case = TxCase::new(
        real_idx,
        same_note.clone(), // in0
        same_note.clone(), // in1 (same nullifier)
        out_real,
        out_dummy,
    );

    let leaves = prepopulated_leaves(LEVELS, 0xC0FFEEu64, &[0, real_idx], 24);

    // Run: should fail because circuit enforces all input nullifiers to be distinct
    let res = run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64));
    assert!(
        res.is_err(),
        "Same-nullifier case unexpectedly verified; expected rejection due to duplicate nullifiers"
    );

    if let Err(e) = res {
        println!("same-nullifier correctly rejected: {e:?}");
    }
    Ok(())
}
