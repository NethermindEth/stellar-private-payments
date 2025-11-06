use crate::test::utils::circom_tester::{Inputs, SignalKey, prove_and_verify};
use crate::test::utils::general::{poseidon2_hash2, scalar_to_bigint};
use crate::test::utils::keypair::{derive_public_key, sign};
use crate::test::utils::merkle_tree::{merkle_proof, merkle_root};
use crate::test::utils::transaction::{commitment, nullifier, prepopulated_leaves};
use anyhow::{Context, Result};
use num_bigint::BigInt;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use zkhash::ark_ff::Zero;
use zkhash::fields::bn256::FpBN256 as Scalar;

const LEVELS: usize = 5;
const N_INPUTS: usize = 2;
const N_OUTPUTS: usize = 2;
const N_MEM_PROOFS: usize = 1;
const N_NON_PROOFS: usize = 1;

#[derive(Clone, Debug)]
pub struct InputNote {
    pub real_id: usize,
    pub priv_key: Scalar,
    pub blinding: Scalar,
    pub amount: Scalar,
}

#[derive(Clone, Debug)]
pub struct OutputNote {
    pub pub_key: Scalar,
    pub blinding: Scalar,
    pub amount: Scalar,
}

pub struct TxCase {
    pub input: [InputNote; N_INPUTS],
    pub output: [OutputNote; N_OUTPUTS],
}

pub struct MembershipTree {
    pub leaves: Vec<Scalar>,
    pub index: usize,
    pub blinding: Scalar,
}

impl TxCase {
    pub fn new(in0: InputNote, in1: InputNote, out0: OutputNote, out1: OutputNote) -> Self {
        Self {
            input: [in0, in1],
            output: [out0, out1],
        }
    }
}



fn run_case<F>(
    wasm: &PathBuf,
    r1cs: &PathBuf,
    case: &TxCase,
    mut leaves: Vec<Scalar>,
    public_amount: Scalar,
    membership_trees: &[MembershipTree],
    mutate_inputs: Option<F>,
) -> Result<()>  where F: FnOnce(&mut Inputs){
    // === INPUTS ===
    let mut commits = Vec::with_capacity(N_INPUTS);
    let mut pubs = Vec::with_capacity(N_INPUTS);
    let mut nullifiers = Vec::with_capacity(N_INPUTS);
    let mut path_indices = Vec::with_capacity(N_INPUTS);
    let mut path_elements_flat: Vec<BigInt> = Vec::with_capacity(N_INPUTS * LEVELS);

    // First pass, build commitments and patch tree
    for note in &case.input {
        let pk = derive_public_key(note.priv_key);
        let cm = commitment(note.amount, pk, note.blinding);
        pubs.push(pk);
        commits.push(cm);
        leaves[note.real_id] = cm;
    }

    let root_scalar = merkle_root(leaves.clone());

    // Second pass, merkle paths, nullifiers
    for (i, note) in case.input.iter().enumerate() {
        let (siblings, indices, depth) = merkle_proof(&leaves, note.real_id);
        assert_eq!(depth, LEVELS, "unexpected depth for input {i}");

        path_elements_flat.extend(siblings.into_iter().map(scalar_to_bigint));

        let path_idx = Scalar::from(indices);
        path_indices.push(path_idx);

        let sig = sign(note.priv_key, commits[i], path_idx);
        let nul = nullifier(commits[i], path_idx, sig);
        nullifiers.push(nul);
    }

    // === MEMBERSHIP PROOF ===
    let mut mp_leaf:          Vec<Vec<BigInt>>      = Vec::with_capacity(N_INPUTS);
    let mut mp_pk:            Vec<Vec<BigInt>>      = Vec::with_capacity(N_INPUTS);
    let mut mp_blinding:      Vec<Vec<BigInt>>      = Vec::with_capacity(N_INPUTS);
    let mut mp_path_indices:  Vec<Vec<BigInt>>      = Vec::with_capacity(N_INPUTS);
    let mut mp_path_elements: Vec<Vec<Vec<BigInt>>> = Vec::with_capacity(N_INPUTS);
    let mut membership_roots: Vec<BigInt>           = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);

    for _ in 0..N_INPUTS {
        mp_leaf.push(Vec::with_capacity(N_MEM_PROOFS));
        mp_pk.push(Vec::with_capacity(N_MEM_PROOFS));
        mp_blinding.push(Vec::with_capacity(N_MEM_PROOFS));
        mp_path_indices.push(Vec::with_capacity(N_MEM_PROOFS));
        mp_path_elements.push(Vec::with_capacity(N_MEM_PROOFS));
    }

    // For each j H(pk_k, blinding_{k,j}
    for j in 0..N_MEM_PROOFS {
        let base_idx = 0 * N_MEM_PROOFS + j;
        let mut frozen_leaves = membership_trees[base_idx].leaves.clone();

        
        for k in 0..N_INPUTS {
            let tree = &membership_trees[k * N_MEM_PROOFS + j];
            let pk = pubs[k];
            let leaf = poseidon2_hash2(pk, tree.blinding); // H(pk_k, blinding_{k,j})
            frozen_leaves[tree.index] = leaf;
        }

        // the shared root for j
        let root_scalar = merkle_root(frozen_leaves.clone());

        // now produce proofs for each input i against the same frozen tree
        for i in 0..N_INPUTS {
            let t = &membership_trees[i * N_MEM_PROOFS + j];
            let pk_scalar   = pubs[i];
            let leaf_scalar = poseidon2_hash2(pk_scalar, t.blinding);

            let (siblings, path_idx_u64, depth) = merkle_proof(&frozen_leaves, t.index);
            assert_eq!(depth, LEVELS, "unexpected membership depth for input {}", i);

            mp_leaf[i].push(scalar_to_bigint(leaf_scalar));
            mp_pk[i].push(scalar_to_bigint(pk_scalar));
            mp_blinding[i].push(scalar_to_bigint(t.blinding));
            mp_path_indices[i].push(scalar_to_bigint(Scalar::from(path_idx_u64)));
            mp_path_elements[i].push(siblings.into_iter().map(scalar_to_bigint).collect());
            
            membership_roots.push(scalar_to_bigint(root_scalar));
        }
    }


    // === OUTPUTS ===
    let mut output_comms = Vec::with_capacity(N_OUTPUTS);
    for out in &case.output {
        let comm = commitment(out.amount, out.pub_key, out.blinding);
        output_comms.push(comm);
    }

    // === BUILD INPUTS MAP ===
    let mut inputs = Inputs::new();

    // Input arrays
    inputs.set(
        "inAmount",
        case.input.iter().map(|n| scalar_to_bigint(n.amount)).collect::<Vec<_>>(),
    );
    inputs.set(
        "inPrivateKey",
        case.input.iter().map(|n| scalar_to_bigint(n.priv_key)).collect::<Vec<_>>(),
    );
    inputs.set(
        "inBlinding",
        case.input.iter().map(|n| scalar_to_bigint(n.blinding)).collect::<Vec<_>>(),
    );
    inputs.set(
        "inPathIndices",
        path_indices.iter().map(|&x| scalar_to_bigint(x)).collect::<Vec<_>>(),
    );
    inputs.set(
        "inputNullifier",
        nullifiers.iter().map(|&x| scalar_to_bigint(x)).collect::<Vec<_>>(),
    );
    inputs.set("inPathElements", path_elements_flat);

    // Membership proofs
    for i in 0..N_INPUTS {
        for j in 0..N_MEM_PROOFS {
            let key = |field: &str| {
                SignalKey::new("membershipProofs")
                    .idx(i)
                    .idx(j)
                    .field(field)
            };
            inputs.set_key(&key("leaf"),         mp_leaf[i][j].clone());
            inputs.set_key(&key("pk"),           mp_pk[i][j].clone());
            inputs.set_key(&key("blinding"),     mp_blinding[i][j].clone());
            inputs.set_key(&key("pathIndices"),  mp_path_indices[i][j].clone());
            inputs.set_key(&key("pathElements"), mp_path_elements[i][j].clone());
        }
    }
    inputs.set("membershipRoots", membership_roots);

    // Outputs
    inputs.set(
        "outAmount",
        case.output.iter().map(|n| scalar_to_bigint(n.amount)).collect::<Vec<_>>(),
    );
    inputs.set(
        "outPubkey",
        case.output.iter().map(|n| scalar_to_bigint(n.pub_key)).collect::<Vec<_>>(),
    );
    inputs.set(
        "outBlinding",
        case.output.iter().map(|n| scalar_to_bigint(n.blinding)).collect::<Vec<_>>(),
    );
    inputs.set(
        "outputCommitment",
        output_comms.iter().map(|&c| scalar_to_bigint(c)).collect::<Vec<_>>(),
    );

    // Public signals
    inputs.set("root",          scalar_to_bigint(root_scalar));
    inputs.set("publicAmount",  scalar_to_bigint(public_amount));
    inputs.set("extDataHash",   BigInt::from(0u32));

    // Add inputs from test
    if let Some(f) = mutate_inputs {
        f(&mut inputs);
    }
    // --- Prove & verify ---
    let prove_result = panic::catch_unwind(AssertUnwindSafe(|| {
        prove_and_verify(wasm, r1cs, &inputs.into_map())
    }));
    match prove_result {
        Ok(Ok(res)) if res.verified => Ok(()),
        Ok(Ok(_)) => Err(anyhow::anyhow!(
            "Proof failed to verify (res.verified=false)"
        )),
        Ok(Err(e)) => Err(anyhow::anyhow!("Prover error: {e:?}")),
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

// --- helpers unchanged (load_artifacts/test) ---
fn load_artifacts() -> Result<(PathBuf, PathBuf)> {
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/compliant_test_js/compliant_test.wasm");
    let r1cs = out_dir.join("compliant_test.r1cs");
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
        InputNote {
            real_id: 0,
            priv_key: Scalar::from(101u64),
            blinding: Scalar::from(201u64),
            amount: Scalar::from(0u64),
        },
        InputNote {
            real_id: 7,
            priv_key: Scalar::from(101u64),
            blinding: Scalar::from(211u64),
            amount: Scalar::from(13u64),
        },
        OutputNote {
            pub_key: Scalar::from(501u64),
            blinding: Scalar::from(601u64),
            amount: Scalar::from(13u64),
        },
        OutputNote {
            pub_key: Scalar::from(502u64),
            blinding: Scalar::from(602u64),
            amount: Scalar::from(0u64),
        },
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xDEAD_BEEFu64,
        &[case.input[0].real_id, case.input[1].real_id],
        24,
    );

    let mut membership_trees: Vec<MembershipTree> =
        Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);

    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0x1234_5678u64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);

        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves:   base_mem_leaves_j.clone(),     
                index:    case.input[i].real_id,        
                blinding: Scalar::zero(),                
            });
        }
    }

   
    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees, None::<fn(&mut Inputs)>)
}

#[tokio::test]
async fn test_tx_2in_1out() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let a = Scalar::from(9u64);
    let b = Scalar::from(4u64);
    let sum = a + b;

    let case = TxCase::new(
        InputNote { real_id: 0,  priv_key: Scalar::from(201u64), blinding: Scalar::from(301u64), amount: a },
        InputNote { real_id: 19, priv_key: Scalar::from(211u64), blinding: Scalar::from(311u64), amount: b },
        OutputNote { pub_key: Scalar::from(701u64), blinding: Scalar::from(801u64), amount: sum },
        OutputNote { pub_key: Scalar::from(702u64), blinding: Scalar::from(802u64), amount: Scalar::from(0u64) },
    );

    let leaves = prepopulated_leaves(
        LEVELS, 0xFACEu64,
        &[case.input[0].real_id, case.input[1].real_id],
        24,
    );

    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0x1234_5678u64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base_mem_leaves_j.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees, None::<fn(&mut Inputs)>)
}

#[tokio::test]
async fn test_tx_1in_2out_split() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let total = Scalar::from(20u64);
    let a0 = Scalar::from(6u64);
    let a1 = total - a0;

    let case = TxCase::new(
        InputNote { real_id: 0,  priv_key: Scalar::from(301u64), blinding: Scalar::from(401u64), amount: Scalar::from(0u64) },
        InputNote { real_id: 23, priv_key: Scalar::from(311u64), blinding: Scalar::from(411u64), amount: total },
        OutputNote { pub_key: Scalar::from(901u64), blinding: Scalar::from(1001u64), amount: a0 },
        OutputNote { pub_key: Scalar::from(902u64), blinding: Scalar::from(1002u64), amount: a1 },
    );

    let leaves = prepopulated_leaves(
        LEVELS, 0xC0FFEEu64,
        &[case.input[0].real_id, case.input[1].real_id],
        24,
    );

    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0x1234_5678u64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base_mem_leaves_j.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees, None::<fn(&mut Inputs)>)
}

#[tokio::test]
async fn test_tx_2in_2out_split() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let a = Scalar::from(15u64);
    let b = Scalar::from(8u64);
    let sum = a + b;

    let out_a = Scalar::from(10u64);
    let out_b = sum - out_a;

    let case = TxCase::new(
        InputNote { real_id: 0,  priv_key: Scalar::from(401u64), blinding: Scalar::from(501u64), amount: a },
        InputNote { real_id: 30, priv_key: Scalar::from(411u64), blinding: Scalar::from(511u64), amount: b },
        OutputNote { pub_key: Scalar::from(1101u64), blinding: Scalar::from(1201u64), amount: out_a },
        OutputNote { pub_key: Scalar::from(1102u64), blinding: Scalar::from(1202u64), amount: out_b },
    );

    let leaves = prepopulated_leaves(
        LEVELS, 0xBEEFu64,
        &[case.input[0].real_id, case.input[1].real_id],
        24,
    );

    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0x1234_5678u64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base_mem_leaves_j.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees, None::<fn(&mut Inputs)>)
}

#[tokio::test]
async fn test_tx_chained_spend() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    // Tx1 produces an output that Tx2 spends
    let chain_priv  = Scalar::from(777u64);
    let chain_pub   = derive_public_key(chain_priv);
    let chain_blind = Scalar::from(2024u64);
    let chain_amount = Scalar::from(17u64);

    let tx1_real_idx = 9usize;
    let chain_idx    = 13usize;

    let mut leaves = prepopulated_leaves(
        LEVELS, 0xC0DEC0DEu64,
        &[0, tx1_real_idx, chain_idx],
        24,
    );

    // --- TX1 ---
    let tx1_input_real = InputNote { real_id: tx1_real_idx, priv_key: Scalar::from(4242u64), blinding: Scalar::from(5151u64), amount: Scalar::from(25u64) };
    let tx1_out0 = OutputNote { pub_key: chain_pub, blinding: chain_blind, amount: chain_amount };
    let tx1_out1 = OutputNote { pub_key: Scalar::from(3333u64), blinding: Scalar::from(4444u64), amount: tx1_input_real.amount - chain_amount };
    let tx1_in0_dummy = InputNote { real_id: 0, priv_key: Scalar::from(11u64), blinding: Scalar::from(22u64), amount: Scalar::from(0u64) };

    let tx1 = TxCase::new(tx1_in0_dummy, tx1_input_real.clone(), tx1_out0.clone(), tx1_out1.clone());

    // membership trees for TX1 (distinct baseline per j)
    let mut mt1: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0xA11C_3EAFu64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            mt1.push(MembershipTree {
                leaves: base_mem_leaves_j.clone(),
                index: tx1.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    run_case(&wasm, &r1cs, &tx1,
             prepopulated_leaves(LEVELS, 0xC0DEC0DEu64, &[0, tx1_real_idx, chain_idx], 24),
             Scalar::from(0u64),
             &mt1, None::<fn(&mut Inputs)>)?;

    // append Tx1.out0 commitment at chain_idx
    let out0_commit = commitment(tx1_out0.amount, tx1_out0.pub_key, tx1_out0.blinding);
    leaves[chain_idx] = out0_commit;

    // --- TX2 ---
    let tx2_in1 = InputNote { real_id: chain_idx, priv_key: chain_priv, blinding: chain_blind, amount: chain_amount };
    let tx2_in0_dummy = InputNote { real_id: 0, priv_key: Scalar::from(99u64), blinding: Scalar::from(100u64), amount: Scalar::from(0u64) };
    let tx2_out_real = OutputNote { pub_key: Scalar::from(8080u64), blinding: Scalar::from(9090u64), amount: chain_amount };
    let tx2_out_dummy = OutputNote { pub_key: Scalar::from(0u64), blinding: Scalar::from(0u64), amount: Scalar::from(0u64) };

    let tx2 = TxCase::new(tx2_in0_dummy, tx2_in1, tx2_out_real, tx2_out_dummy);

    let mut mt2: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0xB16B_00B5u64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            mt2.push(MembershipTree {
                leaves: base_mem_leaves_j.clone(),
                index: tx2.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    run_case(&wasm, &r1cs, &tx2, leaves, Scalar::from(0u64), &mt2, None::<fn(&mut Inputs)>)
}


#[tokio::test]
async fn test_tx_randomized_stress() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    #[inline]
    fn next_u64(state: &mut u128) -> u64 {
        *state = state.wrapping_mul(6364136223846793005u128).wrapping_add(1442695040888963407u128);
        (*state >> 64) as u64
    }
    #[inline]
    fn rand_scalar(state: &mut u128) -> Scalar { Scalar::from(next_u64(state)) }
    #[inline]
    fn nonzero_amount_u64(state: &mut u128, max: u64) -> u64 { 1 + (next_u64(state) % max.max(1)) }

    const N_ITERS: usize = 100;
    const TREE_LEVELS: usize = LEVELS;
    const N: usize = 1 << TREE_LEVELS;
    let mut rng: u128 = 0xA9_5EED_1337_D3AD_B33Fu128;

    for _ in 0..N_ITERS {
        let scenario = (next_u64(&mut rng) % 4) as u8;

        // pick real index != 0
        let real_idx = {
            let mut idx = usize::try_from(next_u64(&mut rng))? % N;
            if idx == 0 { idx = 1; }
            idx
        };

        let leaves_seed = next_u64(&mut rng);
        let leaves = prepopulated_leaves(TREE_LEVELS, leaves_seed, &[0, real_idx], 24);

        let in0_dummy = InputNote { real_id: 0, priv_key: rand_scalar(&mut rng), blinding: rand_scalar(&mut rng), amount: Scalar::from(0u64) };
        let in1_amt_u64 = nonzero_amount_u64(&mut rng, 1_000);
        let in1_real = InputNote { real_id: real_idx, priv_key: rand_scalar(&mut rng), blinding: rand_scalar(&mut rng), amount: Scalar::from(in1_amt_u64) };

        let in0_alt_amt_u64 = nonzero_amount_u64(&mut rng, 1_000);
        let in0_real_alt = InputNote { real_id: 0, priv_key: rand_scalar(&mut rng), blinding: rand_scalar(&mut rng), amount: Scalar::from(in0_alt_amt_u64) };

        let (in0_used, in1_used, out0_amt_u64, out1_amt_u64) = match scenario {
            0 => (in0_dummy.clone(), in1_real.clone(), in1_amt_u64, 0u64),
            1 => {
                let x = next_u64(&mut rng) % (in1_amt_u64 + 1);
                let y = in1_amt_u64 - x;
                (in0_dummy.clone(), in1_real.clone(), x, y)
            }
            2 => {
                let sum = in0_alt_amt_u64 + in1_amt_u64;
                (in0_real_alt.clone(), in1_real.clone(), sum, 0u64)
            }
            _ => {
                let sum = in0_alt_amt_u64 + in1_amt_u64;
                let x = next_u64(&mut rng) % (sum + 1);
                let y = sum - x;
                (in0_real_alt.clone(), in1_real.clone(), x, y)
            }
        };

        let out0 = OutputNote { pub_key: rand_scalar(&mut rng), blinding: rand_scalar(&mut rng), amount: Scalar::from(out0_amt_u64) };
        let out1 = OutputNote { pub_key: rand_scalar(&mut rng), blinding: rand_scalar(&mut rng), amount: Scalar::from(out1_amt_u64) };

        let case = TxCase::new(in0_used, in1_used, out0, out1);

        // membership trees: distinct baseline per j
        let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
        for j in 0..N_MEM_PROOFS {
            let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ leaves_seed;
            let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
            for i in 0..N_INPUTS {
                membership_trees.push(MembershipTree {
                    leaves: base_mem_leaves_j.clone(),
                    index: case.input[i].real_id,
                    blinding: Scalar::zero(),
                });
            }
        }

        run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees, None::<fn(&mut Inputs)>).with_context(|| {
            format!("randomized iteration failed (seed=0x{leaves_seed:x}, scenario={scenario}, real_idx={real_idx})")
        })?;
    }

    Ok(())
}

#[tokio::test]
async fn test_tx_only_adds_notes_deposit() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    // both inputs dummy -> Merkle checks gated off by amount=0
    let case = TxCase::new(
        InputNote { real_id: 0, priv_key: Scalar::from(11u64), blinding: Scalar::from(21u64), amount: Scalar::from(0u64) },
        InputNote { real_id: 5, priv_key: Scalar::from(12u64), blinding: Scalar::from(22u64), amount: Scalar::from(0u64) },
        OutputNote { pub_key: Scalar::from(101u64), blinding: Scalar::from(201u64), amount: Scalar::from(7u64) },
        OutputNote { pub_key: Scalar::from(102u64), blinding: Scalar::from(202u64), amount: Scalar::from(5u64) },
    );

    let deposit = Scalar::from(12u64);
    let leaves = prepopulated_leaves(
        LEVELS, 0xD3AD0517u64,
        &[case.input[0].real_id, case.input[1].real_id],
        24,
    );

    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0x5555_AAAAu64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base_mem_leaves_j.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    run_case(&wasm, &r1cs, &case, leaves, deposit, &membership_trees, None::<fn(&mut Inputs)>)
}

#[tokio::test]
async fn test_tx_only_spends_notes_withdraw_one_real() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let spend = Scalar::from(9u64);

    let case = TxCase::new(
        InputNote { real_id: 0, priv_key: Scalar::from(1u64), blinding: Scalar::from(2u64), amount: Scalar::from(0u64) },
        InputNote { real_id: 7, priv_key: Scalar::from(111u64), blinding: Scalar::from(211u64), amount: spend },
        OutputNote { pub_key: Scalar::from(0u64), blinding: Scalar::from(0u64), amount: Scalar::from(0u64) },
        OutputNote { pub_key: Scalar::from(0u64), blinding: Scalar::from(0u64), amount: Scalar::from(0u64) },
    );

    let leaves = prepopulated_leaves(
        LEVELS, 0xC0FFEEu64,
        &[case.input[0].real_id, case.input[1].real_id],
        24,
    );
    let neg_spend = Scalar::zero() - spend;

    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0xDEAD_BEEFu64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base_mem_leaves_j.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    run_case(&wasm, &r1cs, &case, leaves, neg_spend, &membership_trees, None::<fn(&mut Inputs)>)
}

#[tokio::test]
async fn test_tx_only_spends_notes_withdraw_two_real() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let a = Scalar::from(5u64);
    let b = Scalar::from(11u64);
    let sum_in = a + b;

    let case = TxCase::new(
        InputNote { real_id: 0,  priv_key: Scalar::from(401u64), blinding: Scalar::from(501u64), amount: a },
        InputNote { real_id: 13, priv_key: Scalar::from(411u64), blinding: Scalar::from(511u64), amount: b },
        OutputNote { pub_key: Scalar::from(0u64), blinding: Scalar::from(0u64), amount: Scalar::from(0u64) },
        OutputNote { pub_key: Scalar::from(0u64), blinding: Scalar::from(0u64), amount: Scalar::from(0u64) },
    );

    let leaves = prepopulated_leaves(
        LEVELS, 0xC0FFEEu64,
        &[case.input[0].real_id, case.input[1].real_id],
        24,
    );
    let neg_sum = Scalar::zero() - sum_in;

    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0xABCD_EF01u64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base_mem_leaves_j.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    run_case(&wasm, &r1cs, &case, leaves, neg_sum, &membership_trees, None::<fn(&mut Inputs)>)
}

#[tokio::test]
async fn test_tx_same_nullifier_should_fail() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    // Same note material used twice
    let privk = Scalar::from(7777u64);
    let blind = Scalar::from(4242u64);
    let amount = Scalar::from(33u64);

    let same_note = InputNote { real_id: 0, priv_key: privk, blinding: blind, amount };

    let out_real  = OutputNote { pub_key: Scalar::from(9001u64), blinding: Scalar::from(8001u64), amount };
    let out_dummy = OutputNote { pub_key: Scalar::from(0u64),    blinding: Scalar::from(0u64),   amount: Scalar::from(0u64) };

    let case = TxCase::new(
        same_note.clone(),                                   // in0 @ real_id=0
        InputNote { real_id: 5, ..same_note.clone() },       // in1 @ real_id=5 (same note material)
        out_real,
        out_dummy,
    );

    let leaves = prepopulated_leaves(
        LEVELS, 0xC0FFEEu64,
        &[case.input[0].real_id, case.input[1].real_id],
        24,
    );

    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j: u64 = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0xFEFE_FEF1u64;
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base_mem_leaves_j.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    let res = run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees,None::<fn(&mut Inputs)>);
    assert!(res.is_err(), "Same-nullifier case unexpectedly verified; expected rejection due to duplicate nullifiers");

    if let Err(e) = res {
        println!("same-nullifier correctly rejected: {e:?}");
    }
    Ok(())
}

#[tokio::test]
async fn test_membership_should_fail_wrong_pk() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let case = TxCase::new(
        InputNote { real_id: 0, priv_key: Scalar::from(101u64), blinding: Scalar::from(201u64), amount: Scalar::from(0u64) },
        InputNote { real_id: 7, priv_key: Scalar::from(111u64), blinding: Scalar::from(211u64), amount: Scalar::from(13u64) },
        OutputNote { pub_key: Scalar::from(501u64), blinding: Scalar::from(601u64), amount: Scalar::from(13u64) },
        OutputNote { pub_key: Scalar::from(502u64), blinding: Scalar::from(602u64), amount: Scalar::from(0u64) },
    );

    let leaves = prepopulated_leaves(
        LEVELS, 0xCAFE_BA5Eu64,
        &[case.input[0].real_id, case.input[1].real_id], 24,
    );

    // Normal membership trees (blinding = 0)
    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0x1111_2222u64;
        let base = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    // Tamper: set membershipProofs[1][0].pk to a bogus value
    let res = run_case(
        &wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees,
        Some(|inputs: &mut Inputs| {
            let key = |field: &str| SignalKey::new("membershipProofs").idx(1).idx(0).field(field);
            inputs.set_key(&key("pk"), scalar_to_bigint(Scalar::from(42u64)));
        })
    );

    assert!(res.is_err(), "membership with wrong pk unexpectedly verified");
    Ok(())
}

#[tokio::test]
async fn test_membership_should_fail_wrong_path() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let case = TxCase::new(
        InputNote { real_id: 0, priv_key: Scalar::from(101u64), blinding: Scalar::from(201u64), amount: Scalar::from(0u64) },
        InputNote { real_id: 7, priv_key: Scalar::from(111u64), blinding: Scalar::from(211u64), amount: Scalar::from(13u64) },
        OutputNote { pub_key: Scalar::from(501u64), blinding: Scalar::from(601u64), amount: Scalar::from(13u64) },
        OutputNote { pub_key: Scalar::from(502u64), blinding: Scalar::from(602u64), amount: Scalar::from(0u64) },
    );

    let leaves = prepopulated_leaves(
        LEVELS, 0xFACE_FEEDu64,
        &[case.input[0].real_id, case.input[1].real_id], 24,
    );

    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0x3333_4444u64;
        let base = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    // Tamper: zero out the pathElements for input 1, proof 0
    let res = run_case(
        &wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees,
        Some(|inputs: &mut Inputs| {
            let key = |field: &str| SignalKey::new("membershipProofs").idx(1).idx(0).field(field);
            let zeros: Vec<BigInt> = (0..LEVELS).map(|_| BigInt::from(0u32)).collect();
            inputs.set_key(&key("pathElements"), zeros);
        })
    );

    assert!(res.is_err(), "membership with wrong path unexpectedly verified");
    Ok(())
}

#[tokio::test]
async fn test_membership_should_fail_wrong_root() -> Result<()> {
    let (wasm, r1cs) = load_artifacts()?;

    let case = TxCase::new(
        InputNote { real_id: 0, priv_key: Scalar::from(101u64), blinding: Scalar::from(201u64), amount: Scalar::from(0u64) },
        InputNote { real_id: 7, priv_key: Scalar::from(111u64), blinding: Scalar::from(211u64), amount: Scalar::from(13u64) },
        OutputNote { pub_key: Scalar::from(501u64), blinding: Scalar::from(601u64), amount: Scalar::from(13u64) },
        OutputNote { pub_key: Scalar::from(502u64), blinding: Scalar::from(602u64), amount: Scalar::from(0u64) },
    );

    let leaves = prepopulated_leaves(
        LEVELS, 0xDEAD_BEEFu64,
        &[case.input[0].real_id, case.input[1].real_id], 24,
    );

    let mut membership_trees: Vec<MembershipTree> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);
    for j in 0..N_MEM_PROOFS {
        let seed_j = 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0x5555_6666u64;
        let base = prepopulated_leaves(LEVELS, seed_j, &[], 24);
        for i in 0..N_INPUTS {
            membership_trees.push(MembershipTree {
                leaves: base.clone(),
                index: case.input[i].real_id,
                blinding: Scalar::zero(),
            });
        }
    }

    // Tamper: replace membershipRoots with bogus constants
    let res = run_case(
        &wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees,
        Some(|inputs: &mut Inputs| {
            let bogus: Vec<BigInt> = (0..(N_INPUTS * N_MEM_PROOFS))
                .map(|_| scalar_to_bigint(Scalar::from(123u64)))
                .collect();
            inputs.set("membershipRoots", bogus);
        })
    );

    assert!(res.is_err(), "membership with wrong root unexpectedly verified");
    Ok(())
}






