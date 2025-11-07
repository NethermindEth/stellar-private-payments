use crate::test::prove_sparse::SMTProof;
use crate::test::utils::circom_tester::{Inputs, SignalKey, prove_and_verify};
use crate::test::utils::general::{poseidon2_hash2, scalar_to_bigint};
use crate::test::utils::keypair::{derive_public_key, sign};
use crate::test::utils::merkle_tree::{merkle_proof, merkle_root};
use crate::test::utils::sparse_merkle_tree::{SMTMemDB, SparseMerkleTree};
use crate::test::utils::transaction::{commitment, nullifier, prepopulated_leaves};
use anyhow::{Context, Result};
use num_bigint::{BigInt, BigUint, ToBigInt};
use std::collections::HashMap;
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
) -> Result<()>
where
    F: FnOnce(&mut Inputs),
{
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
    let mut mp_leaf: Vec<Vec<BigInt>> = Vec::with_capacity(N_INPUTS);
    let mut mp_pk: Vec<Vec<BigInt>> = Vec::with_capacity(N_INPUTS);
    let mut mp_blinding: Vec<Vec<BigInt>> = Vec::with_capacity(N_INPUTS);
    let mut mp_path_indices: Vec<Vec<BigInt>> = Vec::with_capacity(N_INPUTS);
    let mut mp_path_elements: Vec<Vec<Vec<BigInt>>> = Vec::with_capacity(N_INPUTS);
    let mut membership_roots: Vec<BigInt> = Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);

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
            let pk_scalar = pubs[i];
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
        case.input
            .iter()
            .map(|n| scalar_to_bigint(n.amount))
            .collect::<Vec<_>>(),
    );
    inputs.set(
        "inPrivateKey",
        case.input
            .iter()
            .map(|n| scalar_to_bigint(n.priv_key))
            .collect::<Vec<_>>(),
    );
    inputs.set(
        "inBlinding",
        case.input
            .iter()
            .map(|n| scalar_to_bigint(n.blinding))
            .collect::<Vec<_>>(),
    );
    inputs.set(
        "inPathIndices",
        path_indices
            .iter()
            .map(|&x| scalar_to_bigint(x))
            .collect::<Vec<_>>(),
    );
    inputs.set(
        "inputNullifier",
        nullifiers
            .iter()
            .map(|&x| scalar_to_bigint(x))
            .collect::<Vec<_>>(),
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
            inputs.set_key(&key("leaf"), mp_leaf[i][j].clone());
            inputs.set_key(&key("pk"), mp_pk[i][j].clone());
            inputs.set_key(&key("blinding"), mp_blinding[i][j].clone());
            inputs.set_key(&key("pathIndices"), mp_path_indices[i][j].clone());
            inputs.set_key(&key("pathElements"), mp_path_elements[i][j].clone());
        }
    }
    inputs.set("membershipRoots", membership_roots);

    // NON MEMEBERSHIP
    // Build two "existing" leaves in the SMT at keys 1 and 10.
    // (These are the association records you want to assert the *absence* of for other keys.)
    let leaf0 = poseidon2_hash2(pubs[0], Scalar::zero());
    let leaf1 = poseidon2_hash2(pubs[1], Scalar::zero());
    let non_inclusion_keys = [leaf0, leaf1];

    let overrides: Vec<(u32, BigInt)> = vec![
    (1u32, scalar_to_bigint(leaf0)),
    (10u32, scalar_to_bigint(leaf1)),
    ];

    let keys: [u32; N_INPUTS] = [2u32, 12u32];

    // Use the same max sibling length as the circuit's SMT
    const SMT_LEVELS: usize = LEVELS; // or whatever your SMTVerifier(...) uses

    // (Optional) compute the SMT root once (all proofs share it)
    let tmp = prepare_smt_proof_with_overrides(&BigUint::from(keys[0]), &overrides, SMT_LEVELS);
    let mut non_membership_roots: Vec<BigInt> = Vec::with_capacity(N_INPUTS * N_NON_PROOFS);
    for _ in 0..(N_INPUTS * N_NON_PROOFS) {
        non_membership_roots.push(tmp.root.to_bigint().unwrap());
    }


    // === NON MEMBERSHIP ===
    for i in 0..N_INPUTS {
        for j in 0..N_NON_PROOFS {
            let proof = prepare_smt_proof_with_overrides(&BigUint::from(keys[i]), &overrides, SMT_LEVELS);

            // We expect NON-inclusion here
            assert!(!proof.found, "non-membership: key {} unexpectedly exists", keys[i]);

            let key = |field: &str| {
                SignalKey::new("nonMembershipProofs").idx(i).idx(j).field(field)
            };

            // 1) key being queried
            inputs.set_key(&key("key"), BigInt::from(keys[i]));

            // 2) queried value must be ZERO for non-inclusion
            // inputs.set_key(&key("value"), BigInt::from(0u32));
            inputs.set_key(&key("value"), scalar_to_bigint(non_inclusion_keys[i]));

            // 3) neighbors / emptiness flags from the proof
            if proof.is_old0 {
                // empty path case
                inputs.set_key(&key("oldKey"),   BigInt::from(0u32));
                inputs.set_key(&key("oldValue"), BigInt::from(0u32));
                inputs.set_key(&key("isOld0"),   BigInt::from(1u32));
            } else {
                // collision-with-existing-leaf case
                inputs.set_key(&key("oldKey"),   proof.not_found_key.to_bigint().unwrap());
                inputs.set_key(&key("oldValue"), proof.not_found_value.to_bigint().unwrap());
                inputs.set_key(&key("isOld0"),   BigInt::from(0u32));
            }

            // 4) siblings for THIS key (do NOT reuse across keys)
            let sibs: Vec<BigInt> = proof.siblings.into_iter()
                .map(|x| x.to_bigint().unwrap())
                .collect();
            inputs.set_key(&key("siblings"), sibs);

            // 5) pk/blinding are irrelevant to the SMT—set to anything or drop if circuit ignores them
            inputs.set_key(&key("pk"),       scalar_to_bigint(pubs[i]));
            inputs.set_key(&key("blinding"), BigInt::from(0u32));
        }
    }
    inputs.set("nonMembershipRoots", non_membership_roots);


    // Outputs
    inputs.set(
        "outAmount",
        case.output
            .iter()
            .map(|n| scalar_to_bigint(n.amount))
            .collect::<Vec<_>>(),
    );
    inputs.set(
        "outPubkey",
        case.output
            .iter()
            .map(|n| scalar_to_bigint(n.pub_key))
            .collect::<Vec<_>>(),
    );
    inputs.set(
        "outBlinding",
        case.output
            .iter()
            .map(|n| scalar_to_bigint(n.blinding))
            .collect::<Vec<_>>(),
    );
    inputs.set(
        "outputCommitment",
        output_comms
            .iter()
            .map(|&c| scalar_to_bigint(c))
            .collect::<Vec<_>>(),
    );

    // Public signals
    inputs.set("root", scalar_to_bigint(root_scalar));
    inputs.set("publicAmount", scalar_to_bigint(public_amount));
    inputs.set("extDataHash", BigInt::from(0u32));

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


/// Build a sparse SMT from `overrides` and return a proof for `key`.
/// `overrides` is (key, value) pairs already reduced modulo field.
/// `max_levels` is the number of siblings you want (pad with zeros).
pub fn prepare_smt_proof_with_overrides(
    key: &BigUint,
    overrides: &[(u32, BigInt)],
    max_levels: usize,
) -> SMTProof {
    let db = SMTMemDB::new();
    // start from empty root (0)
    let mut smt = SparseMerkleTree::new(db, BigUint::from(0u32));

    // insert only the provided leaves (sparse!)
    for (k, v) in overrides {
        smt.insert(&BigUint::from(*k), &v.to_biguint().unwrap())
            .expect("SMT insert failed");
    }

    let find_result = smt.find(key).expect("SMT find failed");

    // pad siblings to requested length
    let mut siblings = find_result.siblings.clone();
    while siblings.len() < max_levels {
        siblings.push(BigUint::from(0u32));
    }

    SMTProof {
        found: find_result.found,
        siblings,
        found_value: find_result.found_value,
        not_found_key: find_result.not_found_key,
        not_found_value: find_result.not_found_value,
        is_old0: find_result.is_old0,
        root: smt.root().clone(),
    }
}

// pub fn prepare_smt_proof(key: &BigUint, extra_leaves: &[(u32, BigInt)]) -> SMTProof {
//     let db = SMTMemDB::new();
//     let mut smt = SparseMerkleTree::new(db, BigUint::from(0u32));
//
//     // Up to the level
//     let max_keys = 1u32 << (LEVELS as u32); // 32
//     let mut map = HashMap::new();
//     for (k, v) in extra_leaves {
//         assert!(
//             *k < max_keys,
//             "override key {} out of range (0..{})",
//             k,
//             max_keys - 1
//         );
//         map.insert(*k, v.clone());
//     }
//
//     // Fill every position 0..31 with default value=key, unless an override exists.
//     for i in 0u32..max_keys {
//         let val: BigInt = map.get(&i).cloned().unwrap_or_else(|| BigInt::from(i));
//         smt.insert(&BigUint::from(i), &val.to_biguint().unwrap())
//             .expect("insert failed");
//     }
//
//     let find_result = smt.find(key).expect("Failed to find key");
//
//     // Pad siblings with zeros to reach max_levels
//     let mut siblings = find_result.siblings.clone();
//     while siblings.len() < LEVELS {
//         siblings.push(BigUint::from(0u32));
//     }
//
//     SMTProof {
//         found: find_result.found,
//         siblings,
//         found_value: find_result.found_value,
//         not_found_key: find_result.not_found_key,
//         not_found_value: find_result.not_found_value,
//         is_old0: find_result.is_old0,
//         root: smt.root().clone(),
//     }
// }

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

    run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        None::<fn(&mut Inputs)>,
    )
}
