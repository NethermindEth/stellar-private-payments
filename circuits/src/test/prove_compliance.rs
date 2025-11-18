use crate::test::utils::circom_tester::{Inputs, SignalKey, prove_and_verify};
use crate::test::utils::general::{load_artifacts, poseidon2_hash2, scalar_to_bigint};
use crate::test::utils::keypair::derive_public_key;
use crate::test::utils::merkle_tree::{merkle_proof, merkle_root};
use crate::test::utils::sparse_merkle_tree::prepare_smt_proof_with_overrides;
use crate::test::utils::transaction::{commitment, prepopulated_leaves};
use crate::test::utils::transaction_case::{
    InputNote, OutputNote, TxCase, build_base_inputs, prepare_transaction_witness,
};
use anyhow::{Context, Result, ensure};
use num_bigint::BigInt;
use std::convert::TryInto;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use zkhash::ark_ff::Zero;
use zkhash::fields::bn256::FpBN256 as Scalar;

const LEVELS: usize = 5;
const N_MEM_PROOFS: usize = 1;
const N_NON_PROOFS: usize = 1;

pub struct MembershipTree {
    pub leaves: [Scalar; 1 << LEVELS],
    pub index: usize,
    pub blinding: Scalar,
}

pub struct NonMembership {
    pub key_non_inclusion: u32,
    pub key_of_leaf: u32,
}

fn build_membership_trees<F>(case: &TxCase, seed_fn: F) -> Vec<MembershipTree>
where
    F: Fn(usize) -> u64,
{
    let n_inputs = case.inputs.len();
    let mut membership_trees = Vec::with_capacity(n_inputs * N_MEM_PROOFS);

    for j in 0..N_MEM_PROOFS {
        let seed_j = seed_fn(j);
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);

        for input in &case.inputs {
            membership_trees.push(MembershipTree {
                leaves: base_mem_leaves_j
                    .clone()
                    .try_into()
                    .expect("Failed to convert into list"),
                index: input.leaf_index,
                blinding: Scalar::zero(),
            });
        }
    }

    membership_trees
}

fn default_membership_trees(case: &TxCase, suffix: u64) -> Vec<MembershipTree> {
    build_membership_trees(case, |j| 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ suffix)
}

#[allow(clippy::too_many_arguments)]
fn run_case<F>(
    wasm: &PathBuf,
    r1cs: &PathBuf,
    case: &TxCase,
    leaves: Vec<Scalar>,
    public_amount: Scalar,
    membership_trees: &[MembershipTree],
    non_membership: &[NonMembership],
    mutate_inputs: Option<F>,
) -> Result<()>
where
    F: FnOnce(&mut Inputs),
{
    let n_inputs = case.inputs.len();
    ensure!(
        n_inputs == non_membership.len(),
        "non-membership entries ({}) must match number of inputs ({n_inputs})",
        non_membership.len()
    );

    let witness = prepare_transaction_witness(case, leaves, LEVELS)?;
    let mut inputs = build_base_inputs(case, &witness, public_amount);
    let pubs = &witness.public_keys;

    // === MEMBERSHIP PROOF ===
    let mut mp_leaf: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut mp_pk: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut mp_blinding: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut mp_path_indices: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut mp_path_elements: Vec<Vec<Vec<BigInt>>> = Vec::with_capacity(n_inputs);
    let mut membership_roots: Vec<BigInt> = Vec::with_capacity(n_inputs * N_MEM_PROOFS);

    for _ in 0..n_inputs {
        mp_leaf.push(Vec::with_capacity(N_MEM_PROOFS));
        mp_pk.push(Vec::with_capacity(N_MEM_PROOFS));
        mp_blinding.push(Vec::with_capacity(N_MEM_PROOFS));
        mp_path_indices.push(Vec::with_capacity(N_MEM_PROOFS));
        mp_path_elements.push(Vec::with_capacity(N_MEM_PROOFS));
    }

    ensure!(
        membership_trees.len() == n_inputs * N_MEM_PROOFS,
        "expected {} membership trees, found {}",
        n_inputs * N_MEM_PROOFS,
        membership_trees.len()
    );

    for j in 0..N_MEM_PROOFS {
        let base_idx = j
            .checked_mul(n_inputs)
            .ok_or_else(|| anyhow::anyhow!("index overflow in membership_trees"))?;
        let mut frozen_leaves = membership_trees[base_idx].leaves;

        for (k, &pk_scalar) in pubs.iter().enumerate() {
            let index = k
                .checked_mul(N_MEM_PROOFS)
                .and_then(|v| v.checked_add(j))
                .ok_or_else(|| anyhow::anyhow!("index overflow in membership_trees"))?;

            let tree = membership_trees.get(index).ok_or_else(|| {
                anyhow::anyhow!("missing membership tree for input {k}, proof {j}")
            })?;
            let leaf = poseidon2_hash2(pk_scalar, tree.blinding);
            frozen_leaves[tree.index] = leaf;
        }

        let root_scalar = merkle_root(frozen_leaves.to_vec().clone());

        for i in 0..n_inputs {
            let idx = i
                .checked_mul(N_MEM_PROOFS)
                .and_then(|v| v.checked_add(j))
                .ok_or_else(|| anyhow::anyhow!("index overflow in membership_trees"))?;

            let t = &membership_trees[idx];
            let pk_scalar = pubs[i];
            let leaf_scalar = poseidon2_hash2(pk_scalar, t.blinding);

            let (siblings, path_idx_u64, depth) = merkle_proof(&frozen_leaves, t.index);
            assert_eq!(depth, LEVELS, "unexpected membership depth for input {i}");

            mp_leaf[i].push(scalar_to_bigint(leaf_scalar));
            mp_pk[i].push(scalar_to_bigint(pk_scalar));
            mp_blinding[i].push(scalar_to_bigint(t.blinding));
            mp_path_indices[i].push(scalar_to_bigint(Scalar::from(path_idx_u64)));
            mp_path_elements[i].push(siblings.into_iter().map(scalar_to_bigint).collect());

            membership_roots.push(scalar_to_bigint(root_scalar));
        }
    }

    // === NON MEMBERSHIP PROOF ===

    let overrides: Vec<(u32, BigInt)> = non_membership
        .iter()
        .zip(pubs.iter())
        .map(|(nm, &pk_scalar)| {
            (
                nm.key_of_leaf,
                scalar_to_bigint(poseidon2_hash2(pk_scalar, Scalar::zero())),
            )
        })
        .collect();

    let mut nmp_key: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut nmp_value: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut nmp_old_key: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut nmp_old_value: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut nmp_is_old0: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut nmp_siblings: Vec<Vec<Vec<BigInt>>> = Vec::with_capacity(n_inputs);
    let mut nmp_pk: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut nmp_blinding: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
    let mut non_membership_roots: Vec<BigInt> = Vec::with_capacity(n_inputs * N_NON_PROOFS);

    for _ in 0..n_inputs {
        nmp_key.push(Vec::with_capacity(N_NON_PROOFS));
        nmp_value.push(Vec::with_capacity(N_NON_PROOFS));
        nmp_old_key.push(Vec::with_capacity(N_NON_PROOFS));
        nmp_old_value.push(Vec::with_capacity(N_NON_PROOFS));
        nmp_is_old0.push(Vec::with_capacity(N_NON_PROOFS));
        nmp_siblings.push(Vec::with_capacity(N_NON_PROOFS));
        nmp_pk.push(Vec::with_capacity(N_NON_PROOFS));
        nmp_blinding.push(Vec::with_capacity(N_NON_PROOFS));
    }

    for j in 0..N_NON_PROOFS {
        let idx_mod = j
            .checked_rem(n_inputs)
            .expect("j % n_inputs overflowed or n_inputs == 0");

        let last_valid_idx = n_inputs.checked_sub(1).expect("n_inputs must be > 0");

        let idx = idx_mod.min(last_valid_idx);
        let nm_root = &non_membership[idx];
        let tmp = prepare_smt_proof_with_overrides(
            &BigInt::from(nm_root.key_non_inclusion),
            &overrides,
            LEVELS,
        );

        for i in 0..n_inputs {
            let leaf_ij = poseidon2_hash2(pubs[i], Scalar::zero());

            let proof = prepare_smt_proof_with_overrides(
                &BigInt::from(non_membership[i].key_non_inclusion),
                &overrides,
                LEVELS,
            );

            nmp_key[i].push(BigInt::from(non_membership[i].key_non_inclusion));
            nmp_value[i].push(scalar_to_bigint(leaf_ij));

            if proof.is_old0 {
                nmp_old_key[i].push(BigInt::from(0u32));
                nmp_old_value[i].push(BigInt::from(0u32));
                nmp_is_old0[i].push(BigInt::from(1u32));
            } else {
                nmp_old_key[i].push(proof.not_found_key.clone());
                nmp_old_value[i].push(proof.not_found_value.clone());
                nmp_is_old0[i].push(BigInt::from(0u32));
            }

            nmp_siblings[i].push(proof.siblings.clone());

            nmp_pk[i].push(scalar_to_bigint(pubs[i]));
            nmp_blinding[i].push(BigInt::from(0u32));

            non_membership_roots.push(tmp.root.clone());
        }
    }

    for i in 0..n_inputs {
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

    for i in 0..n_inputs {
        for j in 0..N_NON_PROOFS {
            let key = |field: &str| {
                SignalKey::new("nonMembershipProofs")
                    .idx(i)
                    .idx(j)
                    .field(field)
            };

            inputs.set_key(&key("key"), nmp_key[i][j].clone());
            inputs.set_key(&key("value"), nmp_value[i][j].clone());
            inputs.set_key(&key("oldKey"), nmp_old_key[i][j].clone());
            inputs.set_key(&key("oldValue"), nmp_old_value[i][j].clone());
            inputs.set_key(&key("isOld0"), nmp_is_old0[i][j].clone());
            inputs.set_key(&key("siblings"), nmp_siblings[i][j].clone());
            inputs.set_key(&key("pk"), nmp_pk[i][j].clone());
            inputs.set_key(&key("blinding"), nmp_blinding[i][j].clone());
        }
    }
    inputs.set("nonMembershipRoots", non_membership_roots);

    // Add inputs from test
    if let Some(f) = mutate_inputs {
        f(&mut inputs);
    }
    // --- Prove & verify ---
    let prove_result =
        panic::catch_unwind(AssertUnwindSafe(|| prove_and_verify(wasm, r1cs, &inputs)));
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

fn compliance_artifacts() -> Result<(PathBuf, PathBuf)> {
    load_artifacts("compliant_test")
}

#[tokio::test]
async fn test_tx_1in_1out() -> Result<()> {
    // One real input (in1), one dummy input (in0.amount = 0).
    // One real output (out0 = in1.amount), one dummy output (out1.amount = 0).
    let (wasm, r1cs) = compliance_artifacts()?;

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(201u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 7,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(211u64),
                amount: Scalar::from(13u64),
            },
        ],
        vec![
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
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xDEAD_BEEFu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    let membership_trees = default_membership_trees(&case, 0x1234_5678u64);
    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        None::<fn(&mut Inputs)>,
    )
}

#[tokio::test]
async fn test_tx_2in_1out() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    let a = Scalar::from(9u64);
    let b = Scalar::from(4u64);
    let sum = a + b;

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(201u64),
                blinding: Scalar::from(301u64),
                amount: a,
            },
            InputNote {
                leaf_index: 19,
                priv_key: Scalar::from(211u64),
                blinding: Scalar::from(311u64),
                amount: b,
            },
        ],
        vec![
            OutputNote {
                pub_key: Scalar::from(701u64),
                blinding: Scalar::from(801u64),
                amount: sum,
            },
            OutputNote {
                pub_key: Scalar::from(702u64),
                blinding: Scalar::from(802u64),
                amount: Scalar::from(0u64),
            },
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xFACEu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    let membership_trees = default_membership_trees(&case, 0x1234_5678u64);

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        None::<fn(&mut Inputs)>,
    )
}

#[tokio::test]
async fn test_tx_1in_2out_split() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    let total = Scalar::from(20u64);
    let a0 = Scalar::from(6u64);
    let a1 = total - a0;

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(301u64),
                blinding: Scalar::from(401u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 23,
                priv_key: Scalar::from(311u64),
                blinding: Scalar::from(411u64),
                amount: total,
            },
        ],
        vec![
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
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xC0FFEEu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    let membership_trees = default_membership_trees(&case, 0x1234_5678u64);

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        None::<fn(&mut Inputs)>,
    )
}

#[tokio::test]
async fn test_tx_2in_2out_split() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    let a = Scalar::from(15u64);
    let b = Scalar::from(8u64);
    let sum = a + b;

    let out_a = Scalar::from(10u64);
    let out_b = sum - out_a;

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(401u64),
                blinding: Scalar::from(501u64),
                amount: a,
            },
            InputNote {
                leaf_index: 30,
                priv_key: Scalar::from(411u64),
                blinding: Scalar::from(511u64),
                amount: b,
            },
        ],
        vec![
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
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xBEEFu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    let membership_trees = default_membership_trees(&case, 0x1234_5678u64);

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        None::<fn(&mut Inputs)>,
    )
}

#[tokio::test]
async fn test_tx_chained_spend() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    // Tx1 produces an output that Tx2 spends
    let chain_priv = Scalar::from(777u64);
    let chain_pub = derive_public_key(chain_priv);
    let chain_blind = Scalar::from(2024u64);
    let chain_amount = Scalar::from(17u64);

    let tx1_real_idx = 9usize;
    let chain_idx = 13usize;

    let mut leaves = prepopulated_leaves(LEVELS, 0xC0DEC0DEu64, &[0, tx1_real_idx, chain_idx], 24);

    // --- TX1 ---
    let tx1_input_real = InputNote {
        leaf_index: tx1_real_idx,
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
    let tx1_in0_dummy = InputNote {
        leaf_index: 0,
        priv_key: Scalar::from(11u64),
        blinding: Scalar::from(22u64),
        amount: Scalar::from(0u64),
    };

    let tx1 = TxCase::new(
        vec![tx1_in0_dummy, tx1_input_real.clone()],
        vec![tx1_out0.clone(), tx1_out1.clone()],
    );

    // membership trees for TX1 (distinct baseline per j)
    let mt1 = build_membership_trees(&tx1, |j| {
        0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0xA11C_3EAFu64
    });

    let keys = vec![
        NonMembership {
            key_non_inclusion: 10,
            key_of_leaf: 2,
        },
        NonMembership {
            key_non_inclusion: 20,
            key_of_leaf: 16,
        },
    ];

    run_case(
        &wasm,
        &r1cs,
        &tx1,
        prepopulated_leaves(LEVELS, 0xC0DEC0DEu64, &[0, tx1_real_idx, chain_idx], 24),
        Scalar::from(0u64),
        &mt1,
        &keys,
        None::<fn(&mut Inputs)>,
    )?;

    // append Tx1.out0 commitment at chain_idx
    let out0_commit = commitment(tx1_out0.amount, tx1_out0.pub_key, tx1_out0.blinding);
    leaves[chain_idx] = out0_commit;

    // --- TX2 ---
    let tx2_in1 = InputNote {
        leaf_index: chain_idx,
        priv_key: chain_priv,
        blinding: chain_blind,
        amount: chain_amount,
    };
    let tx2_in0_dummy = InputNote {
        leaf_index: 0,
        priv_key: Scalar::from(99u64),
        blinding: Scalar::from(100u64),
        amount: Scalar::from(0u64),
    };
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
        vec![tx2_in0_dummy, tx2_in1],
        vec![tx2_out_real, tx2_out_dummy],
    );

    let mt2 = build_membership_trees(&tx2, |j| {
        0xFEED_FACEu64 ^ ((j as u64) << 40) ^ 0xB16B_00B5u64
    });

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    run_case(
        &wasm,
        &r1cs,
        &tx2,
        leaves,
        Scalar::from(0u64),
        &mt2,
        &keys,
        None::<fn(&mut Inputs)>,
    )
}

#[tokio::test]
async fn test_tx_only_adds_notes_deposit() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    // both inputs dummy -> Merkle checks gated off by amount=0
    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(11u64),
                blinding: Scalar::from(21u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 5,
                priv_key: Scalar::from(12u64),
                blinding: Scalar::from(22u64),
                amount: Scalar::from(0u64),
            },
        ],
        vec![
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
        ],
    );

    let deposit = Scalar::from(12u64);
    let leaves = prepopulated_leaves(
        LEVELS,
        0xD3AD0517u64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    let membership_trees = default_membership_trees(&case, 0x5555_AAAAu64);

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        deposit,
        &membership_trees,
        &keys,
        None::<fn(&mut Inputs)>,
    )
}

#[tokio::test]
async fn test_tx_only_spends_notes_withdraw_one_real() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    let spend = Scalar::from(9u64);

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(1u64),
                blinding: Scalar::from(2u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 7,
                priv_key: Scalar::from(111u64),
                blinding: Scalar::from(211u64),
                amount: spend,
            },
        ],
        vec![
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
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xC0FFEEu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );
    let neg_spend = Scalar::zero() - spend;

    let membership_trees = default_membership_trees(&case, 0xDEAD_BEEFu64);

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        neg_spend,
        &membership_trees,
        &keys,
        None::<fn(&mut Inputs)>,
    )
}

#[tokio::test]
async fn test_tx_only_spends_notes_withdraw_two_real() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    let a = Scalar::from(5u64);
    let b = Scalar::from(11u64);
    let sum_in = a + b;

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(401u64),
                blinding: Scalar::from(501u64),
                amount: a,
            },
            InputNote {
                leaf_index: 13,
                priv_key: Scalar::from(411u64),
                blinding: Scalar::from(511u64),
                amount: b,
            },
        ],
        vec![
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
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xC0FFEEu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );
    let neg_sum = Scalar::zero() - sum_in;

    let membership_trees = default_membership_trees(&case, 0xABCD_EF01u64);

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        neg_sum,
        &membership_trees,
        &keys,
        None::<fn(&mut Inputs)>,
    )
}

#[tokio::test]
async fn test_tx_same_nullifier_should_fail() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    // Same note material used twice
    let privk = Scalar::from(7777u64);
    let blind = Scalar::from(4242u64);
    let amount = Scalar::from(33u64);

    let same_note = InputNote {
        leaf_index: 0,
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

    let case = TxCase::new(
        vec![
            same_note.clone(), // in0 @ real_id=0
            InputNote {
                leaf_index: 5,
                ..same_note.clone()
            }, // in1 @ real_id=5 (same note material)
        ],
        vec![out_real, out_dummy],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xC0FFEEu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    let membership_trees = default_membership_trees(&case, 0xFEFE_FEF1u64);

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    let res = run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        None::<fn(&mut Inputs)>,
    );
    assert!(
        res.is_err(),
        "Same-nullifier case unexpectedly verified; expected rejection due to duplicate nullifiers"
    );

    if let Err(e) = res {
        println!("same-nullifier correctly rejected: {e:?}");
    }
    Ok(())
}

#[tokio::test]
async fn test_membership_should_fail_wrong_pk() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(201u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 7,
                priv_key: Scalar::from(111u64),
                blinding: Scalar::from(211u64),
                amount: Scalar::from(13u64),
            },
        ],
        vec![
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
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xCAFE_BE5Eu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    // Normal membership trees (blinding = 0)
    let membership_trees = default_membership_trees(&case, 0x1111_2222u64);
    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    // Tamper: set membershipProofs[1][0].pk to a bogus value
    let res = run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        Some(|inputs: &mut Inputs| {
            let key = |field: &str| {
                SignalKey::new("membershipProofs")
                    .idx(1)
                    .idx(0)
                    .field(field)
            };
            inputs.set_key(&key("pk"), scalar_to_bigint(Scalar::from(42u64)));
        }),
    );

    assert!(
        res.is_err(),
        "membership with wrong pk unexpectedly verified"
    );
    Ok(())
}

#[tokio::test]
async fn test_membership_should_fail_wrong_path() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(201u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 7,
                priv_key: Scalar::from(111u64),
                blinding: Scalar::from(211u64),
                amount: Scalar::from(13u64),
            },
        ],
        vec![
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
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xFACE_FEEDu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    let membership_trees = default_membership_trees(&case, 0x3333_4444u64);

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    // Tamper: zero out the pathElements for input 1, proof 0
    let res = run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        Some(|inputs: &mut Inputs| {
            let key = |field: &str| {
                SignalKey::new("membershipProofs")
                    .idx(1)
                    .idx(0)
                    .field(field)
            };
            let zeros: Vec<BigInt> = (0..LEVELS).map(|_| BigInt::from(0u32)).collect();
            inputs.set_key(&key("pathElements"), zeros);
        }),
    );

    assert!(
        res.is_err(),
        "membership with wrong path unexpectedly verified"
    );
    Ok(())
}

#[tokio::test]
async fn test_membership_should_fail_wrong_root() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(201u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 7,
                priv_key: Scalar::from(111u64),
                blinding: Scalar::from(211u64),
                amount: Scalar::from(13u64),
            },
        ],
        vec![
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
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xDEAD_BEEFu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    let membership_trees = default_membership_trees(&case, 0x5555_6666u64);

    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 1,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    // Tamper: replace membershipRoots with bogus constants
    let res = run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        Some(|inputs: &mut Inputs| {
            let bogus: Vec<BigInt> = (0..(case.inputs.len() * N_MEM_PROOFS))
                .map(|_| scalar_to_bigint(Scalar::from(123u64)))
                .collect();
            inputs.set("membershipRoots", bogus);
        }),
    );

    assert!(
        res.is_err(),
        "membership with wrong root unexpectedly verified"
    );
    Ok(())
}

#[tokio::test]
async fn test_non_membership_fails() -> Result<()> {
    // One real input (in1), one dummy input (in0.amount = 0).
    // One real output (out0 = in1.amount), one dummy output (out1.amount = 0).
    let (wasm, r1cs) = compliance_artifacts()?;

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(201u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 7,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(211u64),
                amount: Scalar::from(13u64),
            },
        ],
        vec![
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
        ],
    );

    let leaves = prepopulated_leaves(
        LEVELS,
        0xDEAD_BEEFu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );

    let membership_trees = default_membership_trees(&case, 0x1234_5678u64);
    let keys = vec![
        NonMembership {
            key_non_inclusion: 2,
            key_of_leaf: 2,
        },
        NonMembership {
            key_non_inclusion: 12,
            key_of_leaf: 10,
        },
    ];

    let res = run_case(
        &wasm,
        &r1cs,
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        None::<fn(&mut Inputs)>,
    );

    assert!(res.is_err(), "non membership not found");
    Ok(())
}

#[tokio::test]
async fn test_tx_randomized_stress() -> Result<()> {
    let (wasm, r1cs) = compliance_artifacts()?;

    #[inline]
    fn next_u64(state: &mut u128) -> u64 {
        *state = (*state)
            .wrapping_mul(6364136223846793005u128)
            .wrapping_add(1442695040888963407u128);
        (*state >> 64) as u64
    }

    #[inline]
    fn rand_scalar(state: &mut u128) -> Scalar {
        Scalar::from(next_u64(state))
    }
    #[inline]
    fn nonzero_amount_u64(state: &mut u128, max: u64) -> u64 {
        1 + (next_u64(state) % max.max(1))
    }

    // --- Key fuzzing (bounded to 0..(1<<LEVELS)) ---------------------------
    // Keep pairs with key_of_leaf < key_non_inclusion (matches your examples).
    #[inline]
    fn gen_key_pair(state: &mut u128, max_k_exclusive: u64, max_gap: u64) -> (u64, u64) {
        // need a domain of at least {0,1}
        let max_k_exclusive = max_k_exclusive.max(2);
        let max_gap = max_gap.max(1);

        // pick k in [1, max_k_exclusive-1] so there’s room for a smaller leaf
        let k = 1 + (next_u64(state) % (max_k_exclusive - 1));

        // gap in [1, max_gap]
        let gap = 1 + (next_u64(state) % max_gap);

        // candidate l = k - gap, clamped to [0, k-1]
        let mut l = k.saturating_sub(gap);
        if l >= k {
            // just in case (shouldn’t happen with saturating_sub), force l < k
            l = k - 1;
        }
        // final guard: ensure strict inequality
        if l == k {
            l = k - 1;
        }

        (k, l)
    }

    #[inline]
    fn gen_keys_for_iteration(state: &mut u128, max_k_exclusive: u64) -> [NonMembership; 2] {
        let which = (next_u64(state) % 5) as u8;

        let small_gap = (max_k_exclusive / 128).max(3);
        let med_gap = (max_k_exclusive / 32).max(8);
        let wide_gap = (max_k_exclusive / 8).max(16);

        let (k1, l1, k2, l2) = match which {
            // Tiny values, tight adjacency (cap the domain to 32 if available)
            0 => {
                let cap = max_k_exclusive.min(32);
                let (k1, l1) = gen_key_pair(state, cap, 3);
                let (k2, l2) = gen_key_pair(state, cap, 1);
                (k1, l1, k2, l2)
            }
            // Values across full domain with moderate gaps
            1 => {
                let (k1, l1) = gen_key_pair(state, max_k_exclusive, med_gap);
                let (k2, l2) = gen_key_pair(state, max_k_exclusive, small_gap);
                (k1, l1, k2, l2)
            }
            // Neighbor-ish cases (gap 1 or very small)
            2 => {
                let (k1, l1) = gen_key_pair(state, max_k_exclusive, 1);
                let (k2, l2) = gen_key_pair(state, max_k_exclusive, 2);
                (k1, l1, k2, l2)
            }
            // Edge near the top of the domain (still < max_k_exclusive)
            3 => {
                #[allow(clippy::manual_clamp)]
                let window = max_k_exclusive.min(1024).max(2);
                let top_k = max_k_exclusive - 1 - (next_u64(state) % (window - 1));
                let gap1 = 1 + (next_u64(state) % med_gap);
                let gap2 = 1 + (next_u64(state) % wide_gap);
                let k1 = top_k;
                let l1 = k1.saturating_sub(gap1).min(k1.saturating_sub(1));
                let k2 = top_k.saturating_sub(1 + (next_u64(state) % (window / 2).max(1)));
                let l2 = k2.saturating_sub(gap2).min(k2.saturating_sub(1));
                (k1, l1, k2, l2)
            }
            // Default: full domain, mixed gaps
            _ => {
                let (k1, l1) = gen_key_pair(state, max_k_exclusive, wide_gap);
                let (k2, l2) = gen_key_pair(state, max_k_exclusive, med_gap);
                (k1, l1, k2, l2)
            }
        };

        [
            NonMembership {
                key_non_inclusion: u32::try_from(k1).expect("usize overflow"),
                key_of_leaf: u32::try_from(l1).expect("usize overflow"),
            },
            NonMembership {
                key_non_inclusion: u32::try_from(k2).expect("usize overflow"),
                key_of_leaf: u32::try_from(l2).expect("usize overflow"),
            },
        ]
    }
    // -----------------------------------------------------------------------

    const N_ITERS: usize = 20;

    const N: usize = 1 << LEVELS;
    let mut rng: u128 = 0xA9_5EED_1337_D3AD_B33Fu128;

    for _ in 0..N_ITERS {
        let scenario = (next_u64(&mut rng) % 4) as u8;

        // pick real index != 0
        let real_idx = {
            let mut idx = usize::try_from(next_u64(&mut rng))? % N;
            if idx == 0 {
                idx = 1;
            }
            idx
        };

        let leaves_seed = next_u64(&mut rng);
        let leaves = prepopulated_leaves(LEVELS, leaves_seed, &[0, real_idx], 24);

        let in0_dummy = InputNote {
            leaf_index: 0,
            priv_key: rand_scalar(&mut rng),
            blinding: rand_scalar(&mut rng),
            amount: Scalar::from(0u64),
        };
        let in1_amt_u64 = nonzero_amount_u64(&mut rng, 1_000);
        let in1_real = InputNote {
            leaf_index: real_idx,
            priv_key: rand_scalar(&mut rng),
            blinding: rand_scalar(&mut rng),
            amount: Scalar::from(in1_amt_u64),
        };

        let in0_alt_amt_u64 = nonzero_amount_u64(&mut rng, 1_000);
        let in0_real_alt = InputNote {
            leaf_index: 0,
            priv_key: rand_scalar(&mut rng),
            blinding: rand_scalar(&mut rng),
            amount: Scalar::from(in0_alt_amt_u64),
        };

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

        let out0 = OutputNote {
            pub_key: rand_scalar(&mut rng),
            blinding: rand_scalar(&mut rng),
            amount: Scalar::from(out0_amt_u64),
        };
        let out1 = OutputNote {
            pub_key: rand_scalar(&mut rng),
            blinding: rand_scalar(&mut rng),
            amount: Scalar::from(out1_amt_u64),
        };

        let case = TxCase::new(vec![in0_used, in1_used], vec![out0, out1]);

        // membership trees: distinct baseline per j
        let membership_trees =
            build_membership_trees(&case, |j| 0xFEED_FACEu64 ^ ((j as u64) << 40) ^ leaves_seed);

        // Keys strictly in 0..(1<<LEVELS)
        let keys = gen_keys_for_iteration(&mut rng, N as u64);

        run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees, &keys, None::<fn(&mut Inputs)>).with_context(|| {
            format!(
                "randomized iteration failed (seed=0x{leaves_seed:x}, scenario={scenario}, real_idx={real_idx}, \
                 keys=[({}, {}), ({}, {})])",
                keys[0].key_non_inclusion, keys[0].key_of_leaf, keys[1].key_non_inclusion, keys[1].key_of_leaf
            )
        })?;
    }

    Ok(())
}
