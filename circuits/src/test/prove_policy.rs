#[cfg(test)]
mod tests {
    use crate::test::utils::{
        circom_tester::{Inputs, SignalKey, prove_and_verify},
        general::{load_artifacts, poseidon2_hash2, scalar_to_bigint},
        keypair::derive_public_key,
        merkle_tree::{merkle_proof, merkle_root},
        sparse_merkle_tree::{SMTProof, prepare_smt_proof_with_overrides},
        transaction::{commitment, prepopulated_leaves},
        transaction_case::{
            InputNote, OutputNote, TxCase, build_base_inputs, prepare_transaction_witness,
        },
    };
    use anyhow::{Context, Result, ensure};
    use num_bigint::BigInt;
    use std::{
        convert::TryInto,
        panic::{self, AssertUnwindSafe},
        path::PathBuf,
    };
    use zkhash::{ark_ff::Zero, fields::bn256::FpBN256 as Scalar};

    const LEVELS: usize = 10;
    const N_MEM_PROOFS: usize = 1;
    const N_NON_PROOFS: usize = 1;

    pub struct MembershipTree {
        pub leaves: [Scalar; 1 << LEVELS],
        pub index: usize,
        pub blinding: Scalar,
    }

    pub struct NonMembership {
        pub key_non_inclusion: BigInt,
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

    fn non_membership_overrides_from_pubs(pubs: &[Scalar]) -> Vec<(BigInt, BigInt)> {
        pubs.iter()
            .enumerate()
            .map(|(i, pk)| {
                // Make the +1 explicit and checked
                let idx = u64::try_from(i)
                    .expect("Failed to cast i")
                    .checked_add(1)
                    .expect("idx overflow");

                // Make the mul + add explicit and checked
                let override_factor: u64 = 100_000;
                let override_idx = idx
                    .checked_mul(override_factor)
                    .and_then(|v| v.checked_add(idx))
                    .expect("override_idx overflow");

                let override_key = Scalar::from(override_idx);

                let leaf = poseidon2_hash2(*pk, Scalar::zero(), Some(Scalar::from(1u64)));
                (scalar_to_bigint(override_key), scalar_to_bigint(leaf))
            })
            .collect()
    }

    fn default_non_membership_proof_builder(key: &BigInt, pubs: &[Scalar]) -> SMTProof {
        let overrides = non_membership_overrides_from_pubs(pubs);
        prepare_smt_proof_with_overrides(key, &overrides, LEVELS)
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
        run_case_with_non_membership_builder(
            wasm,
            r1cs,
            case,
            leaves,
            public_amount,
            membership_trees,
            non_membership,
            default_non_membership_proof_builder,
            mutate_inputs,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_case_with_non_membership_builder<F, G>(
        wasm: &PathBuf,
        r1cs: &PathBuf,
        case: &TxCase,
        leaves: Vec<Scalar>,
        public_amount: Scalar,
        membership_trees: &[MembershipTree],
        non_membership: &[NonMembership],
        build_non_membership_proof: G,
        mutate_inputs: Option<F>,
    ) -> Result<()>
    where
        F: FnOnce(&mut Inputs),
        G: Fn(&BigInt, &[Scalar]) -> SMTProof,
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
        let mut mp_blinding: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
        let mut mp_path_indices: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
        let mut mp_path_elements: Vec<Vec<Vec<BigInt>>> = Vec::with_capacity(n_inputs);
        let mut membership_roots: Vec<BigInt> = Vec::with_capacity(n_inputs * N_MEM_PROOFS);

        for _ in 0..n_inputs {
            mp_leaf.push(Vec::with_capacity(N_MEM_PROOFS));
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
                let leaf = poseidon2_hash2(pk_scalar, tree.blinding, Some(Scalar::from(1u64))); // H(pk_k, blinding_{k,j})
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
                let leaf_scalar = poseidon2_hash2(pk_scalar, t.blinding, Some(Scalar::from(1u64)));

                let (siblings, path_idx_u64, depth) = merkle_proof(&frozen_leaves, t.index);
                assert_eq!(depth, LEVELS, "unexpected membership depth for input {i}");

                mp_leaf[i].push(scalar_to_bigint(leaf_scalar));
                mp_blinding[i].push(scalar_to_bigint(t.blinding));
                mp_path_indices[i].push(scalar_to_bigint(Scalar::from(path_idx_u64)));
                mp_path_elements[i].push(siblings.into_iter().map(scalar_to_bigint).collect());

                membership_roots.push(scalar_to_bigint(root_scalar));
            }
        }

        // === NON MEMBERSHIP PROOF ===

        let mut nmp_key: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
        let mut nmp_old_key: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
        let mut nmp_old_value: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
        let mut nmp_is_old0: Vec<Vec<BigInt>> = Vec::with_capacity(n_inputs);
        let mut nmp_siblings: Vec<Vec<Vec<BigInt>>> = Vec::with_capacity(n_inputs);
        let mut non_membership_roots: Vec<BigInt> = Vec::with_capacity(n_inputs * N_NON_PROOFS);

        for _ in 0..n_inputs {
            nmp_key.push(Vec::with_capacity(N_NON_PROOFS));
            nmp_old_key.push(Vec::with_capacity(N_NON_PROOFS));
            nmp_old_value.push(Vec::with_capacity(N_NON_PROOFS));
            nmp_is_old0.push(Vec::with_capacity(N_NON_PROOFS));
            nmp_siblings.push(Vec::with_capacity(N_NON_PROOFS));
        }

        for _ in 0..N_NON_PROOFS {
            for i in 0..n_inputs {
                let proof = build_non_membership_proof(&non_membership[i].key_non_inclusion, pubs);

                nmp_key[i].push(scalar_to_bigint(pubs[i]));

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

                non_membership_roots.push(proof.root.clone());
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
                inputs.set_key(&key("oldKey"), nmp_old_key[i][j].clone());
                inputs.set_key(&key("oldValue"), nmp_old_value[i][j].clone());
                inputs.set_key(&key("isOld0"), nmp_is_old0[i][j].clone());
                inputs.set_key(&key("siblings"), nmp_siblings[i][j].clone());
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

    fn policy_artifacts() -> Result<(PathBuf, PathBuf)> {
        load_artifacts("policy_test")
    }

    #[test]
    #[ignore]
    fn test_tx_1in_1out() -> Result<()> {
        // One real input (in1), one dummy input (in0.amount = 0).
        // One real output (out0 = in1.amount), one dummy output (out1.amount = 0).
        let (wasm, r1cs) = policy_artifacts()?;

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
                    priv_key: Scalar::from(102u64),
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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_tx_2in_1out() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_tx_1in_2out_split() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_tx_2in_2out_split() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_tx_chained_spend() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

        // Tx1 produces an output that Tx2 spends
        let chain_priv = Scalar::from(777u64);
        let chain_pub = derive_public_key(chain_priv);
        let chain_blind = Scalar::from(2024u64);
        let chain_amount = Scalar::from(17u64);

        let tx1_real_idx = 9usize;
        let chain_idx = 13usize;

        let mut leaves =
            prepopulated_leaves(LEVELS, 0xC0DEC0DEu64, &[0, tx1_real_idx, chain_idx], 24);

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(tx1.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(tx1.inputs[1].priv_key)),
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
                key_non_inclusion: scalar_to_bigint(derive_public_key(tx2.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(tx2.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_tx_only_adds_notes_deposit() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_tx_only_spends_notes_withdraw_one_real() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_tx_only_spends_notes_withdraw_two_real() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_tx_same_nullifier_should_fail() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
            },
        ];

        let res = run_case_with_non_membership_builder(
            &wasm,
            &r1cs,
            &case,
            leaves,
            Scalar::from(0u64),
            &membership_trees,
            &keys,
            |key, pubs| {
                let overrides = non_membership_overrides_from_pubs(pubs);
                prepare_smt_proof_with_overrides(key, &overrides, LEVELS)
            },
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

    #[test]
    #[ignore]
    fn test_membership_should_fail_wrong_privkey() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
            },
        ];

        // Set inPrivateKey[0] to the wrong value
        let original_keys: Vec<BigInt> = case
            .inputs
            .iter()
            .map(|n| scalar_to_bigint(n.priv_key))
            .collect();
        let mut modified_keys = original_keys.clone();
        modified_keys[0] = scalar_to_bigint(Scalar::from(999u64)); // Wrong private key for index 0

        let res = run_case(
            &wasm,
            &r1cs,
            &case,
            leaves,
            Scalar::from(0u64),
            &membership_trees,
            &keys,
            Some(|inputs: &mut Inputs| {
                inputs.set("inPrivateKey", modified_keys.clone());
            }),
        );

        assert!(
            res.is_err(),
            "membership with wrong pk unexpectedly verified"
        );
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_membership_should_fail_wrong_path() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_membership_should_fail_wrong_root() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
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

    #[test]
    #[ignore]
    fn test_non_membership_fails() -> Result<()> {
        // One real input (in1), one dummy input (in0.amount = 0).
        // One real output (out0 = in1.amount), one dummy output (out1.amount = 0).
        let (wasm, r1cs) = policy_artifacts()?;

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
                    priv_key: Scalar::from(102u64),
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
                key_non_inclusion: BigInt::from(100001u64), /* This will make the proof of
                                                             * non-membership fail */
            },
            NonMembership {
                key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
            },
        ];

        let res = run_case_with_non_membership_builder(
            &wasm,
            &r1cs,
            &case,
            leaves,
            Scalar::from(0u64),
            &membership_trees,
            &keys,
            |key, pubs| {
                assert!(
                    pubs.len() >= 2,
                    "non-membership failure test expects two input notes"
                );
                let leaf_exist_0 =
                    poseidon2_hash2(pubs[0], Scalar::zero(), Some(Scalar::from(1u64)));
                let leaf_exist_1 =
                    poseidon2_hash2(pubs[1], Scalar::zero(), Some(Scalar::from(1u64)));
                let overrides: Vec<(BigInt, BigInt)> = vec![
                    (
                        scalar_to_bigint(Scalar::from(100001u64)),
                        scalar_to_bigint(leaf_exist_0),
                    ),
                    (
                        scalar_to_bigint(Scalar::from(200002u64)),
                        scalar_to_bigint(leaf_exist_1),
                    ),
                ];

                prepare_smt_proof_with_overrides(key, &overrides, LEVELS)
            },
            None::<fn(&mut Inputs)>,
        );

        assert!(res.is_err(), "non membership not found");
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_tx_randomized_stress() -> Result<()> {
        let (wasm, r1cs) = policy_artifacts()?;

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
            let membership_trees = build_membership_trees(&case, |j| {
                0xFEED_FACEu64 ^ ((j as u64) << 40) ^ leaves_seed
            });

            // Keys strictly in 0..(1<<LEVELS)
            let keys = [
                NonMembership {
                    key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
                },
                NonMembership {
                    key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
                },
            ];

            run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), &membership_trees, &keys, None::<fn(&mut Inputs)>).with_context(|| {
            format!(
                "randomized iteration failed (seed=0x{leaves_seed:x}, scenario={scenario}, real_idx={real_idx}, \
                                  keys=[{}, {}])",
                keys[0].key_non_inclusion, keys[1].key_non_inclusion
            )
        })?;
        }

        Ok(())
    }
}
