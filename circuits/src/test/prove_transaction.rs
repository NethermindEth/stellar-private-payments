#[cfg(test)]
mod tests {
    const LEVELS: usize = 5;

    use crate::test::utils::{
        general::load_artifacts,
        keypair::derive_public_key,
        transaction::{commitment, prepopulated_leaves},
        transaction_case::{InputNote, OutputNote, TxCase, prove_transaction_case},
    };
    use anyhow::{Context, Result};
    use zkhash::ark_ff::Zero;
    use zkhash::fields::bn256::FpBN256 as Scalar;

    #[test]
    #[ignore]
    fn test_tx_1in_1out() -> Result<()> {
        // One real input (in1), one dummy input (in0.amount = 0).
        // One real output (out0 = in1.amount), one dummy output (out1.amount = 0).
        let (wasm, r1cs) = load_artifacts("transaction2")?;
        let real_idx = 7;

        let case = TxCase::new(
            vec![
                InputNote {
                    leaf_index: 0,
                    priv_key: Scalar::from(101u64),
                    blinding: Scalar::from(201u64),
                    amount: Scalar::from(0u64),
                }, // dummy
                InputNote {
                    leaf_index: real_idx,
                    priv_key: Scalar::from(111u64),
                    blinding: Scalar::from(211u64),
                    amount: Scalar::from(13u64),
                }, // real
            ],
            vec![
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
            ],
        );

        let leaves = prepopulated_leaves(LEVELS, 0xDEAD_BEEFu64, &[0, real_idx], 24);

        prove_transaction_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), LEVELS)
    }

    #[test]
    #[ignore]
    fn test_tx_2in_1out() -> Result<()> {
        // Two real inputs; single real output equal to sum; one dummy output.
        let (wasm, r1cs) = load_artifacts("transaction2")?;

        let a = Scalar::from(9u64);
        let b = Scalar::from(4u64);
        let sum = a + b;
        let real_idx = 19;

        let case = TxCase::new(
            vec![
                InputNote {
                    leaf_index: 0,
                    priv_key: Scalar::from(201u64),
                    blinding: Scalar::from(301u64),
                    amount: a,
                },
                InputNote {
                    leaf_index: real_idx,
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
                }, // real
                OutputNote {
                    pub_key: Scalar::from(702u64),
                    blinding: Scalar::from(802u64),
                    amount: Scalar::from(0u64),
                }, // dummy
            ],
        );

        let leaves = prepopulated_leaves(LEVELS, 0xFACEu64, &[0, real_idx], 24);

        prove_transaction_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), LEVELS)
    }

    #[test]
    #[ignore]
    fn test_tx_1in_2out_split() -> Result<()> {
        // One real input (in1); two real outputs that split the amount; in0 is dummy.
        let (wasm, r1cs) = load_artifacts("transaction2")?;

        let total = Scalar::from(20u64);
        let a0 = Scalar::from(6u64);
        let a1 = total - a0;
        let real_idx = 23;

        let case = TxCase::new(
            vec![
                InputNote {
                    leaf_index: 0,
                    priv_key: Scalar::from(301u64),
                    blinding: Scalar::from(401u64),
                    amount: Scalar::from(0u64),
                }, // dummy
                InputNote {
                    leaf_index: real_idx,
                    priv_key: Scalar::from(311u64),
                    blinding: Scalar::from(411u64),
                    amount: total,
                }, // real
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

        let leaves = prepopulated_leaves(LEVELS, 0xC0FFEEu64, &[0, real_idx], 24);

        prove_transaction_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), LEVELS)
    }

    #[test]
    #[ignore]
    fn test_tx_2in_2out_split() -> Result<()> {
        // Two real inputs; two outputs splitting the sum.
        let (wasm, r1cs) = load_artifacts("transaction2")?;

        let a = Scalar::from(15u64);
        let b = Scalar::from(8u64);
        let sum = a + b;

        let out_a = Scalar::from(10u64);
        let out_b = sum - out_a;
        let real_idx = 30;

        let case = TxCase::new(
            vec![
                InputNote {
                    leaf_index: 0,
                    priv_key: Scalar::from(401u64),
                    blinding: Scalar::from(501u64),
                    amount: a,
                },
                InputNote {
                    leaf_index: real_idx,
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

        let leaves = prepopulated_leaves(LEVELS, 0xBEEFu64, &[0, real_idx], 24);

        prove_transaction_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), LEVELS)
    }

    #[test]
    #[ignore]
    fn test_tx_chained_spend() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("transaction2")?;

        // We'll spend the output of Tx1 in Tx2
        let chain_priv = Scalar::from(777u64);
        let chain_pub = derive_public_key(chain_priv);
        let chain_blind = Scalar::from(2024u64);
        let chain_amount = Scalar::from(17u64); // this is Tx1.out0 and Tx2.in1

        // Indices
        let tx1_real_idx = 9usize;
        let chain_idx = 13usize;

        let mut leaves =
            prepopulated_leaves(LEVELS, 0xC0DEC0DEu64, &[0, tx1_real_idx, chain_idx], 24);

        // ----------------------------
        // TX1:  one real input -> two outputs (one becomes the chained note)
        // ----------------------------
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

        // dummy in0 to disable its root check
        let tx1_in0_dummy = InputNote {
            leaf_index: 0,
            priv_key: Scalar::from(11u64),
            blinding: Scalar::from(22u64),
            amount: Scalar::from(0u64),
        };

        // Run Tx1
        let tx1 = TxCase::new(
            vec![tx1_in0_dummy, tx1_input_real.clone()],
            vec![tx1_out0.clone(), tx1_out1.clone()],
        );
        prove_transaction_case(
            &wasm,
            &r1cs,
            &tx1,
            leaves.clone(),
            Scalar::from(0u64),
            LEVELS,
        )?;

        // Compute Tx1.out0 commitment and insert it into the tree as if it was appended to the on-chain tree
        let out0_commit = commitment(tx1_out0.amount, tx1_out0.pub_key, tx1_out0.blinding);
        leaves[chain_idx] = out0_commit;

        // ----------------------------
        // TX2: spend Tx1.out0
        // ----------------------------
        // in1 matches Tx1.out0 (priv -> pub matches; amount & blinding match too)
        let tx2_in1 = InputNote {
            leaf_index: chain_idx,
            priv_key: chain_priv,
            blinding: chain_blind,
            amount: chain_amount,
        };
        // in0 remains a dummy
        let tx2_in0_dummy = InputNote {
            leaf_index: 0,
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
            vec![tx2_in0_dummy, tx2_in1],
            vec![tx2_out_real, tx2_out_dummy],
        );

        // Now Tx2 should verify because the tree contains Tx1.out0 at `chain_idx`
        prove_transaction_case(&wasm, &r1cs, &tx2, leaves, Scalar::from(0u64), LEVELS)
    }

    #[test]
    #[ignore]
    fn test_tx_randomized_stress() -> Result<()> {
        use ark_std::rand::{
            RngCore, SeedableRng,
            distributions::{Distribution, Uniform},
            rngs::StdRng,
        };

        use ark_ff::UniformRand; // for Scalar::rand
        let (wasm, r1cs) = load_artifacts("transaction2")?;

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
            let scenario: u8 = Uniform::new_inclusive(0u8, 3u8).sample(&mut rng);
            let real_idx = Uniform::new(1usize, N).sample(&mut rng);

            let leaves_seed: u64 = rng.next_u64();
            let leaves = prepopulated_leaves(TREE_LEVELS, leaves_seed, &[0, real_idx], 24);

            // Input 0 dummy (disables root check for in0)
            let in0_dummy = InputNote {
                leaf_index: 0,
                priv_key: Scalar::rand(&mut rng),
                blinding: Scalar::rand(&mut rng),
                amount: Scalar::from(0u64),
            };

            // Real input 1
            let in1_amt_u64 = Uniform::new_inclusive(1, 1_000).sample(&mut rng);
            let in1_real = InputNote {
                leaf_index: real_idx,
                priv_key: Scalar::rand(&mut rng),
                blinding: Scalar::rand(&mut rng),
                amount: Scalar::from(in1_amt_u64),
            };

            // Optional second real input
            let in0_alt_amt_u64 = Uniform::new_inclusive(1, 1_000).sample(&mut rng);
            let in0_real_alt = InputNote {
                leaf_index: 0,
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

            let case = TxCase::new(vec![in0_used, in1_used], vec![out0, out1]);

            prove_transaction_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), LEVELS)
            .with_context(|| {
                format!(
                    "randomized iteration failed (seed=0x{leaves_seed:x}, scenario={scenario}, real_idx={real_idx})",
                )
            })?;
        }

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_tx_only_adds_notes_deposit() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("transaction2")?;
        let real_idx = 5;

        // both inputs dummy -> Merkle check gated off by amount=0
        let case = TxCase::new(
            vec![
                InputNote {
                    leaf_index: 0,
                    priv_key: Scalar::from(11u64),
                    blinding: Scalar::from(21u64),
                    amount: Scalar::from(0u64),
                },
                InputNote {
                    leaf_index: real_idx,
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
        let leaves = prepopulated_leaves(LEVELS, 0xD3AD0517u64, &[0, real_idx], 24);

        prove_transaction_case(&wasm, &r1cs, &case, leaves, deposit, LEVELS)
    }

    #[test]
    #[ignore]
    fn test_tx_only_spends_notes_withdraw_one_real() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("transaction2")?;

        let spend = Scalar::from(9u64);
        let real_idx = 7;
        let case = TxCase::new(
            vec![
                InputNote {
                    leaf_index: 0,
                    priv_key: Scalar::from(1u64),
                    blinding: Scalar::from(2u64),
                    amount: Scalar::from(0u64),
                },
                InputNote {
                    leaf_index: real_idx,
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

        let leaves = prepopulated_leaves(LEVELS, 0xC0FFEEu64, &[0, real_idx], 24);
        let neg_spend = Scalar::zero() - spend;

        prove_transaction_case(&wasm, &r1cs, &case, leaves, neg_spend, LEVELS)
    }

    #[test]
    #[ignore]
    fn test_tx_only_spends_notes_withdraw_two_real() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("transaction2")?;

        let a = Scalar::from(5u64);
        let b = Scalar::from(11u64);
        let sum_in = a + b;
        let real_idx = 13;

        let case = TxCase::new(
            vec![
                InputNote {
                    leaf_index: 0,
                    priv_key: Scalar::from(401u64),
                    blinding: Scalar::from(501u64),
                    amount: a,
                },
                InputNote {
                    leaf_index: real_idx,
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

        let leaves = prepopulated_leaves(LEVELS, 0xC0FFEEu64, &[0, real_idx], 24);
        let neg_sum = Scalar::zero() - sum_in;

        prove_transaction_case(&wasm, &r1cs, &case, leaves, neg_sum, LEVELS)
    }

    #[test]
    #[ignore]
    fn test_tx_same_nullifier_should_fail() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("transaction2")?;

        // Make one real note and reuse it for BOTH inputs -> identical commitments, signatures, and nullifiers
        let privk = Scalar::from(7777u64);
        let blind = Scalar::from(4242u64);
        let amount = Scalar::from(33u64);

        let real_idx = 13;

        let in0_note = InputNote {
            leaf_index: 0,
            priv_key: privk,
            blinding: blind,
            amount,
        };
        let in1_note = InputNote {
            leaf_index: real_idx,
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
        let case = TxCase::new(vec![in0_note, in1_note], vec![out_real, out_dummy]);

        let leaves = prepopulated_leaves(LEVELS, 0xC0FFEEu64, &[0, real_idx], 24);

        // Run: should fail because circuit enforces all input nullifiers to be distinct
        let res = prove_transaction_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64), LEVELS);
        assert!(
            res.is_err(),
            "Same-nullifier case unexpectedly verified; expected rejection due to duplicate nullifiers"
        );

        if let Err(e) = res {
            println!("same-nullifier correctly rejected: {e:?}");
        }
        Ok(())
    }
}
