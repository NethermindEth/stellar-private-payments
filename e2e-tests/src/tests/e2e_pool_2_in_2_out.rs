//! End-to-end tests for Pool contract with real Groth16 proofs
//!
//! These tests generate actual Groth16 proofs using the circuit crate
//! and verify them through the Pool contract. This demonstrates a complete
//! integration from proof generation to on-chain verification.
//!
//! It bridges the gap between the different crates and versions.
use super::utils::{
    LEVELS, NonMembership, build_membership_trees, bytes32_to_bigint, deploy_contracts,
    generate_proof, non_membership_overrides_from_pubs, scalar_to_u256, u256_to_scalar,
    wrap_groth16_proof,
};
use anyhow::Result;
use asp_membership::ASPMembershipClient;
use asp_non_membership::ASPNonMembershipClient;
use circuits::test::utils::general::poseidon2_hash2;
use circuits::test::utils::general::scalar_to_bigint;
use circuits::test::utils::keypair::derive_public_key;
use circuits::test::utils::transaction::{commitment, prepopulated_leaves};
use circuits::test::utils::transaction_case::{
    InputNote, OutputNote, TxCase, prepare_transaction_witness,
};
use pool::{ExtData, PoolContractClient, Proof, hash_ext_data};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, Env, I256, U256, Vec as SorobanVec};
use zkhash::fields::bn256::FpBN256 as Scalar;

/// Full E2E test: Generate a real proof, deploy contracts, and call transact which verifies the zk-proof
///
/// This test demonstrates a complete integration:
/// 1. Creates a transaction case (2 inputs, 2 outputs)
/// 2. Generates a real Groth16 proof using the compliance circuit
/// 3. Deploys all contracts (Pool, ASP Membership, ASP Non-Membership, Verifier) and syncs the state
/// 4. Initializes the verifier with the real verification key from proof generation
/// 5. Calls the `transact` function on the pool contract
#[tokio::test]
async fn test_e2e_transact_with_real_proof() -> Result<()> {
    // Create ExtData and compute its hash
    let env = Env::default();
    let temp_recipient = Address::generate(&env);

    let ext_data = ExtData {
        recipient: temp_recipient.clone(),
        ext_amount: I256::from_i32(&env, 0),
        encrypted_output0: Bytes::new(&env),
        encrypted_output1: Bytes::new(&env),
    };

    // Compute ext_data_hash as the contract would
    let ext_data_hash_bytes = hash_ext_data(&env, &ext_data);
    let ext_data_hash_bigint = bytes32_to_bigint(&ext_data_hash_bytes);

    // Create transaction case
    // Private transfer: 13 units from one input to one output
    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(201u64),
                amount: Scalar::from(0u64), // Dummy input (amount = 0)
            },
            InputNote {
                leaf_index: 1,
                priv_key: Scalar::from(102u64),
                blinding: Scalar::from(211u64),
                amount: Scalar::from(13u64), // Real input
            },
        ],
        vec![
            OutputNote {
                pub_key: Scalar::from(501u64),
                blinding: Scalar::from(601u64),
                amount: Scalar::from(13u64), // Real output
            },
            OutputNote {
                pub_key: Scalar::from(502u64),
                blinding: Scalar::from(602u64),
                amount: Scalar::from(0u64), // Dummy output
            },
        ],
    );

    // Prepare merkle tree leaves (Pool state)
    let mut leaves = prepopulated_leaves(
        LEVELS,
        0xDEAD_BEEFu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        24,
    );
    // Leave the last 2 position empty (zero value in Merkle tree)
    // Otherwise when the verification succeeds, the pool will revert the transaction because the Merkle tree would be full.
    let zero = U256::from_be_bytes(
        &env,
        &Bytes::from_array(
            &env,
            &[
                37, 48, 34, 136, 219, 153, 53, 3, 68, 151, 65, 131, 206, 49, 13, 99, 181, 58, 187,
                158, 240, 248, 87, 87, 83, 238, 211, 110, 1, 24, 249, 206,
            ],
        ),
    );
    let len = leaves.len();
    leaves[len - 2] = u256_to_scalar(&zero);
    leaves[len - 1] = u256_to_scalar(&zero);

    // Build membership and non-membership trees
    let membership_trees = build_membership_trees(&case, |j| 0xFEED_FACEu64 ^ ((j as u64) << 40));
    let keys = vec![
        NonMembership {
            key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[0].priv_key)),
        },
        NonMembership {
            key_non_inclusion: scalar_to_bigint(derive_public_key(case.inputs[1].priv_key)),
        },
    ];

    // Generate the Groth16 proof using Circom
    println!("Generating Groth16 proof...");
    let witness = prepare_transaction_witness(&case, leaves.clone(), LEVELS)?;
    let result = generate_proof(
        &case,
        leaves.clone(),
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        Some(ext_data_hash_bigint),
    )?;
    assert!(result.verified, "Proof should verify locally");
    // Deploy contracts. Including the verifier with the real verification key
    env.mock_all_auths();
    let contracts = deploy_contracts(&env, &result.vk);
    println!("Contracts deployed!");

    // Sync on-chain state with off-chain proof data
    // Since contracts were just deployed, their merkle trees are basically empty. We need to insert leaves into them to have an state
    // equivalent to what we used to generate the proof off-chain.
    // Insert membership leaves into ASP Membership contract
    let asp_membership_client = ASPMembershipClient::new(&env, &contracts.asp_membership);
    let asp_non_membership_client =
        ASPNonMembershipClient::new(&env, &contracts.asp_non_membership);
    // For membership
    let mut memb_leaves = membership_trees[0].leaves;
    memb_leaves[membership_trees[0].index] = poseidon2_hash2(
        witness.public_keys[0],
        membership_trees[0].blinding,
        Some(Scalar::from(1u64)),
    );
    memb_leaves[membership_trees[1].index] = poseidon2_hash2(
        witness.public_keys[1],
        membership_trees[1].blinding,
        Some(Scalar::from(1u64)),
    );
    for leaf in memb_leaves {
        let leaf_u256 = scalar_to_u256(&env, leaf);
        asp_membership_client.insert_leaf(&leaf_u256);
    }
    // For non-membership
    let overrides = non_membership_overrides_from_pubs(&witness.public_keys);
    for (key, value) in overrides {
        let key_bytes = key.to_bytes_be().1;
        let mut padded_key = [0u8; 32];
        let start = padded_key.len().saturating_sub(key_bytes.len());
        padded_key[start..].copy_from_slice(&key_bytes);

        let value_bytes = value.to_bytes_be().1;
        let mut padded_value = [0u8; 32];
        let start = padded_value.len().saturating_sub(value_bytes.len());
        padded_value[start..].copy_from_slice(&value_bytes);
        asp_non_membership_client.insert_leaf(
            &U256::from_be_bytes(&env, &Bytes::from_array(&env, &padded_key)),
            &U256::from_be_bytes(&env, &Bytes::from_array(&env, &padded_value)),
        );
    }
    // For the main pool contract
    // Ensure the pool contract matches the proof's merkle root
    let pool_client = PoolContractClient::new(&env, &contracts.pool);
    // Modify leaves as generate_proof does
    for note in &case.inputs {
        let pk = derive_public_key(note.priv_key);
        let cm = commitment(note.amount, pk, note.blinding);
        leaves[note.leaf_index] = cm;
    }
    // Ensure leaves is even as we insert leaves directly in pairs
    assert_eq!(leaves.len() % 2, 0, "Leaves should be even for this test");
    // Insert leaves directly into th Pool contract
    for (i, leaf) in leaves.iter().enumerate().take(len - 2).step_by(2) {
        let leaf_1 = scalar_to_u256(&env, *leaf);
        let leaf_2 = scalar_to_u256(&env, leaves[i + 1]);
        env.as_contract(&contracts.pool, || {
            let _ = pool::merkle_with_history::MerkleTreeWithHistory::insert_two_leaves(
                &env, leaf_1, leaf_2,
            );
        });
    }
    // Check if roots match
    let circuit_root = scalar_to_u256(&env, witness.root);
    let pool_root = pool_client.get_root();
    assert_eq!(
        circuit_root, pool_root,
        "Pool root should match circuit root. Otherwise, the verification will fail"
    );

    // Get ASP roots from deployed contracts
    let asp_membership_root = asp_membership_client.get_root();
    let asp_non_membership_root = asp_non_membership_client.get_root();

    let groth16_proof = wrap_groth16_proof(&env, result);

    // Build input nullifiers
    let mut input_nullifiers: SorobanVec<U256> = SorobanVec::new(&env);
    for nul in &witness.nullifiers {
        input_nullifiers.push_back(scalar_to_u256(&env, *nul));
    }

    // Build output commitments
    let output_commitment0 = scalar_to_u256(
        &env,
        commitment(
            case.outputs[0].amount,
            case.outputs[0].pub_key,
            case.outputs[0].blinding,
        ),
    );
    let output_commitment1 = scalar_to_u256(
        &env,
        commitment(
            case.outputs[1].amount,
            case.outputs[1].pub_key,
            case.outputs[1].blinding,
        ),
    );

    // Build the complete Proof struct
    let proof = Proof {
        proof: groth16_proof,
        root: circuit_root,
        input_nullifiers,
        output_commitment0,
        output_commitment1,
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_data_hash_bytes,
        asp_membership_root,
        asp_non_membership_root,
    };

    // Call transact
    println!("Calling transact method");
    let sender = Address::generate(&env);
    let transact_result = pool_client.try_transact(&proof, &ext_data, &sender);

    match transact_result {
        Ok(_) => {
            println!("Transaction succeeded!");
        }
        Err(e) => {
            println!("Transaction failed with error: {e:?}");
            panic!("Transaction failed");
        }
    }

    Ok(())
}
