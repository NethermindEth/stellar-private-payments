//! End-to-end tests for Pool contract with real Groth16 proofs
//!
//! These tests generate actual Groth16 proofs using the circuit crate
//! and verify them through the Pool contract. This demonstrates a complete
//! integration from proof generation to on-chain verification.
//!
//! It bridges the gap between the different crates and versions.
use anyhow::Result;
use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use circom_groth16_verifier::{CircomGroth16Verifier, CircomGroth16VerifierClient, Groth16Proof};
use circuits::test::utils::circom_tester::{CircomResult, SignalKey, prove_and_verify};
use circuits::test::utils::general::{load_artifacts, poseidon2_hash2, scalar_to_bigint};
use circuits::test::utils::keypair::derive_public_key;
use circuits::test::utils::merkle_tree::{merkle_proof, merkle_root};
use circuits::test::utils::sparse_merkle_tree::prepare_smt_proof_with_overrides;
use circuits::test::utils::transaction::{commitment, prepopulated_leaves};
use circuits::test::utils::transaction_case::{
    InputNote, OutputNote, TxCase, build_base_inputs, prepare_transaction_witness,
};
use num_bigint::{BigInt, BigUint};
use pool::{ExtData, PoolContract, PoolContractClient, Proof};
use soroban_sdk::crypto::bn254::{G1Affine, G2Affine};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Bytes, BytesN, Env, I256, U256, Vec as SorobanVec};
use soroban_utils::constants::bn256_modulus;
use soroban_utils::utils::{MockToken, g1_bytes_from_ark, g2_bytes_from_ark, vk_bytes_from_ark};
use zkhash::ark_ff::{BigInteger as BigInteger04, PrimeField, Zero}; // For zkhash Scalar (0.4)
use zkhash::fields::bn256::FpBN256 as Scalar;

/// Circuit configuration constants (MUST match the compliant_test in the circuit crate)
const LEVELS: usize = 5;
const N_MEM_PROOFS: usize = 1;
const N_NON_PROOFS: usize = 1;

/// Contract configuration
const ASP_MEMBERSHIP_LEVELS: u32 = 5;
const MAX_DEPOSIT: u32 = 1_000_000;

/// Deployed contract addresses
struct DeployedContracts {
    pool: Address,
    asp_membership: Address,
    asp_non_membership: Address,
}

// Util functions

/// Deploy and initialize all contracts with a real verification key
fn deploy_contracts(
    env: &Env,
    vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>,
) -> DeployedContracts {
    let admin = Address::generate(env);

    // Deploy mock token
    let token_address = env.register(MockToken, ());

    // Deploy and initialize verifier with real VK
    let verifier_address = env.register(CircomGroth16Verifier, ());
    let verifier_client = CircomGroth16VerifierClient::new(env, &verifier_address);
    let vk_bytes = vk_bytes_from_ark(env, vk);
    verifier_client.init(&vk_bytes);

    // Deploy ASP Membership
    let asp_membership = env.register(ASPMembership, ());
    ASPMembershipClient::new(env, &asp_membership).init(&admin, &ASP_MEMBERSHIP_LEVELS);

    // Deploy ASP Non-Membership
    let asp_non_membership = env.register(ASPNonMembership, ());
    ASPNonMembershipClient::new(env, &asp_non_membership).init(&admin);

    // Deploy Pool
    let pool = env.register(PoolContract, ());
    let max_deposit = U256::from_u32(env, MAX_DEPOSIT);
    PoolContractClient::new(env, &pool).init(
        &admin,
        &token_address,
        &verifier_address,
        &asp_membership,
        &asp_non_membership,
        &max_deposit,
        &(LEVELS as u32),
    );

    DeployedContracts {
        pool,
        asp_membership,
        asp_non_membership,
    }
}

/// Compute ext data hash
fn compute_ext_hash(env: &Env, ext: &ExtData) -> BytesN<32> {
    let payload = ext.clone().to_xdr(env);
    let digest: BytesN<32> = env.crypto().keccak256(&payload).into();
    let digest_u256 = U256::from_be_bytes(env, &Bytes::from(digest));
    let reduced = digest_u256.rem_euclid(&bn256_modulus(env));
    let mut buf = [0u8; 32];
    reduced.to_be_bytes().copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}

/// Membership tree data for proof generation
struct MembershipTree {
    leaves: [Scalar; 1 << LEVELS],
    index: usize,
    blinding: Scalar,
}

/// Non-membership proof key
struct NonMembership {
    key_non_inclusion: BigInt,
}

/// Build membership trees for a transaction case
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
                    .expect("Failed to convert to array"),
                index: input.leaf_index,
                blinding: Scalar::zero(),
            });
        }
    }

    membership_trees
}

/// Generate non-membership proof overrides from public keys
fn non_membership_overrides_from_pubs(pubs: &[Scalar]) -> Vec<(BigInt, BigInt)> {
    pubs.iter()
        .enumerate()
        .map(|(i, pk)| {
            let idx = (i as u64) + 1;
            let override_idx = idx * 100_000 + idx;
            let override_key = Scalar::from(override_idx);
            let leaf = poseidon2_hash2(*pk, Scalar::zero(), Some(Scalar::from(1u64)));
            (scalar_to_bigint(override_key), scalar_to_bigint(leaf))
        })
        .collect()
}

/// Convert a scalar to U256 for Soroban
fn scalar_to_u256(env: &Env, s: Scalar) -> U256 {
    let bytes = s.into_bigint().to_bytes_be();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    U256::from_be_bytes(env, &Bytes::from_array(env, &buf))
}

/// Convert Soroban U256 to off-chain Scalar FpBN256
fn u256_to_scalar(_env: &Env, u256: &U256) -> Scalar {
    // Convert U256 to bytes (big-endian)
    let bytes: Bytes = u256.to_be_bytes();
    let mut bytes_array = [0u8; 32];
    bytes.copy_into_slice(&mut bytes_array);

    // Convert bytes to BigUint
    let biguint = BigUint::from_bytes_be(&bytes_array);

    // Convert BigUint to FpBN256
    zkhash::ark_ff::Fp256::from(biguint)
}

/// Convert a BytesN<32> to BigInt for circuit input
fn bytes32_to_bigint(bytes: &BytesN<32>) -> BigInt {
    let mut buf = [0u8; 32];
    bytes.copy_into_slice(&mut buf);
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &buf)
}

/// Generate a real Groth16 proof for a transaction
#[allow(clippy::too_many_arguments)]
fn generate_proof(
    case: &TxCase,
    leaves: Vec<Scalar>,
    public_amount: Scalar,
    membership_trees: &[MembershipTree],
    non_membership: &[NonMembership],
    ext_data_hash: Option<BigInt>,
) -> Result<CircomResult> {
    let (wasm, r1cs) = load_artifacts("compliant_test")?;

    let n_inputs = case.inputs.len();
    let witness = prepare_transaction_witness(case, leaves, LEVELS)?;
    let mut inputs = build_base_inputs(case, &witness, public_amount);
    let pubs = &witness.public_keys;

    // Override extDataHash if provided
    if let Some(hash) = ext_data_hash {
        inputs.set("extDataHash", hash);
    }

    // Build membership proof inputs
    let mut mp_leaf: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut mp_blinding: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut mp_path_indices: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut mp_path_elements: Vec<Vec<Vec<BigInt>>> = vec![Vec::new(); n_inputs];
    let mut membership_roots: Vec<BigInt> = Vec::new();

    for j in 0..N_MEM_PROOFS {
        let base_idx = j * n_inputs;
        let mut frozen_leaves = membership_trees[base_idx].leaves;

        for (k, &pk_scalar) in pubs.iter().enumerate() {
            let index = k * N_MEM_PROOFS + j;
            let tree = &membership_trees[index];
            let leaf = poseidon2_hash2(pk_scalar, tree.blinding, Some(Scalar::from(1u64)));
            frozen_leaves[tree.index] = leaf;
        }

        let root_scalar = merkle_root(frozen_leaves.to_vec());

        for i in 0..n_inputs {
            let idx = i * N_MEM_PROOFS + j;
            let t = &membership_trees[idx];
            let pk_scalar = pubs[i];
            let leaf_scalar = poseidon2_hash2(pk_scalar, t.blinding, Some(Scalar::from(1u64)));

            let (siblings, path_idx_u64, _depth) = merkle_proof(&frozen_leaves, t.index);

            mp_leaf[i].push(scalar_to_bigint(leaf_scalar));
            mp_blinding[i].push(scalar_to_bigint(t.blinding));
            mp_path_indices[i].push(scalar_to_bigint(Scalar::from(path_idx_u64)));
            mp_path_elements[i].push(siblings.into_iter().map(scalar_to_bigint).collect());

            membership_roots.push(scalar_to_bigint(root_scalar));
        }
    }

    // Build non-membership proof inputs
    let mut nmp_key: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut nmp_old_key: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut nmp_old_value: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut nmp_is_old0: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut nmp_siblings: Vec<Vec<Vec<BigInt>>> = vec![Vec::new(); n_inputs];
    let mut non_membership_roots: Vec<BigInt> = Vec::new();

    for _ in 0..N_NON_PROOFS {
        for i in 0..n_inputs {
            let overrides = non_membership_overrides_from_pubs(pubs);
            let proof = prepare_smt_proof_with_overrides(
                &non_membership[i].key_non_inclusion,
                &overrides,
                LEVELS,
            );

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

    // Set all inputs
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

    // Generate the proof
    prove_and_verify(&wasm, &r1cs, &inputs)
}

// ========== E2E TESTS ==========
/// Full E2E test: Generate a real proof, deploy contracts, and call transact
///
/// This test demonstrates a complete integration:
/// 1. Creates a transaction case (2 inputs, 2 outputs)
/// 2. Generates a real Groth16 proof using the compliance circuit
/// 3. Deploys all contracts (Pool, ASP Membership, ASP Non-Membership, Verifier)
/// 4. Initializes the verifier with the real verification key from proof generation
/// 5. Calls the `transact` function on the pool contract
#[tokio::test]
async fn test_e2e_transact_with_real_proof() -> Result<()> {
    // Step 1: Create ExtData and compute its hash
    let env = Env::default();
    let temp_recipient = Address::generate(&env);

    let ext_data = ExtData {
        recipient: temp_recipient.clone(),
        ext_amount: I256::from_i32(&env, 0),
        fee: U256::from_u32(&env, 0),
        encrypted_output0: Bytes::new(&env),
        encrypted_output1: Bytes::new(&env),
    };

    // Compute ext_data_hash as the contract would
    let payload = ext_data.clone().to_xdr(&env);
    let digest: BytesN<32> = env.crypto().keccak256(&payload).into();
    let digest_u256 = U256::from_be_bytes(&env, &Bytes::from(digest.clone()));
    let reduced = digest_u256.rem_euclid(&bn256_modulus(&env));
    let mut ext_hash_buf = [0u8; 32];
    reduced.to_be_bytes().copy_into_slice(&mut ext_hash_buf);
    let ext_data_hash_bytes = BytesN::from_array(&env, &ext_hash_buf);
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
    leaves[len - 2] = u256_to_scalar(&env, &zero);
    leaves[len - 1] = u256_to_scalar(&env, &zero);

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
    // Since contracts were just deployed, their merkle trees are basically empty. We need to insert leaves into them.
    // Insert membership leaves into ASP Membership contract
    let asp_membership_client = ASPMembershipClient::new(&env, &contracts.asp_membership);
    let asp_non_membership_client =
        ASPNonMembershipClient::new(&env, &contracts.asp_non_membership);
    // For membership
    let mut memb_leaves = membership_trees[0].leaves.clone();
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
            pool::merkle_with_history::MerkleTreeWithHistory::insert_two_leaves(
                &env, leaf_1, leaf_2,
            )
                .unwrap();
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

    // Convert proof from Groth16 to Soroban format
    let a_bytes = g1_bytes_from_ark(result.proof.a);
    let b_bytes = g2_bytes_from_ark(result.proof.b);
    let c_bytes = g1_bytes_from_ark(result.proof.c);

    let groth16_proof = Groth16Proof {
        a: G1Affine::from_array(&env, &a_bytes),
        b: G2Affine::from_array(&env, &b_bytes),
        c: G1Affine::from_array(&env, &c_bytes),
    };

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

    // Compute ext_data_hash
    let ext_hash = compute_ext_hash(&env, &ext_data);

    // Build the complete Proof struct
    let proof = Proof {
        proof: groth16_proof,
        root: circuit_root,
        input_nullifiers,
        output_commitment0,
        output_commitment1,
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
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
            println!("Transaction failed with error: {:?}", e);
            panic!("Transaction failed");
        }
    }

    Ok(())
}
