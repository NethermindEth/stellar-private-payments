//! Utility functions and types for end-to-end tests

use anyhow::Result;
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use asp_membership::ASPMembership;
use asp_non_membership::ASPNonMembership;
use circom_groth16_verifier::{CircomGroth16Verifier, Groth16Proof};
use circuits::test::utils::circom_tester::{CircomResult, SignalKey, prove_and_verify};
use circuits::test::utils::general::{load_artifacts, poseidon2_hash2, scalar_to_bigint};
use circuits::test::utils::merkle_tree::{merkle_proof, merkle_root};
use circuits::test::utils::sparse_merkle_tree::prepare_smt_proof_with_overrides;
use circuits::test::utils::transaction::prepopulated_leaves;
use circuits::test::utils::transaction_case::{
    TxCase, build_base_inputs, prepare_transaction_witness,
};
use num_bigint::BigInt;
use num_bigint::BigUint;
use pool::PoolContract;
use soroban_sdk::crypto::bn254::{Bn254G1Affine as G1Affine, Bn254G2Affine as G2Affine};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, U256};
use soroban_utils::utils::{MockToken, vk_bytes_from_ark};
use soroban_utils::{g1_bytes_from_ark, g2_bytes_from_ark};
use zkhash::ark_ff::{BigInteger, PrimeField, Zero};
use zkhash::fields::bn256::FpBN256 as Scalar;

/// Number of levels in the pool's commitment Merkle tree
pub const LEVELS: usize = 5;

/// Number of membership proofs required per input
pub const N_MEM_PROOFS: usize = 1;

/// Number of non-membership proofs required per input
pub const N_NON_PROOFS: usize = 1;

/// Number of levels in the ASP membership Merkle tree
pub const ASP_MEMBERSHIP_LEVELS: u32 = 5;

/// Maximum deposit amount allowed per transaction
pub const MAX_DEPOSIT: u32 = 1_000_000;

/// Addresses of deployed contracts for E2E tests
pub struct DeployedContracts {
    /// Address of the pool contract
    pub pool: Address,
    /// Address of the ASP membership contract
    pub asp_membership: Address,
    /// Address of the ASP non-membership contract
    pub asp_non_membership: Address,
}

/// Deploy all contracts required for E2E testing
///
/// Deploys and runs constructors for the Pool, ASP Membership, ASP Non-Membership,
/// and Groth16 Verifier contracts with the provided verification key.
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `vk` - The Groth16 verification key for proof verification
///
/// # Returns
///
/// A `DeployedContracts` struct containing all deployed contract addresses
pub fn deploy_contracts(env: &Env, vk: &VerifyingKey<Bn254>) -> DeployedContracts {
    let admin = Address::generate(env);

    let token_address = env.register(MockToken, ());

    let vk_bytes = vk_bytes_from_ark(env, vk);
    let verifier_address = env.register(CircomGroth16Verifier, (vk_bytes.clone(),));

    let asp_membership = env.register(ASPMembership, (admin.clone(), ASP_MEMBERSHIP_LEVELS));

    let asp_non_membership = env.register(ASPNonMembership, (admin.clone(),));

    let max_deposit = U256::from_u32(env, MAX_DEPOSIT);
    let pool = env.register(
        PoolContract,
        (
            admin,
            token_address.clone(),
            verifier_address.clone(),
            asp_membership.clone(),
            asp_non_membership.clone(),
            max_deposit,
            u32::try_from(LEVELS).expect("Failed to convert LEVELS to u32"),
        ),
    );

    DeployedContracts {
        pool,
        asp_membership,
        asp_non_membership,
    }
}

/// Convert a BN256 scalar field element to Soroban U256
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `s` - The scalar field element to convert
///
/// # Returns
///
/// The scalar as a Soroban U256 in big-endian format
pub fn scalar_to_u256(env: &Env, s: Scalar) -> U256 {
    let bytes = s.into_bigint().to_bytes_be();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    U256::from_be_bytes(env, &Bytes::from_array(env, &buf))
}

/// Convert a Soroban U256 to a BN256 scalar field element
///
/// # Arguments
///
/// * `u256` - The U256 value to convert
///
/// # Returns
///
/// The value as a BN256 scalar field element
pub fn u256_to_scalar(u256: &U256) -> Scalar {
    let bytes: Bytes = u256.to_be_bytes();
    let mut bytes_array = [0u8; 32];
    bytes.copy_into_slice(&mut bytes_array);
    let biguint = BigUint::from_bytes_be(&bytes_array);
    Scalar::from(biguint)
}

/// Convert a 32-byte array to a BigInt
///
/// # Arguments
///
/// * `bytes` - The 32-byte array to convert
///
/// # Returns
///
/// The bytes interpreted as a positive big-endian BigInt
pub fn bytes32_to_bigint(bytes: &BytesN<32>) -> BigInt {
    let mut buf = [0u8; 32];
    bytes.copy_into_slice(&mut buf);
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &buf)
}

/// Merkle tree data for membership proofs
///
/// Contains the leaves and position information needed to construct
/// membership proofs for a given public key.
pub struct MembershipTreeProof {
    /// All leaves in the membership tree
    pub leaves: [Scalar; 1 << LEVELS],
    /// Index where the public key leaf is inserted
    pub index: usize,
    /// Blinding factor used in the leaf commitment
    pub blinding: Scalar,
}

/// Data for non-membership proofs
///
/// Contains the key to prove non-inclusion in the sparse Merkle tree.
pub struct NonMembership {
    /// Key to prove is not in the tree
    pub key_non_inclusion: BigInt,
}

/// Build membership trees for all inputs in a transaction case
///
/// Creates membership trees with prepopulated leaves for each input note.
/// The seed function allows customizing the random seed per proof index.
///
/// # Arguments
///
/// * `case` - The transaction case containing input notes
/// * `seed_fn` - Function that returns a seed given the proof index
///
/// # Returns
///
/// A vector of membership trees proof information, one per input per membership proof
pub fn build_membership_trees<F>(case: &TxCase, seed_fn: F) -> Vec<MembershipTreeProof>
where
    F: Fn(usize) -> u64,
{
    let n_inputs = case.inputs.len();
    let mut membership_trees = Vec::with_capacity(n_inputs * N_MEM_PROOFS);

    for j in 0..N_MEM_PROOFS {
        let seed_j = seed_fn(j);
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);

        for input in &case.inputs {
            membership_trees.push(MembershipTreeProof {
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

/// Generate sparse merkle tree overrides from public keys
///
/// Creates key-value pairs to insert into the sparse Merkle tree for
/// non-membership proofs.
///
/// # Arguments
///
/// * `pubs` - Slice of public keys to generate overrides for
///
/// # Returns
///
/// Vector of (key, value) pairs for sparse Merkle tree insertion
pub fn non_membership_overrides_from_pubs(pubs: &[Scalar]) -> Vec<(BigInt, BigInt)> {
    pubs.iter()
        .enumerate()
        .map(|(i, pk)| {
            let idx = (i as u64)
                .checked_add(1)
                .expect("Failed to calculate override index: public key index exceeds u64::MAX");
            let override_idx = idx
                .checked_mul(100_000)
                .expect("Failed to calculate override index multiplication")
                .checked_add(idx)
                .expect("Failed to calculate override index addition");
            let override_key = Scalar::from(override_idx);
            let leaf = poseidon2_hash2(*pk, Scalar::zero(), Some(Scalar::from(1u64)));
            (scalar_to_bigint(override_key), scalar_to_bigint(leaf))
        })
        .collect()
}

/// Generate a Groth16 proof for a transaction
///
/// Builds the complete witness for the compliance circuit and generates
/// a Groth16 proof. This includes membership proofs, non-membership proofs,
/// and all transaction data.
///
/// # Arguments
///
/// * `case` - Transaction case with input and output notes
/// * `leaves` - Current Merkle tree leaves for the pool
/// * `public_amount` - Net public amount (deposit - withdrawal)
/// * `membership_trees` - Membership tree data for each input
/// * `non_membership` - Non-membership proof data for each input
/// * `ext_data_hash` - Optional external data hash to bind to the proof
///
/// # Returns
///
/// The circuit result containing the proof and verification key
///
/// # Errors
///
/// Returns an error if proof generation fails
#[allow(clippy::too_many_arguments)]
pub fn generate_proof(
    case: &TxCase,
    leaves: Vec<Scalar>,
    public_amount: Scalar,
    membership_trees: &[MembershipTreeProof],
    non_membership: &[NonMembership],
    ext_data_hash: Option<BigInt>,
) -> Result<CircomResult> {
    let (wasm, r1cs) = load_artifacts("compliant_test")?;

    let n_inputs = case.inputs.len();
    let witness = prepare_transaction_witness(case, leaves, LEVELS)?;
    let mut inputs = build_base_inputs(case, &witness, public_amount);
    let pubs = &witness.public_keys;

    if let Some(hash) = ext_data_hash {
        inputs.set("extDataHash", hash);
    }

    let mut mp_leaf: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut mp_blinding: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut mp_path_indices: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut mp_path_elements: Vec<Vec<Vec<BigInt>>> = vec![Vec::new(); n_inputs];
    let mut membership_roots: Vec<BigInt> = Vec::new();

    for j in 0..N_MEM_PROOFS {
        let base_idx = j
            .checked_mul(n_inputs)
            .expect("Failed to calculate base index");
        let mut frozen_leaves = membership_trees[base_idx].leaves;

        for (k, &pk_scalar) in pubs.iter().enumerate() {
            let index = k
                .checked_mul(N_MEM_PROOFS)
                .expect("Failed to calculate membership tree index multiplication")
                .checked_add(j)
                .expect("Failed to calculate membership tree index addition");
            let tree = &membership_trees[index];
            let leaf = poseidon2_hash2(pk_scalar, tree.blinding, Some(Scalar::from(1u64)));
            frozen_leaves[tree.index] = leaf;
        }

        let root_scalar = merkle_root(frozen_leaves.to_vec());

        for i in 0..n_inputs {
            let idx = i
                .checked_mul(N_MEM_PROOFS)
                .expect("Failed to calculate membership tree index multiplication")
                .checked_add(j)
                .expect("Failed to calculate membership tree index addition");
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

    prove_and_verify(&wasm, &r1cs, &inputs)
}

pub fn wrap_groth16_proof(env: &Env, result: CircomResult) -> Groth16Proof {
    // Convert proof from Groth16 to Soroban format
    let a_bytes = g1_bytes_from_ark(result.proof.a);
    let b_bytes = g2_bytes_from_ark(result.proof.b);
    let c_bytes = g1_bytes_from_ark(result.proof.c);

    Groth16Proof {
        a: G1Affine::from_array(env, &a_bytes),
        b: G2Affine::from_array(env, &b_bytes),
        c: G1Affine::from_array(env, &c_bytes),
    }
}
