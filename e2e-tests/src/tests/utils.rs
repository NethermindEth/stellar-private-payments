//! Utility functions and types for end-to-end tests

use anyhow::{Context as _, Result, ensure};
use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use circom_groth16_verifier::{CircomGroth16Verifier, Groth16Proof};
use circuits::test::utils::{
    circom_tester::{Inputs, SignalKey},
    general::{load_artifacts, poseidon2_hash2, scalar_to_bigint},
    keypair::derive_public_key,
    merkle_tree::PrefixTree,
    sparse_merkle_tree::prepare_smt_proof_with_overrides,
    transaction::{commitment, prepopulated_prefix},
    transaction_case::{
        TransactionWitness, TxCase, build_base_inputs, prepare_transaction_witness,
    },
};
use num_bigint::{BigInt, BigUint};
use pool::{PoolContract, PoolContractClient};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, U256,
    crypto::bn254::{Bn254G1Affine as G1Affine, Bn254G2Affine as G2Affine},
    testutils::Address as _,
};
use stellar_private_payments::{
    types::PolicyFlags,
    zk::{prover::Prover, witness::WitnessCalculator},
};

use soroban_utils::utils::MockToken;

use ark_bn254::Fr as Scalar;
use ark_ff::{BigInteger, PrimeField, Zero};

/// Number of levels in the pool's commitment Merkle tree
pub const LEVELS: usize = 20;

/// Number of membership proofs required per input
pub const N_MEM_PROOFS: usize = 1;

/// Number of non-membership proofs required per input
pub const N_NON_PROOFS: usize = 1;

/// Number of levels in the ASP membership Merkle tree
pub const ASP_MEMBERSHIP_LEVELS: usize = 10;

/// Number of levels in the ASP non-membership sparse Merkle tree
pub const SMT_LEVELS: usize = 10;

/// Leaves seeded into the pool and ASP membership trees before a case runs.
///
/// Every `leaf_index` a case picks must stay inside it; `transact` appends its
/// outputs at it.
pub const LEAF_PREFIX: usize = 64;

/// Maximum deposit amount allowed per transaction
pub const MAX_DEPOSIT: u32 = 1_000_000;

/// Create a test environment that disables snapshot writing under Miri.
/// Miri's isolation mode blocks filesystem operations, which the Soroban SDK
/// uses for test snapshots.
pub fn test_env() -> Env {
    #[cfg(miri)]
    {
        use soroban_sdk::testutils::EnvTestConfig;
        Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        })
    }
    #[cfg(not(miri))]
    {
        Env::default()
    }
}

/// Transact circuit stem the pool e2e tests prove against.
///
/// The Groth16 verifier contract embeds this circuit's verification key (see
/// `VERIFIER_VK_JSON` in `.cargo/config.toml`), so it is the only stem that can
/// be verified on chain.
pub const POLICY_STEM: &str = "policy_tx_2_2_AB";

/// All transact circuit stems that ship a committed witness graph.
pub const TRANSACT_STEMS: &[&str] = &[
    "policy_tx_2_2",
    "policy_tx_2_2_A",
    "policy_tx_2_2_B",
    POLICY_STEM,
];

/// Workspace root, derived from this crate's manifest directory.
///
/// `e2e-tests` sits at `<workspace>/e2e-tests`, so the parent is the root.
pub fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get workspace root")
        .to_path_buf()
}

/// Path of the committed `circom-witness-rs` operation graph for a circuit.
///
/// These are the same binaries the CLI, the SDK and the browser load at
/// runtime, so proving from them is what makes these tests end to end.
pub fn committed_graph_path(stem: &str) -> std::path::PathBuf {
    workspace_root()
        .join("deployments/testnet/circuit_keys")
        .join(format!("{stem}.graph.bin"))
}

/// Path of the locally generated Groth16 proving key for a circuit.
///
/// `tools/circuit-compiler` writes these into `testdata/`, together with the
/// verification key that the verifier contract embeds.
pub fn proving_key_path(stem: &str) -> std::path::PathBuf {
    workspace_root().join(format!("testdata/{stem}_proving_key.bin"))
}

/// Outcome of a Groth16 prove and verify cycle.
///
/// Holds everything the pool tests need: the local verification outcome, the
/// Soroban proof bytes, and the public inputs the proof commits to.
pub struct ProofResult {
    /// True when the proof verifies locally against the proving key's own
    /// verification key.
    pub verified: bool,
    /// Uncompressed Soroban proof bytes: `A (64) || B (128) || C (64)`.
    pub proof_uncompressed: Vec<u8>,
    /// Public inputs as little-endian field elements, 32 bytes each.
    pub public_inputs: Vec<u8>,
}

impl ProofResult {
    /// Number of public inputs the proof commits to.
    pub fn num_public_inputs(&self) -> usize {
        self.public_inputs.len() / 32
    }
}

/// Prove a circuit from its committed witness graph, then verify locally.
///
/// This is the production pipeline: `*.graph.bin` supplies the witness, the
/// R1CS and the proving key supply the Groth16 proof. The WASM witness path is
/// not involved.
pub fn prove_with_graph(stem: &str, inputs: &Inputs) -> Result<ProofResult> {
    let graph_path = committed_graph_path(stem);
    let graph_bytes = std::fs::read(&graph_path)
        .with_context(|| format!("failed to read witness graph {}", graph_path.display()))?;
    let calculator = WitnessCalculator::from_graph(&graph_bytes)?;
    let witness_bytes = calculator.compute_witness(&inputs.to_witness_json()?)?;

    let (_wasm, r1cs_path) = load_artifacts(stem)?;
    let r1cs_bytes = std::fs::read(&r1cs_path)
        .with_context(|| format!("failed to read R1CS {}", r1cs_path.display()))?;
    let pk_path = proving_key_path(stem);
    let pk_bytes = std::fs::read(&pk_path)
        .with_context(|| format!("failed to read proving key {}", pk_path.display()))?;

    let prover = Prover::new(&pk_bytes, &r1cs_bytes)?;
    let proof_compressed = prover.prove_bytes(&witness_bytes)?;
    let public_inputs = prover.extract_public_inputs(&witness_bytes)?;
    let verified = prover.verify(&proof_compressed, &public_inputs)?;
    let proof_uncompressed = prover.proof_bytes_to_uncompressed(&proof_compressed)?;
    ensure!(
        proof_uncompressed.len() == 256,
        "unexpected uncompressed proof length: {}",
        proof_uncompressed.len()
    );

    Ok(ProofResult {
        verified,
        proof_uncompressed,
        public_inputs,
    })
}

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
/// Deploys and runs constructors for the Pool, ASP Membership, ASP
/// Non-Membership, and Groth16 Verifier contracts.  The verifier uses the
/// verification key embedded at compile time via `VERIFIER_VK_JSON`.
///
/// # Arguments
///
/// * `env` - The Soroban environment
///
/// # Returns
///
/// A `DeployedContracts` struct containing all deployed contract addresses
pub fn deploy_contracts(env: &Env) -> DeployedContracts {
    let admin = Address::generate(env);

    let token_address = env.register(MockToken, ());

    let verifier_address = env.register(CircomGroth16Verifier, ());

    let asp_membership = env.register(
        ASPMembership,
        (
            admin.clone(),
            u32::try_from(ASP_MEMBERSHIP_LEVELS).expect("ASP_MEMBERSHIP_LEVELS fits in u32"),
        ),
    );

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
            (PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST).bits(),
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
    /// Filled leaf prefix of the membership tree
    pub leaves: Vec<Scalar>,
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
/// A vector of membership trees proof information, one per input per membership
/// proof
pub fn build_membership_trees<F>(case: &TxCase, seed_fn: F) -> Vec<MembershipTreeProof>
where
    F: Fn(usize) -> u64,
{
    let n_inputs = case.inputs.len();
    let mut membership_trees = Vec::with_capacity(n_inputs * N_MEM_PROOFS);

    for j in 0..N_MEM_PROOFS {
        let seed_j = seed_fn(j);
        let base_mem_leaves_j = prepopulated_prefix(seed_j, &[], LEAF_PREFIX);

        for input in &case.inputs {
            membership_trees.push(MembershipTreeProof {
                leaves: base_mem_leaves_j.clone(),
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

/// Build the complete input signal set for the policy transact circuit
///
/// Covers the transaction data, the membership proofs and the non-membership
/// proofs. The same signal set feeds the graph witness calculator and, in the
/// circuits crate, the WASM one.
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
/// The circuit input signals
///
/// # Errors
///
/// Returns an error if the transaction witness cannot be prepared
pub fn build_policy_inputs(
    case: &TxCase,
    leaves: Vec<Scalar>,
    public_amount: Scalar,
    membership_trees: &[MembershipTreeProof],
    non_membership: &[NonMembership],
    ext_data_hash: Option<BigInt>,
) -> Result<Inputs> {
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
        let mut frozen_leaves = membership_trees[base_idx].leaves.clone();

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

        let membership_tree = PrefixTree::new(&frozen_leaves, ASP_MEMBERSHIP_LEVELS);
        let root_scalar = membership_tree.root();

        for i in 0..n_inputs {
            let idx = i
                .checked_mul(N_MEM_PROOFS)
                .expect("Failed to calculate membership tree index multiplication")
                .checked_add(j)
                .expect("Failed to calculate membership tree index addition");
            let t = &membership_trees[idx];
            let pk_scalar = pubs[i];
            let leaf_scalar = poseidon2_hash2(pk_scalar, t.blinding, Some(Scalar::from(1u64)));

            let (siblings, path_idx_u64) = membership_tree.proof(t.index);

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
                SMT_LEVELS,
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

    Ok(inputs)
}

/// Generate a Groth16 proof for a transaction from the committed witness graph
///
/// Builds the circuit inputs, computes the witness with
/// `stellar_private_payments::zk::witness::WitnessCalculator`, then proves and
/// verifies with `stellar_private_payments::zk::prover::Prover`. This is the
/// pipeline the CLI and the SDK use.
///
/// # Arguments
///
/// See [`build_policy_inputs`].
///
/// # Returns
///
/// The proof bytes, the public inputs, and the local verification outcome
///
/// # Errors
///
/// Returns an error if witness computation or proof generation fails
pub fn generate_proof(
    case: &TxCase,
    leaves: Vec<Scalar>,
    public_amount: Scalar,
    membership_trees: &[MembershipTreeProof],
    non_membership: &[NonMembership],
    ext_data_hash: Option<BigInt>,
) -> Result<ProofResult> {
    let inputs = build_policy_inputs(
        case,
        leaves,
        public_amount,
        membership_trees,
        non_membership,
        ext_data_hash,
    )?;
    prove_with_graph(POLICY_STEM, &inputs)
}

/// Merkle roots of the contracts after a state sync
pub struct SyncedRoots {
    /// Pool commitment root, which must equal the root inside the proof
    pub pool_root: U256,
    /// ASP membership (allowlist) root
    pub asp_membership_root: U256,
    /// ASP non-membership (blocklist) root
    pub asp_non_membership_root: U256,
}

/// Put the deployed contracts into the state that the proof was made from
///
/// A fresh deployment has empty trees. The proof commits to off-chain trees, so
/// the tests must insert the same leaves before they call `transact`. The
/// function inserts the membership leaves, the non-membership overrides and the
/// pool commitments, then checks that the pool root equals the circuit root.
///
/// The last two pool leaves stay empty, so that the tree is not full and the
/// pool accepts the two new output commitments.
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `contracts` - Addresses from [`deploy_contracts`]
/// * `case` - The transaction case that the proof used
/// * `leaves` - Pool leaves; the input commitments are written into them
/// * `membership_trees` - Membership tree data from [`build_membership_trees`]
/// * `witness` - Transaction witness from `prepare_transaction_witness`
///
/// # Panics
///
/// Panics if the pool root does not equal the circuit root, because the
/// on-chain verification cannot succeed in that state.
pub fn sync_contract_state(
    env: &Env,
    contracts: &DeployedContracts,
    case: &TxCase,
    leaves: &mut [Scalar],
    membership_trees: &[MembershipTreeProof],
    witness: &TransactionWitness,
) -> SyncedRoots {
    let asp_membership_client = ASPMembershipClient::new(env, &contracts.asp_membership);
    let asp_non_membership_client = ASPNonMembershipClient::new(env, &contracts.asp_non_membership);

    // Membership tree: rebuild the frozen leaves the proof used.
    let mut memb_leaves = membership_trees[0].leaves.clone();
    for (i, tree) in membership_trees.iter().enumerate().take(case.inputs.len()) {
        memb_leaves[tree.index] = poseidon2_hash2(
            witness.public_keys[i],
            tree.blinding,
            Some(Scalar::from(1u64)),
        );
    }
    for leaf in &memb_leaves {
        asp_membership_client.insert_leaf(&scalar_to_u256(env, *leaf));
    }

    // Non-membership tree: insert the same sparse Merkle tree overrides.
    for (key, value) in non_membership_overrides_from_pubs(&witness.public_keys) {
        asp_non_membership_client
            .insert_leaf(&bigint_to_u256(env, &key), &bigint_to_u256(env, &value));
    }

    // Pool tree: write the input commitments, then insert the leaves in pairs.
    for note in &case.inputs {
        let pub_key = derive_public_key(note.priv_key);
        leaves[note.leaf_index] = commitment(note.amount, pub_key, note.blinding);
    }
    assert_eq!(leaves.len() % 2, 0, "Leaves should be even for this test");
    let pool_client = PoolContractClient::new(env, &contracts.pool);
    for pair in leaves.chunks_exact(2) {
        let leaf_1 = scalar_to_u256(env, pair[0]);
        let leaf_2 = scalar_to_u256(env, pair[1]);
        env.as_contract(&contracts.pool, || {
            let _ = pool::merkle_with_history::MerkleTreeWithHistory::insert_two_leaves(
                env, leaf_1, leaf_2,
            );
        });
    }

    let circuit_root = scalar_to_u256(env, witness.root);
    let pool_root = pool_client.get_root();
    assert_eq!(
        circuit_root, pool_root,
        "Pool root should match circuit root. Otherwise, the verification will fail"
    );

    SyncedRoots {
        pool_root,
        asp_membership_root: asp_membership_client.get_root(),
        asp_non_membership_root: asp_non_membership_client.get_root(),
    }
}

/// Convert a non-negative `BigInt` into a Soroban `U256`
///
/// # Panics
///
/// Panics if the value needs more than 32 bytes.
pub fn bigint_to_u256(env: &Env, value: &BigInt) -> U256 {
    let bytes = value.to_bytes_be().1;
    let mut padded = [0u8; 32];
    let start = padded
        .len()
        .checked_sub(bytes.len())
        .expect("value exceeds 32 bytes");
    padded[start..].copy_from_slice(&bytes);
    U256::from_be_bytes(env, &Bytes::from_array(env, &padded))
}

/// Convert the uncompressed proof bytes into the Soroban proof type.
///
/// The SDK prover already writes Soroban point ordering: `x || y` for G1,
/// and `c1 || c0` per coordinate for G2.
pub fn wrap_groth16_proof(env: &Env, result: ProofResult) -> Groth16Proof {
    let bytes = &result.proof_uncompressed;
    let a_bytes: [u8; 64] = bytes[..64].try_into().expect("proof A is 64 bytes");
    let b_bytes: [u8; 128] = bytes[64..192].try_into().expect("proof B is 128 bytes");
    let c_bytes: [u8; 64] = bytes[192..].try_into().expect("proof C is 64 bytes");

    Groth16Proof {
        a: G1Affine::from_array(env, &a_bytes),
        b: G2Affine::from_array(env, &b_bytes),
        c: G1Affine::from_array(env, &c_bytes),
    }
}
