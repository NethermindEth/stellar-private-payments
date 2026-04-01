//! Unified WASM facade for the app crates.
use log::{info, error, debug};
use stellar::Client;
use types::ContractConfig;
use anyhow::Result;
use state::Storage;
use sqlite_wasm_vfs::sahpool::{install as install_opfs_sahpool, OpfsSAHPoolCfg};

use wasm_bindgen::prelude::*;

const DEPLOYMENT: &str = include_str!("../../../../scripts/deployments.json");
const PROVING_KEY: &[u8] = include_bytes!("../../../../scripts/testdata/policy_tx_2_2_proving_key.bin");
const VERIFICATION_KEY: &str = include_str!("../../../../scripts/testdata/policy_tx_2_2_vk.json");

/// Install a panic hook for clearer browser-side failures.
#[wasm_bindgen]
pub async fn init_facade() {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    install_opfs_sahpool::<sqlite_wasm_rs::WasmOsCallback>(&OpfsSAHPoolCfg::default(), true)
            .await
            .unwrap();

    let mut storage = Storage::connect().unwrap();
    let leaf = types::PoolLeaf{index: 1, commitment: "ss".to_string(), ledger: 3};
    //storage.put_pool_leaf(&leaf).unwrap();
    info!("== pool leaves {}", storage.count_pool_leaves().unwrap());

    let client = Client::new("https://soroban-testnet.stellar.org").unwrap();
    let config: ContractConfig = serde_json::from_str(DEPLOYMENT)
            .expect("JSON was not well-formatted or did not match struct");

    state::all_contracts_data(&client, &config).await.unwrap();

    info!("init wasm facade");

}

// #[wasm_bindgen]
// pub async fn fetch_contract_data(client: &Client, config: &ContractConfig) -> Result<()> {
//     debug!("async fetch_contract_data");
// }

// /// Get the prover crate version.
// #[wasm_bindgen]
// pub fn prover_version() -> String {
//     prover::version()
// }

// /// Get the witness crate version.
// #[wasm_bindgen]
// pub fn witness_version() -> String {
//     witness::version()
// }

// /// Browser-facing Groth16 prover.
// #[wasm_bindgen]
// pub struct Prover {
//     inner: prover::prover::Prover,
// }

// #[wasm_bindgen]
// impl Prover {
//     /// Create a prover from proving key and R1CS bytes.
//     #[wasm_bindgen(constructor)]
//     pub fn new(pk_bytes: &[u8], r1cs_bytes: &[u8]) -> Result<Prover, JsValue> {
//         Ok(Self {
//             inner: prover::prover::Prover::new(pk_bytes, r1cs_bytes)?,
//         })
//     }

//     /// Get the number of public inputs.
//     #[wasm_bindgen(getter)]
//     pub fn num_public_inputs(&self) -> u32 {
//         self.inner.num_public_inputs()
//     }

//     /// Get the number of constraints.
//     #[wasm_bindgen(getter)]
//     pub fn num_constraints(&self) -> usize {
//         self.inner.num_constraints()
//     }

//     /// Get the number of wires.
//     #[wasm_bindgen(getter)]
//     pub fn num_wires(&self) -> u32 {
//         self.inner.num_wires()
//     }

//     /// Get the verifying key bytes.
//     #[wasm_bindgen]
//     pub fn get_verifying_key(&self) -> Result<Vec<u8>, JsValue> {
//         self.inner.get_verifying_key()
//     }

//     /// Generate a proof object from witness bytes.
//     #[wasm_bindgen]
//     pub fn prove(&self, witness_bytes: &[u8]) -> Result<Groth16Proof, JsValue> {
//         self.inner.prove(witness_bytes).map(Groth16Proof::from_inner)
//     }

//     /// Generate compressed proof bytes.
//     #[wasm_bindgen]
//     pub fn prove_bytes(&self, witness_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
//         self.inner.prove_bytes(witness_bytes)
//     }

//     /// Generate Soroban-compatible uncompressed proof bytes.
//     #[wasm_bindgen]
//     pub fn prove_bytes_uncompressed(&self, witness_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
//         self.inner.prove_bytes_uncompressed(witness_bytes)
//     }

//     /// Convert compressed proof bytes to uncompressed Soroban bytes.
//     #[wasm_bindgen]
//     pub fn proof_bytes_to_uncompressed(&self, proof_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
//         self.inner.proof_bytes_to_uncompressed(proof_bytes)
//     }

//     /// Extract public inputs from witness bytes.
//     #[wasm_bindgen]
//     pub fn extract_public_inputs(&self, witness_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
//         self.inner.extract_public_inputs(witness_bytes)
//     }

//     /// Verify a proof locally.
//     #[wasm_bindgen]
//     pub fn verify(&self, proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> Result<bool, JsValue> {
//         self.inner.verify(proof_bytes, public_inputs_bytes)
//     }
// }

// /// Witness calculator facade.
// #[wasm_bindgen]
// pub struct WitnessCalculator {
//     inner: witness::WitnessCalculator,
// }

// #[wasm_bindgen]
// impl WitnessCalculator {
//     /// Create a witness calculator from compiled circuit and R1CS bytes.
//     #[wasm_bindgen(constructor)]
//     pub fn new(circuit_wasm: &[u8], r1cs_bytes: &[u8]) -> Result<WitnessCalculator, JsValue> {
//         Ok(Self {
//             inner: witness::WitnessCalculator::new(circuit_wasm, r1cs_bytes)?,
//         })
//     }

//     /// Compute a witness from JSON-encoded inputs.
//     #[wasm_bindgen]
//     pub fn compute_witness(&mut self, inputs_json: &str) -> Result<Vec<u8>, JsValue> {
//         self.inner.compute_witness(inputs_json)
//     }

//     /// Get the witness size.
//     #[wasm_bindgen(getter)]
//     pub fn witness_size(&self) -> u32 {
//         self.inner.witness_size()
//     }

//     /// Get the number of public inputs.
//     #[wasm_bindgen(getter)]
//     pub fn num_public_inputs(&self) -> u32 {
//         self.inner.num_public_inputs()
//     }
// }

// /// Groth16 proof wrapper.
// #[wasm_bindgen]
// pub struct Groth16Proof {
//     inner: prover::types::Groth16Proof,
// }

// impl Groth16Proof {
//     fn from_inner(inner: prover::types::Groth16Proof) -> Self {
//         Self { inner }
//     }
// }

// #[wasm_bindgen]
// impl Groth16Proof {
//     /// Get proof point A bytes.
//     #[wasm_bindgen(getter)]
//     pub fn a(&self) -> Vec<u8> {
//         self.inner.a()
//     }

//     /// Get proof point B bytes.
//     #[wasm_bindgen(getter)]
//     pub fn b(&self) -> Vec<u8> {
//         self.inner.b()
//     }

//     /// Get proof point C bytes.
//     #[wasm_bindgen(getter)]
//     pub fn c(&self) -> Vec<u8> {
//         self.inner.c()
//     }

//     /// Concatenate proof bytes as `[A || B || C]`.
//     #[wasm_bindgen]
//     pub fn to_bytes(&self) -> Vec<u8> {
//         self.inner.to_bytes()
//     }
// }

// /// Dense Merkle proof wrapper.
// #[wasm_bindgen]
// pub struct MerkleProof {
//     inner: prover::merkle::MerkleProof,
// }

// impl MerkleProof {
//     fn from_inner(inner: prover::merkle::MerkleProof) -> Self {
//         Self { inner }
//     }
// }

// #[wasm_bindgen]
// impl MerkleProof {
//     /// Get flattened path elements.
//     #[wasm_bindgen(getter)]
//     pub fn path_elements(&self) -> Vec<u8> {
//         self.inner.path_elements()
//     }

//     /// Get path indices bytes.
//     #[wasm_bindgen(getter)]
//     pub fn path_indices(&self) -> Vec<u8> {
//         self.inner.path_indices()
//     }

//     /// Get the proof root.
//     #[wasm_bindgen(getter)]
//     pub fn root(&self) -> Vec<u8> {
//         self.inner.root()
//     }

//     /// Get the proof depth.
//     #[wasm_bindgen(getter)]
//     pub fn levels(&self) -> usize {
//         self.inner.levels()
//     }
// }

// /// Dense Merkle tree wrapper.
// #[wasm_bindgen]
// pub struct MerkleTree {
//     inner: prover::merkle::MerkleTree,
// }

// #[wasm_bindgen]
// impl MerkleTree {
//     /// Create a tree with the default zero leaf.
//     #[wasm_bindgen(constructor)]
//     pub fn new(depth: usize) -> Result<MerkleTree, JsValue> {
//         Ok(Self {
//             inner: prover::merkle::MerkleTree::new(depth)?,
//         })
//     }

//     /// Create a tree with a custom zero leaf.
//     #[wasm_bindgen]
//     pub fn new_with_zero_leaf(depth: usize, zero_leaf_bytes: &[u8]) -> Result<MerkleTree, JsValue> {
//         Ok(Self {
//             inner: prover::merkle::MerkleTree::new_with_zero_leaf(depth, zero_leaf_bytes)?,
//         })
//     }

//     /// Insert a leaf and return its index.
//     #[wasm_bindgen]
//     pub fn insert(&mut self, leaf_bytes: &[u8]) -> Result<u32, JsValue> {
//         self.inner.insert(leaf_bytes)
//     }

//     /// Get the tree root.
//     #[wasm_bindgen]
//     pub fn root(&self) -> Vec<u8> {
//         self.inner.root()
//     }

//     /// Get a Merkle proof for a leaf index.
//     #[wasm_bindgen]
//     pub fn get_proof(&self, index: u32) -> Result<MerkleProof, JsValue> {
//         self.inner.get_proof(index).map(MerkleProof::from_inner)
//     }

//     /// Get the next insert index.
//     #[wasm_bindgen(getter)]
//     pub fn next_index(&self) -> u64 {
//         self.inner.next_index()
//     }

//     /// Get the tree depth.
//     #[wasm_bindgen(getter)]
//     pub fn depth(&self) -> usize {
//         self.inner.depth()
//     }
// }

// /// Sparse Merkle operation result wrapper.
// #[wasm_bindgen]
// pub struct WasmSMTResult {
//     inner: prover::sparse_merkle::WasmSMTResult,
// }

// impl WasmSMTResult {
//     fn from_inner(inner: prover::sparse_merkle::WasmSMTResult) -> Self {
//         Self { inner }
//     }
// }

// #[wasm_bindgen]
// impl WasmSMTResult {
//     /// Get the old root.
//     #[wasm_bindgen(getter)]
//     pub fn old_root(&self) -> Vec<u8> {
//         self.inner.old_root()
//     }

//     /// Get the new root.
//     #[wasm_bindgen(getter)]
//     pub fn new_root(&self) -> Vec<u8> {
//         self.inner.new_root()
//     }

//     /// Get flattened siblings.
//     #[wasm_bindgen(getter)]
//     pub fn siblings(&self) -> Vec<u8> {
//         self.inner.siblings()
//     }

//     /// Get the number of siblings.
//     #[wasm_bindgen(getter)]
//     pub fn num_siblings(&self) -> usize {
//         self.inner.num_siblings()
//     }

//     /// Get the old key bytes.
//     #[wasm_bindgen(getter)]
//     pub fn old_key(&self) -> Vec<u8> {
//         self.inner.old_key()
//     }

//     /// Get the old value bytes.
//     #[wasm_bindgen(getter)]
//     pub fn old_value(&self) -> Vec<u8> {
//         self.inner.old_value()
//     }

//     /// Get the new key bytes.
//     #[wasm_bindgen(getter)]
//     pub fn new_key(&self) -> Vec<u8> {
//         self.inner.new_key()
//     }

//     /// Get the new value bytes.
//     #[wasm_bindgen(getter)]
//     pub fn new_value(&self) -> Vec<u8> {
//         self.inner.new_value()
//     }

//     /// Whether the previous value was zero.
//     #[wasm_bindgen(getter)]
//     pub fn is_old0(&self) -> bool {
//         self.inner.is_old0()
//     }
// }

// /// Sparse Merkle lookup result wrapper.
// #[wasm_bindgen]
// pub struct WasmFindResult {
//     inner: prover::sparse_merkle::WasmFindResult,
// }

// impl WasmFindResult {
//     fn from_inner(inner: prover::sparse_merkle::WasmFindResult) -> Self {
//         Self { inner }
//     }
// }

// #[wasm_bindgen]
// impl WasmFindResult {
//     /// Whether the key was found.
//     #[wasm_bindgen(getter)]
//     pub fn found(&self) -> bool {
//         self.inner.found()
//     }

//     /// Get flattened siblings.
//     #[wasm_bindgen(getter)]
//     pub fn siblings(&self) -> Vec<u8> {
//         self.inner.siblings()
//     }

//     /// Get the number of siblings.
//     #[wasm_bindgen(getter)]
//     pub fn num_siblings(&self) -> usize {
//         self.inner.num_siblings()
//     }

//     /// Get the found value bytes.
//     #[wasm_bindgen(getter)]
//     pub fn found_value(&self) -> Vec<u8> {
//         self.inner.found_value()
//     }

//     /// Get the collided key when not found.
//     #[wasm_bindgen(getter)]
//     pub fn not_found_key(&self) -> Vec<u8> {
//         self.inner.not_found_key()
//     }

//     /// Get the collided value when not found.
//     #[wasm_bindgen(getter)]
//     pub fn not_found_value(&self) -> Vec<u8> {
//         self.inner.not_found_value()
//     }

//     /// Whether the path ended at zero.
//     #[wasm_bindgen(getter)]
//     pub fn is_old0(&self) -> bool {
//         self.inner.is_old0()
//     }

//     /// Get the current root.
//     #[wasm_bindgen(getter)]
//     pub fn root(&self) -> Vec<u8> {
//         self.inner.root()
//     }
// }

// /// Sparse Merkle proof wrapper.
// #[wasm_bindgen]
// pub struct WasmSMTProof {
//     inner: prover::sparse_merkle::WasmSMTProof,
// }

// impl WasmSMTProof {
//     fn from_inner(inner: prover::sparse_merkle::WasmSMTProof) -> Self {
//         Self { inner }
//     }
// }

// #[wasm_bindgen]
// impl WasmSMTProof {
//     /// Whether the key was found.
//     #[wasm_bindgen(getter)]
//     pub fn found(&self) -> bool {
//         self.inner.found()
//     }

//     /// Get flattened siblings.
//     #[wasm_bindgen(getter)]
//     pub fn siblings(&self) -> Vec<u8> {
//         self.inner.siblings()
//     }

//     /// Get the number of siblings.
//     #[wasm_bindgen(getter)]
//     pub fn num_siblings(&self) -> usize {
//         self.inner.num_siblings()
//     }

//     /// Get the found value bytes.
//     #[wasm_bindgen(getter)]
//     pub fn found_value(&self) -> Vec<u8> {
//         self.inner.found_value()
//     }

//     /// Get the collided key when not found.
//     #[wasm_bindgen(getter)]
//     pub fn not_found_key(&self) -> Vec<u8> {
//         self.inner.not_found_key()
//     }

//     /// Get the collided value when not found.
//     #[wasm_bindgen(getter)]
//     pub fn not_found_value(&self) -> Vec<u8> {
//         self.inner.not_found_value()
//     }

//     /// Whether the path ended at zero.
//     #[wasm_bindgen(getter)]
//     pub fn is_old0(&self) -> bool {
//         self.inner.is_old0()
//     }

//     /// Get the current root.
//     #[wasm_bindgen(getter)]
//     pub fn root(&self) -> Vec<u8> {
//         self.inner.root()
//     }
// }

// /// Sparse Merkle tree wrapper.
// #[wasm_bindgen]
// pub struct WasmSparseMerkleTree {
//     inner: prover::sparse_merkle::WasmSparseMerkleTree,
// }

// #[wasm_bindgen]
// impl WasmSparseMerkleTree {
//     /// Create an empty sparse Merkle tree.
//     #[wasm_bindgen(constructor)]
//     pub fn new() -> WasmSparseMerkleTree {
//         Self {
//             inner: prover::sparse_merkle::WasmSparseMerkleTree::new(),
//         }
//     }

//     /// Get the current root.
//     #[wasm_bindgen]
//     pub fn root(&self) -> Vec<u8> {
//         self.inner.root()
//     }

//     /// Insert a key-value pair.
//     #[wasm_bindgen]
//     pub fn insert(
//         &mut self,
//         key_bytes: &[u8],
//         value_bytes: &[u8],
//     ) -> Result<WasmSMTResult, JsValue> {
//         self.inner
//             .insert(key_bytes, value_bytes)
//             .map(WasmSMTResult::from_inner)
//     }

//     /// Update an existing key.
//     #[wasm_bindgen]
//     pub fn update(
//         &mut self,
//         key_bytes: &[u8],
//         new_value_bytes: &[u8],
//     ) -> Result<WasmSMTResult, JsValue> {
//         self.inner
//             .update(key_bytes, new_value_bytes)
//             .map(WasmSMTResult::from_inner)
//     }

//     /// Find a key and return membership or non-membership data.
//     #[wasm_bindgen]
//     pub fn find(&self, key_bytes: &[u8]) -> Result<WasmFindResult, JsValue> {
//         self.inner.find(key_bytes).map(WasmFindResult::from_inner)
//     }

//     /// Get a circuit-friendly proof for a key.
//     #[wasm_bindgen]
//     pub fn get_proof(&self, key_bytes: &[u8], max_levels: usize) -> Result<WasmSMTProof, JsValue> {
//         self.inner
//             .get_proof(key_bytes, max_levels)
//             .map(WasmSMTProof::from_inner)
//     }
// }

// impl Default for WasmSparseMerkleTree {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// /// Compute a Poseidon2 public key from a private key.
// #[wasm_bindgen]
// pub fn derive_public_key(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
//     prover::crypto::derive_public_key(private_key)
// }

// /// Compute a Poseidon2 public key and format it as hex.
// #[wasm_bindgen]
// pub fn derive_public_key_hex(private_key: &[u8]) -> Result<String, JsValue> {
//     prover::crypto::derive_public_key_hex(private_key)
// }

// /// Compute a note commitment.
// #[wasm_bindgen]
// pub fn compute_commitment(
//     amount: &[u8],
//     public_key: &[u8],
//     blinding: &[u8],
// ) -> Result<Vec<u8>, JsValue> {
//     prover::crypto::compute_commitment(amount, public_key, blinding)
// }

// /// Compute a signature used in nullifier derivation.
// #[wasm_bindgen]
// pub fn compute_signature(
//     private_key: &[u8],
//     commitment: &[u8],
//     merkle_path: &[u8],
// ) -> Result<Vec<u8>, JsValue> {
//     prover::crypto::compute_signature(private_key, commitment, merkle_path)
// }

// /// Compute a nullifier.
// #[wasm_bindgen]
// pub fn compute_nullifier(
//     commitment: &[u8],
//     path_indices: &[u8],
//     signature: &[u8],
// ) -> Result<Vec<u8>, JsValue> {
//     prover::crypto::compute_nullifier(commitment, path_indices, signature)
// }

// /// Compute Poseidon2 hash with domain separation.
// #[wasm_bindgen]
// pub fn poseidon2_hash2(
//     input0: &[u8],
//     input1: &[u8],
//     domain_separation: u8,
// ) -> Result<Vec<u8>, JsValue> {
//     prover::crypto::poseidon2_hash2(input0, input1, domain_separation)
// }

// /// Compute Poseidon2 compression.
// #[wasm_bindgen]
// pub fn poseidon2_compression_wasm(input0: &[u8], input1: &[u8]) -> Result<Vec<u8>, JsValue> {
//     prover::crypto::poseidon2_compression_wasm(input0, input1)
// }

// /// Convert a `u64` into field bytes.
// #[wasm_bindgen]
// pub fn u64_to_field_bytes(value: u64) -> Vec<u8> {
//     prover::serialization::u64_to_field_bytes(value)
// }

// /// Convert a hex field string into bytes.
// #[wasm_bindgen]
// pub fn hex_to_field_bytes(hex: &str) -> Result<Vec<u8>, JsValue> {
//     prover::serialization::hex_to_field_bytes(hex)
// }

// /// Convert field bytes into big-endian hex.
// #[wasm_bindgen]
// pub fn field_bytes_to_hex(bytes: &[u8]) -> Result<String, JsValue> {
//     prover::serialization::field_bytes_to_hex(bytes)
// }

// /// Derive an encryption keypair from a wallet signature.
// #[wasm_bindgen]
// pub fn derive_keypair_from_signature(signature: &[u8]) -> Result<Vec<u8>, JsValue> {
//     prover::encryption::derive_keypair_from_signature(signature)
// }

// /// Derive a BN254 note private key from a wallet signature.
// #[wasm_bindgen]
// pub fn derive_note_private_key(signature: &[u8]) -> Result<Vec<u8>, JsValue> {
//     prover::encryption::derive_note_private_key(signature)
// }

// /// Generate a fresh random blinding factor.
// #[wasm_bindgen]
// pub fn generate_random_blinding() -> Result<Vec<u8>, JsValue> {
//     prover::encryption::generate_random_blinding()
// }

// /// Encrypt note payload bytes.
// #[wasm_bindgen]
// pub fn encrypt_note_data(
//     recipient_pubkey_bytes: &[u8],
//     plaintext: &[u8],
// ) -> Result<Vec<u8>, JsValue> {
//     prover::encryption::encrypt_note_data(recipient_pubkey_bytes, plaintext)
// }

// /// Decrypt note payload bytes.
// #[wasm_bindgen]
// pub fn decrypt_note_data(
//     private_key_bytes: &[u8],
//     encrypted_data: &[u8],
// ) -> Result<Vec<u8>, JsValue> {
//     prover::encryption::decrypt_note_data(private_key_bytes, encrypted_data)
// }

// /// Convert compressed proof bytes into Soroban format.
// #[wasm_bindgen]
// pub fn convert_proof_to_soroban(proof_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
//     prover::prover::convert_proof_to_soroban(proof_bytes)
// }

// /// Get the BN254 modulus bytes.
// #[wasm_bindgen]
// pub fn bn256_modulus() -> Vec<u8> {
//     prover::crypto::bn256_modulus()
// }

// /// Get the default zero leaf bytes.
// #[wasm_bindgen]
// pub fn zero_leaf() -> Vec<u8> {
//     prover::crypto::zero_leaf()
// }

// /// Open or create the SQLite-backed state database.
// #[wasm_bindgen]
// pub fn init_state_db(name: Option<String>) -> Result<(), JsValue> {
//     todo!
// }

// /// Insert or update a state record.
// #[wasm_bindgen]
// pub fn state_put(store_name: String, value: JsValue) -> Result<JsValue, JsValue> {
//     todo!
// }

// /// Fetch a single state record by key.
// #[wasm_bindgen]
// pub fn state_get(store_name: String, key: JsValue) -> Result<JsValue, JsValue> {
//     todo!
// }

// /// Fetch all records from a state store.
// #[wasm_bindgen]
// pub fn state_get_all(store_name: String, count: Option<u32>) -> Result<JsValue, JsValue> {
//     todo!
// }

// /// Fetch the first record matching a secondary index.
// #[wasm_bindgen]
// pub fn state_get_by_index(
//     store_name: String,
//     index_name: String,
//     value: JsValue,
// ) -> Result<JsValue, JsValue> {
//     todo!
// }

// /// Fetch all records matching a secondary index.
// #[wasm_bindgen]
// pub fn state_get_all_by_index(
//     store_name: String,
//     index_name: String,
//     value: JsValue,
// ) -> Result<JsValue, JsValue> {
//     todo!
// }

// /// Count records in a state store.
// #[wasm_bindgen]
// pub fn state_count(store_name: String) -> Result<u32, JsValue> {
//     todo!
// }

// /// Delete a state record by key.
// #[wasm_bindgen]
// pub fn state_delete(store_name: String, key: JsValue) -> Result<(), JsValue> {
//     todo!
// }

// /// Clear a single state store.
// #[wasm_bindgen]
// pub fn state_clear(store_name: String) -> Result<(), JsValue> {
//     todo!
// }

// /// Clear all logical state stores.
// #[wasm_bindgen]
// pub fn state_clear_all() -> Result<(), JsValue> {
//     todo!
// }

// /// Apply a batch of state operations.
// #[wasm_bindgen]
// pub fn state_batch(operations: JsValue) -> Result<(), JsValue> {
//     todo!
// }

// /// Reset the current database contents.
// #[wasm_bindgen]
// pub fn state_delete_database() -> Result<(), JsValue> {
//     todo!
// }

// /// Close the current state database connection.
// #[wasm_bindgen]
// pub fn state_close() {
//     todo!
// }
