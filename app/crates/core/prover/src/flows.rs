//! High-level transaction flows (transact/deposit/withdraw/transfer).

#![allow(clippy::needless_pass_by_value)]

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};

use anyhow::{Result, anyhow};
use types::{
    AspMembershipProof, AspNonMembershipProof, EncryptionPublicKey, ExtAmount, ExtData, Field,
    NoteAmount, NotePrivateKey, NotePublicKey,
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto,
    encryption,
    serialization::field_bytes_to_hex,
    types::CircuitInputs,
};

/// Number of input note slots supported by the current circuit.
pub const N_INPUTS: usize = 2;
/// Number of output note slots supported by the current circuit.
pub const N_OUTPUTS: usize = 2;

/// Input note data for a pool transaction.
///
/// The user provides existing note commitments along with their Merkle proofs.
///
/// Circuit note: the current circuit expects exactly 2 inputs; callers may provide
/// 0, 1, or 2, and `transact()` will pad with dummy inputs as needed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactInputNote {
    /// Note amount in stroops (1 XLM = 10_000_000 stroops).
    pub amount_stroops: NoteAmount,
    /// Note blinding factor as a BN254 scalar field element.
    pub blinding: Field,
    /// Merkle proof sibling hashes as BN254 scalars (little-endian field bytes),
    /// one element per tree level.
    pub merkle_path_elements: Vec<[u8; 32]>,
    /// Merkle path indices packed into a scalar (little-endian field bytes).
    pub merkle_path_indices: [u8; 32],
}

/// Output note specification for a pool transaction.
///
/// In transact flow, each output may either be addressed to "self" or to an
/// external recipient by providing both:
/// - a BN254 note public key (used to compute the commitment), and
/// - an X25519 encryption public key (used to encrypt note data on-chain).
///
/// Circuit note: the current circuit expects exactly 2 outputs; callers may provide
/// 0, 1, or 2, and `transact()` will pad with dummy outputs as needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactOutput {
    /// Output amount in stroops.
    pub amount_stroops: NoteAmount,
    /// Output blinding factor as a BN254 scalar field element.
    pub blinding: Field,
    /// Optional external recipient note public key (BN254 - used for commitment).
    ///
    /// If set, `recipient_encryption_pubkey` must also be set.
    pub recipient_note_pubkey: Option<NotePublicKey>,
    /// Optional external recipient encryption public key (X25519 - used for encrypting note data).
    ///
    /// If set, `recipient_note_pubkey` must also be set.
    pub recipient_encryption_pubkey: Option<EncryptionPublicKey>,
}

/// Convenience bundle of values typically needed to submit a pool transaction.
///
/// This is not a contract type; it's a helper output to reduce recomputation
/// at call sites (e.g., when constructing Soroban arguments).
#[derive(Clone, Debug)]
pub struct PreparedTx {
    /// Pool Merkle root used as the circuit public input.
    ///
    /// For witness/public-input encoding, use `pool_root.to_le_bytes()`.
    pub pool_root: Field,
    /// Computed nullifiers for both input slots (little-endian field bytes).
    pub input_nullifiers: [[u8; 32]; N_INPUTS],
    /// Computed commitments for both output slots (little-endian field bytes).
    pub output_commitments: [[u8; 32]; N_OUTPUTS],
    /// Field element representation of ext_amount (LE bytes).
    pub public_amount_field: [u8; 32],
    /// Hash of extData used by both circuit and contract checks (32-byte big-endian).
    pub ext_data_hash_be: [u8; 32],
    /// ASP membership root used for the circuit public inputs (little-endian field bytes).
    pub asp_membership_root: [u8; 32],
    /// ASP non-membership root used for the circuit public inputs (little-endian field bytes).
    pub asp_non_membership_root: [u8; 32],
}

/// Full output of `transact()` and the wrapper flows.
///
/// - `circuit_inputs` is suitable for feeding into the witness calculator (JSON object)
/// - `ext_data` contains encrypted outputs to be passed to the contract
/// - `prepared` contains convenience values (nullifiers/commitments) derived during building
#[derive(Clone, Debug)]
pub struct TransactArtifacts {
    /// Circuit inputs object matching the Circom signal names.
    pub circuit_inputs: CircuitInputs,
    /// External data (recipient/ext_amount + encrypted outputs).
    pub ext_data: ExtData,
    /// Derived values convenient for transaction submission.
    pub prepared: PreparedTx,
}

/// Parameters for the generic pool transaction builder.
///
/// Invariant: the equation must balance:
/// `Inputs + Public = Outputs`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactParams {
    /// User's BN254 note private key used to authorize spends (32 bytes).
    pub priv_key: NotePrivateKey,
    /// User's X25519 encryption public key used for encrypting self-addressed outputs (32 bytes).
    pub encryption_pubkey: EncryptionPublicKey,

    /// Pool Merkle root as a field element.
    pub pool_root: Field,

    /// External recipient for extData (address/contract id as string, treated as opaque here).
    pub ext_recipient: String,
    /// External amount in stroops. See `types::ExtData::ext_amount` for semantics.
    pub ext_amount: ExtAmount,

    /// Input notes to spend (0..=2). If empty, `transact()` uses dummy inputs (deposit-style).
    pub inputs: Vec<TransactInputNote>,
    /// Output notes to create (0..=2). If fewer than 2, `transact()` pads with dummy output notes.
    pub outputs: Vec<TransactOutput>,

    /// ASP membership proof data required by the circuit (provided by caller).
    /// ASP membership proof (provided by caller).
    pub membership_proof: AspMembershipProof,
    /// ASP non-membership proof (provided by caller).
    pub non_membership_proof: AspNonMembershipProof,

    /// Pool Merkle tree depth.
    pub tree_depth: u32,
    /// ASP sparse Merkle tree depth.
    pub smt_depth: u32,
}

/// Parameters for a deposit transaction.
///
/// Handles XLM deposits into the privacy pool.
///
/// Deposit invariant:
/// `Deposit amount must equal sum of outputs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositParams {
    /// User's BN254 note private key (32 bytes).
    pub priv_key: NotePrivateKey,
    /// User's X25519 encryption public key (32 bytes).
    pub encryption_pubkey: EncryptionPublicKey,
    /// Pool Merkle root as a field element.
    pub pool_root: Field,

    /// Pool contract address (recipient for extData).
    pub pool_address: String,
    /// Total amount to deposit (stroops). Passed as `ext_amount > 0`.
    pub amount_stroops: ExtAmount,
    /// Output distribution (<= 2 outputs). `transact()` pads to 2.
    pub outputs: Vec<TransactOutput>,

    /// ASP membership proof data required by the circuit (provided by caller).
    pub membership_proof: AspMembershipProof,
    /// ASP non-membership proof data required by the circuit (provided by caller).
    pub non_membership_proof: AspNonMembershipProof,
    /// Pool Merkle tree depth.
    pub tree_depth: u32,
    /// ASP sparse Merkle tree depth.
    pub smt_depth: u32,
}

/// Parameters for a withdrawal transaction.
///
/// Handles XLM withdrawals from the privacy pool.
///
/// Withdrawal semantics:
/// - spends existing notes (inputs),
/// - sends tokens to an external recipient (extData recipient),
/// - sets `ext_amount < 0`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawParams {
    /// User's BN254 note private key (32 bytes).
    pub priv_key: NotePrivateKey,
    /// User's X25519 encryption public key (32 bytes).
    pub encryption_pubkey: EncryptionPublicKey,
    /// Pool Merkle root (little-endian field bytes).
    pub pool_root: Field,

    /// Address to receive withdrawn tokens (extData recipient).
    pub withdraw_recipient: String,
    /// Amount to withdraw in stroops. `withdraw()` sets `ext_amount = -withdraw_amount`.
    pub withdraw_amount_stroops: ExtAmount,
    /// Notes to spend (1..=2). If one is provided, `transact()` pads the second input with a dummy.
    pub inputs: Vec<TransactInputNote>,
    /// Optional outputs override (must satisfy equation if provided).
    pub outputs: Option<Vec<TransactOutput>>,

    /// ASP membership proof data required by the circuit (provided by caller).
    pub membership_proof: AspMembershipProof,
    /// ASP non-membership proof data required by the circuit (provided by caller).
    pub non_membership_proof: AspNonMembershipProof,
    /// Pool Merkle tree depth.
    pub tree_depth: u32,
    /// ASP sparse Merkle tree depth.
    pub smt_depth: u32,
}

/// Parameters for a private transfer transaction.
///
/// Handles private note transfers to other users.
///
/// Transfer invariant:
/// `Input notes must equal output notes`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferParams {
    /// Sender's BN254 note private key (32 bytes).
    pub priv_key: NotePrivateKey,
    /// Sender's X25519 encryption public key (32 bytes).
    pub encryption_pubkey: EncryptionPublicKey,
    /// Pool Merkle root (little-endian field bytes).
    pub pool_root: Field,

    /// Pool contract address (extData recipient for transfers).
    pub pool_address: String,
    /// Notes to spend (1..=2). If one is provided, `transact()` pads the second input with a dummy.
    pub inputs: Vec<TransactInputNote>,
    /// Outputs to create (<= 2). Recipient keys can be set per output to transfer privately.
    pub outputs: Vec<TransactOutput>,

    /// ASP membership proof data required by the circuit (provided by caller).
    pub membership_proof: AspMembershipProof,
    /// ASP non-membership proof data required by the circuit (provided by caller).
    pub non_membership_proof: AspNonMembershipProof,
    /// Pool Merkle tree depth.
    pub tree_depth: u32,
    /// ASP sparse Merkle tree depth.
    pub smt_depth: u32,
}

/// Deposit flow
pub fn deposit<H>(params: DepositParams, hash_ext_data: H) -> Result<TransactArtifacts>
where
    H: Fn(&ExtData) -> Result<[u8; 32]>,
{
    let DepositParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        pool_address,
        amount_stroops,
        outputs,
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    } = params;

    transact(TransactParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        ext_recipient: pool_address,
        ext_amount: amount_stroops,
        inputs: Vec::new(),
        outputs,
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    }, hash_ext_data)
}

/// Withdraw flow
pub fn withdraw<H>(params: WithdrawParams, hash_ext_data: H) -> Result<TransactArtifacts>
where
    H: Fn(&ExtData) -> Result<[u8; 32]>,
{
    let WithdrawParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        withdraw_recipient,
        withdraw_amount_stroops,
        inputs,
        outputs,
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    } = params;

    let input_total = sum_amounts(&inputs)?;
    if input_total < withdraw_amount_stroops {
        return Err(anyhow!(
            "insufficient input amount: have {}, need {}",
            input_total,
            withdraw_amount_stroops
        ));
    }
    let change = input_total
        .checked_sub(withdraw_amount_stroops)
        .ok_or_else(|| anyhow!("insufficient input amount"))?;

    let outputs = match outputs {
        Some(v) => v,
        None => {
            let (out0_amount, out1_amount) = match NoteAmount::try_from(change) {
                Ok(v) => (v, NoteAmount::ZERO),
                Err(_) => {
                    let max_ext = ExtAmount::from(NoteAmount::MAX);
                    let remainder = change
                        .checked_sub(max_ext)
                        .ok_or_else(|| anyhow!("negative withdrawal change remainder"))?;
                    (NoteAmount::MAX, NoteAmount::try_from(remainder)?)
                }
            };
            let change_blinding = encryption::generate_random_blinding()?;
            let dummy_blinding = encryption::generate_random_blinding()?;
            vec![
                TransactOutput {
                    amount_stroops: out0_amount,
                    blinding: change_blinding,
                    recipient_note_pubkey: None,
                    recipient_encryption_pubkey: None,
                },
                TransactOutput {
                    amount_stroops: out1_amount,
                    blinding: dummy_blinding,
                    recipient_note_pubkey: None,
                    recipient_encryption_pubkey: None,
                },
            ]
        }
    };

    transact(TransactParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        ext_recipient: withdraw_recipient,
        ext_amount: -ExtAmount::from(withdraw_amount_stroops),
        inputs,
        outputs,
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    }, hash_ext_data)
}

/// Transfer flow
pub fn transfer<H>(params: TransferParams, hash_ext_data: H) -> Result<TransactArtifacts>
where
    H: Fn(&ExtData) -> Result<[u8; 32]>,
{
    let TransferParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        pool_address,
        inputs,
        outputs,
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    } = params;

    transact(TransactParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        ext_recipient: pool_address,
        ext_amount: ExtAmount::ZERO,
        inputs,
        outputs,
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    }, hash_ext_data)
}

/// Generic pool transaction builder used by all flows.
///
/// This function produces:
/// - circuit inputs suitable for the witness calculator,
/// - per-output encrypted note data, and
/// - convenience derived values (nullifiers/commitments).
pub fn transact<H>(params: TransactParams, hash_ext_data: H) -> Result<TransactArtifacts>
where
    H: Fn(&ExtData) -> Result<[u8; 32]>,
{
    let TransactParams {
        priv_key,
        encryption_pubkey,
        pool_root,
        ext_recipient,
        ext_amount,
        inputs,
        outputs,
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    } = params;

    if tree_depth == 0 {
        return Err(anyhow!("tree_depth must be > 0"));
    }
    if smt_depth == 0 {
        return Err(anyhow!("smt_depth must be > 0"));
    }

    let tree_depth_usize =
        usize::try_from(tree_depth).map_err(|_| anyhow!("tree_depth too large"))?;
    let smt_depth_usize = usize::try_from(smt_depth).map_err(|_| anyhow!("smt_depth too large"))?;

    // Validate ASP proof shapes early.
    if membership_proof.path_elements.len() != tree_depth_usize {
        return Err(anyhow!(
            "membership_proof.path_elements length mismatch: expected {}, got {}",
            tree_depth,
            membership_proof.path_elements.len()
        ));
    }
    if non_membership_proof.siblings.len() != smt_depth_usize {
        return Err(anyhow!(
            "non_membership_proof.siblings length mismatch: expected {}, got {}",
            smt_depth,
            non_membership_proof.siblings.len()
        ));
    }

    if outputs.len() > N_OUTPUTS {
        return Err(anyhow!(
            "too many outputs: expected at most {}, got {}",
            N_OUTPUTS,
            outputs.len()
        ));
    }

    // Enforce the conservation equation: inputs + ext_amount == outputs.
    let inputs_sum = sum_amounts(&inputs)?;
    let outputs_sum = sum_amounts_outputs(&outputs)?;
    let lhs = inputs_sum
        .checked_add(ext_amount)
        .ok_or_else(|| anyhow!("overflow computing LHS"))?;
    let rhs = outputs_sum;
    if lhs != rhs {
        return Err(anyhow!(
            "equation not balanced: inputs({}) + public({}) != outputs({})",
            inputs_sum,
            ext_amount,
            outputs_sum
        ));
    }

    let sender_note_pubkey_bytes = crypto::derive_public_key(&priv_key.0)?;
    let sender_note_pubkey: [u8; 32] = sender_note_pubkey_bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("derive_public_key: expected 32 bytes, got {}", v.len()))?;

    // Prepare inputs (pad to 2).
    let mut input_slots: Vec<TransactInputNote> = inputs;
    if input_slots.is_empty() {
        // Deposit-style: 2 dummy inputs with independent random blindings.
        input_slots.push(dummy_input(tree_depth_usize)?);
        input_slots.push(dummy_input(tree_depth_usize)?);
    } else {
        if input_slots.len() > N_INPUTS {
            return Err(anyhow!(
                "too many inputs: expected at most {}, got {}",
                N_INPUTS,
                input_slots.len()
            ));
        }
        while input_slots.len() < N_INPUTS {
            input_slots.push(dummy_input(tree_depth_usize)?);
        }
    }

    // Validate all real/dummy inputs have the right proof shape.
    for (i, inp) in input_slots.iter().enumerate() {
        if inp.merkle_path_elements.len() != tree_depth_usize {
            return Err(anyhow!(
                "input[{}].merkle_path_elements length mismatch: expected {}, got {}",
                i,
                tree_depth,
                inp.merkle_path_elements.len()
            ));
        }
    }

    // Prepare outputs (pad to 2).
    let mut output_slots: Vec<TransactOutput> = outputs;
    while output_slots.len() < N_OUTPUTS {
        let blinding = encryption::generate_random_blinding()?;
        output_slots.push(TransactOutput {
            amount_stroops: NoteAmount::ZERO,
            blinding,
            recipient_note_pubkey: None,
            recipient_encryption_pubkey: None,
        });
    }

    // Validate recipient key pairing.
    for (i, out) in output_slots.iter().enumerate() {
        let has_note = out.recipient_note_pubkey.is_some();
        let has_enc = out.recipient_encryption_pubkey.is_some();
        if has_note != has_enc {
            return Err(anyhow!(
                "output[{}]: recipient_note_pubkey and recipient_encryption_pubkey must be both set or both unset",
                i
            ));
        }
    }

    // Build circuit inputs arrays.
    let mut circuit = CircuitInputs::new();

    // Public inputs.
    circuit.set_single("root", &field_bytes_to_hex(&pool_root.to_le_bytes())?);
    let public_amount_field_le = Field::try_from(ext_amount)?.to_le_bytes();
    circuit.set_single("publicAmount", &field_bytes_to_hex(&public_amount_field_le)?);
    // `extDataHash` is injected later (after building `ExtData`) by the calling layer.

    // Input notes: compute commitments/signatures/nullifiers.
    let priv_key_hex = field_bytes_to_hex(&priv_key.0)?;

    let mut input_nullifiers_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let mut in_amount_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let mut in_priv_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let mut in_blinding_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let mut in_path_indices_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let mut in_path_elements_hex: Vec<String> = Vec::with_capacity(N_INPUTS * tree_depth_usize);

    let mut input_nullifiers_bytes: [[u8; 32]; N_INPUTS] = [[0u8; 32]; N_INPUTS];

    for (idx, inp) in input_slots.iter().enumerate() {
        let amount_field = note_amount_to_field_le(inp.amount_stroops);
        let inp_blinding_le = inp.blinding.to_le_bytes();
        let commitment =
            crypto::compute_commitment(&amount_field, &sender_note_pubkey, &inp_blinding_le)?;
        let signature = crypto::compute_signature(&priv_key.0, &commitment, &inp.merkle_path_indices)?;
        let nullifier = crypto::compute_nullifier(&commitment, &inp.merkle_path_indices, &signature)?;

        let nullifier_arr: [u8; 32] = nullifier
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("nullifier: expected 32 bytes, got {}", v.len()))?;
        input_nullifiers_bytes[idx] = nullifier_arr;

        input_nullifiers_hex.push(field_bytes_to_hex(&nullifier_arr)?);
        in_amount_hex.push(field_bytes_to_hex(&amount_field)?);
        in_priv_hex.push(priv_key_hex.clone());
        in_blinding_hex.push(field_bytes_to_hex(&inp_blinding_le)?);
        in_path_indices_hex.push(field_bytes_to_hex(&inp.merkle_path_indices)?);
        for pe in &inp.merkle_path_elements {
            in_path_elements_hex.push(field_bytes_to_hex(pe)?);
        }
    }

    // Outputs: compute commitments and encrypt amount/blinding for recipients.
    let mut out_amount_hex: Vec<String> = Vec::with_capacity(N_OUTPUTS);
    let mut out_pubkey_hex: Vec<String> = Vec::with_capacity(N_OUTPUTS);
    let mut out_blinding_hex: Vec<String> = Vec::with_capacity(N_OUTPUTS);
    let mut output_commitments_hex: Vec<String> = Vec::with_capacity(N_OUTPUTS);

    let mut output_commitments_bytes: [[u8; 32]; N_OUTPUTS] = [[0u8; 32]; N_OUTPUTS];
    let mut encrypted_outputs: [Vec<u8>; N_OUTPUTS] = [Vec::new(), Vec::new()];

    for (idx, out) in output_slots.iter().enumerate() {
        let recipient_note_pubkey: [u8; 32] = out
            .recipient_note_pubkey
            .as_ref()
            .map(|k| *k.as_ref())
            .unwrap_or(sender_note_pubkey);
        let recipient_enc_pubkey: EncryptionPublicKey = out
            .recipient_encryption_pubkey
            .clone()
            .unwrap_or_else(|| encryption_pubkey.clone());

        let amount_field = note_amount_to_field_le(out.amount_stroops);
        let out_blinding_le = out.blinding.to_le_bytes();
        let commitment =
            crypto::compute_commitment(&amount_field, &recipient_note_pubkey, &out_blinding_le)?;
        let commitment_arr: [u8; 32] = commitment
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("commitment: expected 32 bytes, got {}", v.len()))?;
        output_commitments_bytes[idx] = commitment_arr;

        let enc = encryption::encrypt_output_note(&recipient_enc_pubkey, out.amount_stroops, &out.blinding)?;
        encrypted_outputs[idx] = enc;

        out_amount_hex.push(field_bytes_to_hex(&amount_field)?);
        out_pubkey_hex.push(field_bytes_to_hex(&recipient_note_pubkey)?);
        out_blinding_hex.push(field_bytes_to_hex(&out_blinding_le)?);
        output_commitments_hex.push(field_bytes_to_hex(&commitment_arr)?);
    }

    // Wire public arrays.
    circuit.set_array("inputNullifier", input_nullifiers_hex);
    circuit.set_array("outputCommitment", output_commitments_hex);

    // Private inputs: input notes.
    circuit.set_array("inAmount", in_amount_hex);
    circuit.set_array("inPrivateKey", in_priv_hex);
    circuit.set_array("inBlinding", in_blinding_hex);
    circuit.set_array("inPathIndices", in_path_indices_hex);
    circuit.set_array("inPathElements", in_path_elements_hex);

    // Private inputs: outputs.
    circuit.set_array("outAmount", out_amount_hex);
    circuit.set_array("outPubkey", out_pubkey_hex);
    circuit.set_array("outBlinding", out_blinding_hex);

    // ASP roots arrays (flattened).
    let membership_root_hex = field_bytes_to_hex(&membership_proof.root.to_le_bytes())?;
    let non_membership_root_hex = field_bytes_to_hex(&non_membership_proof.root.to_le_bytes())?;
    circuit.set_array(
        "membershipRoots",
        vec![membership_root_hex.clone(), membership_root_hex.clone()],
    );
    circuit.set_array(
        "nonMembershipRoots",
        vec![non_membership_root_hex.clone(), non_membership_root_hex.clone()],
    );

    // ASP proofs objects, duplicated across input slots, with a single [0] entry per slot.
    for slot in 0..N_INPUTS {
        let prefix_m = format!("membershipProofs[{}][0].", slot);
        circuit.set_single(
            &(prefix_m.clone() + "leaf"),
            &field_bytes_to_hex(&membership_proof.leaf.to_le_bytes())?,
        );
        circuit.set_single(
            &(prefix_m.clone() + "blinding"),
            &field_bytes_to_hex(&membership_proof.blinding.to_le_bytes())?,
        );
        circuit.set_single(
            &(prefix_m.clone() + "pathIndices"),
            &field_bytes_to_hex(&membership_proof.path_indices.to_le_bytes())?,
        );
        circuit.set_array(
            &(prefix_m.clone() + "pathElements"),
            membership_proof
                .path_elements
                .iter()
                .map(|e| field_bytes_to_hex(&e.to_le_bytes()))
                .collect::<Result<Vec<_>>>()?,
        );
        circuit.set_single(
            &(prefix_m.clone() + "root"),
            &field_bytes_to_hex(&membership_proof.root.to_le_bytes())?,
        );

        let prefix_n = format!("nonMembershipProofs[{}][0].", slot);
        circuit.set_single(
            &(prefix_n.clone() + "key"),
            &field_bytes_to_hex(&non_membership_proof.key.to_le_bytes())?,
        );
        circuit.set_single(
            &(prefix_n.clone() + "oldKey"),
            &field_bytes_to_hex(&non_membership_proof.old_key.to_le_bytes())?,
        );
        circuit.set_single(
            &(prefix_n.clone() + "oldValue"),
            &field_bytes_to_hex(&non_membership_proof.old_value.to_le_bytes())?,
        );
        circuit.set_single(
            &(prefix_n.clone() + "isOld0"),
            &field_bytes_to_hex(
                &if non_membership_proof.is_old0 {
                    Field::from(NoteAmount::ONE).to_le_bytes()
                } else {
                    Field::ZERO.to_le_bytes()
                },
            )?,
        );
        circuit.set_array(
            &(prefix_n.clone() + "siblings"),
            non_membership_proof
                .siblings
                .iter()
                .map(|s| field_bytes_to_hex(&s.to_le_bytes()))
                .collect::<Result<Vec<_>>>()?,
        );
        circuit.set_single(
            &(prefix_n.clone() + "root"),
            &field_bytes_to_hex(&non_membership_proof.root.to_le_bytes())?,
        );
    }

    // Build extData with per-output encrypted note data.
    let ext_data = ExtData {
        recipient: ext_recipient,
        ext_amount,
        encrypted_output0: encrypted_outputs[0].clone(),
        encrypted_output1: encrypted_outputs[1].clone(),
    };

    let ext_data_hash_be = hash_ext_data(&ext_data)?;
    circuit.set_single("extDataHash", &be32_to_0x_hex(&ext_data_hash_be));

    Ok(TransactArtifacts {
        circuit_inputs: circuit,
        ext_data,
        prepared: PreparedTx {
            pool_root,
            input_nullifiers: input_nullifiers_bytes,
            output_commitments: output_commitments_bytes,
            public_amount_field: public_amount_field_le,
            ext_data_hash_be,
            asp_membership_root: membership_proof.root.to_le_bytes(),
            asp_non_membership_root: non_membership_proof.root.to_le_bytes(),
        },
    })
}

fn dummy_input(tree_depth: usize) -> Result<TransactInputNote> {
    let blinding = encryption::generate_random_blinding()?;
    Ok(TransactInputNote {
        amount_stroops: NoteAmount::ZERO,
        blinding,
        merkle_path_elements: vec![[0u8; 32]; tree_depth],
        merkle_path_indices: [0u8; 32],
    })
}

fn note_amount_to_field_le(amount: NoteAmount) -> [u8; 32] {
    Field::from(amount).to_le_bytes()
}

// Note: `ExtAmount -> Field` conversion happens via `types::Field::try_from(ExtAmount)`,
// and is serialized into the circuit as a normal field element (Little-Endian bytes).

fn be32_to_0x_hex(be: &[u8; 32]) -> String {
    let mut out = String::from("0x");
    for b in be {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn sum_amounts(inputs: &[TransactInputNote]) -> Result<ExtAmount> {
    let mut sum = ExtAmount::ZERO;
    for n in inputs {
        sum = sum
            .checked_add(ExtAmount::from(n.amount_stroops))
            .ok_or_else(|| anyhow!("overflow summing input amounts"))?;
    }
    Ok(sum)
}

fn sum_amounts_outputs(outputs: &[TransactOutput]) -> Result<ExtAmount> {
    let mut sum = ExtAmount::ZERO;
    for o in outputs {
        sum = sum
            .checked_add(ExtAmount::from(o.amount_stroops))
            .ok_or_else(|| anyhow!("overflow summing output amounts"))?;
    }
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_membership(tree_depth: usize) -> AspMembershipProof {
        AspMembershipProof {
            leaf: Field::ZERO,
            blinding: Field::ZERO,
            path_elements: vec![Field::ZERO; tree_depth],
            path_indices: Field::ZERO,
            root: Field::ZERO,
        }
    }

    fn zero_non_membership(smt_depth: usize) -> AspNonMembershipProof {
        AspNonMembershipProof {
            key: Field::ZERO,
            old_key: Field::ZERO,
            old_value: Field::ZERO,
            is_old0: true,
            siblings: vec![Field::ZERO; smt_depth],
            root: Field::ZERO,
        }
    }

    #[test]
    fn deposit_pads_inputs_and_outputs() {
        let tree_depth: u32 = 10;
        let smt_depth: u32 = 10;
        let tree_depth_usize = usize::try_from(tree_depth).expect("tree_depth");
        let smt_depth_usize = usize::try_from(smt_depth).expect("smt_depth");

        let priv_key = NotePrivateKey([1u8; 32]);
        let encryption_pubkey = EncryptionPublicKey([2u8; 32]);

        let out_blinding = Field::try_from_le_bytes([3u8; 32]).expect("field");
        let artifacts = deposit(
            DepositParams {
                priv_key,
                encryption_pubkey,
                pool_root: Field::try_from_le_bytes([9u8; 32]).expect("field"),
                pool_address: "POOL".into(),
                amount_stroops: ExtAmount::from(NoteAmount(10)),
                outputs: vec![TransactOutput {
                    amount_stroops: NoteAmount(10),
                blinding: out_blinding,
                recipient_note_pubkey: None,
                recipient_encryption_pubkey: None,
            }],
                membership_proof: zero_membership(tree_depth_usize),
                non_membership_proof: zero_non_membership(smt_depth_usize),
                tree_depth,
                smt_depth,
            },
            |_| Ok([0u8; 32]),
        )
        .expect("deposit builds");

        assert!(artifacts.circuit_inputs.signals.contains_key("root"));
        assert!(artifacts.circuit_inputs.signals.contains_key("publicAmount"));
        assert!(artifacts.circuit_inputs.signals.contains_key("extDataHash"));
        assert!(artifacts.circuit_inputs.signals.contains_key("inputNullifier"));
        assert!(artifacts.circuit_inputs.signals.contains_key("outputCommitment"));

        // Encrypted outputs should be present for both slots.
        assert!(artifacts.ext_data.encrypted_output0.len() >= 112);
        assert!(artifacts.ext_data.encrypted_output1.len() >= 112);
    }

    #[test]
    fn withdraw_auto_builds_change_outputs() {
        let tree_depth: u32 = 10;
        let smt_depth: u32 = 10;
        let tree_depth_usize = usize::try_from(tree_depth).expect("tree_depth");
        let smt_depth_usize = usize::try_from(smt_depth).expect("smt_depth");

        let priv_key = NotePrivateKey([1u8; 32]);
        let encryption_pubkey = EncryptionPublicKey([2u8; 32]);

        let input = TransactInputNote {
            amount_stroops: NoteAmount(10),
            blinding: Field::try_from_le_bytes([4u8; 32]).expect("field"),
            merkle_path_elements: vec![[0u8; 32]; tree_depth_usize],
            merkle_path_indices: [0u8; 32],
        };

        let artifacts = withdraw(
            WithdrawParams {
                priv_key,
                encryption_pubkey,
                pool_root: Field::try_from_le_bytes([9u8; 32]).expect("field"),
                withdraw_recipient: "G...".into(),
                withdraw_amount_stroops: ExtAmount::from(NoteAmount(7)),
                inputs: vec![input],
                outputs: None,
                membership_proof: zero_membership(tree_depth_usize),
                non_membership_proof: zero_non_membership(smt_depth_usize),
                tree_depth,
                smt_depth,
            },
            |_| Ok([0u8; 32]),
        )
        .expect("withdraw builds");

        // public amount should be encoded as field element (non-zero).
        let v = artifacts
            .circuit_inputs
            .signals
            .get("publicAmount")
            .expect("publicAmount exists");
        match v {
            crate::types::InputValue::Single(s) => assert!(s.starts_with("0x")),
            _ => panic!("publicAmount not a single"),
        }
    }

    #[test]
    fn transfer_requires_balanced_equation() {
        let tree_depth: u32 = 10;
        let smt_depth: u32 = 10;
        let tree_depth_usize = usize::try_from(tree_depth).expect("tree_depth");
        let smt_depth_usize = usize::try_from(smt_depth).expect("smt_depth");

        let priv_key = NotePrivateKey([1u8; 32]);
        let encryption_pubkey = EncryptionPublicKey([2u8; 32]);

        let input = TransactInputNote {
            amount_stroops: NoteAmount(10),
            blinding: Field::try_from_le_bytes([4u8; 32]).expect("field"),
            merkle_path_elements: vec![[0u8; 32]; tree_depth_usize],
            merkle_path_indices: [0u8; 32],
        };
        let out = TransactOutput {
            amount_stroops: NoteAmount(9), // unbalanced
            blinding: Field::try_from_le_bytes([7u8; 32]).expect("field"),
            recipient_note_pubkey: None,
            recipient_encryption_pubkey: None,
        };

        let res = transfer(
            TransferParams {
                priv_key,
                encryption_pubkey,
                pool_root: Field::try_from_le_bytes([9u8; 32]).expect("field"),
                pool_address: "POOL".into(),
                inputs: vec![input],
                outputs: vec![out],
                membership_proof: zero_membership(tree_depth_usize),
                non_membership_proof: zero_non_membership(smt_depth_usize),
                tree_depth,
                smt_depth,
            },
            |_| Ok([0u8; 32]),
        );

        assert!(res.is_err());
    }

    #[test]
    fn withdraw_splits_change_when_exceeds_note_amount_max() {
        let tree_depth: u32 = 10;
        let smt_depth: u32 = 10;
        let tree_depth_usize = usize::try_from(tree_depth).expect("tree_depth");
        let smt_depth_usize = usize::try_from(smt_depth).expect("smt_depth");

        let priv_key = NotePrivateKey([1u8; 32]);
        let encryption_pubkey = EncryptionPublicKey([2u8; 32]);

        let input0 = TransactInputNote {
            amount_stroops: NoteAmount::MAX,
            blinding: Field::try_from_le_bytes([4u8; 32]).expect("field"),
            merkle_path_elements: vec![[0u8; 32]; tree_depth_usize],
            merkle_path_indices: [0u8; 32],
        };
        let input1 = TransactInputNote {
            amount_stroops: NoteAmount::MAX,
            blinding: Field::try_from_le_bytes([5u8; 32]).expect("field"),
            merkle_path_elements: vec![[0u8; 32]; tree_depth_usize],
            merkle_path_indices: [0u8; 32],
        };

        // Withdraw a small amount so `change` is > NoteAmount::MAX.
        let res = withdraw(
            WithdrawParams {
                priv_key,
                encryption_pubkey,
                pool_root: Field::try_from_le_bytes([9u8; 32]).expect("field"),
                withdraw_recipient: "G...".into(),
                withdraw_amount_stroops: ExtAmount::from(NoteAmount(1)),
                inputs: vec![input0, input1],
                outputs: None,
                membership_proof: zero_membership(tree_depth_usize),
                non_membership_proof: zero_non_membership(smt_depth_usize),
                tree_depth,
                smt_depth,
            },
            |_| Ok([0u8; 32]),
        );

        assert!(res.is_ok());
    }
}
