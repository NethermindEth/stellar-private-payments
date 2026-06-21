//! High-level transaction flows (transact/deposit/withdraw/transfer).

#![allow(clippy::needless_pass_by_value)]

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use types::{
    AspMembershipProof, AspNonMembershipProof, EncryptionPublicKey, ExtAmount, ExtData, Field,
    NoteAmount, NotePrivateKey, NotePublicKey,
};

use crate::{crypto, encryption, serialization::field_bytes_to_hex, types::CircuitInputs};

/// Number of input note slots supported by the current circuit.
pub const N_INPUTS: usize = 2;
/// Number of output note slots supported by the current circuit.
pub const N_OUTPUTS: usize = 2;

/// Input note data for a pool transaction.
///
/// The user provides existing note commitments along with their Merkle proofs.
///
/// Circuit note: the current circuit expects exactly 2 inputs; callers may
/// provide 0, 1, or 2, and `transact()` will pad with dummy inputs as needed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactInputNote {
    /// Note amount in token base units (e.g. for XLM it is stroops).
    pub amount: NoteAmount,
    /// Note blinding factor as a BN254 scalar field element.
    pub blinding: Field,
    /// Merkle proof sibling hashes as BN254 field elements, one element per
    /// tree level.
    pub merkle_path_elements: Vec<Field>,
    /// Merkle path indices packed into a BN254 field element.
    pub merkle_path_indices: Field,
}

/// Output note specification for a pool transaction.
///
/// In transact flow, each output may either be addressed to "self" or to an
/// external recipient by providing both:
/// - a BN254 note public key (used to compute the commitment), and
/// - an X25519 encryption public key (used to encrypt note data on-chain).
///
/// Circuit note: the current circuit expects exactly 2 outputs; callers may
/// provide 0, 1, or 2, and `transact()` will pad with dummy outputs as needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactOutput {
    /// Output amount in token base units (e.g. for XLM it is stroops).
    pub amount: NoteAmount,
    /// Output blinding factor as a BN254 scalar field element.
    pub blinding: Field,
    /// Optional external recipient note public key (BN254 - used for
    /// commitment).
    ///
    /// If set, `recipient_encryption_pubkey` must also be set.
    pub recipient_note_pubkey: Option<NotePublicKey>,
    /// Optional external recipient encryption public key (X25519 - used for
    /// encrypting note data).
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
    /// Computed nullifiers for both input slots.
    pub input_nullifiers: [Field; N_INPUTS],
    /// Computed commitments for both output slots.
    pub output_commitments: [Field; N_OUTPUTS],
    /// Field element representation of ext_amount.
    pub public_amount_field: Field,
    /// Hash of extData used by both circuit and contract checks (32-byte
    /// big-endian).
    pub ext_data_hash_be: [u8; 32],
    /// ASP membership root used for the circuit public inputs.
    pub asp_membership_root: Field,
    /// ASP non-membership root used for the circuit public inputs.
    pub asp_non_membership_root: Field,
}

/// Full output of `transact()` and the wrapper flows.
///
/// - `circuit_inputs` is suitable for feeding into the witness calculator (JSON
///   object)
/// - `ext_data` contains encrypted outputs to be passed to the contract
/// - `prepared` contains convenience values (nullifiers/commitments) derived
///   during building
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
    /// User's X25519 encryption public key used for encrypting self-addressed
    /// outputs (32 bytes).
    pub encryption_pubkey: EncryptionPublicKey,

    /// Pool Merkle root as a field element.
    pub pool_root: Field,

    /// External recipient for extData (address/contract id as string, treated
    /// as opaque here).
    pub ext_recipient: String,
    /// External amount in stroops. See `types::ExtData::ext_amount` for
    /// semantics.
    pub ext_amount: ExtAmount,

    /// Input notes to spend (0..=2). If empty, `transact()` uses dummy inputs
    /// (deposit-style).
    pub inputs: Vec<TransactInputNote>,
    /// Output notes to create (0..=2). If fewer than 2, `transact()` pads with
    /// dummy output notes.
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
/// Handles deposits into the privacy pool.
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
    pub amount: ExtAmount,
    /// Output distribution (<= 2 outputs). `transact()` pads to 2.
    pub outputs: Vec<TransactOutput>,

    /// ASP membership proof data required by the circuit (provided by caller).
    pub membership_proof: AspMembershipProof,
    /// ASP non-membership proof data required by the circuit (provided by
    /// caller).
    pub non_membership_proof: AspNonMembershipProof,
    /// Pool Merkle tree depth.
    pub tree_depth: u32,
    /// ASP sparse Merkle tree depth.
    pub smt_depth: u32,
}

/// Parameters for a withdrawal transaction.
///
/// Handles withdrawals from the privacy pool.
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
    /// Amount to withdraw in stroops. `withdraw()` sets `ext_amount =
    /// -withdraw_amount`.
    pub withdraw_amount: ExtAmount,
    /// Notes to spend (1..=2). If one is provided, `transact()` pads the second
    /// input with a dummy.
    pub inputs: Vec<TransactInputNote>,
    /// Optional outputs override (must satisfy equation if provided).
    pub outputs: Option<Vec<TransactOutput>>,

    /// ASP membership proof data required by the circuit (provided by caller).
    pub membership_proof: AspMembershipProof,
    /// ASP non-membership proof data required by the circuit (provided by
    /// caller).
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
    /// Notes to spend (1..=2). If one is provided, `transact()` pads the second
    /// input with a dummy.
    pub inputs: Vec<TransactInputNote>,
    /// Outputs to create (<= 2). Recipient keys can be set per output to
    /// transfer privately.
    pub outputs: Vec<TransactOutput>,

    /// ASP membership proof data required by the circuit (provided by caller).
    pub membership_proof: AspMembershipProof,
    /// ASP non-membership proof data required by the circuit (provided by
    /// caller).
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
        amount,
        outputs,
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    } = params;

    transact(
        TransactParams {
            priv_key,
            encryption_pubkey,
            pool_root,
            ext_recipient: pool_address,
            ext_amount: amount,
            inputs: Vec::new(),
            outputs,
            membership_proof,
            non_membership_proof,
            tree_depth,
            smt_depth,
        },
        hash_ext_data,
    )
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
        withdraw_amount,
        inputs,
        outputs,
        membership_proof,
        non_membership_proof,
        tree_depth,
        smt_depth,
    } = params;

    let input_total = sum_note_amounts_inputs(&inputs)?;
    let withdraw_note_amount = NoteAmount::try_from(withdraw_amount)?;
    if input_total < withdraw_note_amount {
        return Err(anyhow!(
            "insufficient input amount: have {}, need {}",
            input_total,
            withdraw_amount
        ));
    }
    let change = input_total
        .checked_sub(withdraw_note_amount)
        .ok_or_else(|| anyhow!("insufficient input amount"))?;

    let outputs = match outputs {
        Some(v) => v,
        None => {
            let out0_amount = change;
            let out1_amount = NoteAmount::ZERO;
            let change_blinding = encryption::generate_random_blinding()?;
            let dummy_blinding = encryption::generate_random_blinding()?;
            vec![
                TransactOutput {
                    amount: out0_amount,
                    blinding: change_blinding,
                    recipient_note_pubkey: None,
                    recipient_encryption_pubkey: None,
                },
                TransactOutput {
                    amount: out1_amount,
                    blinding: dummy_blinding,
                    recipient_note_pubkey: None,
                    recipient_encryption_pubkey: None,
                },
            ]
        }
    };

    transact(
        TransactParams {
            priv_key,
            encryption_pubkey,
            pool_root,
            ext_recipient: withdraw_recipient,
            ext_amount: withdraw_amount
                .checked_neg()
                .ok_or_else(|| anyhow!("withdraw amount overflow"))?,
            inputs,
            outputs,
            membership_proof,
            non_membership_proof,
            tree_depth,
            smt_depth,
        },
        hash_ext_data,
    )
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

    transact(
        TransactParams {
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
        },
        hash_ext_data,
    )
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
    let inputs_sum = sum_note_amounts_inputs(&inputs)?;
    let outputs_sum = sum_note_amounts_outputs(&outputs)?;

    let balanced = if ext_amount >= ExtAmount::ZERO {
        let public_note = NoteAmount::try_from(ext_amount)?;
        let lhs = inputs_sum
            .checked_add(public_note)
            .ok_or_else(|| anyhow!("overflow computing note amount LHS"))?;
        lhs == outputs_sum
    } else {
        let public_note = NoteAmount::try_from(
            ext_amount
                .checked_neg()
                .ok_or_else(|| anyhow!("public amount negation overflow"))?,
        )?;
        let rhs = outputs_sum
            .checked_add(public_note)
            .ok_or_else(|| anyhow!("overflow computing note amount RHS"))?;
        inputs_sum == rhs
    };

    if !balanced {
        return Err(anyhow!(
            "not balanced: inputs({}) + public({}) != outputs({})",
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
            amount: NoteAmount::ZERO,
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
    circuit.set_single("root", &field_to_circuit_hex(&pool_root)?);
    let public_amount_field = Field::try_from(ext_amount)?;
    circuit.set_single("publicAmount", &ext_amount_to_circuit_hex(ext_amount)?);

    // Input notes: compute commitments/signatures/nullifiers.
    let priv_key_hex = field_bytes_to_hex(&priv_key.0)?;

    let mut input_nullifiers_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let mut in_amount_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let mut in_priv_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let mut in_blinding_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let mut in_path_indices_hex: Vec<String> = Vec::with_capacity(N_INPUTS);
    let in_path_elements_capacity = N_INPUTS
        .checked_mul(tree_depth_usize)
        .ok_or_else(|| anyhow!("path elements capacity overflow"))?;
    let mut in_path_elements_hex: Vec<String> = Vec::with_capacity(in_path_elements_capacity);

    let mut input_nullifiers_fields: [Field; N_INPUTS] = [Field::ZERO; N_INPUTS];

    for (idx, inp) in input_slots.iter().enumerate() {
        let amount_field = note_amount_to_field(&inp.amount);
        let amount_field_le = amount_field.to_le_bytes();
        let inp_blinding_le = inp.blinding.to_le_bytes();
        let merkle_path_indices = inp.merkle_path_indices.to_le_bytes();
        let commitment =
            crypto::compute_commitment(&amount_field_le, &sender_note_pubkey, &inp_blinding_le)?;
        let signature = crypto::compute_signature(&priv_key.0, &commitment, &merkle_path_indices)?;
        let nullifier = crypto::compute_nullifier(&commitment, &merkle_path_indices, &signature)?;

        let nullifier_arr: [u8; 32] = nullifier
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("nullifier: expected 32 bytes, got {}", v.len()))?;
        let nullifier_field = Field::try_from_le_bytes(nullifier_arr)?;
        input_nullifiers_fields[idx] = nullifier_field;

        input_nullifiers_hex.push(field_to_circuit_hex(&nullifier_field)?);
        in_amount_hex.push(field_to_circuit_hex(&amount_field)?);
        in_priv_hex.push(priv_key_hex.clone());
        in_blinding_hex.push(field_bytes_to_hex(&inp_blinding_le)?);
        in_path_indices_hex.push(field_to_circuit_hex(&inp.merkle_path_indices)?);
        for pe in &inp.merkle_path_elements {
            in_path_elements_hex.push(field_to_circuit_hex(pe)?);
        }
    }

    // Outputs: compute commitments and encrypt amount/blinding for recipients.
    let mut out_amount_hex: Vec<String> = Vec::with_capacity(N_OUTPUTS);
    let mut out_pubkey_hex: Vec<String> = Vec::with_capacity(N_OUTPUTS);
    let mut out_blinding_hex: Vec<String> = Vec::with_capacity(N_OUTPUTS);
    let mut output_commitments_hex: Vec<String> = Vec::with_capacity(N_OUTPUTS);

    let mut output_commitments_fields: [Field; N_OUTPUTS] = [Field::ZERO; N_OUTPUTS];
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

        let amount_field = note_amount_to_field(&out.amount);
        let amount_field_le = amount_field.to_le_bytes();
        let out_blinding_le = out.blinding.to_le_bytes();
        let commitment =
            crypto::compute_commitment(&amount_field_le, &recipient_note_pubkey, &out_blinding_le)?;
        let commitment_arr: [u8; 32] = commitment
            .try_into()
            .map_err(|v: Vec<u8>| anyhow!("commitment: expected 32 bytes, got {}", v.len()))?;
        let commitment_field = Field::try_from_le_bytes(commitment_arr)?;
        output_commitments_fields[idx] = commitment_field;

        let enc =
            encryption::encrypt_output_note(&recipient_enc_pubkey, out.amount, &out.blinding)?;
        encrypted_outputs[idx] = enc;

        out_amount_hex.push(field_to_circuit_hex(&amount_field)?);
        out_pubkey_hex.push(field_bytes_to_hex(&recipient_note_pubkey)?);
        out_blinding_hex.push(field_bytes_to_hex(&out_blinding_le)?);
        output_commitments_hex.push(field_to_circuit_hex(&commitment_field)?);
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
    let membership_root_hex = field_to_circuit_hex(&membership_proof.root)?;
    let non_membership_root_hex = field_to_circuit_hex(&non_membership_proof.root)?;
    circuit.set_array(
        "membershipRoots",
        vec![membership_root_hex.clone(), membership_root_hex.clone()],
    );
    circuit.set_array(
        "nonMembershipRoots",
        vec![
            non_membership_root_hex.clone(),
            non_membership_root_hex.clone(),
        ],
    );

    // ASP proofs objects, duplicated across input slots, with a single [0] entry
    // per slot.
    for slot in 0..N_INPUTS {
        let prefix_m = format!("membershipProofs[{}][0].", slot);
        circuit.set_single(
            &format!("{prefix_m}leaf"),
            &field_to_circuit_hex(&membership_proof.leaf)?,
        );
        circuit.set_single(
            &format!("{prefix_m}blinding"),
            &field_to_circuit_hex(&membership_proof.blinding)?,
        );
        circuit.set_single(
            &format!("{prefix_m}pathIndices"),
            &field_to_circuit_hex(&membership_proof.path_indices)?,
        );
        circuit.set_array(
            &format!("{prefix_m}pathElements"),
            membership_proof
                .path_elements
                .iter()
                .map(field_to_circuit_hex)
                .collect::<Result<Vec<_>>>()?,
        );
        circuit.set_single(
            &format!("{prefix_m}root"),
            &field_to_circuit_hex(&membership_proof.root)?,
        );

        let prefix_n = format!("nonMembershipProofs[{}][0].", slot);
        circuit.set_single(
            &format!("{prefix_n}key"),
            &field_to_circuit_hex(&non_membership_proof.key)?,
        );
        circuit.set_single(
            &format!("{prefix_n}oldKey"),
            &field_to_circuit_hex(&non_membership_proof.old_key)?,
        );
        circuit.set_single(
            &format!("{prefix_n}oldValue"),
            &field_to_circuit_hex(&non_membership_proof.old_value)?,
        );
        circuit.set_single(
            &format!("{prefix_n}isOld0"),
            &field_to_circuit_hex(&if non_membership_proof.is_old0 {
                Field::from(NoteAmount::ONE)
            } else {
                Field::ZERO
            })?,
        );
        circuit.set_array(
            &format!("{prefix_n}siblings"),
            non_membership_proof
                .siblings
                .iter()
                .map(field_to_circuit_hex)
                .collect::<Result<Vec<_>>>()?,
        );
        circuit.set_single(
            &format!("{prefix_n}root"),
            &field_to_circuit_hex(&non_membership_proof.root)?,
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
            input_nullifiers: input_nullifiers_fields,
            output_commitments: output_commitments_fields,
            public_amount_field,
            ext_data_hash_be,
            asp_membership_root: membership_proof.root,
            asp_non_membership_root: non_membership_proof.root,
        },
    })
}

fn dummy_input(tree_depth: usize) -> Result<TransactInputNote> {
    let blinding = encryption::generate_random_blinding()?;
    Ok(TransactInputNote {
        amount: NoteAmount::ZERO,
        blinding,
        merkle_path_elements: vec![Field::ZERO; tree_depth],
        merkle_path_indices: Field::ZERO,
    })
}

fn note_amount_to_field(amount: &NoteAmount) -> Field {
    Field::from(*amount)
}

fn field_to_circuit_hex(field: &Field) -> Result<String> {
    field_bytes_to_hex(&field.to_le_bytes())
}

fn ext_amount_to_circuit_hex(amount: ExtAmount) -> Result<String> {
    let field = Field::try_from(amount)?;
    field_to_circuit_hex(&field)
}

// Note: `ExtAmount -> Field` conversion happens via
// `types::Field::try_from(ExtAmount)`, and is serialized into the circuit as a
// normal field element (Little-Endian bytes).

fn be32_to_0x_hex(be: &[u8; 32]) -> String {
    let mut out = String::from("0x");
    for b in be {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Parameters for a selective disclosure (1 note).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectiveDisclosure1Params {
    pub root: Field,
    pub note_commitment: Field,
    pub note_amount: NoteAmount,
    pub note_private_key: NotePrivateKey,
    pub note_blinding: Field,
    pub merkle_path_indices: Field,
    pub merkle_path_elements: Vec<Field>,
    pub ext_context_hash: Field,
}

/// Artifacts generated for selective disclosure.
#[derive(Clone, Debug)]
pub struct DisclosureArtifacts {
    pub circuit_inputs: CircuitInputs,
    pub ext_context_hash: Field,
}

/// Generates circuit inputs for selectiveDisclosure_1.
pub fn selective_disclosure_1(params: SelectiveDisclosure1Params) -> Result<DisclosureArtifacts> {
    let mut circuit = CircuitInputs::new();

    // Public inputs
    circuit.set_array("roots", vec![field_to_circuit_hex(&params.root)?]);
    circuit.set_array(
        "noteCommitments",
        vec![field_to_circuit_hex(&params.note_commitment)?],
    );
    circuit.set_single(
        "extContextHash",
        &field_to_circuit_hex(&params.ext_context_hash)?,
    );

    // Private inputs
    let amount_field = note_amount_to_field(&params.note_amount);
    circuit.set_array("inAmount", vec![field_to_circuit_hex(&amount_field)?]);

    let priv_key_hex = field_bytes_to_hex(&params.note_private_key.0)?;
    circuit.set_array("inPrivateKey", vec![priv_key_hex]);

    let blinding_hex = field_bytes_to_hex(&params.note_blinding.to_le_bytes())?;
    circuit.set_array("inBlinding", vec![blinding_hex]);

    circuit.set_array(
        "inPathIndices",
        vec![field_to_circuit_hex(&params.merkle_path_indices)?],
    );

    let mut path_elements_hex = Vec::with_capacity(params.merkle_path_elements.len());
    for pe in &params.merkle_path_elements {
        path_elements_hex.push(field_to_circuit_hex(pe)?);
    }
    circuit.set_array("inPathElements", path_elements_hex);

    Ok(DisclosureArtifacts {
        circuit_inputs: circuit,
        ext_context_hash: params.ext_context_hash,
    })
}

fn sum_note_amounts_inputs(inputs: &[TransactInputNote]) -> Result<NoteAmount> {
    let mut sum = NoteAmount::ZERO;
    for n in inputs {
        sum = sum
            .checked_add(n.amount)
            .ok_or_else(|| anyhow!("overflow summing input amounts"))?;
    }
    Ok(sum)
}

fn sum_note_amounts_outputs(outputs: &[TransactOutput]) -> Result<NoteAmount> {
    let mut sum = NoteAmount::ZERO;
    for o in outputs {
        sum = sum
            .checked_add(o.amount)
            .ok_or_else(|| anyhow!("overflow summing output amounts"))?;
    }
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InputValue;

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
                amount: ExtAmount::from(10),
                outputs: vec![TransactOutput {
                    amount: NoteAmount::from(10),
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
        assert!(
            artifacts
                .circuit_inputs
                .signals
                .contains_key("publicAmount")
        );
        assert!(artifacts.circuit_inputs.signals.contains_key("extDataHash"));
        assert!(
            artifacts
                .circuit_inputs
                .signals
                .contains_key("inputNullifier")
        );
        assert!(
            artifacts
                .circuit_inputs
                .signals
                .contains_key("outputCommitment")
        );

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
            amount: NoteAmount::from(10),
            blinding: Field::try_from_le_bytes([4u8; 32]).expect("field"),
            merkle_path_elements: vec![Field::ZERO; tree_depth_usize],
            merkle_path_indices: Field::ZERO,
        };

        let artifacts = withdraw(
            WithdrawParams {
                priv_key,
                encryption_pubkey,
                pool_root: Field::try_from_le_bytes([9u8; 32]).expect("field"),
                withdraw_recipient: "G...".into(),
                withdraw_amount: ExtAmount::from(7),
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
            amount: NoteAmount::from(10),
            blinding: Field::try_from_le_bytes([4u8; 32]).expect("field"),
            merkle_path_elements: vec![Field::ZERO; tree_depth_usize],
            merkle_path_indices: Field::ZERO,
        };
        let out = TransactOutput {
            amount: NoteAmount::from(9), // unbalanced
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
            amount: NoteAmount::MAX,
            blinding: Field::try_from_le_bytes([4u8; 32]).expect("field"),
            merkle_path_elements: vec![Field::ZERO; tree_depth_usize],
            merkle_path_indices: Field::ZERO,
        };

        // Withdraw a small amount; large change should still be valid.
        let res = withdraw(
            WithdrawParams {
                priv_key,
                encryption_pubkey,
                pool_root: Field::try_from_le_bytes([9u8; 32]).expect("field"),
                withdraw_recipient: "G...".into(),
                withdraw_amount: ExtAmount::ONE,
                inputs: vec![input0],
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

    #[test]
    fn selective_disclosure_1_witness_shape_is_correct() {
        let tree_depth: u32 = 10;
        let tree_depth_usize = usize::try_from(tree_depth).expect("tree_depth");

        let params = SelectiveDisclosure1Params {
            root: Field::try_from_le_bytes([1u8; 32]).expect("field"),
            note_commitment: Field::try_from_le_bytes([2u8; 32]).expect("field"),
            note_amount: NoteAmount::from(42),
            note_private_key: NotePrivateKey([3u8; 32]),
            note_blinding: Field::try_from_le_bytes([4u8; 32]).expect("field"),
            merkle_path_indices: Field::try_from_le_bytes([5u8; 32]).expect("field"),
            merkle_path_elements: vec![
                Field::try_from_le_bytes([6u8; 32]).expect("field");
                tree_depth_usize
            ],
            ext_context_hash: Field::try_from_le_bytes([7u8; 32]).expect("field"),
        };

        let artifacts = selective_disclosure_1(params.clone()).expect("builds witness");

        // Public inputs
        assert!(artifacts.circuit_inputs.signals.contains_key("roots"));
        assert!(
            artifacts
                .circuit_inputs
                .signals
                .contains_key("noteCommitments")
        );
        assert!(
            artifacts
                .circuit_inputs
                .signals
                .contains_key("extContextHash")
        );

        // Private inputs
        assert!(artifacts.circuit_inputs.signals.contains_key("inAmount"));
        assert!(
            artifacts
                .circuit_inputs
                .signals
                .contains_key("inPrivateKey")
        );
        assert!(artifacts.circuit_inputs.signals.contains_key("inBlinding"));
        assert!(
            artifacts
                .circuit_inputs
                .signals
                .contains_key("inPathIndices")
        );
        assert!(
            artifacts
                .circuit_inputs
                .signals
                .contains_key("inPathElements")
        );

        // Array shapes for n_notes = 1
        match artifacts
            .circuit_inputs
            .signals
            .get("roots")
            .expect("roots present")
        {
            InputValue::Array(v) => assert_eq!(v.len(), 1),
            _ => panic!("roots should be an array"),
        }
        match artifacts
            .circuit_inputs
            .signals
            .get("noteCommitments")
            .expect("noteCommitments present")
        {
            InputValue::Array(v) => assert_eq!(v.len(), 1),
            _ => panic!("noteCommitments should be an array"),
        }
        match artifacts
            .circuit_inputs
            .signals
            .get("inAmount")
            .expect("inAmount present")
        {
            InputValue::Array(v) => assert_eq!(v.len(), 1),
            _ => panic!("inAmount should be an array"),
        }
        match artifacts
            .circuit_inputs
            .signals
            .get("inPrivateKey")
            .expect("inPrivateKey present")
        {
            InputValue::Array(v) => assert_eq!(v.len(), 1),
            _ => panic!("inPrivateKey should be an array"),
        }
        match artifacts
            .circuit_inputs
            .signals
            .get("inBlinding")
            .expect("inBlinding present")
        {
            InputValue::Array(v) => assert_eq!(v.len(), 1),
            _ => panic!("inBlinding should be an array"),
        }
        match artifacts
            .circuit_inputs
            .signals
            .get("inPathIndices")
            .expect("inPathIndices present")
        {
            InputValue::Array(v) => assert_eq!(v.len(), 1),
            _ => panic!("inPathIndices should be an array"),
        }
        match artifacts
            .circuit_inputs
            .signals
            .get("inPathElements")
            .expect("inPathElements present")
        {
            InputValue::Array(v) => assert_eq!(v.len(), tree_depth_usize),
            _ => panic!("inPathElements should be an array"),
        }

        // ext_context_hash is preserved
        assert_eq!(artifacts.ext_context_hash, params.ext_context_hash);
    }
}
