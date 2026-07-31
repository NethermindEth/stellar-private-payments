//! Byte-identical witness check: optimized vs unoptimized circuit WASM.
//!
//! For every shipped circuit this test loads the raw (unoptimized) witness WASM
//! from `target/circuits-artifacts/release/` and the optimized WASM from
//! `sdk/web/dist/circuits/`, computes the witness for a fixed valid input using
//! the same R1CS, and asserts the two witness byte vectors are identical.

use std::{
    collections::HashMap,
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use ark_bn254::Fr;
use ark_circom::{WitnessCalculator as ArkWitnessCalculator, circom::R1CSFile};
use num_bigint::BigInt;
use types::PolicyFlags;
use wasmer::{Module, Store};
use zkhash::{ark_ff::Zero, fields::bn256::FpBN256 as Scalar};

use circuits::test::utils::{
    circom_tester::Inputs,
    general::{poseidon2_hash2, scalar_to_bigint},
    keypair::{derive_public_key, sign},
    merkle_tree::{merkle_proof, merkle_root},
    sparse_merkle_tree::{SMTProof, prepare_smt_proof_with_overrides},
    transaction::{commitment, nullifier, prepopulated_leaves},
    transaction_case::{
        InputNote, OutputNote, TxCase, build_base_inputs, prepare_transaction_witness,
    },
};

const LEVELS: usize = 10;
const N_MEM_PROOFS: usize = 1;
const N_NON_PROOFS: usize = 1;
const EXT_CONTEXT_HASH: u64 = 0xC0FFEE_u64;

/// Return the workspace root from `CARGO_MANIFEST_DIR` (e2e-tests sits one
/// level down).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e-tests crate must be inside a workspace")
        .to_path_buf()
}

/// Cargo profile for the current test binary.
///
/// Cargo does not set `PROFILE` at test runtime, so we use `debug_assertions`
/// as the debug/release proxy. This matches the pattern used in
/// `sdk/tests/pool.rs`.
fn cargo_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn circuit_artifacts_dir() -> PathBuf {
    workspace_root()
        .join("target/circuits-artifacts")
        .join(cargo_profile())
}

fn unoptimized_wasm_path(stem: &str) -> PathBuf {
    circuit_artifacts_dir().join(format!("{stem}.wasm"))
}

fn optimized_wasm_path(stem: &str) -> PathBuf {
    workspace_root()
        .join("sdk/web/dist/circuits")
        .join(format!("{stem}.wasm"))
}

fn r1cs_path(stem: &str) -> PathBuf {
    circuit_artifacts_dir().join(format!("{stem}.r1cs"))
}

/// Compute the full witness bytes for a circuit given its wasm, r1cs, and flat
/// inputs.
fn compute_witness_bytes(wasm_path: &Path, r1cs_path: &Path, inputs: &Inputs) -> Result<Vec<u8>> {
    let wasm_bytes = std::fs::read(wasm_path)
        .with_context(|| format!("failed to read wasm {}", wasm_path.display()))?;
    let r1cs_bytes = std::fs::read(r1cs_path)
        .with_context(|| format!("failed to read r1cs {}", r1cs_path.display()))?;

    let cursor = Cursor::new(r1cs_bytes);
    let _r1cs_file: R1CSFile<Fr> = R1CSFile::new(cursor).context("failed to parse R1CS")?;

    let mut store = Store::default();
    let module = Module::new(&store, wasm_bytes).context("failed to load circuit WASM")?;
    let mut calculator = ArkWitnessCalculator::from_module(&mut store, module)
        .map_err(|e| anyhow::anyhow!("failed to init witness calc: {e}"))?;

    // Convert the flat Inputs hashmap to the HashMap<String, Vec<BigInt>> that
    // ark-circom expects.
    let mut inputs_map: HashMap<String, Vec<BigInt>> = HashMap::new();
    for (key, value) in inputs.iter() {
        match value {
            circuits::test::utils::circom_tester::InputValue::Single(v) => {
                inputs_map.insert(key.clone(), vec![v.clone()]);
            }
            circuits::test::utils::circom_tester::InputValue::Array(arr) => {
                inputs_map.insert(key.clone(), arr.clone());
            }
        }
    }

    let witness = calculator
        .calculate_witness(&mut store, inputs_map, false)
        .map_err(|e| anyhow::anyhow!("witness calculation failed: {e}"))?;

    Ok(witness_to_bytes(&witness))
}

/// Convert a witness vector to the same little-endian 32-byte chunk format that
/// `sdk/witness` emits.
fn witness_to_bytes(witness: &[BigInt]) -> Vec<u8> {
    use num_bigint::Sign;
    let mut bytes = Vec::with_capacity(
        witness
            .len()
            .checked_mul(32)
            .expect("overflow in witness size"),
    );
    for bi in witness {
        let (sign, be_bytes) = bi.to_bytes_be();
        assert!(be_bytes.len() <= 32, "field element exceeds 32 bytes");
        assert!(sign != Sign::Minus, "negative number in witness output");
        let mut padded = vec![0u8; 32];
        let offset = 32usize.saturating_sub(be_bytes.len());
        padded[offset..].copy_from_slice(&be_bytes);
        padded.reverse();
        bytes.extend_from_slice(&padded);
    }
    bytes
}

/// Compare optimized and unoptimized witnesses for a circuit stem.
///
/// Skips silently when the required artifacts are not built so that `cargo
/// test` in a fresh checkout does not fail. The real assertion runs only after
/// a matching-profile circuits build + `npm run build --prefix sdk/web` (or
/// `make sdk-web-build`) has produced both the raw and optimized wasm files.
///
/// Set `REQUIRE_WITNESS_ARTIFACTS=1` (as CI does) to turn a missing artifact
/// into a hard failure instead of a silent skip.
fn assert_witness_identity(stem: &str, inputs: &Inputs) -> Result<()> {
    let unopt = unoptimized_wasm_path(stem);
    let opt = optimized_wasm_path(stem);
    let r1cs = r1cs_path(stem);

    let require_artifacts = std::env::var("REQUIRE_WITNESS_ARTIFACTS").is_ok_and(|v| !v.is_empty());
    if require_artifacts {
        ensure!(
            unopt.exists(),
            "missing unoptimized wasm: {}",
            unopt.display()
        );
        ensure!(opt.exists(), "missing optimized wasm: {}", opt.display());
        ensure!(r1cs.exists(), "missing r1cs: {}", r1cs.display());
    } else if !(unopt.exists() && opt.exists() && r1cs.exists()) {
        eprintln!(
            "skipping {stem}: optimized/unoptimized wasm artifacts not built (run cargo build -p circuits + sdk-web build)"
        );
        return Ok(());
    }

    let unopt_bytes = compute_witness_bytes(&unopt, &r1cs, inputs)
        .with_context(|| format!("unoptimized witness failed for {stem}"))?;
    let opt_bytes = compute_witness_bytes(&opt, &r1cs, inputs)
        .with_context(|| format!("optimized witness failed for {stem}"))?;

    ensure!(
        unopt_bytes == opt_bytes,
        "witness bytes differ for {stem}: unoptimized {} bytes, optimized {} bytes",
        unopt_bytes.len(),
        opt_bytes.len()
    );
    Ok(())
}

// ============================================================================
// Policy transaction circuit inputs
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyAspWitness {
    None,
    Membership,
    NonMembership,
    Both,
}

impl From<PolicyFlags> for PolicyAspWitness {
    fn from(flags: PolicyFlags) -> Self {
        match (
            flags.requires_membership_proofs(),
            flags.requires_non_membership_proofs(),
        ) {
            (false, false) => Self::None,
            (true, false) => Self::Membership,
            (false, true) => Self::NonMembership,
            (true, true) => Self::Both,
        }
    }
}

struct MembershipTree {
    leaves: [Scalar; 1 << LEVELS],
    index: usize,
    blinding: Scalar,
}

struct NonMembership {
    key_non_inclusion: BigInt,
}

fn build_membership_trees(case: &TxCase, seed: u64) -> Vec<MembershipTree> {
    let n_inputs = case.inputs.len();
    let mut membership_trees = Vec::with_capacity(n_inputs * N_MEM_PROOFS);

    for j in 0..N_MEM_PROOFS {
        let seed_j = seed ^ ((j as u64) << 40);
        let base_mem_leaves_j = prepopulated_leaves(LEVELS, seed_j, &[], 24);

        for input in &case.inputs {
            membership_trees.push(MembershipTree {
                leaves: base_mem_leaves_j
                    .clone()
                    .try_into()
                    .expect("failed to convert into list"),
                index: input.leaf_index,
                blinding: Scalar::zero(),
            });
        }
    }

    membership_trees
}

fn non_membership_overrides_from_pubs(pubs: &[Scalar]) -> Vec<(BigInt, BigInt)> {
    pubs.iter()
        .enumerate()
        .map(|(i, pk)| {
            let idx = (i as u64).checked_add(1).expect("idx overflow");
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

fn default_non_membership_keys(case: &TxCase) -> Vec<NonMembership> {
    case.inputs
        .iter()
        .map(|input| NonMembership {
            key_non_inclusion: scalar_to_bigint(derive_public_key(input.priv_key)),
        })
        .collect()
}

fn apply_membership_proofs(
    inputs: &mut Inputs,
    case: &TxCase,
    pubs: &[Scalar],
    membership_trees: &[MembershipTree],
) -> Result<()> {
    let n_inputs = case.inputs.len();
    ensure!(
        membership_trees.len() == n_inputs * N_MEM_PROOFS,
        "expected {} membership trees, found {}",
        n_inputs * N_MEM_PROOFS,
        membership_trees.len()
    );

    let mut mp_leaf: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut mp_blinding: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut mp_path_indices: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut mp_path_elements: Vec<Vec<Vec<BigInt>>> = vec![Vec::new(); n_inputs];
    let mut membership_roots: Vec<BigInt> = Vec::with_capacity(n_inputs * N_MEM_PROOFS);

    for j in 0..N_MEM_PROOFS {
        let base_idx = j
            .checked_mul(n_inputs)
            .ok_or_else(|| anyhow::anyhow!("index overflow"))?;
        let mut frozen_leaves = membership_trees[base_idx].leaves;

        for (k, &pk_scalar) in pubs.iter().enumerate() {
            let index = k
                .checked_mul(N_MEM_PROOFS)
                .and_then(|v| v.checked_add(j))
                .ok_or_else(|| anyhow::anyhow!("index overflow"))?;
            let tree = &membership_trees[index];
            let leaf = poseidon2_hash2(pk_scalar, tree.blinding, Some(Scalar::from(1u64)));
            frozen_leaves[tree.index] = leaf;
        }

        let root_scalar = merkle_root(frozen_leaves.to_vec());

        for i in 0..n_inputs {
            let idx = i
                .checked_mul(N_MEM_PROOFS)
                .and_then(|v| v.checked_add(j))
                .ok_or_else(|| anyhow::anyhow!("index overflow"))?;
            let t = &membership_trees[idx];
            let pk_scalar = pubs[i];
            let leaf_scalar = poseidon2_hash2(pk_scalar, t.blinding, Some(Scalar::from(1u64)));
            let (siblings, path_idx_u64, depth) = merkle_proof(&frozen_leaves, t.index);
            ensure!(depth == LEVELS, "unexpected membership depth");

            mp_leaf[i].push(scalar_to_bigint(leaf_scalar));
            mp_blinding[i].push(scalar_to_bigint(t.blinding));
            mp_path_indices[i].push(scalar_to_bigint(Scalar::from(path_idx_u64)));
            mp_path_elements[i].push(siblings.into_iter().map(scalar_to_bigint).collect());
            membership_roots.push(scalar_to_bigint(root_scalar));
        }
    }

    use circuits::test::utils::circom_tester::SignalKey;
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
    Ok(())
}

fn apply_non_membership_proofs<G>(
    inputs: &mut Inputs,
    case: &TxCase,
    pubs: &[Scalar],
    non_membership: &[NonMembership],
    build_non_membership_proof: G,
) -> Result<()>
where
    G: Fn(&BigInt, &[Scalar]) -> SMTProof,
{
    let n_inputs = case.inputs.len();
    ensure!(
        n_inputs == non_membership.len(),
        "non-membership entries must match number of inputs"
    );

    let mut nmp_key: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut nmp_old_key: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut nmp_old_value: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut nmp_is_old0: Vec<Vec<BigInt>> = vec![Vec::new(); n_inputs];
    let mut nmp_siblings: Vec<Vec<Vec<BigInt>>> = vec![Vec::new(); n_inputs];
    let mut non_membership_roots: Vec<BigInt> = Vec::with_capacity(n_inputs * N_NON_PROOFS);

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

    use circuits::test::utils::circom_tester::SignalKey;
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
    Ok(())
}

#[allow(clippy::arithmetic_side_effects)]
fn build_policy_inputs(asp: PolicyAspWitness) -> Result<Inputs> {
    // 2 real inputs, 2 outputs splitting the sum.
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

    let leaves = prepopulated_leaves(LEVELS, 0xBEEFu64, &[0, 30], 24);
    let witness = prepare_transaction_witness(&case, leaves, LEVELS)?;
    let mut inputs = build_base_inputs(&case, &witness, Scalar::from(0u64));

    let membership_trees = build_membership_trees(&case, 0x1234_5678u64);
    let non_membership = default_non_membership_keys(&case);
    let pubs = &witness.public_keys;

    match asp {
        PolicyAspWitness::None => {}
        PolicyAspWitness::Membership => {
            apply_membership_proofs(&mut inputs, &case, pubs, &membership_trees)?;
        }
        PolicyAspWitness::NonMembership => {
            apply_non_membership_proofs(
                &mut inputs,
                &case,
                pubs,
                &non_membership,
                default_non_membership_proof_builder,
            )?;
        }
        PolicyAspWitness::Both => {
            apply_membership_proofs(&mut inputs, &case, pubs, &membership_trees)?;
            apply_non_membership_proofs(
                &mut inputs,
                &case,
                pubs,
                &non_membership,
                default_non_membership_proof_builder,
            )?;
        }
    }

    Ok(inputs)
}

fn run_policy_identity(stem: &str, asp: PolicyAspWitness) -> Result<()> {
    assert_witness_identity(stem, &build_policy_inputs(asp)?)
}

#[cfg_attr(miri, ignore)]
#[ignore = "needs circuits + sdk-web-build artifacts"]
#[test]
fn test_witness_identity_policy_tx_all() -> Result<()> {
    for flags in PolicyFlags::all_flags() {
        let stem = flags.circuit_stem();
        let asp = PolicyAspWitness::from(flags);
        run_policy_identity(&stem, asp)
            .with_context(|| format!("policy identity check failed for {stem}"))?;
    }
    Ok(())
}

// ============================================================================
// Selective disclosure circuit inputs
// ============================================================================

#[derive(Clone)]
struct DisclosureNote {
    leaf_index: usize,
    priv_key: Scalar,
    blinding: Scalar,
    amount: Scalar,
}

fn sample_note(leaf_index: usize, priv_key: u64, blinding: u64, amount: u64) -> DisclosureNote {
    DisclosureNote {
        leaf_index,
        priv_key: Scalar::from(priv_key),
        blinding: Scalar::from(blinding),
        amount: Scalar::from(amount),
    }
}

fn sample_leaves(notes: &[DisclosureNote]) -> Vec<Scalar> {
    let indices: Vec<usize> = notes.iter().map(|n| n.leaf_index).collect();
    prepopulated_leaves(LEVELS, 0xD15C_105E_u64, &indices, 24)
}

fn build_disclosure_inputs(notes: &[DisclosureNote], leaves: &mut [Scalar]) -> Result<Inputs> {
    let mut roots = Vec::with_capacity(notes.len());
    let mut note_commitments = Vec::with_capacity(notes.len());
    let mut output_nullifiers = Vec::with_capacity(notes.len());
    let mut in_amount = Vec::with_capacity(notes.len());
    let mut in_private_key = Vec::with_capacity(notes.len());
    let mut in_blinding = Vec::with_capacity(notes.len());
    let mut in_path_indices = Vec::with_capacity(notes.len());
    let mut in_path_elements = Vec::new();

    for note in notes {
        let pub_key = derive_public_key(note.priv_key);
        let note_commitment = commitment(note.amount, pub_key, note.blinding);
        leaves[note.leaf_index] = note_commitment;

        let root = merkle_root(leaves.to_vec());
        let (siblings, path_idx_u64, depth) = merkle_proof(leaves, note.leaf_index);
        ensure!(depth == LEVELS, "unexpected Merkle depth");

        let path_indices = Scalar::from(path_idx_u64);
        let sig = sign(note.priv_key, note_commitment, path_indices);
        let note_nullifier = nullifier(note_commitment, path_indices, sig);

        roots.push(scalar_to_bigint(root));
        note_commitments.push(scalar_to_bigint(note_commitment));
        output_nullifiers.push(scalar_to_bigint(note_nullifier));
        in_amount.push(note.amount);
        in_private_key.push(note.priv_key);
        in_blinding.push(note.blinding);
        in_path_indices.push(path_indices);
        in_path_elements.extend(siblings.into_iter().map(scalar_to_bigint));
    }

    let mut inputs = Inputs::new();
    inputs.set("roots", roots);
    inputs.set("noteCommitments", note_commitments);
    inputs.set("extContextHash", Scalar::from(EXT_CONTEXT_HASH));
    inputs.set("expectedNullifier", output_nullifiers);
    inputs.set("inAmount", in_amount);
    inputs.set("inPrivateKey", in_private_key);
    inputs.set("inBlinding", in_blinding);
    inputs.set("inPathIndices", in_path_indices);
    inputs.set("inPathElements", in_path_elements);
    Ok(inputs)
}

#[allow(clippy::arithmetic_side_effects)]
fn run_selective_disclosure_identity(n_notes: usize) -> Result<()> {
    let stem = format!("selectiveDisclosure_{n_notes}");
    let notes: Vec<DisclosureNote> = (0..n_notes)
        .map(|i| sample_note(7 + i * 5, 4242 + i as u64, 5151 + i as u64, 17 + i as u64))
        .collect();
    let mut leaves = sample_leaves(&notes);
    let inputs = build_disclosure_inputs(&notes, &mut leaves)?;
    assert_witness_identity(&stem, &inputs)
}

#[cfg_attr(miri, ignore)]
#[ignore = "needs circuits + sdk-web-build artifacts"]
#[test]
fn test_witness_identity_selective_disclosure_1() -> Result<()> {
    run_selective_disclosure_identity(1)
}

#[cfg_attr(miri, ignore)]
#[ignore = "needs circuits + sdk-web-build artifacts"]
#[test]
fn test_witness_identity_selective_disclosure_2() -> Result<()> {
    run_selective_disclosure_identity(2)
}

#[cfg_attr(miri, ignore)]
#[ignore = "needs circuits + sdk-web-build artifacts"]
#[test]
fn test_witness_identity_selective_disclosure_3() -> Result<()> {
    run_selective_disclosure_identity(3)
}

#[cfg_attr(miri, ignore)]
#[ignore = "needs circuits + sdk-web-build artifacts"]
#[test]
fn test_witness_identity_selective_disclosure_4() -> Result<()> {
    run_selective_disclosure_identity(4)
}
