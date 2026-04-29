use prover::merkle::MerklePrefixTree;
use serde::Serialize;
use types::Field;
use wasm_bindgen::{JsError, JsValue, prelude::*};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MerkleBenchmarkReport {
    depth: u32,
    rounds: u32,
    proofs_per_round: u32,
    cases: Vec<MerkleBenchmarkCase>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MerkleBenchmarkCase {
    leaves: u32,
    avg_new_ms: f64,
    avg_build_ms: f64,
    avg_proofs_ms: f64,
    avg_total_ms: f64,
}

#[wasm_bindgen(js_name = benchmarkMerklePrefixTree)]
pub fn benchmark_merkle_prefix_tree(
    depth: u32,
    leaf_counts: js_sys::Uint32Array,
    rounds: u32,
    proofs_per_round: u32,
) -> Result<JsValue, JsError> {
    if depth == 0 || depth > 32 {
        return Err(JsError::new("depth must be between 1 and 32"));
    }
    if rounds == 0 {
        return Err(JsError::new("rounds must be greater than 0"));
    }
    if proofs_per_round == 0 {
        return Err(JsError::new("proofs_per_round must be greater than 0"));
    }

    let leaf_counts = leaf_counts.to_vec();
    let mut cases = Vec::with_capacity(leaf_counts.len());
    let capacity = 1u64
        .checked_shl(depth)
        .ok_or_else(|| JsError::new("depth is too large"))?;

    for leaf_count in leaf_counts {
        if leaf_count == 0 {
            return Err(JsError::new("leaf counts must be greater than 0"));
        }
        if u64::from(leaf_count) > capacity {
            return Err(JsError::new("leaf count exceeds tree capacity"));
        }

        cases.push(run_case(depth, leaf_count, rounds, proofs_per_round)?);
    }

    serde_wasm_bindgen::to_value(&MerkleBenchmarkReport {
        depth,
        rounds,
        proofs_per_round,
        cases,
    })
    .map_err(|e| JsError::new(&e.to_string()))
}

fn run_case(
    depth: u32,
    leaf_count: u32,
    rounds: u32,
    proofs_per_round: u32,
) -> Result<MerkleBenchmarkCase, JsError> {
    let leaves = deterministic_leaves(leaf_count)?;
    let proof_indices = proof_indices(leaf_count, proofs_per_round);

    let mut new_ms = 0.0;
    let mut build_ms = 0.0;
    let mut proofs_ms = 0.0;

    for _ in 0..rounds {
        let started = now_ms();
        let tree = MerklePrefixTree::new(depth, &leaves).map_err(to_js_error)?;
        let after_new = now_ms();
        let built = tree.into_built();
        let after_build = now_ms();

        for index in &proof_indices {
            built.proof(*index).map_err(to_js_error)?;
        }
        let after_proofs = now_ms();

        new_ms += after_new - started;
        build_ms += after_build - after_new;
        proofs_ms += after_proofs - after_build;
    }

    let rounds_f = f64::from(rounds);
    let avg_new_ms = new_ms / rounds_f;
    let avg_build_ms = build_ms / rounds_f;
    let avg_proofs_ms = proofs_ms / rounds_f;

    Ok(MerkleBenchmarkCase {
        leaves: leaf_count,
        avg_new_ms,
        avg_build_ms,
        avg_proofs_ms,
        avg_total_ms: avg_new_ms + avg_build_ms + avg_proofs_ms,
    })
}

fn deterministic_leaves(count: u32) -> Result<Vec<Field>, JsError> {
    let count = usize::try_from(count).map_err(|_| JsError::new("leaf count is too large"))?;
    let mut leaves = Vec::with_capacity(count);

    for i in 0..count {
        let value = u64::try_from(i)
            .map_err(|_| JsError::new("leaf index is too large"))?
            .checked_add(1)
            .ok_or_else(|| JsError::new("leaf value overflow"))?;
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        leaves.push(Field::try_from_le_bytes(bytes).map_err(to_js_error)?);
    }

    Ok(leaves)
}

fn proof_indices(leaf_count: u32, proofs_per_round: u32) -> Vec<u32> {
    let mut indices = Vec::new();

    for i in 0..proofs_per_round {
        indices.push(i.wrapping_mul(2_654_435_761) % leaf_count);
    }

    indices
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

fn to_js_error(e: impl core::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}
