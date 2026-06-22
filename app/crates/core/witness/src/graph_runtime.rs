use anyhow::{Context as _, Result, anyhow};
use ark_ff_05::{AdditiveGroup as _, BigInteger as _, Field as _, PrimeField as _};
use circom_witness_rs::{Graph, HashSignalInfo};
use num_bigint::BigInt;
use ruint::aliases::U256;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use crate::{field::inputs_hashmap_to_u256, witness_bytes::witness_u256_to_bytes};

pub(crate) fn validate_graph_shape(graph: &Graph, expected_witness_size: u32) -> Result<()> {
    let expected_witness_size =
        usize::try_from(expected_witness_size).context("R1CS witness size does not fit usize")?;
    if graph.signals.len() != expected_witness_size {
        anyhow::bail!(
            "Witness graph output size {} does not match R1CS witness size {}",
            graph.signals.len(),
            expected_witness_size
        );
    }

    let inputs_size = circom_witness_rs::get_inputs_size(graph);
    let mut seen_hashes = HashMap::new();
    for input in &graph.input_mapping {
        let start = usize::try_from(input.signalid)
            .context("Witness graph input signal index does not fit usize")?;
        let width = usize::try_from(input.signalsize)
            .context("Witness graph input width does not fit usize")?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| anyhow!("Witness graph input range overflows usize"))?;
        if end > inputs_size {
            anyhow::bail!(
                "Witness graph input range [{start}, {end}) exceeds input buffer size {inputs_size}"
            );
        }

        if input.hash == 0 {
            continue;
        }

        if let Some(previous) = seen_hashes.insert(input.hash, input) {
            anyhow::bail!(
                "Witness graph contains duplicate input hash {} for signal IDs {} and {}",
                input.hash,
                previous.signalid,
                input.signalid
            );
        }
    }

    Ok(())
}

pub(crate) fn compute_graph_witness_bytes(
    inputs_hashmap: HashMap<String, Vec<BigInt>>,
    graph: &Graph,
    witness_size: u32,
) -> Result<Vec<u8>> {
    let mut witness_inputs = inputs_hashmap_to_u256(inputs_hashmap)?;
    coalesce_policy_bus_inputs(&mut witness_inputs, graph)?;
    validate_graph_inputs(&witness_inputs, graph)?;
    let witness = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        circom_witness_rs::calculate_witness(
            witness_inputs,
            graph,
            Some(&graph_black_box_functions()),
        )
    }))
    .map_err(|panic| {
        anyhow!(
            "Witness graph calculation panicked after input validation: {}",
            panic_payload_message(panic)
        )
    })?
    .map_err(|e| anyhow!("Witness graph calculation failed: {e}"))?;
    ensure_witness_len(&witness, witness_size)?;

    Ok(witness_u256_to_bytes(&witness))
}

fn validate_graph_inputs(inputs: &HashMap<String, Vec<U256>>, graph: &Graph) -> Result<()> {
    let metadata_by_hash: HashMap<u64, &HashSignalInfo> = graph
        .input_mapping
        .iter()
        .filter(|input| input.hash != 0)
        .map(|input| (input.hash, input))
        .collect();
    let mut provided_hashes = HashSet::with_capacity(inputs.len());

    for (name, values) in inputs {
        let input_hash = fnv1a(name);
        let input = metadata_by_hash
            .get(&input_hash)
            .with_context(|| format!("Unknown circuit input `{name}`"))?;
        provided_hashes.insert(input_hash);

        let expected_len = usize::try_from(input.signalsize)
            .context("Witness graph input width does not fit usize")?;
        if values.len() != expected_len {
            anyhow::bail!(
                "Input `{name}` has {} value(s), expected {}",
                values.len(),
                expected_len
            );
        }
    }

    for input in graph.input_mapping.iter().filter(|input| input.hash != 0) {
        if !provided_hashes.contains(&input.hash) {
            anyhow::bail!(
                "Missing circuit input with witness graph hash {}",
                input.hash
            );
        }
    }

    Ok(())
}

fn ensure_witness_len(witness: &[U256], expected_witness_size: u32) -> Result<()> {
    let expected_witness_size =
        usize::try_from(expected_witness_size).context("R1CS witness size does not fit usize")?;
    if witness.len() != expected_witness_size {
        anyhow::bail!(
            "Witness graph produced {} field element(s), expected {}",
            witness.len(),
            expected_witness_size
        );
    }

    Ok(())
}

fn graph_black_box_functions() -> HashMap<String, circom_witness_rs::BlackBoxFunction> {
    let mut bbfs: HashMap<String, circom_witness_rs::BlackBoxFunction> = HashMap::new();
    bbfs.insert(
        "bbf_inv".to_string(),
        Arc::new(|args| {
            let operand = bbf_inv_operand(args);
            operand.inverse().unwrap_or(ark_bn254_05::Fr::ZERO)
        }),
    );
    bbfs.insert(
        "bbf_bit".to_string(),
        Arc::new(|args| {
            expect_black_box_arity("bbf_bit", args, 2);
            let value = fr_to_u256(args[0]);
            let bit = fr_to_u256(args[1]).try_into().unwrap_or(usize::MAX);
            if bit < 256 && value.bit(bit) {
                ark_bn254_05::Fr::from(1u64)
            } else {
                ark_bn254_05::Fr::ZERO
            }
        }),
    );
    bbfs
}

fn bbf_inv_operand(args: &[ark_bn254_05::Fr]) -> ark_bn254_05::Fr {
    assert!(
        matches!(args.len(), 1 | 2),
        "bbf_inv expects 1 or 2 argument(s), got {}",
        args.len()
    );
    args[0]
}

fn expect_black_box_arity(name: &str, args: &[ark_bn254_05::Fr], expected: usize) {
    assert_eq!(
        args.len(),
        expected,
        "{name} expects {expected} argument(s), got {}",
        args.len()
    );
}

fn fr_to_u256(value: ark_bn254_05::Fr) -> U256 {
    let bytes = value.into_bigint().to_bytes_le();
    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    U256::from_le_bytes(padded)
}

fn coalesce_policy_bus_inputs(
    inputs: &mut HashMap<String, Vec<U256>>,
    graph: &Graph,
) -> Result<()> {
    coalesce_bus_input(
        inputs,
        graph,
        "membershipProofs",
        &["leaf", "blinding", "pathElements", "pathIndices"],
    )?;
    coalesce_bus_input(
        inputs,
        graph,
        "nonMembershipProofs",
        &["key", "siblings", "oldKey", "oldValue", "isOld0"],
    )
}

fn coalesce_bus_input(
    inputs: &mut HashMap<String, Vec<U256>>,
    graph: &Graph,
    bus_name: &str,
    field_order: &[&str],
) -> Result<()> {
    if !graph_has_input(graph, bus_name) {
        return Ok(());
    }

    let mut by_index: BTreeMap<(usize, usize), HashMap<String, Vec<U256>>> = BTreeMap::new();
    let mut consumed_keys = Vec::new();
    for (key, value) in inputs.iter() {
        if let Some((first, second, field)) = parse_bus_field_key(key, bus_name) {
            if !field_order.contains(&field) {
                anyhow::bail!("Unknown expanded bus field `{bus_name}[{first}][{second}].{field}`");
            }
            consumed_keys.push(key.clone());
            by_index
                .entry((first, second))
                .or_default()
                .insert(field.to_string(), value.clone());
        }
    }

    if by_index.is_empty() {
        return Ok(());
    }

    reject_sparse_bus_indices(bus_name, by_index.keys().copied())?;

    let mut coalesced = Vec::new();
    for ((first, second), fields) in by_index {
        for field in field_order {
            let values = fields.get(*field).with_context(|| {
                format!("Missing `{bus_name}[{first}][{second}].{field}` for grouped bus input")
            })?;
            coalesced.extend(values.iter().copied());
        }
    }

    if let Some(grouped) = inputs.get(bus_name) {
        if grouped != &coalesced {
            anyhow::bail!(
                "Conflicting grouped and expanded inputs for `{bus_name}` encode different values"
            );
        }
    } else {
        inputs.insert(bus_name.to_string(), coalesced);
    }

    for key in consumed_keys {
        if !graph_has_input(graph, &key) {
            inputs.remove(&key);
        }
    }
    Ok(())
}

fn reject_sparse_bus_indices(
    bus_name: &str,
    indices: impl IntoIterator<Item = (usize, usize)>,
) -> Result<()> {
    let mut rows: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (first, second) in indices {
        rows.entry(first).or_default().insert(second);
    }

    let mut expected_row_width = None;
    for (expected_first, (actual_first, seconds)) in rows.iter().enumerate() {
        if *actual_first != expected_first {
            anyhow::bail!(
                "Sparse expanded bus input `{bus_name}[{}][{}]`; expected `{bus_name}[{}][0]`",
                actual_first,
                seconds.first().copied().unwrap_or_default(),
                expected_first,
            );
        }

        for (expected_second, actual_second) in seconds.iter().enumerate() {
            if *actual_second != expected_second {
                anyhow::bail!(
                    "Sparse expanded bus input `{bus_name}[{}][{}]`; expected `{bus_name}[{}][{}]`",
                    actual_first,
                    actual_second,
                    actual_first,
                    expected_second,
                );
            }
        }

        match expected_row_width {
            Some(width) if seconds.len() != width => {
                anyhow::bail!(
                    "Jagged expanded bus input `{bus_name}[{}]`; expected {} second-level item(s), got {}",
                    actual_first,
                    width,
                    seconds.len(),
                );
            }
            None => expected_row_width = Some(seconds.len()),
            Some(_) => {}
        }
    }

    Ok(())
}

fn graph_has_input(graph: &Graph, name: &str) -> bool {
    let hash = fnv1a(name);
    graph.input_mapping.iter().any(|input| input.hash == hash)
}

fn parse_bus_field_key<'a>(key: &'a str, bus_name: &str) -> Option<(usize, usize, &'a str)> {
    let rest = key.strip_prefix(bus_name)?;
    let (first, rest) = parse_bracket_index(rest)?;
    let (second, rest) = parse_bracket_index(rest)?;
    let field = rest.strip_prefix('.')?;
    if field.is_empty() || field.contains('.') || field.contains('[') {
        return None;
    }
    Some((first, second, field))
}

fn parse_bracket_index(input: &str) -> Option<(usize, &str)> {
    let input = input.strip_prefix('[')?;
    let end = input.find(']')?;
    let index = input[..end].parse().ok()?;
    Some((index, &input[end + 1..]))
}

fn fnv1a(input: &str) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic payload".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_inputs_reject_unknown_names_before_runtime_population() {
        let graph = graph_with_amount_input();
        let mut inputs = HashMap::new();
        inputs.insert("unknown".to_string(), vec![U256::from(7)]);

        let err = validate_graph_inputs(&inputs, &graph)
            .expect_err("unknown graph input must fail before runtime population");

        assert!(err.to_string().contains("Unknown circuit input `unknown`"));
    }

    #[test]
    fn graph_inputs_reject_wrong_signal_width_before_runtime_population() {
        let graph = graph_with_amount_input();
        let mut inputs = HashMap::new();
        inputs.insert("amount".to_string(), vec![U256::from(7), U256::from(8)]);

        let err = validate_graph_inputs(&inputs, &graph)
            .expect_err("wrong graph input width must fail before runtime population");

        assert!(
            err.to_string()
                .contains("Input `amount` has 2 value(s), expected 1"),
            "{err:#}"
        );
    }

    #[test]
    fn graph_inputs_reject_missing_names_before_zero_filling() {
        let graph = graph_with_amount_input();
        let inputs = HashMap::new();

        let err = validate_graph_inputs(&inputs, &graph)
            .expect_err("missing graph input must not be silently zero-filled");

        assert!(
            err.to_string()
                .contains("Missing circuit input with witness graph hash"),
            "{err:#}"
        );
    }

    #[test]
    fn policy_bus_inputs_are_coalesced_when_graph_requires_grouped_bus() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![HashSignalInfo {
                hash: fnv1a("nonMembershipProofs"),
                signalid: 0,
                signalsize: 14,
            }],
        };
        let mut inputs = non_membership_flattened_inputs();

        coalesce_policy_bus_inputs(&mut inputs, &graph).expect("bus coalescing should succeed");

        assert_eq!(
            inputs.get("nonMembershipProofs").expect("grouped bus"),
            &non_membership_flattened_values(1)
        );
        assert!(
            !inputs
                .keys()
                .any(|key| key.starts_with("nonMembershipProofs[0][0].")),
            "expanded bus aliases must not remain after grouped canonicalization"
        );
        validate_graph_inputs(&inputs, &graph)
            .expect("coalesced grouped bus should satisfy graph validation");
    }

    #[test]
    fn policy_bus_inputs_are_coalesced_across_dense_first_indices() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![HashSignalInfo {
                hash: fnv1a("nonMembershipProofs"),
                signalid: 0,
                signalsize: 28,
            }],
        };
        let mut inputs = HashMap::new();
        insert_non_membership_flattened_inputs(&mut inputs, 0, 0, 1);
        insert_non_membership_flattened_inputs(&mut inputs, 1, 0, 15);

        coalesce_policy_bus_inputs(&mut inputs, &graph).expect("dense bus coalescing should work");

        let mut expected = non_membership_flattened_values(1);
        expected.extend(non_membership_flattened_values(15));
        assert_eq!(
            inputs.get("nonMembershipProofs").expect("grouped bus"),
            &expected
        );
        validate_graph_inputs(&inputs, &graph)
            .expect("two dense rows should satisfy graph validation");
    }

    #[test]
    fn policy_bus_coalescing_rejects_sparse_first_index() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![HashSignalInfo {
                hash: fnv1a("nonMembershipProofs"),
                signalid: 0,
                signalsize: 14,
            }],
        };
        let mut inputs = non_membership_flattened_inputs_with_index(99, 0);

        let err = coalesce_policy_bus_inputs(&mut inputs, &graph)
            .expect_err("sparse first bus index must not be canonicalized");

        assert!(
            err.to_string()
                .contains("Sparse expanded bus input `nonMembershipProofs[99][0]`; expected `nonMembershipProofs[0][0]`"),
            "{err:#}"
        );
    }

    #[test]
    fn policy_bus_coalescing_rejects_sparse_second_index() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![HashSignalInfo {
                hash: fnv1a("nonMembershipProofs"),
                signalid: 0,
                signalsize: 14,
            }],
        };
        let mut inputs = non_membership_flattened_inputs_with_index(0, 1);

        let err = coalesce_policy_bus_inputs(&mut inputs, &graph)
            .expect_err("sparse second bus index must not be canonicalized");

        assert!(
            err.to_string()
                .contains("Sparse expanded bus input `nonMembershipProofs[0][1]`; expected `nonMembershipProofs[0][0]`"),
            "{err:#}"
        );
    }

    #[test]
    fn policy_bus_coalescing_rejects_jagged_second_indices() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![HashSignalInfo {
                hash: fnv1a("nonMembershipProofs"),
                signalid: 0,
                signalsize: 28,
            }],
        };
        let mut inputs = HashMap::new();
        insert_non_membership_flattened_inputs(&mut inputs, 0, 0, 1);
        insert_non_membership_flattened_inputs(&mut inputs, 0, 1, 15);
        insert_non_membership_flattened_inputs(&mut inputs, 1, 0, 29);

        let err = coalesce_policy_bus_inputs(&mut inputs, &graph)
            .expect_err("jagged bus rows must not be canonicalized");

        assert!(
            err.to_string().contains(
                "Jagged expanded bus input `nonMembershipProofs[1]`; expected 2 second-level item(s), got 1"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn policy_bus_coalescing_rejects_conflicting_grouped_and_flattened_inputs() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![
                HashSignalInfo {
                    hash: fnv1a("nonMembershipProofs"),
                    signalid: 0,
                    signalsize: 14,
                },
                HashSignalInfo {
                    hash: fnv1a("nonMembershipProofs[0][0].key"),
                    signalid: 0,
                    signalsize: 1,
                },
            ],
        };
        let mut inputs = non_membership_flattened_inputs();
        inputs.insert(
            "nonMembershipProofs".to_string(),
            (100u64..114).map(U256::from).collect(),
        );

        let err = coalesce_policy_bus_inputs(&mut inputs, &graph)
            .expect_err("conflicting grouped and flattened bus values must fail");

        assert!(
            err.to_string()
                .contains("Conflicting grouped and expanded inputs for `nonMembershipProofs`"),
            "{err:#}"
        );
    }

    #[test]
    fn policy_bus_coalescing_keeps_required_aliases_when_equivalent() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![
                HashSignalInfo {
                    hash: fnv1a("nonMembershipProofs"),
                    signalid: 0,
                    signalsize: 14,
                },
                HashSignalInfo {
                    hash: fnv1a("nonMembershipProofs[0][0].key"),
                    signalid: 0,
                    signalsize: 1,
                },
            ],
        };
        let mut inputs = non_membership_flattened_inputs();
        inputs.insert(
            "nonMembershipProofs".to_string(),
            (1u64..=14).map(U256::from).collect(),
        );

        coalesce_policy_bus_inputs(&mut inputs, &graph).expect("equivalent aliases are valid");

        assert_eq!(
            inputs.get("nonMembershipProofs").expect("grouped bus"),
            &(1u64..=14).map(U256::from).collect::<Vec<_>>()
        );
        assert_eq!(
            inputs
                .get("nonMembershipProofs[0][0].key")
                .expect("required alias"),
            &vec![U256::from(1)]
        );
        assert!(
            !inputs.contains_key("nonMembershipProofs[0][0].siblings"),
            "aliases not required by graph metadata should be removed"
        );
        validate_graph_inputs(&inputs, &graph)
            .expect("equivalent grouped and required alias inputs should validate");
    }

    #[test]
    fn policy_bus_inputs_coalesce_membership_and_non_membership() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![
                HashSignalInfo {
                    hash: fnv1a("membershipProofs"),
                    signalid: 0,
                    signalsize: 13,
                },
                HashSignalInfo {
                    hash: fnv1a("nonMembershipProofs"),
                    signalid: 13,
                    signalsize: 14,
                },
            ],
        };
        let mut inputs = non_membership_flattened_inputs();
        inputs.insert(
            "membershipProofs[0][0].pathElements".to_string(),
            (17u64..27).map(U256::from).collect(),
        );
        inputs.insert(
            "membershipProofs[0][0].leaf".to_string(),
            vec![U256::from(15)],
        );
        inputs.insert(
            "membershipProofs[0][0].pathIndices".to_string(),
            vec![U256::from(27)],
        );
        inputs.insert(
            "membershipProofs[0][0].blinding".to_string(),
            vec![U256::from(16)],
        );

        coalesce_policy_bus_inputs(&mut inputs, &graph).expect("bus coalescing should succeed");

        assert_eq!(
            inputs.get("membershipProofs").expect("membership bus"),
            &(15u64..=27).map(U256::from).collect::<Vec<_>>()
        );
        assert_eq!(
            inputs
                .get("nonMembershipProofs")
                .expect("non-membership bus"),
            &(1u64..=14).map(U256::from).collect::<Vec<_>>()
        );
        validate_graph_inputs(&inputs, &graph)
            .expect("both coalesced buses should satisfy graph validation");
    }

    #[test]
    fn policy_bus_coalescing_reports_missing_fields() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![HashSignalInfo {
                hash: fnv1a("membershipProofs"),
                signalid: 0,
                signalsize: 13,
            }],
        };
        let mut inputs = HashMap::new();
        inputs.insert(
            "membershipProofs[0][0].leaf".to_string(),
            vec![U256::from(1)],
        );

        let err = coalesce_policy_bus_inputs(&mut inputs, &graph)
            .expect_err("incomplete grouped bus input must fail clearly");

        assert!(
            err.to_string()
                .contains("Missing `membershipProofs[0][0].blinding`"),
            "{err:#}"
        );
    }

    #[test]
    fn policy_bus_coalescing_rejects_unknown_expanded_fields() {
        let graph = Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![HashSignalInfo {
                hash: fnv1a("nonMembershipProofs"),
                signalid: 0,
                signalsize: 14,
            }],
        };
        let mut inputs = non_membership_flattened_inputs();
        inputs.insert(
            "nonMembershipProofs[0][0].unexpected".to_string(),
            vec![U256::from(15)],
        );

        let err = coalesce_policy_bus_inputs(&mut inputs, &graph)
            .expect_err("unknown expanded bus fields must not be silently discarded");

        assert!(
            err.to_string()
                .contains("Unknown expanded bus field `nonMembershipProofs[0][0].unexpected`"),
            "{err:#}"
        );
    }

    fn non_membership_flattened_inputs() -> HashMap<String, Vec<U256>> {
        non_membership_flattened_inputs_with_index(0, 0)
    }

    fn non_membership_flattened_inputs_with_index(
        first: usize,
        second: usize,
    ) -> HashMap<String, Vec<U256>> {
        let mut inputs = HashMap::new();
        insert_non_membership_flattened_inputs(&mut inputs, first, second, 1);
        inputs
    }

    fn insert_non_membership_flattened_inputs(
        inputs: &mut HashMap<String, Vec<U256>>,
        first: usize,
        second: usize,
        value_start: u64,
    ) {
        let prefix = format!("nonMembershipProofs[{first}][{second}].");
        inputs.insert(format!("{prefix}key"), vec![U256::from(value_start)]);
        inputs.insert(
            format!("{prefix}siblings"),
            ((value_start + 1)..=(value_start + 10))
                .map(U256::from)
                .collect(),
        );
        inputs.insert(
            format!("{prefix}oldKey"),
            vec![U256::from(value_start + 11)],
        );
        inputs.insert(
            format!("{prefix}oldValue"),
            vec![U256::from(value_start + 12)],
        );
        inputs.insert(
            format!("{prefix}isOld0"),
            vec![U256::from(value_start + 13)],
        );
    }

    fn non_membership_flattened_values(value_start: u64) -> Vec<U256> {
        (value_start..=(value_start + 13)).map(U256::from).collect()
    }

    #[test]
    fn graph_shape_must_match_r1cs_witness_size() {
        let graph = graph_with_amount_input();
        let err = validate_graph_shape(&graph, 2)
            .expect_err("graph/R1CS witness-size mismatch must fail at construction");

        assert!(
            err.to_string()
                .contains("Witness graph output size 1 does not match R1CS witness size 2"),
            "{err:#}"
        );
    }

    #[test]
    fn graph_shape_allows_unnamed_hash_zero_placeholders() {
        let mut graph = graph_with_amount_input();
        graph.input_mapping.push(HashSignalInfo::default());
        graph.input_mapping.push(HashSignalInfo::default());

        validate_graph_shape(&graph, 1)
            .expect("unnamed hash-zero placeholders are valid graph metadata");
        let mut inputs = HashMap::new();
        inputs.insert("amount".to_string(), vec![U256::from(7)]);

        validate_graph_inputs(&inputs, &graph)
            .expect("unnamed hash-zero placeholders are not required JSON inputs");
    }

    #[test]
    fn graph_shape_rejects_duplicate_named_hashes() {
        let mut graph = graph_with_amount_input();
        graph.input_mapping.push(HashSignalInfo {
            hash: fnv1a("amount"),
            signalid: 0,
            signalsize: 1,
        });

        let err = validate_graph_shape(&graph, 1)
            .expect_err("duplicate named graph input hashes must fail at construction");

        assert!(
            err.to_string()
                .contains("Witness graph contains duplicate input hash"),
            "{err:#}"
        );
    }

    #[test]
    fn graph_black_box_functions_reject_wrong_arity_with_context() {
        let bbfs = graph_black_box_functions();
        let bbf_bit = bbfs.get("bbf_bit").expect("bbf_bit registered");

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            bbf_bit(&[ark_bn254_05::Fr::from(1u64)]);
        }))
        .expect_err("wrong BBF arity must panic with a clear message");
        let message = panic_payload_message(panic);

        assert!(
            message.contains("bbf_bit expects 2 argument(s), got 1"),
            "{message}"
        );
    }

    #[test]
    fn graph_inverse_black_box_accepts_graph_dependency_forms() {
        let value = ark_bn254_05::Fr::from(7u64);
        let placeholder = ark_bn254_05::Fr::from(42u64);

        assert_eq!(bbf_inv_operand(&[value]), value);
        assert_eq!(bbf_inv_operand(&[value, placeholder]), value);
        assert_eq!(
            bbf_inv_operand(&[ark_bn254_05::Fr::from(1u64), placeholder]),
            ark_bn254_05::Fr::from(1u64)
        );
    }

    fn graph_with_amount_input() -> Graph {
        Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![HashSignalInfo {
                hash: fnv1a("amount"),
                signalid: 0,
                signalsize: 1,
            }],
        }
    }
}
