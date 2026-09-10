//! Ledger keys the keeper measures, restores, and extends.
//!
//! Every key is derived from the deployment manifest, from a contract's own
//! stored state, or from the pool events that record spent nullifiers. A key
//! this module cannot enumerate is one the keeper never touches.
//!
//! Enumeration is exhaustive rather than exact: every root ring slot, every
//! role holder the manifest names, and every pause entry is listed whether or
//! not the contract has written it. The RPC reports which of them exist, so a
//! key that was never written costs one slot in a read and nothing else.

use anyhow::{Context, Result, anyhow, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};
use stellar_private_payments::{
    chain::Client,
    types::{ContractConfig, GovernanceConfig},
};
use stellar_xdr::{self as xdr, LedgerKey, Limits, ReadXdr, WriteXdr};

/// First topic of the event a pool publishes when a nullifier is spent.
const NULLIFIER_EVENT: &str = "new_nullifier_event";

/// Historical roots a pool keeps before overwriting the oldest.
const ROOT_HISTORY_SIZE: u32 = 90;

/// Events read from the RPC in one page.
const EVENT_PAGE_SIZE: usize = 200;

/// Keys the RPC accepts in one `getLedgerEntries` call.
pub const LEDGER_KEY_CHUNK: usize = 200;

/// Roles the governor's access control table holds.
const ROLES: [&str; 4] = ["council", "operator", "guardian", "recovery"];

/// Parses a contract or account address into its XDR form.
///
/// # Errors
///
/// Returns an error if `address` is not a valid strkey.
pub fn address(address: &str) -> Result<xdr::ScAddress> {
    xdr::ScAddress::from_str(address).with_context(|| format!("invalid address {address}"))
}

fn symbol(name: &str) -> Result<xdr::ScVal> {
    Ok(xdr::ScVal::Symbol(
        xdr::ScSymbol::try_from(name).map_err(|_| anyhow!("invalid symbol {name}"))?,
    ))
}

/// Builds the persistent contract-data key a storage enum variant occupies.
///
/// `parts` holds the variant's arguments, in declaration order. A variant with
/// no arguments passes an empty slice.
///
/// # Errors
///
/// Returns an error if `variant` is too long to be a Soroban symbol.
pub fn data_key(
    contract: &xdr::ScAddress,
    variant: &str,
    parts: Vec<xdr::ScVal>,
) -> Result<LedgerKey> {
    let mut fields = Vec::with_capacity(parts.len().saturating_add(1));
    fields.push(symbol(variant)?);
    fields.extend(parts);
    Ok(LedgerKey::ContractData(xdr::LedgerKeyContractData {
        contract: contract.clone(),
        key: xdr::ScVal::Vec(Some(xdr::ScVec::try_from(fields)?)),
        durability: xdr::ContractDataDurability::Persistent,
    }))
}

/// Builds the key of a contract's instance entry.
pub fn instance_key(contract: &xdr::ScAddress) -> LedgerKey {
    LedgerKey::ContractData(xdr::LedgerKeyContractData {
        contract: contract.clone(),
        key: xdr::ScVal::LedgerKeyContractInstance,
        durability: xdr::ContractDataDurability::Persistent,
    })
}

/// Builds the key of the wasm a contract instance runs.
pub fn code_key(wasm_hash: xdr::Hash) -> LedgerKey {
    LedgerKey::ContractCode(xdr::LedgerKeyContractCode { hash: wasm_hash })
}

/// Converts 32 big-endian bytes into the four parts of an XDR `u256`.
///
/// # Panics
///
/// Panics if a fixed slice of the 32-byte input is not eight bytes, which the
/// array's own length rules out.
pub fn u256(bytes: [u8; 32]) -> xdr::ScVal {
    xdr::ScVal::U256(xdr::UInt256Parts {
        hi_hi: u64::from_be_bytes(bytes[0..8].try_into().expect("u256 hi_hi slice")),
        hi_lo: u64::from_be_bytes(bytes[8..16].try_into().expect("u256 hi_lo slice")),
        lo_hi: u64::from_be_bytes(bytes[16..24].try_into().expect("u256 lo_hi slice")),
        lo_lo: u64::from_be_bytes(bytes[24..32].try_into().expect("u256 lo_lo slice")),
    })
}

/// Converts an XDR `u256` back into 32 big-endian bytes.
///
/// # Errors
///
/// Returns an error if `value` is not a `u256`.
pub fn u256_bytes(value: &xdr::ScVal) -> Result<[u8; 32]> {
    let xdr::ScVal::U256(parts) = value else {
        bail!("expected a u256 value");
    };
    let mut out = [0u8; 32];
    for (chunk, part) in
        out.chunks_exact_mut(8)
            .zip([parts.hi_hi, parts.hi_lo, parts.lo_hi, parts.lo_lo])
    {
        chunk.copy_from_slice(&part.to_be_bytes());
    }
    Ok(out)
}

fn hex_to_bytes(text: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(text.strip_prefix("0x").unwrap_or(text), &mut out)
        .context("expected 64 hexadecimal digits")?;
    Ok(out)
}

/// Renders 32 bytes as lowercase hexadecimal without a prefix.
pub fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// Returns every key a pool contract owns, apart from its instance and wasm.
///
/// The root ring is enumerated in full rather than up to the current index,
/// because an unwritten slot is absent from the response and a written one
/// must stay live for proof verification against a recent root.
///
/// # Errors
///
/// Returns an error if a nullifier is not 32 bytes of hexadecimal.
pub fn pool_keys(
    contract: &xdr::ScAddress,
    levels: u32,
    nullifiers: &BTreeSet<String>,
) -> Result<Vec<LedgerKey>> {
    const ENUM_KEYS: [&str; 13] = [
        "Admin",
        "Token",
        "Verifier",
        "ASPMembership",
        "ASPNonMembership",
        "Levels",
        "CurrentRootIndex",
        "NextIndex",
        "MaximumDepositAmount",
        "PolicyFlags",
        "AdminViewKey",
        "GvkMode",
        "Pause",
    ];

    let mut keys = Vec::new();
    for variant in ENUM_KEYS {
        keys.push(data_key(contract, variant, vec![])?);
    }
    for level in 0..=levels {
        keys.push(data_key(
            contract,
            "FilledSubtree",
            vec![xdr::ScVal::U32(level)],
        )?);
        keys.push(data_key(contract, "Zeroes", vec![xdr::ScVal::U32(level)])?);
    }
    for index in 0..ROOT_HISTORY_SIZE {
        keys.push(data_key(contract, "Root", vec![xdr::ScVal::U32(index)])?);
    }
    for nullifier in nullifiers {
        keys.push(data_key(
            contract,
            "Nullifier",
            vec![u256(hex_to_bytes(nullifier)?)],
        )?);
    }
    Ok(keys)
}

/// Returns every key the membership association set owns.
///
/// # Errors
///
/// Returns an error if a key cannot be encoded.
pub fn membership_keys(contract: &xdr::ScAddress, levels: u32) -> Result<Vec<LedgerKey>> {
    let mut keys = Vec::new();
    for variant in ["Admin", "Levels", "NextIndex", "Root", "Pause"] {
        keys.push(data_key(contract, variant, vec![])?);
    }
    for level in 0..=levels {
        keys.push(data_key(
            contract,
            "FilledSubtrees",
            vec![xdr::ScVal::U32(level)],
        )?);
        keys.push(data_key(contract, "Zeroes", vec![xdr::ScVal::U32(level)])?);
    }
    Ok(keys)
}

/// Returns every key the non-membership association set owns.
///
/// `nodes` comes from [`walk_sparse_tree`], because the sparse tree's node
/// hashes exist only in its own stored values.
///
/// # Errors
///
/// Returns an error if a key cannot be encoded.
pub fn non_membership_keys(
    contract: &xdr::ScAddress,
    nodes: &[[u8; 32]],
) -> Result<Vec<LedgerKey>> {
    let mut keys = Vec::new();
    for variant in ["Admin", "Root", "Pause"] {
        keys.push(data_key(contract, variant, vec![])?);
    }
    for node in nodes {
        keys.push(data_key(contract, "Node", vec![u256(*node)])?);
    }
    Ok(keys)
}

/// Returns the child hashes a sparse-tree node's stored value names.
///
/// An internal node holds the two hashes of its children. A leaf holds three
/// elements and has no children. The zero hash marks an empty subtree and is
/// not a node.
///
/// # Errors
///
/// Returns an error if the value is neither a two-element nor a three-element
/// vector of `u256`.
pub fn node_children(value: &xdr::ScVal) -> Result<Vec<[u8; 32]>> {
    let xdr::ScVal::Vec(Some(elements)) = value else {
        bail!("expected a sparse tree node vector");
    };
    match elements.len() {
        3 => Ok(Vec::new()),
        2 => {
            let mut children = Vec::new();
            for element in elements.iter() {
                let child = u256_bytes(element)?;
                if child != [0u8; 32] {
                    children.push(child);
                }
            }
            Ok(children)
        }
        n => bail!("expected 2 or 3 elements in a sparse tree node, got {n}"),
    }
}

/// Returns every node reachable from `root`, without repeats.
///
/// `children` maps a node hash to the hashes its value names. A hash absent
/// from the map is a node whose value was never stored, and ends that branch.
pub fn walk_sparse_tree(
    root: [u8; 32],
    children: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
) -> Vec<[u8; 32]> {
    if root == [0u8; 32] {
        return Vec::new();
    }
    let mut seen = BTreeSet::new();
    let mut frontier = vec![root];
    let mut visited = Vec::new();

    while let Some(node) = frontier.pop() {
        if !seen.insert(node) {
            continue;
        }
        visited.push(node);
        if let Some(kids) = children.get(&node) {
            frontier.extend(kids.iter().filter(|k| **k != [0u8; 32]));
        }
    }
    visited
}

/// Returns every key the governor owns for the roles and rows the manifest
/// implies.
///
/// `operations` names the queued operations, and `functions` the permission
/// table rows as pairs of target address and function name.
///
/// # Errors
///
/// Returns an error if an address in the governance block is not a valid
/// strkey.
pub fn governor_keys(
    governance: &GovernanceConfig,
    operations: &[[u8; 32]],
    functions: &[(String, String)],
    role_members: &[(String, u32)],
) -> Result<Vec<LedgerKey>> {
    let governor = address(&governance.governor)?;
    let mut keys = vec![
        pending_key(&governor)?,
        // Written once when the governor is constructed, and touched again
        // only on a role change, which makes it the entry most likely to be
        // archived first.
        data_key(&governor, "ExistingRoles", vec![])?,
    ];

    for id in operations {
        let bytes = xdr::ScVal::Bytes(xdr::ScBytes(id.to_vec().try_into()?));
        keys.push(data_key(&governor, "Operation", vec![bytes.clone()])?);
        // The OpenZeppelin timelock keeps the ready ledger under its own key,
        // so an operation whose lifetime is extended only here is half alive.
        keys.push(data_key(&governor, "OperationLedger", vec![bytes])?);
    }
    for (target, function) in functions {
        keys.push(data_key(
            &governor,
            "FnRole",
            vec![xdr::ScVal::Address(address(target)?), symbol(function)?],
        )?);
    }

    let holders = [
        (&governance.council, "council"),
        (&governance.operator, "operator"),
        (&governance.guardian, "guardian"),
        (&governance.recovery, "recovery"),
    ];
    for (holder, role) in holders {
        keys.push(data_key(
            &governor,
            "HasRole",
            vec![xdr::ScVal::Address(address(holder)?), symbol(role)?],
        )?);
    }
    for role in ROLES {
        keys.push(role_count_key(&governor, role)?);
    }
    for (role, count) in role_members {
        for index in 0..*count {
            keys.push(data_key(
                &governor,
                "RoleAccounts",
                vec![role_account_key(role, index)?],
            )?);
        }
    }
    Ok(keys)
}

/// Builds the `RoleAccountKey` struct value that indexes one role holder.
///
/// An `ScMap` is ordered by key symbol, so `index` precedes `role` however the
/// struct itself declares them.
///
/// # Errors
///
/// Returns an error if `role` is too long to be a Soroban symbol.
fn role_account_key(role: &str, index: u32) -> Result<xdr::ScVal> {
    let field = |name: &str, value: xdr::ScVal| -> Result<xdr::ScMapEntry> {
        Ok(xdr::ScMapEntry {
            key: symbol(name)?,
            val: value,
        })
    };
    Ok(xdr::ScVal::Map(Some(xdr::ScMap::try_from(vec![
        field("index", xdr::ScVal::U32(index))?,
        field("role", symbol(role)?)?,
    ])?)))
}

/// Returns the permission table rows the manifest implies.
///
/// The governor administers association set writes, so the rows it needs are
/// the two association sets' mutating entry points.
pub fn permission_rows(config: &ContractConfig) -> Vec<(String, String)> {
    vec![
        (config.asp_membership.clone(), "insert_leaf".to_owned()),
        (config.asp_non_membership.clone(), "insert_leaf".to_owned()),
        (config.asp_non_membership.clone(), "delete_leaf".to_owned()),
    ]
}

/// Returns the nullifier a pool event records, or `None` for another event.
///
/// # Errors
///
/// Returns an error if the event names a nullifier that is not a `u256`.
pub fn nullifier_from_event(topics: &[String]) -> Result<Option<[u8; 32]>> {
    let decode = |b64: &String| -> Result<xdr::ScVal> {
        xdr::ScVal::from_xdr_base64(b64, Limits::none()).context("decode event topic")
    };
    let Some(name) = topics.first().map(decode).transpose()? else {
        return Ok(None);
    };
    if !matches!(&name, xdr::ScVal::Symbol(s) if s.to_string() == NULLIFIER_EVENT) {
        return Ok(None);
    }
    let value = topics
        .get(1)
        .ok_or_else(|| anyhow!("{NULLIFIER_EVENT} carries no nullifier topic"))?;
    u256_bytes(&decode(value)?).map(Some)
}

/// Reads every nullifier the pools published since `cursor`, keyed by the pool
/// that published it, and the cursor to resume from.
///
/// All pools are paged together, because an event cursor is a position in the
/// ledger rather than in one contract's history: resuming a second contract
/// from the first one's cursor would skip its events entirely.
///
/// Reads through `bootnode` first, because public RPC keeps events for about a
/// week and a pool's history is longer than that, and falls back to `rpc` when
/// the bootnode refuses the range.
///
/// # Errors
///
/// Returns an error if both endpoints refuse the range, or if an event carries
/// a nullifier that is not a `u256`.
pub async fn nullifiers_since(
    bootnode: &Client,
    rpc: &Client,
    pools: &[(String, u32)],
    cursor: Option<String>,
) -> Result<(BTreeMap<String, Vec<[u8; 32]>>, Option<String>)> {
    let contracts: Vec<String> = pools.iter().map(|(id, _)| id.clone()).collect();
    let start_ledger = pools.iter().map(|(_, from)| *from).min().unwrap_or(0);
    let mut nullifiers: BTreeMap<String, Vec<[u8; 32]>> = BTreeMap::new();
    let mut page_cursor = cursor;
    let mut on_bootnode = true;

    loop {
        let client = if on_bootnode { bootnode } else { rpc };
        let page = client
            .get_contract_events(
                &contracts,
                start_ledger,
                EVENT_PAGE_SIZE,
                page_cursor.clone(),
            )
            .await;
        let (next, events, _) = match page {
            Ok(page) => page,
            // The bootnode's own error type is not reachable from here, so a
            // handoff and an unreachable bootnode look alike. Warn rather than
            // fall back quietly: past its retention window the RPC answers
            // with fewer events, not an error.
            Err(e) if on_bootnode => {
                tracing::warn!(error = %e, "bootnode_events_unavailable_falling_back_to_rpc");
                on_bootnode = false;
                continue;
            }
            Err(e) => return Err(e).context("read pool events"),
        };

        for event in &events {
            if let Some(nullifier) = nullifier_from_event(&event.topic)? {
                nullifiers
                    .entry(event.contract_id.clone())
                    .or_default()
                    .push(nullifier);
            }
        }
        if events.is_empty() || next.is_none() {
            return Ok((nullifiers, next.or(page_cursor)));
        }
        page_cursor = next;
    }
}

/// Reads the values of `keys`, keyed by their base64 XDR form.
///
/// A key the ledger no longer holds is absent from the result.
///
/// # Errors
///
/// Returns an error if the RPC refuses the request or an entry does not decode.
pub async fn read_values(
    client: &Client,
    keys: &[LedgerKey],
) -> Result<BTreeMap<String, xdr::ScVal>> {
    let mut values = BTreeMap::new();

    // The RPC refuses a request naming more than `LEDGER_KEY_CHUNK` keys, and
    // the sparse tree's frontier grows with the size of the blocklist.
    for chunk in keys.chunks(LEDGER_KEY_CHUNK) {
        let response = client
            .get_ledger_entries(chunk)
            .await
            .context("read contract data")?;

        for entry in response.entries.unwrap_or_default() {
            let data = xdr::LedgerEntryData::from_xdr_base64(&entry.xdr, Limits::none())
                .context("decode ledger entry")?;
            if let xdr::LedgerEntryData::ContractData(contract_data) = data {
                values.insert(entry.key, contract_data.val);
            }
        }
    }
    Ok(values)
}

async fn read_value(client: &Client, key: &LedgerKey) -> Result<Option<xdr::ScVal>> {
    let encoded = key.to_xdr_base64(Limits::none())?;
    Ok(read_values(client, std::slice::from_ref(key))
        .await?
        .remove(&encoded))
}

/// Looks an already read entry up by its key.
///
/// # Errors
///
/// Returns an error if the key does not encode.
fn fetched<'a>(
    values: &'a BTreeMap<String, xdr::ScVal>,
    key: &LedgerKey,
) -> Result<Option<&'a xdr::ScVal>> {
    Ok(values.get(&key.to_xdr_base64(Limits::none())?))
}

/// Returns the `u32` a contract stores under `variant`, or `None` when the
/// ledger no longer holds it.
///
/// An absent entry is the state the keeper exists to repair, so it is not an
/// error: raising here would abort the round that would have restored it, for
/// every contract in the deployment.
///
/// # Errors
///
/// Returns an error if the entry is present but is not a `u32`.
fn fetched_u32(
    values: &BTreeMap<String, xdr::ScVal>,
    key: &LedgerKey,
    what: &str,
) -> Result<Option<u32>> {
    match fetched(values, key)? {
        Some(xdr::ScVal::U32(value)) => Ok(Some(*value)),
        Some(other) => bail!("{what} is {other:?}, expected a u32"),
        None => Ok(None),
    }
}

/// Builds the key of the tree depth a pool or a membership provider stores.
///
/// # Errors
///
/// Returns an error if the variant is too long to be a Soroban symbol.
fn levels_key(contract: &xdr::ScAddress) -> Result<LedgerKey> {
    data_key(contract, "Levels", vec![])
}

/// Builds the key of the governor's list of queued operation hashes.
///
/// # Errors
///
/// Returns an error if the variant is too long to be a Soroban symbol.
fn pending_key(governor: &xdr::ScAddress) -> Result<LedgerKey> {
    data_key(governor, "Pending", vec![])
}

/// Builds the key of how many addresses hold `role`.
///
/// # Errors
///
/// Returns an error if `role` is too long to be a Soroban symbol.
fn role_count_key(governor: &xdr::ScAddress, role: &str) -> Result<LedgerKey> {
    data_key(governor, "RoleAccountsCount", vec![symbol(role)?])
}

/// Returns the wasm hash a contract instance runs, or `None` when the instance
/// is absent or runs a built-in contract rather than uploaded wasm.
///
/// # Errors
///
/// Returns an error if the value is not a contract instance.
fn instance_wasm(value: Option<&xdr::ScVal>) -> Result<Option<xdr::Hash>> {
    match value {
        None => Ok(None),
        Some(xdr::ScVal::ContractInstance(instance)) => match &instance.executable {
            xdr::ContractExecutable::Wasm(hash) => Ok(Some(hash.clone())),
            xdr::ContractExecutable::StellarAsset => Ok(None),
        },
        Some(other) => bail!("contract instance is {other:?}"),
    }
}

/// Returns every contract the manifest names.
fn manifest_contracts(config: &ContractConfig) -> impl Iterator<Item = &str> {
    config
        .enabled_pools()
        .map(|pool| pool.pool_contract_id.as_str())
        .chain([
            config.asp_membership.as_str(),
            config.asp_non_membership.as_str(),
            config.public_key_registry.as_str(),
        ])
        .chain(config.verifiers.values().map(String::as_str))
        .chain(config.governance.iter().map(|g| g.governor.as_str()))
}

/// Walks the non-membership tree and returns every node it holds.
///
/// The sparse tree names its nodes only inside its own stored values, so the
/// walk fetches one level at a time until no child is left to read.
///
/// # Errors
///
/// Returns an error if a node value does not decode.
pub async fn non_membership_nodes(
    client: &Client,
    contract: &xdr::ScAddress,
) -> Result<Vec<[u8; 32]>> {
    let Some(root_value) = read_value(client, &data_key(contract, "Root", vec![])?).await? else {
        return Ok(Vec::new());
    };
    let root = u256_bytes(&root_value)?;

    let mut children: BTreeMap<[u8; 32], Vec<[u8; 32]>> = BTreeMap::new();
    let mut frontier = vec![root];

    while !frontier.is_empty() {
        let node_keys = frontier
            .iter()
            .map(|node| data_key(contract, "Node", vec![u256(*node)]))
            .collect::<Result<Vec<_>>>()?;
        let values = read_values(client, &node_keys).await?;

        let mut next = Vec::new();
        for (node, key) in frontier.iter().zip(node_keys.iter()) {
            let encoded = key.to_xdr_base64(Limits::none())?;
            let Some(value) = values.get(&encoded) else {
                continue;
            };
            let kids = node_children(value)?;
            next.extend(kids.iter().filter(|k| !children.contains_key(*k)).copied());
            children.insert(*node, kids);
        }
        frontier = next;
    }
    Ok(walk_sparse_tree(root, &children))
}

/// Builds every key the keeper is responsible for.
///
/// One batched read answers everything the enumeration needs: every contract's
/// instance, and the scalars a contract's key list depends on. Reading them per
/// contract would make a round's setup cost grow with the manifest, and every
/// extra call is another chance for the round to fail.
///
/// # Errors
///
/// Returns an error if the manifest holds an invalid address, if the RPC
/// refuses a read, or if an entry it returns holds a value of the wrong type.
/// A contract the ledger no longer holds is not an error: it contributes no
/// code key and the keeper restores what the RPC reports archived.
pub async fn build(
    client: &Client,
    config: &ContractConfig,
    nullifiers: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Vec<LedgerKey>> {
    let mut keys = manifest_contracts(config)
        .map(|id| Ok(instance_key(&address(id)?)))
        .collect::<Result<Vec<_>>>()?;
    keys.extend(scalar_keys(config)?);
    let values = read_values(client, &keys).await?;

    let nodes = non_membership_nodes(client, &address(&config.asp_non_membership)?).await?;

    assemble(config, nullifiers, &values, &nodes)
}

/// Returns the entries [`assemble`] looks up by value rather than by name.
///
/// # Errors
///
/// Returns an error if the manifest holds an invalid address.
fn scalar_keys(config: &ContractConfig) -> Result<Vec<LedgerKey>> {
    let mut keys = Vec::new();
    for pool in config.enabled_pools() {
        keys.push(levels_key(&address(&pool.pool_contract_id)?)?);
    }
    keys.push(levels_key(&address(&config.asp_membership)?)?);
    if let Some(governance) = &config.governance {
        let governor = address(&governance.governor)?;
        keys.push(pending_key(&governor)?);
        for role in ROLES {
            keys.push(role_count_key(&governor, role)?);
        }
    }
    Ok(keys)
}

/// Builds the key list from the manifest, the entries already read, and the
/// nodes the non-membership walk found.
///
/// # Errors
///
/// Returns an error if the manifest holds an invalid address, or an entry
/// holds a value of the wrong type.
fn assemble(
    config: &ContractConfig,
    nullifiers: &BTreeMap<String, BTreeSet<String>>,
    values: &BTreeMap<String, xdr::ScVal>,
    nodes: &[[u8; 32]],
) -> Result<Vec<LedgerKey>> {
    let mut keys = Vec::new();

    for contract_id in manifest_contracts(config) {
        let instance = instance_key(&address(contract_id)?);
        if let Some(hash) = instance_wasm(fetched(values, &instance)?)? {
            keys.push(code_key(hash));
        }
        keys.push(instance);
    }

    let empty = BTreeSet::new();
    for pool in config.enabled_pools() {
        let contract = address(&pool.pool_contract_id)?;
        // A pool whose `Levels` entry is archived still gets its fixed keys, so
        // the restore that brings the entry back can run.
        let levels = fetched_u32(values, &levels_key(&contract)?, "Levels")?.unwrap_or(0);
        let spent = nullifiers.get(&pool.pool_contract_id).unwrap_or(&empty);
        keys.extend(pool_keys(&contract, levels, spent)?);
    }

    let membership = address(&config.asp_membership)?;
    let levels = fetched_u32(values, &levels_key(&membership)?, "Levels")?.unwrap_or(0);
    keys.extend(membership_keys(&membership, levels)?);

    keys.extend(non_membership_keys(
        &address(&config.asp_non_membership)?,
        nodes,
    )?);

    if let Some(governance) = &config.governance {
        let governor = address(&governance.governor)?;
        let pending = match fetched(values, &pending_key(&governor)?)? {
            Some(xdr::ScVal::Vec(Some(ids))) => ids
                .iter()
                .map(|id| match id {
                    xdr::ScVal::Bytes(bytes) => bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow!("operation id is not 32 bytes")),
                    other => Err(anyhow!("operation id is {other:?}")),
                })
                .collect::<Result<Vec<[u8; 32]>>>()?,
            _ => Vec::new(),
        };
        let mut role_members = Vec::with_capacity(ROLES.len());
        for role in ROLES {
            let count = fetched_u32(values, &role_count_key(&governor, role)?, role)?;
            role_members.push((role.to_owned(), count.unwrap_or(0)));
        }

        keys.extend(governor_keys(
            governance,
            &pending,
            &permission_rows(config),
            &role_members,
        )?);
    }

    // Two contracts that run the same wasm name the same code key, and a
    // footprint that lists one key twice is refused.
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POOL: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn internal(left: [u8; 32], right: [u8; 32]) -> xdr::ScVal {
        xdr::ScVal::Vec(Some(
            xdr::ScVec::try_from(vec![u256(left), u256(right)]).expect("vec"),
        ))
    }

    #[test]
    fn the_pool_key_list_covers_the_whole_root_ring() {
        let contract = address(POOL).expect("address");
        let keys = pool_keys(&contract, 3, &BTreeSet::new()).expect("keys");

        // 13 enum keys, then FilledSubtree and Zeroes for levels 0 to 3, then
        // the 90 root slots.
        assert_eq!(keys.len(), 111);
        assert!(
            keys.contains(&data_key(&contract, "Root", vec![xdr::ScVal::U32(89)]).expect("89"))
        );
        assert!(
            !keys.contains(&data_key(&contract, "Root", vec![xdr::ScVal::U32(90)]).expect("90"))
        );
    }

    #[test]
    fn a_nullifier_becomes_a_valued_pool_key() {
        let contract = address(POOL).expect("address");
        let spent = BTreeSet::from([bytes_to_hex(&hash(7))]);
        let keys = pool_keys(&contract, 1, &spent).expect("keys");

        assert!(
            keys.contains(&data_key(&contract, "Nullifier", vec![u256(hash(7))]).expect("key"))
        );
    }

    #[test]
    fn the_sparse_tree_walk_visits_every_node_once_and_stops_at_zero_children() {
        // root -> (a, b); a -> (c, zero); b is a leaf; c has no stored value.
        let (root, a, b, c) = (hash(1), hash(2), hash(3), hash(4));
        let children = BTreeMap::from([(root, vec![a, b]), (a, vec![c]), (b, Vec::new())]);

        let mut visited = walk_sparse_tree(root, &children);
        visited.sort_unstable();
        assert_eq!(visited, vec![root, a, b, c]);
    }

    #[test]
    fn a_zero_root_walks_to_nothing() {
        assert!(walk_sparse_tree([0u8; 32], &BTreeMap::new()).is_empty());
    }

    #[test]
    fn a_leaf_names_no_children_and_a_zero_child_is_skipped() {
        let leaf = xdr::ScVal::Vec(Some(
            xdr::ScVec::try_from(vec![u256(hash(1)), u256(hash(2)), xdr::ScVal::U32(1)])
                .expect("vec"),
        ));
        assert!(node_children(&leaf).expect("leaf").is_empty());
        assert_eq!(
            node_children(&internal(hash(5), [0u8; 32])).expect("internal"),
            vec![hash(5)]
        );
    }

    #[test]
    fn a_nullifier_event_decodes_and_an_unrelated_event_is_skipped() {
        let topic = |value: &xdr::ScVal| {
            value
                .to_xdr_base64(Limits::none())
                .expect("encode event topic")
        };
        let name = |text: &str| topic(&symbol(text).expect("symbol"));

        let spent = vec![name(NULLIFIER_EVENT), topic(&u256(hash(9)))];
        assert_eq!(nullifier_from_event(&spent).expect("decode"), Some(hash(9)));

        let other = vec![name("new_commitment_event"), topic(&xdr::ScVal::U32(1))];
        assert_eq!(nullifier_from_event(&other).expect("decode"), None);
        assert_eq!(nullifier_from_event(&[]).expect("decode"), None);
    }

    /// The governor's storage keys as OpenZeppelin encodes them, in lowercase
    /// hexadecimal XDR.
    ///
    /// The same five constants appear in `contracts/governor/src/test.rs`,
    /// asserted there against the key types themselves. This crate cannot see
    /// those types, so the pair of tests is what ties the variant names below
    /// to the contract: a rename upstream fails the contract's test, and a
    /// wrong name here fails this one.
    const EXISTING_ROLES_XDR: &str = concat!(
        "0000001000000001000000010000000f0000000d4578697374696e67526f6c65",
        "73000000",
    );
    const HAS_ROLE_XDR: &str = concat!(
        "0000001000000001000000030000000f00000007486173526f6c650000000012",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000f00000008677561726469616e",
    );
    const ROLE_ACCOUNTS_COUNT_XDR: &str = concat!(
        "0000001000000001000000020000000f00000011526f6c654163636f756e7473",
        "436f756e740000000000000f00000008677561726469616e",
    );
    const ROLE_ACCOUNTS_XDR: &str = concat!(
        "0000001000000001000000020000000f0000000c526f6c654163636f756e7473",
        "0000001100000001000000020000000f00000005696e64657800000000000003",
        "000000000000000f00000004726f6c650000000f00000008677561726469616e",
    );
    const OPERATION_LEDGER_XDR: &str = concat!(
        "0000001000000001000000020000000f0000000f4f7065726174696f6e4c6564",
        "676572000000000d000000200707070707070707070707070707070707070707",
        "070707070707070707070707",
    );
    /// The role holder the pinned `HasRole` and `RoleAccounts` keys name.
    const PINNED_HOLDER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    /// Returns the hexadecimal XDR of the value a contract-data key holds.
    fn key_hex(key: &LedgerKey) -> String {
        match key {
            LedgerKey::ContractData(data) => hex::encode(
                data.key
                    .to_xdr(Limits::none())
                    .expect("encode a contract data key"),
            ),
            _ => panic!("not a contract data key"),
        }
    }

    #[test]
    fn the_openzeppelin_key_encodings_are_pinned() {
        let governor =
            address("CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE").expect("governor");
        let holder = xdr::ScVal::Address(address(PINNED_HOLDER).expect("holder"));
        let guardian = symbol("guardian").expect("role");
        let operation = xdr::ScVal::Bytes(xdr::ScBytes(
            hash(7).to_vec().try_into().expect("operation id"),
        ));

        for (key, expected) in [
            (
                data_key(&governor, "ExistingRoles", vec![]).expect("roles"),
                EXISTING_ROLES_XDR,
            ),
            (
                data_key(&governor, "HasRole", vec![holder, guardian.clone()]).expect("has role"),
                HAS_ROLE_XDR,
            ),
            (
                data_key(&governor, "RoleAccountsCount", vec![guardian]).expect("count"),
                ROLE_ACCOUNTS_COUNT_XDR,
            ),
            (
                data_key(
                    &governor,
                    "RoleAccounts",
                    vec![role_account_key("guardian", 0).expect("member")],
                )
                .expect("accounts"),
                ROLE_ACCOUNTS_XDR,
            ),
            (
                data_key(&governor, "OperationLedger", vec![operation]).expect("ledger"),
                OPERATION_LEDGER_XDR,
            ),
        ] {
            assert_eq!(key_hex(&key), expected);
        }
    }

    #[test]
    fn the_governor_key_list_covers_the_openzeppelin_entries() {
        let governance: GovernanceConfig = serde_json::from_str(
            r#"{
                "governor": "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE",
                "council": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "operator": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "guardian": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "recovery": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "ttlKeeper": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "delay": 1, "recoveryDelay": 2, "grace": 3, "guardianPause": 4
            }"#,
        )
        .expect("governance block");
        let governor = address(&governance.governor).expect("address");
        let operation = hash(5);

        let keys = governor_keys(&governance, &[operation], &[], &[("council".to_owned(), 2)])
            .expect("keys");

        let bytes = xdr::ScVal::Bytes(xdr::ScBytes(operation.to_vec().try_into().expect("bytes")));
        for expected in [
            data_key(&governor, "ExistingRoles", vec![]).expect("roles"),
            data_key(&governor, "OperationLedger", vec![bytes]).expect("ledger"),
            data_key(
                &governor,
                "RoleAccounts",
                vec![role_account_key("council", 1).expect("member")],
            )
            .expect("accounts"),
        ] {
            assert!(keys.contains(&expected));
        }
    }

    fn manifest_with_governance() -> ContractConfig {
        serde_json::from_str(
            r#"{
                "network": "testnet",
                "deployer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "admin": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "asp_membership": "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE",
                "asp_non_membership": "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE",
                "verifiers": {},
                "public_key_registry": "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE",
                "pools": [],
                "governance": {
                    "governor": "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE",
                    "council": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "operator": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "guardian": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "recovery": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "ttlKeeper": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "delay": 1, "recoveryDelay": 2, "grace": 3, "guardianPause": 4
                }
            }"#,
        )
        .expect("manifest")
    }

    /// Keys a contract writes only under some conditions are enumerated all
    /// the same: the RPC reports which exist, and an absent one costs nothing.
    #[test]
    fn conditionally_written_governor_keys_are_enumerated() {
        let config = manifest_with_governance();
        let governance = config.governance.as_ref().expect("governance");
        let governor = address(&governance.governor).expect("address");

        let listed = governor_keys(
            governance,
            &[],
            &permission_rows(&config),
            &[("operator".to_owned(), 0)],
        )
        .expect("keys");

        for expected in [
            data_key(&governor, "Pending", vec![]).expect("pending"),
            data_key(
                &governor,
                "FnRole",
                vec![
                    xdr::ScVal::Address(address(&config.asp_membership).expect("asp")),
                    symbol("insert_leaf").expect("symbol"),
                ],
            )
            .expect("row"),
            data_key(
                &governor,
                "HasRole",
                vec![
                    xdr::ScVal::Address(address(&governance.operator).expect("operator")),
                    symbol("operator").expect("symbol"),
                ],
            )
            .expect("operator role"),
        ] {
            assert!(listed.contains(&expected));
        }
    }

    /// An archived `Levels` entry is the state the keeper exists to repair, so
    /// the pool still contributes its fixed keys and the restore can name them.
    #[test]
    fn a_pool_whose_levels_entry_is_gone_still_yields_its_fixed_keys() {
        let contract = address(POOL).expect("address");
        let keys = pool_keys(&contract, 0, &BTreeSet::new()).expect("keys");

        for variant in ["Admin", "Levels", "NextIndex", "CurrentRootIndex"] {
            assert!(keys.contains(&data_key(&contract, variant, vec![]).expect("key")));
        }
    }

    /// Two pools of the same deployment run byte-identical wasm, so they name
    /// one `LedgerKeyContractCode`. A footprint that lists a key twice is
    /// refused, and the extend and restore counters would double-count it.
    #[test]
    fn one_wasm_shared_by_two_contracts_yields_one_code_key() {
        let hash = xdr::Hash([4u8; 32]);
        let mut keys = vec![
            instance_key(&address(POOL).expect("address")),
            code_key(hash.clone()),
            code_key(hash),
        ];
        keys.sort_unstable();
        keys.dedup();

        let code = keys
            .iter()
            .filter(|k| matches!(k, LedgerKey::ContractCode(_)))
            .count();
        assert_eq!(code, 1);
        assert_eq!(keys.len(), 2);
    }

    const POOL_A: &str = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526";
    const POOL_B: &str = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
    const MEMBERSHIP: &str = "CABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGCK3";
    const NON_MEMBERSHIP: &str = "CACAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAINCW";
    const REGISTRY: &str = "CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U";
    const GOVERNOR: &str = "CADAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMSST";
    const WASM: [u8; 32] = [9u8; 32];
    const POOL_A_LEVELS: u32 = 2;
    const POOL_B_LEVELS: u32 = 5;
    const MEMBERSHIP_LEVELS: u32 = 7;
    const COUNCIL_MEMBERS: u32 = 2;

    fn two_pools_with_governance() -> ContractConfig {
        let pool = |id: &str, ledger: u32| {
            format!(
                r#"{{"poolContractId": "{id}", "tokenContractId": "{POOL_A}",
                     "deploymentLedger": {ledger}, "enabled": true,
                     "policyFlags": [], "asset": {{"kind": "native"}}}}"#
            )
        };
        serde_json::from_str(&format!(
            r#"{{
                "network": "testnet",
                "deployer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "admin": "{GOVERNOR}",
                "asp_membership": "{MEMBERSHIP}",
                "asp_non_membership": "{NON_MEMBERSHIP}",
                "verifiers": {{}},
                "public_key_registry": "{REGISTRY}",
                "pools": [{}, {}],
                "governance": {{
                    "governor": "{GOVERNOR}",
                    "council": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "operator": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "guardian": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "recovery": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "ttlKeeper": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                    "delay": 1, "recoveryDelay": 2, "grace": 3, "guardianPause": 4
                }}
            }}"#,
            pool(POOL_A, 1),
            pool(POOL_B, 2),
        ))
        .expect("manifest")
    }

    /// The entries the two batched reads bring back: one instance per contract,
    /// one `Levels` per tree, and the governor's queue and role counts.
    fn stored_entries(config: &ContractConfig) -> BTreeMap<String, xdr::ScVal> {
        let encode = |key: LedgerKey| key.to_xdr_base64(Limits::none()).expect("encode key");
        let instance = xdr::ScVal::ContractInstance(xdr::ScContractInstance {
            executable: xdr::ContractExecutable::Wasm(xdr::Hash(WASM)),
            storage: None,
        });

        let mut values = BTreeMap::new();
        for contract_id in manifest_contracts(config) {
            let contract = address(contract_id).expect("address");
            values.insert(encode(instance_key(&contract)), instance.clone());
        }

        // Stored under the very keys `build` reads, so a lookup in `assemble`
        // that names a different key finds nothing and the assembled
        // list comes out short. The three role counts the zip leaves
        // out are the ones a governor with one council holder never
        // wrote.
        let operation = xdr::ScVal::Bytes(xdr::ScBytes(
            hash(5).to_vec().try_into().expect("operation id"),
        ));
        let scalars = scalar_keys(config).expect("scalar keys");
        assert_eq!(
            scalars.len(),
            8,
            "two depths, one depth, the queue, four counts"
        );
        for (key, value) in scalars.iter().zip([
            xdr::ScVal::U32(POOL_A_LEVELS),
            xdr::ScVal::U32(POOL_B_LEVELS),
            xdr::ScVal::U32(MEMBERSHIP_LEVELS),
            xdr::ScVal::Vec(Some(xdr::ScVec::try_from(vec![operation]).expect("vec"))),
            xdr::ScVal::U32(COUNCIL_MEMBERS),
        ]) {
            values.insert(encode(key.clone()), value);
        }
        values
    }

    /// Batching moved the reads, not the enumeration. The same manifest and the
    /// same stored entries still produce the union of the per-contract lists,
    /// and each tree keeps the depth its own `Levels` entry gave it.
    #[test]
    fn the_batched_reads_assemble_the_same_key_list() {
        let config = two_pools_with_governance();
        let values = stored_entries(&config);
        let nodes = [hash(8)];

        let built = assemble(&config, &BTreeMap::new(), &values, &nodes).expect("assemble");

        let mut expected = vec![code_key(xdr::Hash(WASM))];
        for contract_id in manifest_contracts(&config) {
            expected.push(instance_key(&address(contract_id).expect("address")));
        }
        for (contract_id, levels) in [(POOL_A, POOL_A_LEVELS), (POOL_B, POOL_B_LEVELS)] {
            let contract = address(contract_id).expect("address");
            expected.extend(pool_keys(&contract, levels, &BTreeSet::new()).expect("pool"));
        }
        expected.extend(
            membership_keys(&address(MEMBERSHIP).expect("membership"), MEMBERSHIP_LEVELS)
                .expect("membership"),
        );
        expected.extend(
            non_membership_keys(&address(NON_MEMBERSHIP).expect("non-membership"), &nodes)
                .expect("non-membership"),
        );
        let role_members = ROLES.map(|role| {
            let count = if role == "council" {
                COUNCIL_MEMBERS
            } else {
                0
            };
            (role.to_owned(), count)
        });
        expected.extend(
            governor_keys(
                config.governance.as_ref().expect("governance"),
                &[hash(5)],
                &permission_rows(&config),
                &role_members,
            )
            .expect("governor"),
        );
        expected.sort_unstable();
        expected.dedup();

        assert_eq!(built, expected);
    }

    #[test]
    fn hexadecimal_nullifiers_round_trip() {
        assert_eq!(hex_to_bytes(&bytes_to_hex(&hash(3))).expect("hex"), hash(3));
        assert!(hex_to_bytes("abcd").is_err());
    }
}
