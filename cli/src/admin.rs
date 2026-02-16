//! ASP admin commands.

use anyhow::Result;
use ark_ff::{BigInteger, PrimeField, Zero};
use zkhash::fields::bn256::FpBN256 as Scalar;

use crate::config::DeploymentConfig;
use crate::crypto;
use crate::keys;
use crate::stellar;

/// Add a member to the ASP membership tree.
///
/// Derives the member's BN254 note public key, computes the membership leaf,
/// and invokes `asp_membership.insert_leaf(leaf)`.
pub fn add_member(
    cfg: &DeploymentConfig,
    network: &str,
    account: &str,
    source: &str,
) -> Result<()> {
    // Derive the account's note public key
    let note_privkey = keys::derive_note_private_key(account, network)?;
    let note_pubkey = crypto::derive_public_key(&note_privkey);

    // Compute membership leaf: Poseidon2(note_pubkey, 0, domain=1)
    let leaf = crypto::membership_leaf(note_pubkey, Scalar::zero());

    // Convert leaf to U256 hex representation for the CLI
    let leaf_bytes = leaf.into_bigint().to_bytes_be();
    let leaf_hex = hex::encode(&leaf_bytes);

    // Invoke asp_membership.insert_leaf
    stellar::contract_invoke(
        &cfg.asp_membership,
        source,
        network,
        "insert_leaf",
        &["--leaf", &format!("0x{leaf_hex}")],
    )?;

    let pubkey_hex = hex::encode(note_pubkey.into_bigint().to_bytes_be());
    println!("Added member {account} (note pubkey: {pubkey_hex})");
    println!("Membership leaf: {leaf_hex}");

    Ok(())
}

/// Remove a member from the ASP membership tree.
///
/// Note: The ASP membership contract may not support direct removal.
/// This is a placeholder for when that functionality is available.
pub fn remove_member(
    _cfg: &DeploymentConfig,
    _network: &str,
    account: &str,
    _source: &str,
) -> Result<()> {
    anyhow::bail!("ASP membership removal not yet supported for account '{account}'. The Merkle tree contract does not have a remove_leaf function.")
}

/// Update the ASP admin address.
pub fn update_admin(
    cfg: &DeploymentConfig,
    network: &str,
    new_admin: &str,
    contract: Option<&str>,
    source: &str,
) -> Result<()> {
    let new_admin_address = stellar::keys_address(new_admin, network)?;

    let contract_id = contract.unwrap_or(&cfg.asp_membership);

    stellar::contract_invoke(
        contract_id,
        source,
        network,
        "update_admin",
        &["--new_admin", &new_admin_address],
    )?;

    println!("Admin updated to {new_admin} ({new_admin_address}) on contract {contract_id}");
    Ok(())
}
