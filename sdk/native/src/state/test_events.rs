//! Contract events as RPC serves them, for the state tests.

use crate::types::ContractEvent;
use anyhow::Result;
use stellar_xdr::{self as xdr, WriteXdr};

pub(super) fn b64(val: &xdr::ScVal) -> Result<String> {
    Ok(val.to_xdr_base64(xdr::Limits::none())?)
}

pub(super) fn symbol(s: &str) -> Result<xdr::ScVal> {
    Ok(xdr::ScVal::Symbol(xdr::ScSymbol(s.try_into()?)))
}

pub(super) fn u256(lo_lo: u64) -> xdr::ScVal {
    xdr::ScVal::U256(xdr::UInt256Parts {
        hi_hi: 0,
        hi_lo: 0,
        lo_hi: 0,
        lo_lo,
    })
}

pub(super) fn raw_event(
    id: &str,
    topics: &[xdr::ScVal],
    entries: Vec<xdr::ScMapEntry>,
) -> Result<ContractEvent> {
    Ok(ContractEvent {
        id: id.to_string(),
        ledger: 1,
        contract_id: "CPOOL".to_string(),
        topics: topics.iter().map(b64).collect::<Result<_>>()?,
        value: b64(&xdr::ScVal::Map(Some(xdr::ScMap(entries.try_into()?))))?,
    })
}

pub(super) fn commitment_event(
    id: &str,
    commitment: u64,
    entries: Vec<xdr::ScMapEntry>,
) -> Result<ContractEvent> {
    raw_event(
        id,
        &[symbol("new_commitment_event")?, u256(commitment)],
        entries,
    )
}

/// An ASP non-membership event as `contracts/asp-non-membership` emits it:
/// the name is the only topic and the fields are the data map, in key order.
pub(super) fn leaf_event(
    id: &str,
    name: &str,
    fields: &[(&str, xdr::ScVal)],
) -> Result<ContractEvent> {
    let mut entries = fields
        .iter()
        .map(|(key, val)| {
            Ok(xdr::ScMapEntry {
                key: symbol(key)?,
                val: val.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(ContractEvent {
        contract_id: "CNONMEMBERSHIP".to_string(),
        ..raw_event(id, &[symbol(name)?], entries)?
    })
}

/// An ASP membership event as `contracts/asp-membership` emits it, shaped like
/// [`leaf_event`].
pub(super) fn membership_event(
    id: &str,
    name: &str,
    fields: &[(&str, xdr::ScVal)],
) -> Result<ContractEvent> {
    Ok(ContractEvent {
        contract_id: "CMEMBERSHIP".to_string(),
        ..leaf_event(id, name, fields)?
    })
}

pub(super) fn commitment_entries(index: u32) -> Result<Vec<xdr::ScMapEntry>> {
    Ok(vec![
        xdr::ScMapEntry {
            key: symbol("encrypted_output")?,
            val: xdr::ScVal::Bytes(xdr::ScBytes::default()),
        },
        xdr::ScMapEntry {
            key: symbol("index")?,
            val: xdr::ScVal::U32(index),
        },
    ])
}
