//! Walletless synchronous selective-disclosure verification.

use anyhow::Context;

use crate::types::{ContractConfig, DisclosureReceipt, DisclosureVerificationReport};

use crate::{
    Error, Prover,
    chain::{RpcClient, StateFetcher},
    disclosure::verify_disclosure_receipt as verify_disclosure_receipt_async,
};

use super::runtime::block_on;

pub fn verify_disclosure_receipt(
    rpc_url: impl AsRef<str>,
    contract_config: ContractConfig,
    prover: &dyn Prover,
    receipt: &DisclosureReceipt,
    expected_vk_hash: &str,
) -> Result<DisclosureVerificationReport, Error> {
    let rpc = RpcClient::new(rpc_url.as_ref()).context("rpc error")?;
    let fetcher = StateFetcher::new(rpc, contract_config).context("state fetcher error")?;
    block_on(verify_disclosure_receipt_async(
        &fetcher,
        prover,
        receipt,
        expected_vk_hash,
    ))
}
