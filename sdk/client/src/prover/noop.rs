//! A [`Prover`] that proves nothing — for read-only pool sessions.
//!
//! Balance/notes/sync never touch the prover, so read-only clients can open a
//! pool with this instead of paying the [`LocalProver`](super::LocalProver)
//! cost (deserializing the proving key, compiling the circuit WASM). Any
//! attempt to actually prove returns an error rather than silently misbehaving.

use prover::flows::TransactParams;
use types::DisclosureReceipt;

use crate::{disclosure::DisclosureProveParams, error::Error, transact::PreparedProverTx};

use super::Prover;

const READ_ONLY: &str = "read-only pool session cannot prove; open a full session";

/// A no-op [`Prover`]; every proving method errors.
pub struct NoopProver;

#[async_trait::async_trait(?Send)]
impl Prover for NoopProver {
    async fn prove_transact(&self, _params: TransactParams) -> Result<PreparedProverTx, Error> {
        Err(Error::Other(READ_ONLY.into()))
    }

    async fn prove_disclosure(
        &self,
        _params: DisclosureProveParams,
    ) -> Result<DisclosureReceipt, Error> {
        Err(Error::Other(READ_ONLY.into()))
    }

    async fn verify_disclosure_proof(
        &self,
        _receipt: &DisclosureReceipt,
        _expected_vk_hash: &str,
    ) -> Result<bool, Error> {
        Err(Error::Other(READ_ONLY.into()))
    }
}
