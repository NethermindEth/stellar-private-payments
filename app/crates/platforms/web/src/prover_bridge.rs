//! Worker-backed [`Prover`] for browser main-thread pool use.

use crate::{
    protocol::{ProverWorkerRequest, ProverWorkerResponse},
    workers::prover::ProverWorker,
};
use futures::FutureExt;
use gloo_timers::future::TimeoutFuture;
use gloo_worker::oneshot::OneshotBridge;
use stellar_private_payments_sdk::{
    PoolError, PreparedProverTx, Prover, tx::flows::TransactParams,
};

const PROVE_TIMEOUT_MS: u32 = 20_000;

/// Proves transact steps in the dedicated prover web worker.
pub struct WorkerProver {
    bridge: OneshotBridge<ProverWorker>,
}

impl WorkerProver {
    pub fn new(bridge: OneshotBridge<ProverWorker>) -> Self {
        Self { bridge }
    }

    async fn request(
        &self,
        req: ProverWorkerRequest,
        timeout_ms: u32,
    ) -> Result<ProverWorkerResponse, PoolError> {
        let mut bridge = self.bridge.fork();
        let fut = bridge.run(req).fuse();
        let timeout = TimeoutFuture::new(timeout_ms).fuse();
        futures::pin_mut!(fut, timeout);

        let resp = futures::select! {
            resp = fut => resp,
            _ = timeout => {
                return Err(PoolError::Other(format!(
                    "prover worker timed out after {timeout_ms} ms"
                )));
            }
        };

        match resp {
            ProverWorkerResponse::Error(message) => {
                Err(PoolError::Other(format!("prover worker: {message}")))
            }
            other => Ok(other),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Prover for WorkerProver {
    async fn prove_transact(&self, params: TransactParams) -> Result<PreparedProverTx, PoolError> {
        match self
            .request(ProverWorkerRequest::Transact(params), PROVE_TIMEOUT_MS)
            .await?
        {
            ProverWorkerResponse::TransactPrepared(prepared) => Ok(prepared),
            other => Err(PoolError::Other(format!(
                "unexpected prover worker response: {other:?}"
            ))),
        }
    }
}
