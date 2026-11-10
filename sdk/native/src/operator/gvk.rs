use zeroize::Zeroizing;

use crate::{
    Error, StorageHandle,
    chain::RpcClient,
    gvk::GvkAudit,
    sync::SyncHandle,
    types::{ContractConfig, Field, GvkMode, validate_gvk_authority_key},
};

/// Session for the holder of a Global View Key private key.
///
/// Open with [`crate::Client::gvk_authority`].
pub struct GvkAuthority {
    rpc: RpcClient,
    storage: StorageHandle,
    sync: SyncHandle,
    contract_config: ContractConfig,
    global_view_private_key: Zeroizing<Field>,
}

impl GvkAuthority {
    pub(crate) fn new(
        rpc: RpcClient,
        storage: StorageHandle,
        sync: SyncHandle,
        contract_config: ContractConfig,
        global_view_private_key: Field,
    ) -> Self {
        Self {
            rpc,
            storage,
            sync,
            contract_config,
            global_view_private_key: Zeroizing::new(global_view_private_key),
        }
    }

    /// Syncs local storage, then opens an audit cursor over a pool's private
    /// transacts.
    ///
    /// # Errors
    /// Returns [`Error::InvalidConfig`] before syncing when the pool is not in
    /// the deployment, is not a pool-gvk deployment, or has another authority
    /// key.
    pub async fn audit(&self, pool_contract_id: &str) -> Result<GvkAudit, Error> {
        let pool = self
            .contract_config
            .pool(pool_contract_id)
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        if pool.gvk_mode == GvkMode::Off {
            return Err(Error::InvalidConfig(format!(
                "GVK audit requires a pool-gvk deployment; {pool_contract_id} is configured with gvk_mode Off"
            )));
        }
        validate_gvk_authority_key(&self.global_view_private_key, pool)
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        self.sync
            .ensure_synced(&self.rpc, &self.storage, &self.contract_config)
            .await?;
        Ok(GvkAudit::new(
            self.storage.fork()?,
            pool_contract_id,
            *self.global_view_private_key,
        ))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::operator::test_support::{MEMBERSHIP, POOL, client};

    fn authority(dir: &tempfile::TempDir) -> GvkAuthority {
        client(dir)
            .gvk_authority(Field::ZERO)
            .expect("open authority")
    }

    #[tokio::test]
    async fn audit_refuses_a_pool_without_gvk_before_syncing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let error = authority(&dir)
            .audit(POOL)
            .await
            .err()
            .expect("a pool with gvk_mode Off has nothing to audit");
        assert!(
            matches!(&error, Error::InvalidConfig(message) if message.contains("gvk_mode Off")),
            "{error}"
        );
    }

    #[tokio::test]
    async fn audit_refuses_a_contract_that_is_not_a_pool() {
        let dir = tempfile::tempdir().expect("temp dir");
        let error = authority(&dir)
            .audit(MEMBERSHIP)
            .await
            .err()
            .expect("a tree has nothing to audit");
        assert!(
            matches!(&error, Error::InvalidConfig(message) if message.contains("not found")),
            "{error}"
        );
    }
}
