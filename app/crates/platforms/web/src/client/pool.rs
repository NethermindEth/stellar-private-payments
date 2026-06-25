use std::rc::Rc;

use crate::workers::storage::StorageBridge;
use stellar_private_payments_sdk::PrivatePool;

pub(crate) struct PoolSession {
    pool_contract_id: String,
    user_address: String,
    network_passphrase: String,
    private_pool: Rc<PrivatePool<StorageBridge>>,
}

impl PoolSession {
    pub(crate) fn new(
        pool_contract_id: String,
        user_address: String,
        network_passphrase: String,
        private_pool: Rc<PrivatePool<StorageBridge>>,
    ) -> Self {
        Self {
            pool_contract_id,
            user_address,
            network_passphrase,
            private_pool,
        }
    }

    pub(crate) fn matches(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        network_passphrase: &str,
    ) -> bool {
        self.pool_contract_id == pool_contract_id
            && self.user_address == user_address
            && self.network_passphrase == network_passphrase
    }

    pub(crate) fn private_pool(&self) -> Rc<PrivatePool<StorageBridge>> {
        Rc::clone(&self.private_pool)
    }
}
