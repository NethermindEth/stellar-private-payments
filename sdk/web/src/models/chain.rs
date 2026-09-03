use stellar_private_payments::types::{
    AspMembership as NativeAspMembership, AspNonMembership as NativeAspNonMembership,
    ContractsStateData as NativeContractsStateData,
    OperationalFeedItem as NativeOperationalFeedItem, PoolInfo as NativePoolInfo,
    PublicKeyEntry as NativePublicKeyEntry, RecipientLookup as NativeRecipientLookup,
};
use wasm_bindgen::prelude::*;

use super::{
    baby_jubjub_point::BabyJubJubPoint,
    convert::{encryption_public_key_hex, field_hex, note_public_key_hex, policy_flag_names},
};

#[wasm_bindgen]
pub struct PublicKeyEntry {
    inner: NativePublicKeyEntry,
}

#[wasm_bindgen]
impl PublicKeyEntry {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.inner.address.clone()
    }

    #[wasm_bindgen(getter, js_name = encryptionKey)]
    pub fn encryption_key(&self) -> String {
        encryption_public_key_hex(&self.inner.encryption_key)
    }

    #[wasm_bindgen(getter, js_name = noteKey)]
    pub fn note_key(&self) -> String {
        note_public_key_hex(&self.inner.note_key)
    }

    #[wasm_bindgen(getter)]
    pub fn ledger(&self) -> u32 {
        self.inner.ledger
    }
}

impl From<NativePublicKeyEntry> for PublicKeyEntry {
    fn from(inner: NativePublicKeyEntry) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct RecipientLookup {
    inner: NativeRecipientLookup,
}

#[wasm_bindgen]
impl RecipientLookup {
    #[wasm_bindgen(getter)]
    pub fn entry(&self) -> Option<PublicKeyEntry> {
        self.inner.entry.clone().map(PublicKeyEntry::from)
    }

    #[wasm_bindgen(getter, js_name = registryFullySynced)]
    pub fn registry_fully_synced(&self) -> bool {
        self.inner.registry_fully_synced
    }

    #[wasm_bindgen(getter, js_name = networkTipLedger)]
    pub fn network_tip_ledger(&self) -> u32 {
        self.inner.network_tip_ledger
    }

    #[wasm_bindgen(getter, js_name = registryLastFullyIndexedLedger)]
    pub fn registry_last_fully_indexed_ledger(&self) -> u32 {
        self.inner.registry_last_fully_indexed_ledger
    }
}

impl From<NativeRecipientLookup> for RecipientLookup {
    fn from(inner: NativeRecipientLookup) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct OperationalFeedItem {
    inner: NativeOperationalFeedItem,
}

#[wasm_bindgen]
impl OperationalFeedItem {
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.inner.kind.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn title(&self) -> String {
        self.inner.title.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn body(&self) -> String {
        self.inner.body.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ledger(&self) -> u32 {
        self.inner.ledger
    }

    #[wasm_bindgen(getter, js_name = contractId)]
    pub fn contract_id(&self) -> Option<String> {
        self.inner.contract_id.clone()
    }

    #[wasm_bindgen(getter, js_name = poolContractId)]
    pub fn pool_contract_id(&self) -> Option<String> {
        self.inner.pool_contract_id.clone()
    }

    #[wasm_bindgen(getter, js_name = txType)]
    pub fn tx_type(&self) -> Option<String> {
        self.inner.tx_type.clone()
    }
}

impl From<NativeOperationalFeedItem> for OperationalFeedItem {
    fn from(inner: NativeOperationalFeedItem) -> Self {
        Self { inner }
    }
}

pub(crate) fn operational_feed_items(
    values: Vec<NativeOperationalFeedItem>,
) -> Vec<OperationalFeedItem> {
    values.into_iter().map(OperationalFeedItem::from).collect()
}

#[wasm_bindgen]
pub struct AspMembership {
    inner: NativeAspMembership,
}

#[wasm_bindgen]
impl AspMembership {
    #[wasm_bindgen(getter)]
    pub fn ledger(&self) -> u32 {
        self.inner.ledger
    }

    #[wasm_bindgen(getter, js_name = contractId)]
    pub fn contract_id(&self) -> String {
        self.inner.contract_id.clone()
    }

    #[wasm_bindgen(getter, js_name = contractType)]
    pub fn contract_type(&self) -> String {
        self.inner.contract_type.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> String {
        field_hex(&self.inner.root)
    }

    #[wasm_bindgen(getter)]
    pub fn levels(&self) -> u32 {
        self.inner.levels
    }

    #[wasm_bindgen(getter, js_name = nextIndex)]
    pub fn next_index(&self) -> String {
        self.inner.next_index.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn admin(&self) -> String {
        self.inner.admin.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn capacity(&self) -> u64 {
        self.inner.capacity
    }

    #[wasm_bindgen(getter, js_name = usedSlots)]
    pub fn used_slots(&self) -> String {
        self.inner.used_slots.clone()
    }
}

impl From<NativeAspMembership> for AspMembership {
    fn from(inner: NativeAspMembership) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct AspNonMembership {
    inner: NativeAspNonMembership,
}

#[wasm_bindgen]
impl AspNonMembership {
    #[wasm_bindgen(getter)]
    pub fn ledger(&self) -> u32 {
        self.inner.ledger
    }

    #[wasm_bindgen(getter, js_name = contractId)]
    pub fn contract_id(&self) -> String {
        self.inner.contract_id.clone()
    }

    #[wasm_bindgen(getter, js_name = contractType)]
    pub fn contract_type(&self) -> String {
        self.inner.contract_type.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> String {
        field_hex(&self.inner.root)
    }

    #[wasm_bindgen(getter, js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty
    }

    #[wasm_bindgen(getter)]
    pub fn admin(&self) -> String {
        self.inner.admin.clone()
    }
}

impl From<NativeAspNonMembership> for AspNonMembership {
    fn from(inner: NativeAspNonMembership) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct PoolInfo {
    inner: NativePoolInfo,
}

#[wasm_bindgen]
impl PoolInfo {
    #[wasm_bindgen(getter)]
    pub fn ledger(&self) -> u32 {
        self.inner.ledger
    }

    #[wasm_bindgen(getter, js_name = contractId)]
    pub fn contract_id(&self) -> String {
        self.inner.contract_id.clone()
    }

    #[wasm_bindgen(getter, js_name = contractType)]
    pub fn contract_type(&self) -> String {
        self.inner.contract_type.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn admin(&self) -> String {
        self.inner.admin.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn token(&self) -> String {
        self.inner.token.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn verifier(&self) -> String {
        self.inner.verifier.clone()
    }

    #[wasm_bindgen(getter, js_name = aspMembership)]
    pub fn aspmembership(&self) -> String {
        self.inner.asp_membership.clone()
    }

    #[wasm_bindgen(getter, js_name = aspNonMembership)]
    pub fn aspnonmembership(&self) -> String {
        self.inner.asp_non_membership.clone()
    }

    #[wasm_bindgen(getter, js_name = merkleLevels)]
    pub fn merkle_levels(&self) -> u32 {
        self.inner.merkle_levels
    }

    #[wasm_bindgen(getter, js_name = merkleCurrentRootIndex)]
    pub fn merkle_current_root_index(&self) -> Option<u32> {
        self.inner.merkle_current_root_index
    }

    #[wasm_bindgen(getter, js_name = merkleNextIndex)]
    pub fn merkle_next_index(&self) -> String {
        self.inner.merkle_next_index.clone()
    }

    #[wasm_bindgen(getter, js_name = maximumDepositAmount)]
    pub fn maximum_deposit_amount(&self) -> String {
        self.inner.maximum_deposit_amount.to_string()
    }

    #[wasm_bindgen(getter, js_name = merkleRoot)]
    pub fn merkle_root(&self) -> Option<String> {
        self.inner.merkle_root.as_ref().map(field_hex)
    }

    #[wasm_bindgen(getter, js_name = merkleCapacity)]
    pub fn merkle_capacity(&self) -> u64 {
        self.inner.merkle_capacity
    }

    #[wasm_bindgen(getter, js_name = totalCommitments)]
    pub fn total_commitments(&self) -> String {
        self.inner.total_commitments.clone()
    }

    #[wasm_bindgen(getter, js_name = policyFlags)]
    pub fn policy_flags(&self) -> Vec<String> {
        policy_flag_names(self.inner.policy_flags)
    }

    #[wasm_bindgen(getter, js_name = gvkMode)]
    pub fn gvk_mode(&self) -> Option<u32> {
        self.inner.gvk_mode
    }

    #[wasm_bindgen(getter, js_name = adminViewKey)]
    pub fn admin_view_key(&self) -> Option<BabyJubJubPoint> {
        self.inner
            .admin_view_key
            .as_ref()
            .map(BabyJubJubPoint::from)
    }
}

impl From<NativePoolInfo> for PoolInfo {
    fn from(inner: NativePoolInfo) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct ContractsStateData {
    inner: NativeContractsStateData,
}

#[wasm_bindgen]
impl ContractsStateData {
    #[wasm_bindgen(getter)]
    pub fn pools(&self) -> Vec<PoolInfo> {
        self.inner
            .pools
            .iter()
            .cloned()
            .map(PoolInfo::from)
            .collect()
    }

    #[wasm_bindgen(getter, js_name = aspMembership)]
    pub fn asp_membership(&self) -> AspMembership {
        AspMembership::from(self.inner.asp_membership.clone())
    }

    #[wasm_bindgen(getter, js_name = aspNonMembership)]
    pub fn asp_non_membership(&self) -> AspNonMembership {
        AspNonMembership::from(self.inner.asp_non_membership.clone())
    }
}

impl From<NativeContractsStateData> for ContractsStateData {
    fn from(inner: NativeContractsStateData) -> Self {
        Self { inner }
    }
}
