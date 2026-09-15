use crate::types::{
    ContractConfig, EncryptionPublicKey, Field, NoteOwnerAddress, NotePublicKey, PortfolioBalance,
    SignerAddress, UserNoteSummary,
};

use stellar_xdr as xdr;

use crate::chain::{
    Limits, ReadXdr, StateFetcher, TransactionEnvelope, scval_to_address_string, submit_tx,
};

use crate::{
    Error, Handle, PrivatePool, Prover, Signer, Storage,
    chain::{RpcClient, RpcError},
    sync::{SyncHandle, catch_up, confirm_tx},
    types::{PrivatePoolConfig, TransactionResult},
};

/// Stellar account session
///
/// Construct via [`crate::Client::account`].
pub struct Account<S: Storage> {
    rpc: RpcClient,
    storage: S,
    prover: Handle<dyn Prover>,
    user_address: NoteOwnerAddress,
    signer_address: SignerAddress,
    signer: Handle<dyn Signer>,
    sync: SyncHandle,
    contract_config: ContractConfig,
}

impl<S: Storage> Account<S> {
    // Bundling these into a struct would trade the lint for an indirection at
    // the only two call sites, both of which name every field explicitly.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        rpc: RpcClient,
        storage: S,
        prover: Handle<dyn Prover>,
        user_address: NoteOwnerAddress,
        signer_address: SignerAddress,
        signer: Handle<dyn Signer>,
        sync: SyncHandle,
        contract_config: ContractConfig,
    ) -> Self {
        Self {
            rpc,
            storage,
            prover,
            user_address,
            signer_address,
            signer,
            sync,
            contract_config,
        }
    }

    /// The account that owns the notes.
    pub fn user_address(&self) -> &NoteOwnerAddress {
        &self.user_address
    }

    /// The account that signs and pays. A distinct type from
    /// [`Self::user_address`] so the two cannot be confused.
    pub fn signer_address(&self) -> &SignerAddress {
        &self.signer_address
    }

    pub fn signer(&self) -> &Handle<dyn Signer> {
        &self.signer
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Catch local storage up to the current chain tip for the deployment.
    pub async fn sync(&self) -> Result<(), Error> {
        catch_up(
            &self.rpc,
            &self.storage,
            &self.contract_config,
            self.sync.bootnode_url(),
        )
        .await
    }

    /// Portfolio balances across all enabled pools in the deployment.
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn portfolio(&self) -> Result<Vec<PortfolioBalance>, Error> {
        self.ensure_synced().await?;
        self.storage
            .list_portfolio_balances(
                self.user_address.as_str(),
                &self.contract_config.portfolio_pools(),
            )
            .await
    }

    /// Locally derived note and encryption public keys for this account.
    pub async fn user_public_keys(&self) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        self.storage
            .user_public_keys(self.user_address.as_str())
            .await
    }

    /// Locally derived ASP membership blinding for this account.
    pub async fn asp_secret(&self) -> Result<Field, Error> {
        self.storage.asp_secret(self.user_address.as_str()).await
    }

    /// Derive the ASP membership tree leaf for this account's note public key.
    pub async fn derive_asp_user_leaf(&self) -> Result<Field, Error> {
        let note = self
            .storage
            .user_public_keys(self.user_address.as_str())
            .await?
            .0;
        let blinding = self.storage.asp_secret(self.user_address.as_str()).await?;
        crate::crypto::derive_asp_user_leaf(&note, &blinding)
    }

    /// Notes for this account across all pools (newest first).
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn user_notes(&self, limit: u32) -> Result<Vec<UserNoteSummary>, Error> {
        self.ensure_synced().await?;
        self.storage
            .list_user_notes(self.user_address.as_str(), limit)
            .await
    }

    /// Whether this account's public keys are registered on-chain.
    ///
    /// With [`SyncMode::Inline`], local storage is synced before reading.
    pub async fn is_registered(&self) -> Result<bool, Error> {
        self.ensure_synced().await?;
        Ok(self
            .storage
            .recipient_lookup(self.user_address.as_str(), &self.contract_config)
            .await?
            .entry
            .is_some())
    }

    /// Register this account's public keys on the deployment-wide registry.
    ///
    /// The owner is the registration: it is the registry's storage key and the
    /// address its `require_auth()` names. The signing account only sources the
    /// envelope and pays the fee, so the two may differ. On a delegated session
    /// simulation returns an auth entry keyed to the owner, and this session's
    /// [`Signer`] has to fill it as well as sign the envelope. Neither
    /// [`crate::LocalSigner`] nor the web SDK's wallet signer does: each fills
    /// only the entries for the account it signs as, so delegated registration
    /// needs a `Signer` that holds both.
    ///
    /// # Errors
    /// Returns [`Error::PayingAccountNotFound`] if the signing account does not
    /// exist on-ledger, before anything is built or signed, and
    /// [`Error::MissingAuthorization`] if the signer left the owner's auth
    /// entry empty — checked before submission, so the fee is not spent on
    /// a transaction `require_auth()` would refuse.
    pub async fn register_public_keys(
        &self,
        note_public_key: Option<NotePublicKey>,
        encryption_public_key: Option<EncryptionPublicKey>,
    ) -> Result<TransactionResult, Error> {
        let (note_pk, enc_pk) = match (note_public_key, encryption_public_key) {
            (Some(note), Some(enc)) => (note, enc),
            (None, None) => {
                self.storage()
                    .user_public_keys(self.user_address.as_str())
                    .await?
            }
            _ => {
                return Err(Error::Other(
                    "note and encryption public keys must both be provided or both omitted".into(),
                ));
            }
        };

        ensure_payer_exists(&self.rpc, &self.signer_address).await?;

        let fetcher = StateFetcher::new(self.rpc.clone(), self.contract_config.clone())
            .map_err(|e| Error::Other(format!("state fetcher: {e:#}")))?;
        let prepared = fetcher
            // The owner is the registration; the signer only pays for it.
            .prepare_register(
                &self.user_address,
                &self.signer_address,
                note_pk.0,
                enc_pk.0,
            )
            .await
            .map_err(|e| Error::Other(format!("prepare register: {e:#}")))?;
        let signed = self.signer.sign_soroban_transaction(&prepared).await?;
        let envelope = TransactionEnvelope::from_xdr_base64(&signed.signed_xdr, Limits::none())
            .map_err(|e| Error::Other(format!("invalid signed transaction xdr: {e}")))?;
        ensure_authorizations_signed(&envelope)?;
        let hash = submit_tx(fetcher.rpc(), &envelope)
            .await
            .map_err(|e| Error::Other(format!("submit register: {e:#}")))?;
        confirm_tx(fetcher.rpc(), hash).await
    }

    /// Create an owned pool session for `pool_contract_id`.
    pub fn pool(&self, pool_contract_id: impl Into<String>) -> Result<PrivatePool<S>, Error> {
        let cfg = PrivatePoolConfig {
            contract_config: self.contract_config.clone(),
            pool_contract_id: pool_contract_id.into(),
            user_address: self.user_address.clone(),
            signer_address: self.signer_address.clone(),
        };

        PrivatePool::init(
            self.rpc.clone(),
            cfg,
            self.storage.fork()?,
            self.signer.clone(),
            self.prover.clone(),
            self.sync.clone(),
        )
    }

    async fn ensure_synced(&self) -> Result<(), Error> {
        self.sync
            .ensure_synced(&self.rpc, &self.storage, &self.contract_config)
            .await
    }
}

/// Refuse to submit a transaction whose authorizations are not all filled.
///
/// A signer fills the auth entries for the accounts whose keys it holds and
/// leaves the rest empty, which the contract refuses at `require_auth()` —
/// after the fee is spent. Address credentials carry those signatures;
/// source-account credentials are covered by the envelope signature and need
/// none.
fn ensure_authorizations_signed(envelope: &TransactionEnvelope) -> Result<(), Error> {
    let TransactionEnvelope::Tx(v1) = envelope else {
        return Err(Error::Other("expected a v1 transaction envelope".into()));
    };
    for op in v1.tx.operations.iter() {
        let xdr::OperationBody::InvokeHostFunction(invoke) = &op.body else {
            continue;
        };
        for entry in invoke.auth.iter() {
            let xdr::SorobanCredentials::Address(creds) = &entry.credentials else {
                continue;
            };
            if matches!(creds.signature, xdr::ScVal::Void) {
                let address = scval_to_address_string(&xdr::ScVal::Address(creds.address.clone()))
                    .map_err(|e| Error::Other(format!("unsigned auth entry address: {e}")))?;
                return Err(Error::MissingAuthorization { address });
            }
        }
    }
    Ok(())
}

/// Refuse a transaction whose paying account is not on the network.
///
/// The payer sources every envelope, so building one reads its sequence number.
/// A Stellar account exists only once it is funded, and without this the
/// failure arrives from that read, naming neither the account nor the reason.
async fn ensure_payer_exists(rpc: &RpcClient, payer: &SignerAddress) -> Result<(), Error> {
    match rpc.get_account(payer.as_str()).await {
        Ok(_) => Ok(()),
        Err(RpcError::NotFound(..)) => Err(Error::PayingAccountNotFound {
            payer: payer.as_str().to_string(),
        }),
        Err(e) => Err(Error::Other(format!("read paying account: {e}"))),
    }
}

/// Refuse an operation that needs the note owner's own signature when the
/// session signs with a different account.
///
/// Call this only from the steps whose signature the owner alone can produce:
/// key derivation, where the signature *is* the note secret. Opening a session,
/// spending from it and registering the owner's keys are not among them — the
/// first two run entirely on the payer's signature, and registration carries
/// the owner's authorization as an auth entry instead. Exported so the
/// derivation paths outside this crate — the web SDK's and the CLI's — can hold
/// the rule rather than each restate it.
pub fn ensure_signer_is_note_owner(
    user_address: &NoteOwnerAddress,
    signer_address: &SignerAddress,
) -> Result<(), Error> {
    if signer_address.as_str() == user_address.as_str() {
        return Ok(());
    }
    Err(Error::SignerIsNotNoteOwner {
        owner: user_address.as_str().to_string(),
        signer: signer_address.as_str().to_string(),
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod delegated_registration_tests {
    use super::*;
    use crate::{
        Client, LocalSigner, LocalStorage,
        chain::{
            LocalSigner as ChainSigner, PreparedSorobanTx, auth_sign_steps, test_fixtures,
            unsigned_tx_for_signing, verify_tx,
        },
        types::SignedTransaction,
    };
    use serde_json::json;
    use stellar_strkey::ed25519;
    use stellar_xdr::{self as xdr, Limits, ReadXdr, WriteXdr};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method},
    };

    const PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const REGISTRY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
    const TX_HASH: &str = "3aeb2c48e1f3b6a1c0d5e9f2a7b4c6d8e0f1a2b3c4d5e6f708192a3b4c5d6e7f";

    fn owner() -> NoteOwnerAddress {
        NoteOwnerAddress::new(ed25519::PublicKey([1u8; 32]).to_string().as_str())
    }

    /// A payer, and a session signer holding that account's key and no other.
    fn payer() -> (SignerAddress, Handle<dyn Signer>) {
        let secret = ed25519::PrivateKey([2u8; 32]).as_unredacted().to_string();
        let address = SignerAddress::new(
            ChainSigner::from_secret(&secret)
                .expect("payer signer")
                .public_key(),
        );
        let signer = Handle::from_box(Box::new(
            LocalSigner::new(&secret, PASSPHRASE, address.clone()).expect("build signer"),
        ) as Box<dyn Signer>);
        (address, signer)
    }

    fn test_client(rpc_url: &str) -> Client<LocalStorage> {
        static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let db = std::env::temp_dir().join(format!(
            "spp-delegated-register-{}-{}.sqlite",
            std::process::id(),
            RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&db);
        Client::init_readonly(
            rpc_url,
            LocalStorage::open(db.to_string_lossy().as_ref()).expect("open storage"),
            ContractConfig {
                network: PASSPHRASE.to_string(),
                deployer: String::new(),
                admin: String::new(),
                asp_membership: String::new(),
                asp_non_membership: String::new(),
                verifiers: Default::default(),
                public_key_registry: REGISTRY.to_string(),
                pools: Vec::new(),
            },
            None,
        )
        .expect("init client")
    }

    fn account_id(address: &str) -> xdr::AccountId {
        let pk = ed25519::PublicKey::from_string(address).expect("strkey");
        xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk.0)))
    }

    async fn mount_ledger_entries(server: &MockServer, entries: serde_json::Value) {
        Mock::given(method("POST"))
            .and(body_string_contains("getLedgerEntries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "entries": entries, "latestLedger": 1 },
            })))
            .mount(server)
            .await;
    }

    /// `getLedgerEntries` answering for a funded account sitting at `seq`.
    async fn mount_funded_account(server: &MockServer, address: &str, seq: i64) {
        let entry = xdr::AccountEntry {
            account_id: account_id(address),
            balance: 100_000_000,
            seq_num: xdr::SequenceNumber(seq),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: xdr::String32::default(),
            thresholds: xdr::Thresholds([1, 0, 0, 0]),
            signers: xdr::VecM::default(),
            ext: xdr::AccountEntryExt::V0,
        };
        let key = xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
            account_id: account_id(address),
        });
        mount_ledger_entries(
            server,
            json!([{
                "key": key.to_xdr_base64(Limits::none()).expect("ledger key xdr"),
                "xdr": xdr::LedgerEntryData::Account(entry)
                    .to_xdr_base64(Limits::none())
                    .expect("ledger entry xdr"),
                "lastModifiedLedgerSeq": 1,
            }]),
        )
        .await;
    }

    /// Recording-mode simulation of `register`: the registry requires the
    /// owner's authorization, so the auth entry it returns is the owner's.
    async fn mount_simulation(server: &MockServer, owner: &NoteOwnerAddress) {
        let entry = xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                address: owner.as_str().parse().expect("owner address"),
                nonce: 7,
                signature_expiration_ledger: 0,
                signature: xdr::ScVal::Void,
            }),
            root_invocation: xdr::SorobanAuthorizedInvocation {
                function: xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
                    contract_address: REGISTRY.parse().expect("registry address"),
                    function_name: xdr::ScSymbol::try_from("register").expect("symbol"),
                    args: xdr::VecM::default(),
                }),
                sub_invocations: xdr::VecM::default(),
            },
        };
        Mock::given(method("POST"))
            .and(body_string_contains("simulateTransaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "latestLedger": 100,
                    "results": [{
                        "auth": [entry.to_xdr_base64(Limits::none()).expect("auth entry xdr")],
                    }],
                    "transactionData": test_fixtures::empty_soroban_data()
                        .to_xdr_base64(Limits::none())
                        .expect("soroban data xdr"),
                    "minResourceFee": "250",
                },
            })))
            .mount(server)
            .await;
    }

    async fn mount_submission(server: &MockServer) {
        Mock::given(method("POST"))
            .and(body_string_contains("sendTransaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "hash": TX_HASH, "status": "PENDING", "latestLedger": 100 },
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("getTransaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "status": "SUCCESS" },
            })))
            .mount(server)
            .await;
    }

    async fn request_bodies(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .expect("recorded requests")
            .into_iter()
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect()
    }

    async fn submitted_envelope(server: &MockServer) -> xdr::TransactionEnvelope {
        let body = request_bodies(server)
            .await
            .into_iter()
            .find(|b| b.contains("sendTransaction"))
            .expect("a sendTransaction call");
        let json: serde_json::Value = serde_json::from_str(&body).expect("request json");
        xdr::TransactionEnvelope::from_xdr_base64(
            json["params"]["transaction"].as_str().expect("envelope"),
            Limits::none(),
        )
        .expect("submitted envelope xdr")
    }

    fn test_keys() -> (Option<NotePublicKey>, Option<EncryptionPublicKey>) {
        (
            Some(NotePublicKey([0xAB; 32])),
            Some(EncryptionPublicKey([0xEE; 32])),
        )
    }

    /// A signer that produces both signatures a delegated registration needs:
    /// the owner's on the auth entry, then the payer's on the envelope that
    /// carries it. Neither shipped signer does this — each fills only the
    /// entries for the one account it signs as.
    struct OwnerAndPayerSigner {
        owner: ChainSigner,
        owner_as_signer: SignerAddress,
        payer: ChainSigner,
    }

    #[async_trait::async_trait(?Send)]
    impl Signer for OwnerAndPayerSigner {
        async fn sign_transaction(
            &self,
            prepared: &crate::PreparedTransaction,
        ) -> Result<SignedTransaction, Error> {
            self.sign_soroban_transaction(&prepared.soroban_tx).await
        }

        async fn sign_soroban_transaction(
            &self,
            prepared: &PreparedSorobanTx,
        ) -> Result<SignedTransaction, Error> {
            let steps = auth_sign_steps(prepared, PASSPHRASE, &self.owner_as_signer)
                .map_err(|e| Error::Other(format!("auth steps: {e:#}")))?;
            let mut signatures = Vec::with_capacity(steps.len());
            for step in &steps {
                let preimage = xdr::HashIdPreimage::from_xdr_base64(
                    &step
                        .wallet_preimage_b64()
                        .map_err(|e| Error::Other(format!("auth preimage: {e:#}")))?,
                    Limits::none(),
                )
                .map_err(|e| Error::Other(format!("auth preimage xdr: {e}")))?;
                signatures.push((
                    step.entry_index,
                    self.owner
                        .sign_auth_preimage(&preimage)
                        .map_err(|e| Error::Other(format!("sign auth preimage: {e:#}")))?,
                ));
            }

            let tx_b64 = unsigned_tx_for_signing(prepared, &self.owner_as_signer, &signatures)
                .map_err(|e| Error::Other(format!("attach owner authorization: {e:#}")))?;
            let envelope = TransactionEnvelope::from_xdr_base64(&tx_b64, Limits::none())
                .map_err(|e| Error::Other(format!("authorized tx xdr: {e}")))?;
            let signed = self
                .payer
                .sign_transaction(envelope, PASSPHRASE)
                .map_err(|e| Error::Other(format!("sign envelope: {e:#}")))?;
            Ok(SignedTransaction {
                signed_xdr: signed
                    .to_xdr_base64(Limits::none())
                    .map_err(|e| Error::Other(format!("encode signed tx xdr: {e}")))?,
            })
        }
    }

    /// The registration is the owner's and the transaction is the payer's: the
    /// owner's authorization travels as a filled auth entry inside an envelope
    /// the payer sources and signs.
    #[tokio::test]
    async fn a_delegated_registration_carries_owner_auth_and_payer_signature() {
        let owner = owner();
        let (payer, _) = payer();
        let signer = Handle::from_box(Box::new(OwnerAndPayerSigner {
            owner: ChainSigner::from_seed([1u8; 32]),
            owner_as_signer: SignerAddress::new(owner.as_str()),
            payer: ChainSigner::from_seed([2u8; 32]),
        }) as Box<dyn Signer>);

        let server = MockServer::start().await;
        mount_funded_account(&server, payer.as_str(), 41).await;
        mount_simulation(&server, &owner).await;
        mount_submission(&server).await;

        let account = test_client(&server.uri())
            .account(owner.clone(), payer.clone(), signer)
            .expect("open a delegated session");
        let (note_pk, enc_pk) = test_keys();

        let result = account
            .register_public_keys(note_pk, enc_pk)
            .await
            .expect("a payer must be able to pay for the owner's registration");
        assert_eq!(result.tx_hash, TX_HASH);

        let envelope = submitted_envelope(&server).await;
        verify_tx(&envelope, PASSPHRASE, payer.as_str(), 0)
            .expect("the envelope must carry the payer's own signature");

        let xdr::TransactionEnvelope::Tx(v1) = &envelope else {
            panic!("expected v1 envelope");
        };
        assert_eq!(v1.signatures.len(), 1, "only the payer signs the envelope");
        assert_eq!(
            v1.tx.source_account,
            xdr::MuxedAccount::Ed25519(xdr::Uint256(
                ed25519::PublicKey::from_string(payer.as_str())
                    .expect("strkey")
                    .0
            )),
            "the payer sources the envelope and pays the fee",
        );

        let xdr::OperationBody::InvokeHostFunction(invoke) = &v1.tx.operations[0].body else {
            panic!("expected invoke");
        };
        assert_eq!(invoke.auth.len(), 1);
        let xdr::SorobanCredentials::Address(creds) = &invoke.auth[0].credentials else {
            panic!("expected address credentials");
        };
        assert_eq!(
            creds.address,
            owner.as_str().parse::<xdr::ScAddress>().expect("address"),
            "the authorization the registry requires is the owner's",
        );
        assert_eq!(
            auth_signature_public_key(&creds.signature),
            ed25519::PublicKey::from_string(owner.as_str())
                .expect("strkey")
                .0,
            "the filled authorization must be signed by the owner's own key",
        );
    }

    /// The Ed25519 public key inside a filled address-credentials signature.
    fn auth_signature_public_key(signature: &xdr::ScVal) -> [u8; 32] {
        let xdr::ScVal::Vec(Some(entries)) = signature else {
            panic!("an unfilled authorization: {signature:?}");
        };
        let xdr::ScVal::Map(Some(map)) = &entries[0] else {
            panic!("expected a signature map");
        };
        for xdr::ScMapEntry { key, val } in map.iter() {
            let xdr::ScVal::Symbol(name) = key else {
                continue;
            };
            if name.to_utf8_string().expect("symbol") == "public_key" {
                let xdr::ScVal::Bytes(bytes) = val else {
                    panic!("public_key should be bytes");
                };
                return bytes.0.as_slice().try_into().expect("32-byte public key");
            }
        }
        panic!("signature map has no public_key entry");
    }

    /// The shipped signers hold one account's key, so on a delegated session
    /// the owner's auth entry comes back empty. `require_auth()` would
    /// refuse that transaction after the fee was spent.
    #[tokio::test]
    async fn a_payer_only_signer_is_stopped_before_the_transaction_is_submitted() {
        let owner = owner();
        let (payer, signer) = payer();
        let server = MockServer::start().await;
        mount_funded_account(&server, payer.as_str(), 41).await;
        mount_simulation(&server, &owner).await;
        mount_submission(&server).await;

        let account = test_client(&server.uri())
            .account(owner.clone(), payer, signer)
            .expect("open a delegated session");
        let (note_pk, enc_pk) = test_keys();

        let error = account
            .register_public_keys(note_pk, enc_pk)
            .await
            .expect_err("an unfillable authorization must not reach the network");

        match &error {
            Error::MissingAuthorization { address } => assert_eq!(address, owner.as_str()),
            other => panic!("expected MissingAuthorization, got {other:?}"),
        }

        assert!(
            !request_bodies(&server)
                .await
                .iter()
                .any(|b| b.contains("sendTransaction")),
            "a transaction the contract would refuse must not be submitted",
        );
    }

    /// A Stellar account exists once it is funded, and an absent one has no
    /// sequence number for the envelope to use.
    #[tokio::test]
    async fn an_unfunded_paying_account_is_named_before_anything_is_built() {
        let (payer, signer) = payer();
        let server = MockServer::start().await;
        mount_ledger_entries(&server, json!([])).await;

        let account = test_client(&server.uri())
            .account(owner(), payer.clone(), signer)
            .expect("open a delegated session");
        let (note_pk, enc_pk) = test_keys();

        let error = account
            .register_public_keys(note_pk, enc_pk)
            .await
            .expect_err("an account that is not on the network cannot pay");

        match &error {
            Error::PayingAccountNotFound { payer: named } => assert_eq!(named, payer.as_str()),
            other => panic!("expected PayingAccountNotFound, got {other:?}"),
        }

        // The app classifies a wallet cancellation by substring. A precondition
        // failure is not one, and must not read like one.
        let rendered = error.to_string().to_ascii_lowercase();
        for word in ["rejected", "denied", "cancelled", "canceled"] {
            assert!(
                !rendered.contains(word),
                "{word:?} would be read as a wallet cancellation: {rendered}"
            );
        }

        assert!(
            !request_bodies(&server)
                .await
                .iter()
                .any(|b| b.contains("simulateTransaction")),
            "nothing should be simulated for an account that cannot pay",
        );
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod signer_is_note_owner_tests {
    use super::*;

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const DELEGATE: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ";

    #[test]
    fn the_owner_signing_for_itself_is_accepted() {
        let result =
            ensure_signer_is_note_owner(&NoteOwnerAddress::new(OWNER), &SignerAddress::new(OWNER));
        assert!(result.is_ok());
    }

    #[test]
    fn a_delegate_signing_for_the_owner_is_refused() {
        let error = ensure_signer_is_note_owner(
            &NoteOwnerAddress::new(OWNER),
            &SignerAddress::new(DELEGATE),
        )
        .expect_err("a payer that is not the note owner must not produce an owner signature");

        match &error {
            Error::SignerIsNotNoteOwner { owner, signer } => {
                assert_eq!(owner, OWNER);
                assert_eq!(signer, DELEGATE);
            }
            other => panic!("expected SignerIsNotNoteOwner, got {other:?}"),
        }

        // Both addresses stay available to code; the rendered string redacts
        // them. Not asserted here: the reveal flag is a process global that
        // logging.rs's own tests toggle under a mutex this module cannot reach.
    }

    /// The app classifies a wallet cancellation by substring. An
    /// owner-signature refusal is not one, and must not read like one.
    #[test]
    fn the_refusal_does_not_read_as_a_wallet_cancellation() {
        let rendered = ensure_signer_is_note_owner(
            &NoteOwnerAddress::new(OWNER),
            &SignerAddress::new(DELEGATE),
        )
        .expect_err("a divergent pair must be refused")
        .to_string()
        .to_ascii_lowercase();

        for word in ["rejected", "denied", "cancelled", "canceled"] {
            assert!(
                !rendered.contains(word),
                "{word:?} would be read as a wallet cancellation: {rendered}"
            );
        }
    }

    #[test]
    fn the_comparison_is_exact() {
        // Strkeys are canonical; near-misses are different accounts.
        let owner = NoteOwnerAddress::new(OWNER);
        for near_miss in [
            OWNER.to_ascii_lowercase(),
            format!(" {OWNER}"),
            String::new(),
        ] {
            assert!(
                ensure_signer_is_note_owner(&owner, &SignerAddress::new(near_miss.as_str()))
                    .is_err(),
                "near-miss signer {near_miss:?} must be refused"
            );
        }
    }
}
