//! Test fixtures for [`stellar_private_payments::blocking::PrivatePool`].

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::Result;
use stellar_private_payments::{
    Handle, LocalProver, LocalSigner, LocalStorage, Signer,
    blocking::{Account, Client, PrivatePool},
    types::{
        CircuitStem, ContractConfig, EncryptionPublicKey, Field, GvkMode, NoteAmount,
        NoteOwnerAddress, NotePublicKey, PolicyFlags, SignerAddress, TransferRecipient,
    },
};
use stellar_xdr::{self as xdr, Limits, WriteXdr};

use crate::seed::{self, POOL_MERKLE_LEVELS};

static NOTE_SALT: AtomicUsize = AtomicUsize::new(0);

const TEST_CONFIG_JSON: &str = r#"{
    "network": "test",
    "deployer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    "admin": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    "asp_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "asp_non_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "verifiers": {
        "AB": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
    },
    "public_key_registry": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "pools": [{
        "poolContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "tokenContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "deploymentLedger": 1,
        "enabled": true,
            "policyFlags": ["allowlist", "blocklist"],
        "asset": {"kind": "native"}
    }]
}"#;

pub const POOL_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
const ASP_MEMBERSHIP_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
const USER_ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
/// Ed25519 secret for `SigningKey::from_bytes(&[7u8; 32])` (stellar signer unit
/// tests).
const TEST_SIGNER_SECRET: &str = "SADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP54X";
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TEST_NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// The account the seeded notes belong to.
pub const OWNER_ADDRESS: &str = USER_ADDRESS;
/// The account that signs and pays in a delegated session. Owns no notes.
pub const DELEGATE_ADDRESS: &str = "GD6ROJBYLKQMOW3E7N4M2YBPUHMZD7PL65VRHRMO24BOVSBV5H3BQRSL";
/// Ed25519 secret for `SigningKey::from_bytes(&[9u8; 32])`, whose public key is
/// [`DELEGATE_ADDRESS`]. The pair must match: `LocalSigner` refuses to sign for
/// an address that is not its own key.
const DELEGATE_SIGNER_SECRET: &str = "SAEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQTDMN";
/// A third account, neither the note owner nor the signer: where a withdrawal
/// is asked to send its funds. Public key of `SigningKey::from_bytes(&[7u8;
/// 32])`.
pub const WITHDRAW_RECIPIENT_ADDRESS: &str =
    "GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57";

pub use crate::seed::TEST_NETWORK;

pub fn test_account(wallet: Option<&[u64]>) -> Result<Account> {
    Ok(test_client_and_account(wallet)?.1)
}

pub fn test_pool(wallet: Option<&[u64]>) -> Result<PrivatePool> {
    Ok(test_client_and_account(wallet)?.1.pool(POOL_CONTRACT_ID)?)
}

fn test_client_and_account(wallet: Option<&[u64]>) -> Result<(Client, Account)> {
    let client = test_client(wallet, TESTNET_RPC_URL)?;
    let account = client.account(
        NoteOwnerAddress::new(USER_ADDRESS),
        SignerAddress::new(USER_ADDRESS),
        test_signer()?,
    )?;

    Ok((client, account))
}

/// A session whose note owner and signer are two different accounts: the notes
/// are seeded under [`OWNER_ADDRESS`], and [`DELEGATE_ADDRESS`] signs and pays.
///
/// The client talks to [`stub_rpc_url`], so
/// [`PrivatePool::simulate`](stellar_private_payments::blocking::PrivatePool::simulate)
/// can build a real envelope without a network.
pub fn delegated_test_client_and_account(wallet: Option<&[u64]>) -> Result<(Client, Account)> {
    let client = test_client(wallet, stub_rpc_url())?;
    let account = client.account(
        NoteOwnerAddress::new(OWNER_ADDRESS),
        SignerAddress::new(DELEGATE_ADDRESS),
        delegate_signer()?,
    )?;

    Ok((client, account))
}

fn test_client(wallet: Option<&[u64]>, rpc_url: &str) -> Result<Client> {
    static RUN: AtomicUsize = AtomicUsize::new(0);
    let db_path = std::env::temp_dir().join(format!(
        "stellar-sdk-test-{}-{}.sqlite",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed),
    ));
    let _ = std::fs::remove_file(&db_path);

    let amounts: Vec<u64> = wallet.unwrap_or_default().to_vec();
    seed::seed_prove_wallet(
        &db_path,
        POOL_CONTRACT_ID,
        ASP_MEMBERSHIP_CONTRACT_ID,
        USER_ADDRESS,
        TEST_NETWORK,
        &amounts,
    )?;

    let storage_path = db_path.to_string_lossy().into_owned();
    let storage = LocalStorage::open(&storage_path)?;
    let artifacts = test_prover_artifacts()?;
    let stem = CircuitStem::transact(
        PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST,
        GvkMode::Off,
    );
    let prover = Handle::from_box(Box::new(LocalProver::from_artifacts(&[(stem, artifacts)])?)
        as Box<dyn stellar_private_payments::Prover>);
    let contract_config: ContractConfig = serde_json::from_str(TEST_CONFIG_JSON)?;
    let mut client = Client::init(rpc_url, storage, prover, contract_config, None)?;
    // Mode flip only — tests do not run the indexer loop.
    #[allow(unused_must_use)]
    {
        let _ = client.background_sync()?;
    }

    Ok(client)
}

pub fn test_recipient() -> TransferRecipient {
    TransferRecipient::keys(
        NotePublicKey::parse("0x0000000000000000000000000000000000000000000000000000000000000001")
            .expect("note public key"),
        EncryptionPublicKey::parse(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        )
        .expect("encryption public key"),
    )
}

fn test_signer() -> Result<Handle<dyn Signer>> {
    local_signer(TEST_SIGNER_SECRET, USER_ADDRESS)
}

/// A signer bound to [`DELEGATE_ADDRESS`], holding that account's own key.
pub fn delegate_signer() -> Result<Handle<dyn Signer>> {
    local_signer(DELEGATE_SIGNER_SECRET, DELEGATE_ADDRESS)
}

fn local_signer(secret: &str, address: &str) -> Result<Handle<dyn Signer>> {
    Ok(Handle::from_box(Box::new(LocalSigner::new(
        secret,
        TEST_NETWORK_PASSPHRASE,
        SignerAddress::new(address),
    )?) as Box<dyn Signer>))
}

/// A stand-in for the two RPC calls `PrivatePool::simulate` makes: one canned
/// reply each, since `get_account` does not check that the entry it is handed
/// belongs to the address it asked for. One listener per test binary.
fn stub_rpc_url() -> &'static str {
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub rpc");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("stub rpc local address")
        );
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let _ = serve_stub_rpc(stream);
                });
            }
        });
        url
    })
}

/// Answers one JSON-RPC request, chosen by the method name in the body.
fn serve_stub_rpc(mut stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    let result = if String::from_utf8_lossy(&body).contains("getLedgerEntries") {
        stub_account_entry_result()
    } else {
        stub_simulation_result()
    };
    let payload = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len(),
    )?;
    stream.flush()
}

/// One `getLedgerEntries` entry: an account sitting at sequence 41.
fn stub_account_entry_result() -> String {
    let entry = xdr::LedgerEntryData::Account(xdr::AccountEntry {
        account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
            [0u8; 32],
        ))),
        balance: 0,
        seq_num: xdr::SequenceNumber(41),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: xdr::String32::default(),
        thresholds: xdr::Thresholds([1, 0, 0, 0]),
        signers: xdr::VecM::default(),
        ext: xdr::AccountEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())
    .expect("account ledger entry xdr");
    serde_json::json!({
        "entries": [{"key": "", "xdr": entry, "lastModifiedLedgerSeq": 1}],
        "latestLedger": 1,
    })
    .to_string()
}

/// A successful `simulateTransaction`: no auth entries, no footprint, a fee.
fn stub_simulation_result() -> String {
    let transaction_data = xdr::SorobanTransactionData {
        ext: xdr::SorobanTransactionDataExt::V0,
        resources: xdr::SorobanResources {
            footprint: xdr::LedgerFootprint {
                read_only: xdr::VecM::default(),
                read_write: xdr::VecM::default(),
            },
            instructions: 0,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 0,
    }
    .to_xdr_base64(Limits::none())
    .expect("soroban transaction data xdr");
    serde_json::json!({
        "latestLedger": 1,
        "results": [{"auth": []}],
        "transactionData": transaction_data,
        "minResourceFee": "100",
    })
    .to_string()
}

fn test_prover_artifacts() -> Result<stellar_private_payments::types::ProverArtifacts> {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let circuits = repo.join("target/circuits-artifacts");
    let keys = repo.join("deployments/testnet/circuit_keys");
    Ok(stellar_private_payments::types::ProverArtifacts {
        proving_key: std::fs::read(keys.join("policy_tx_2_2_AB_proving_key.bin"))?,
        circuit_graph: std::fs::read(keys.join("policy_tx_2_2_AB.graph.bin"))?,
        circuit_r1cs: std::fs::read(circuits.join("policy_tx_2_2_AB.r1cs"))?,
    })
}

#[allow(dead_code)]
fn test_note(amount: u64) -> (Field, NoteAmount) {
    let amount = NoteAmount::from(u128::from(amount));
    let salt = NOTE_SALT.fetch_add(1, Ordering::Relaxed);
    let commitment_value = u128::from(amount)
        .checked_add(1_000)
        .and_then(|base| base.checked_add(salt as u128))
        .expect("test note commitment value overflow");
    (Field::from(NoteAmount::from(commitment_value)), amount)
}

#[allow(dead_code)]
pub const TEST_POOL_MERKLE_LEVELS: u32 = POOL_MERKLE_LEVELS;
