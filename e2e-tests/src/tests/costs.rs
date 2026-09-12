//! Resource costs of the contracts' entry points, measured in the test host.
//!
//! Each row of the table these tests print invokes one entry point against a
//! fresh deployment and records what the host metered for that invocation: the
//! ledger entries it touched, the entries it wrote, the bytes it wrote, the CPU
//! instructions and memory it consumed, and the rent it accrued on persistent
//! entries. The entry counts are exact for contract data, and every row pins
//! them, so a change to the storage layout shows up as a diff of the pinned
//! numbers.
//!
//! The entry count is the size of the footprint the host recorded: every
//! contract data and code key the call touched, present or absent, plus the
//! authorizer's nonce entry and the entry of the authorizing address itself.
//! Every native test contract shares one placeholder code entry, so a live
//! deployment adds one code entry per distinct Wasm beyond the first, which is
//! two for a pool call that reaches the verifier and one association set.
//!
//! Two cost terms are out of reach here. The contracts run as native test
//! contracts, so the contract's own arithmetic is not metered: the instruction
//! figures cover host work such as storage reads, XDR decoding, hashing, and
//! pairing checks. Transaction size, and with it the bandwidth and history
//! fees, is not modeled by the host at all.
//!
//! The ledger runs with mainnet's entry lifetimes: a fresh persistent entry
//! lives 120 days and the maximum lifetime is 180 days, so a call on a fresh
//! deployment extends nothing. The row that first advances the ledger 91 days
//! shows the extension burst that a deployment pays once every 150 days.
//!
//! Print the table with:
//!
//! ```bash
//! cargo test -p e2e-tests costs -- --nocapture --test-threads=1
//! ```

use super::utils::{
    ASP_MEMBERSHIP_LEVELS, GOV_DELAY, LEVELS, deploy_contracts, deploy_governed_contracts,
    prove_transaction, sync_contract_state, test_env,
};
use anyhow::Result;
use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use contract_types::Groth16Proof;
use governor::GovernorClient;
use pool::{ExtData, PoolContract, PoolContractClient, hash_ext_data, policy};
use pool_gvk::{
    PoolGvkContract, PoolGvkContractClient,
    gvk::{self, BabyJubJubPoint, GvkCiphertext},
};
use public_key_registry::{Account, PublicKeyRegistry, PublicKeyRegistryClient};
use soroban_env_host::{InvocationResources, fees::FeeConfiguration};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, IntoVal, Symbol, U256, Val, Vec, contract, contractimpl,
    crypto::bn254::{Bn254Fr, Bn254G1Affine as G1Affine, Bn254G2Affine as G2Affine},
    testutils::{Address as _, Ledger as _},
    token::StellarAssetClient,
};
use soroban_utils::{pausable, ttl::THRESHOLD};

/// Mainnet's `min_persistent_ttl`, in ledgers (120 days).
const MIN_PERSISTENT_TTL: u32 = 2_073_600;

/// Mainnet's `max_entry_ttl`, in ledgers (180 days).
const MAX_ENTRY_TTL: u32 = 3_110_400;

/// Fee settings shared by testnet and mainnet, read on 2026-09-11.
const FEES: FeeConfiguration = FeeConfiguration {
    fee_per_instruction_increment: 7,
    fee_per_disk_read_entry: 1_563,
    fee_per_write_entry: 2_500,
    fee_per_disk_read_1kb: 447,
    fee_per_write_1kb: 875,
    fee_per_historical_1kb: 4_059,
    fee_per_contract_event_1kb: 5_000,
    fee_per_transaction_size_1kb: 406,
};

/// Rent per kilobyte and ledger, at the floor both networks charge while their
/// live state stays below target.
const FEE_PER_RENT_1KB: i64 = 1_000;

/// Rent rate denominators for persistent and temporary entries.
const PERSISTENT_RENT_DENOMINATOR: i64 = 1_215;
const TEMPORARY_RENT_DENOMINATOR: i64 = 2_430;

/// Pool tree depth the deployment scripts pass.
const POOL_LEVELS: u32 = 20;
const _: () = assert!(POOL_LEVELS as usize == LEVELS);

/// Membership tree depth the deployment scripts pass.
const MEMBERSHIP_LEVELS: u32 = 10;
const _: () = assert!(MEMBERSHIP_LEVELS as usize == ASP_MEMBERSHIP_LEVELS);

/// Token units minted to the sender and to the pool before a measured call.
const FUNDING: i128 = 1_000_000;

/// Deposit and withdrawal amount of the measured calls.
const AMOUNT: i32 = 100;

/// A verifier that accepts every proof, so a measured `transact` reaches the
/// storage writes without a proving key.
///
/// The pairing check it skips is the one host cost a real verifier adds; the
/// real-proof row measures that separately.
#[contract]
struct AcceptingVerifier;

#[contractimpl]
impl AcceptingVerifier {
    pub fn verify(
        _env: Env,
        _proof: Groth16Proof,
        _public_inputs: Vec<Bn254Fr>,
    ) -> Result<bool, contract_types::Groth16Error> {
        Ok(true)
    }
}

/// What the host metered for one invocation.
struct Row {
    path: &'static str,
    resources: InvocationResources,
}

impl Row {
    fn entries(&self) -> u32 {
        self.resources.memory_read_entries
    }

    fn writes(&self) -> u32 {
        self.resources.write_entries
    }

    fn line(&self) -> String {
        let r = &self.resources;
        let fee = r.estimate_fees(
            &FEES,
            FEE_PER_RENT_1KB,
            PERSISTENT_RENT_DENOMINATOR,
            TEMPORARY_RENT_DENOMINATOR,
        );
        format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            self.path,
            r.memory_read_entries,
            r.write_entries,
            r.write_bytes,
            r.instructions,
            r.mem_bytes,
            r.persistent_entry_rent_bumps,
            r.persistent_rent_ledger_bytes,
            fee.persistent_entry_rent,
            fee.total,
        )
    }
}

const HEADER: &str = "| Path | Entries | Writes | Write bytes | Instructions | Memory | Rent bumps | Rent ledger-bytes | Rent fee | Host fee |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |";

/// Reads the resources of the last invocation on `env` into a row.
fn measure(env: &Env, path: &'static str) -> Row {
    Row {
        path,
        resources: env.cost_estimate().resources(),
    }
}

/// Creates a test environment whose ledger uses mainnet's entry lifetimes.
fn mainnet_env() -> Env {
    let env = test_env();
    env.ledger()
        .set_min_persistent_entry_ttl(MIN_PERSISTENT_TTL);
    env.ledger().set_max_entry_ttl(MAX_ENTRY_TTL);
    env.mock_all_auths();
    env
}

fn advance(env: &Env, ledgers: u32) {
    let target = env.ledger().sequence().saturating_add(ledgers);
    env.ledger().set_sequence_number(target);
}

/// A proof with well-formed curve points that the accepting verifier waves
/// through.
fn placeholder_groth16_proof(env: &Env) -> Groth16Proof {
    let mut g1 = [0u8; 64];
    g1[31] = 1;
    g1[63] = 2;
    let mut g2 = [0u8; 128];
    g2[31] = 1;
    g2[63] = 1;
    g2[95] = 1;
    g2[127] = 1;
    Groth16Proof {
        a: G1Affine::from_array(env, &g1),
        b: G2Affine::from_array(env, &g2),
        c: G1Affine::from_array(env, &g1),
    }
}

fn ext_data(env: &Env, recipient: &Address, ext_amount: i32) -> ExtData {
    ExtData {
        recipient: recipient.clone(),
        ext_amount: I256::from_i32(env, ext_amount),
        encrypted_output0: Bytes::new(env),
        encrypted_output1: Bytes::new(env),
    }
}

/// The nullifiers a measured `transact` spends, distinct per call.
fn nullifiers(env: &Env, seed: u32) -> Vec<U256> {
    soroban_sdk::vec![
        env,
        U256::from_u32(env, seed),
        U256::from_u32(env, seed.saturating_add(1)),
    ]
}

/// A pool wired to the accepting verifier, a Stellar asset token, and the two
/// association set providers, all with the deployment scripts' tree depths.
struct PoolFixture {
    env: Env,
    admin: Address,
    token: Address,
    verifier: Address,
    asp_membership: Address,
    asp_non_membership: Address,
    pool: Address,
    sender: Address,
}

impl PoolFixture {
    fn new(policy_flags: u32) -> Self {
        let env = mainnet_env();
        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(Address::generate(&env))
            .address();
        let verifier = env.register(AcceptingVerifier, ());
        let asp_membership = env.register(ASPMembership, (admin.clone(), MEMBERSHIP_LEVELS));
        let asp_non_membership = env.register(ASPNonMembership, (admin.clone(),));
        let pool = env.register(
            PoolContract,
            (
                admin.clone(),
                token.clone(),
                verifier.clone(),
                asp_membership.clone(),
                asp_non_membership.clone(),
                U256::from_u32(&env, 1_000_000),
                POOL_LEVELS,
                policy_flags,
            ),
        );
        let mint = StellarAssetClient::new(&env, &token);
        mint.mint(&sender, &FUNDING);
        mint.mint(&pool, &FUNDING);
        Self {
            env,
            admin,
            token,
            verifier,
            asp_membership,
            asp_non_membership,
            pool,
            sender,
        }
    }

    fn client(&self) -> PoolContractClient<'_> {
        PoolContractClient::new(&self.env, &self.pool)
    }

    fn roots(&self) -> (U256, U256) {
        (
            ASPMembershipClient::new(&self.env, &self.asp_membership).get_root(),
            ASPNonMembershipClient::new(&self.env, &self.asp_non_membership).get_root(),
        )
    }

    fn proof(&self, root: U256, seed: u32, ext_amount: i32) -> (pool::Proof, ExtData) {
        let ext = ext_data(&self.env, &self.sender, ext_amount);
        let (membership_root, non_membership_root) = self.roots();
        let proof = pool::Proof {
            proof: placeholder_groth16_proof(&self.env),
            root,
            input_nullifiers: nullifiers(&self.env, seed),
            output_commitment0: U256::from_u32(&self.env, seed.saturating_add(10)),
            output_commitment1: U256::from_u32(&self.env, seed.saturating_add(11)),
            public_amount: pool_core::amounts::calculate_public_amount(
                &self.env,
                I256::from_i32(&self.env, ext_amount),
            )
            .expect("amount within range"),
            ext_data_hash: hash_ext_data(&self.env, &ext),
            asp_membership_root: membership_root,
            asp_non_membership_root: non_membership_root,
        };
        (proof, ext)
    }

    /// Sends one transaction against the current root and returns the row.
    fn transact(&self, path: &'static str, seed: u32, ext_amount: i32) -> Row {
        let (proof, ext) = self.proof(self.client().get_root(), seed, ext_amount);
        self.client().transact(&proof, &ext, &self.sender);
        measure(&self.env, path)
    }
}

/// A GVK pool in view-only mode, wired like [`PoolFixture`].
fn gvk_transact_row() -> Row {
    let base = PoolFixture::new(policy::BLOCKLIST_BIT);
    let env = &base.env;
    let view_key = BabyJubJubPoint {
        x: U256::from_u32(env, 1),
        y: U256::from_u32(env, 2),
    };
    let pool = env.register(
        PoolGvkContract,
        (
            base.admin.clone(),
            base.token.clone(),
            base.verifier.clone(),
            base.asp_membership.clone(),
            base.asp_non_membership.clone(),
            U256::from_u32(env, 1_000_000),
            POOL_LEVELS,
            policy::BLOCKLIST_BIT,
            view_key,
            gvk::VIEW_ONLY,
        ),
    );
    let client = PoolGvkContractClient::new(env, &pool);
    let ext = ext_data(env, &base.sender, 0);
    let (membership_root, non_membership_root) = base.roots();
    let ciphertext = |seed: u32| GvkCiphertext {
        r: BabyJubJubPoint {
            x: U256::from_u32(env, seed),
            y: U256::from_u32(env, seed.saturating_add(1)),
        },
        c1: U256::from_u32(env, seed.saturating_add(2)),
        c2: U256::from_u32(env, seed.saturating_add(3)),
        c3: U256::from_u32(env, seed.saturating_add(4)),
    };
    let proof = pool_gvk::Proof {
        proof: placeholder_groth16_proof(env),
        root: client.get_root(),
        input_nullifiers: nullifiers(env, 1),
        output_commitment0: U256::from_u32(env, 11),
        output_commitment1: U256::from_u32(env, 12),
        public_amount: U256::from_u32(env, 0),
        ext_data_hash: hash_ext_data(env, &ext),
        asp_membership_root: membership_root,
        asp_non_membership_root: non_membership_root,
        output_gvk_ciphertexts: soroban_sdk::vec![env, ciphertext(20), ciphertext(30)],
        input_gvk_ciphertexts: Vec::new(env),
    };
    client.transact(&proof, &ext, &base.sender);
    measure(env, "pool-gvk transact, transfer, view-only")
}

fn membership_insert_row() -> Row {
    let env = mainnet_env();
    let admin = Address::generate(&env);
    let id = env.register(ASPMembership, (admin, MEMBERSHIP_LEVELS));
    ASPMembershipClient::new(&env, &id).insert_leaf(&U256::from_u32(&env, 7));
    measure(&env, "asp-membership insert_leaf, first leaf")
}

/// Inserts eight keys, then measures the ninth insert and one delete.
fn non_membership_rows() -> [Row; 2] {
    let env = mainnet_env();
    let admin = Address::generate(&env);
    let id = env.register(ASPNonMembership, (admin,));
    let client = ASPNonMembershipClient::new(&env, &id);
    for key in 1..=8u32 {
        client.insert_leaf(&U256::from_u32(&env, key), &U256::from_u32(&env, 1));
    }
    client.insert_leaf(&U256::from_u32(&env, 9), &U256::from_u32(&env, 1));
    let insert = measure(&env, "asp-non-membership insert_leaf, ninth key");
    client.delete_leaf(&U256::from_u32(&env, 3));
    let delete = measure(&env, "asp-non-membership delete_leaf, one of nine");
    [insert, delete]
}

fn registry_row() -> Row {
    let env = mainnet_env();
    let id = env.register(PublicKeyRegistry, ());
    let owner = Address::generate(&env);
    PublicKeyRegistryClient::new(&env, &id).register(&Account {
        owner,
        encryption_key: Bytes::from_array(&env, &[1u8; 32]),
        note_key: Bytes::from_array(&env, &[2u8; 32]),
    });
    measure(&env, "public-key-registry register, first registration")
}

/// Queues a pool pause from the council and executes it once ready, then
/// writes one allowlist leaf through the operator's undelayed path.
fn governor_rows() -> [Row; 3] {
    let env = mainnet_env();
    let gov = deploy_governed_contracts(&env);
    let governor = GovernorClient::new(&env, &gov.governor);
    let function = Symbol::new(&env, "pause");
    let args: Vec<Val> = soroban_sdk::vec![
        &env,
        pausable::DEPOSITS.into_val(&env),
        Option::<u32>::None.into_val(&env),
    ];
    let predecessor = BytesN::from_array(&env, &[0u8; 32]);
    let salt = BytesN::from_array(&env, &[1u8; 32]);
    governor.schedule(
        &gov.contracts.pool,
        &function,
        &args,
        &predecessor,
        &salt,
        &gov.council,
    );
    let schedule = measure(&env, "governor schedule, council, empty queue");
    advance(&env, GOV_DELAY.saturating_add(1));
    governor.execute(&gov.contracts.pool, &function, &args, &predecessor, &salt);
    let execute = measure(&env, "governor execute, pool pause");
    governor.execute_now(
        &gov.contracts.asp_membership,
        &Symbol::new(&env, "insert_leaf"),
        &soroban_sdk::vec![&env, U256::from_u32(&env, 7).into_val(&env)],
        &gov.operator,
    );
    let execute_now = measure(
        &env,
        "governor execute_now, operator, membership insert_leaf",
    );
    [schedule, execute, execute_now]
}

/// Entry and write counts every row must report.
///
/// A change to what a contract stores updates these in the same commit.
const EXPECTED: &[(&str, u32, u32)] = &[
    ("pool transact, deposit, blocklist, fresh tree", 22, 8),
    ("pool transact, transfer, blocklist, fresh tree", 18, 6),
    ("pool transact, withdrawal, blocklist, fresh tree", 21, 8),
    ("pool transact, transfer, root one transaction old", 19, 6),
    (
        "pool transact, transfer, 91 idle days before the call",
        18,
        6,
    ),
    (
        "pool transact, transfer, allowlist and blocklist, fresh tree",
        21,
        6,
    ),
    ("pool get_root", 4, 0),
    ("pool pause, admin", 6, 2),
    ("pool-gvk transact, transfer, view-only", 20, 6),
    ("asp-membership insert_leaf, first leaf", 10, 4),
    ("asp-non-membership insert_leaf, ninth key", 16, 10),
    ("asp-non-membership delete_leaf, one of nine", 16, 7),
    ("public-key-registry register, first registration", 4, 2),
    ("governor schedule, council, empty queue", 8, 4),
    ("governor execute, pool pause", 8, 4),
    (
        "governor execute_now, operator, membership insert_leaf",
        13,
        4,
    ),
];

fn assert_pinned(rows: &[Row]) {
    assert_eq!(
        rows.len(),
        EXPECTED.len(),
        "every pinned row must be measured"
    );
    let mut mismatches = std::vec::Vec::new();
    for row in rows {
        match EXPECTED.iter().find(|(path, ..)| *path == row.path) {
            Some((_, entries, writes)) if *entries == row.entries() && *writes == row.writes() => {}
            Some((_, entries, writes)) => mismatches.push(format!(
                "{}: pinned {entries} entries and {writes} writes, measured {} and {}",
                row.path,
                row.entries(),
                row.writes()
            )),
            None => mismatches.push(format!("{}: no pinned expectation", row.path)),
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

fn print_table(rows: &[Row]) {
    println!("{HEADER}");
    for row in rows {
        println!("{}", row.line());
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn every_entry_point_reports_its_pinned_entry_counts() {
    let mut rows = std::vec::Vec::new();

    let deposit = PoolFixture::new(policy::BLOCKLIST_BIT);
    rows.push(deposit.transact("pool transact, deposit, blocklist, fresh tree", 1, AMOUNT));

    let transfer = PoolFixture::new(policy::BLOCKLIST_BIT);
    rows.push(transfer.transact("pool transact, transfer, blocklist, fresh tree", 1, 0));

    let withdrawal = PoolFixture::new(policy::BLOCKLIST_BIT);
    rows.push(withdrawal.transact(
        "pool transact, withdrawal, blocklist, fresh tree",
        1,
        -AMOUNT,
    ));

    let stale = PoolFixture::new(policy::BLOCKLIST_BIT);
    let old_root = stale.client().get_root();
    stale.transact("unmeasured", 1, 0);
    let (proof, ext) = stale.proof(old_root, 3, 0);
    stale.client().transact(&proof, &ext, &stale.sender);
    rows.push(measure(
        &stale.env,
        "pool transact, transfer, root one transaction old",
    ));

    let idle = PoolFixture::new(policy::BLOCKLIST_BIT);
    advance(
        &idle.env,
        MIN_PERSISTENT_TTL
            .saturating_sub(THRESHOLD)
            .saturating_add(1),
    );
    rows.push(idle.transact(
        "pool transact, transfer, 91 idle days before the call",
        1,
        0,
    ));

    let both = PoolFixture::new(policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT);
    rows.push(both.transact(
        "pool transact, transfer, allowlist and blocklist, fresh tree",
        1,
        0,
    ));

    let read = PoolFixture::new(policy::BLOCKLIST_BIT);
    read.client().get_root();
    rows.push(measure(&read.env, "pool get_root"));
    read.client().pause(&pausable::DEPOSITS, &None);
    rows.push(measure(&read.env, "pool pause, admin"));

    rows.push(gvk_transact_row());
    rows.push(membership_insert_row());
    rows.extend(non_membership_rows());
    rows.push(registry_row());
    rows.extend(governor_rows());

    print_table(&rows);
    assert_pinned(&rows);
}

/// Entries and writes of a transfer whose proof the real verifier checks.
const EXPECTED_REAL_PROOF: (u32, u32) = (21, 6);

/// The same transfer with a real Groth16 proof and the compiled verifier, so
/// the instruction column shows what the pairing check adds.
///
/// The fixture uses the allowlist-and-blocklist policy and a placeholder token
/// whose transfers touch no balance entries.
#[test]
#[cfg_attr(miri, ignore)]
fn a_real_proof_transfer_reports_its_pinned_entry_counts() -> Result<()> {
    let env = mainnet_env();
    let mut proven = prove_transaction(&env, [0, 13], [13, 0], 0)?;
    let contracts = deploy_contracts(&env);
    let roots = sync_contract_state(
        &env,
        &contracts,
        &proven.case,
        &mut proven.leaves,
        &proven.membership_trees,
        &proven.witness,
    );
    let ext = proven.ext_data.clone();
    let proof = proven.into_proof(&env, &roots);
    PoolContractClient::new(&env, &contracts.pool).transact(&proof, &ext, &Address::generate(&env));

    let row = measure(
        &env,
        "pool transact, transfer, allowlist and blocklist, real proof, 64-leaf tree",
    );
    print_table(std::slice::from_ref(&row));
    assert_eq!(
        (row.entries(), row.writes()),
        EXPECTED_REAL_PROOF,
        "{}",
        row.path
    );
    Ok(())
}
