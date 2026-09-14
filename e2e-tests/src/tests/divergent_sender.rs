//! E2E: a spend whose note owner and transaction sender are different accounts.
//!
//! The pool contract has no notion of a note owner. `transact` takes a
//! `sender`, calls `sender.require_auth()` (`pool.rs:434`) and uses it for
//! exactly one other thing — pulling tokens from it on a deposit
//! (`pool.rs:448`). `internal_transact` is never given `sender` at all
//! (`pool.rs:476`), and a withdrawal pays `ext_data.recipient`
//! (`pool.rs:535`). That is the argument for why this contract needs no change
//! to support paying for someone else's notes, and it has never been executed:
//! the rest of the suite sends every transaction from `Address::generate`, an
//! address no assertion looks at again.
//!
//! Here the three identities are distinct and named, so the claim can fail:
//! the notes are owned by [`OWNER_NOTE_KEY`], the transaction is sent by
//! `payer`, and `owner_account` is a Stellar address the owner holds and the
//! contract never receives.

use super::utils::{
    FundedDeployment, LEAF_PREFIX, LEVELS, MembershipTreeProof, NonMembership,
    build_membership_trees, bytes32_to_bigint, deploy_contracts_with_real_token, generate_proof,
    scalar_to_u256, sync_contract_state, test_env, wrap_groth16_proof,
};
use anyhow::Result;
use ark_bn254::Fr as Scalar;
use circuits::test::utils::{
    general::scalar_to_bigint,
    keypair::derive_public_key,
    transaction::{commitment, prepopulated_prefix},
    transaction_case::{
        InputNote, OutputNote, TransactionWitness, TxCase, prepare_transaction_witness,
    },
};
use pool::{Error as PoolError, ExtData, PoolContractClient, Proof, hash_ext_data};
use soroban_sdk::{
    Address, Bytes, Env, I256, IntoVal, InvokeError, U256, Vec as SorobanVec,
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    token::{StellarAssetClient, TokenClient},
};

/// The note owner's spending key. It never leaves the proof: no contract
/// argument carries it and no ledger entry records it.
const OWNER_NOTE_KEY: u64 = 9_101;

/// Starting token balance of every funded account.
const FUNDED: i128 = 1_000;

/// A proved spend, its deployment, and the three identities involved.
struct DivergentSpend {
    env: Env,
    deployment: FundedDeployment,
    proof: Proof,
    ext_data: ExtData,
    /// Sends and pays for the transaction. Owns none of the notes it spends.
    payer: Address,
    /// The note owner's own Stellar address, which the contract never sees.
    owner_account: Address,
    /// Paid by a withdrawal, and neither of the two above.
    recipient: Address,
    /// Kept so a second pool can be brought to the same state as the first.
    state: SpendState,
}

/// Everything needed to reproduce the ledger state this spend was proved
/// against.
struct SpendState {
    case: TxCase,
    leaves: Vec<Scalar>,
    membership_trees: Vec<MembershipTreeProof>,
    witness: TransactionWitness,
}

/// What `try_transact` answers: the outer error holds a host failure such as a
/// missing authorisation, the inner one a pool error like a bad proof. Keeping
/// them apart is what makes a refusal attributable.
type TransactOutcome =
    Result<Result<(), soroban_sdk::ConversionError>, Result<PoolError, InvokeError>>;

impl DivergentSpend {
    /// Send the transaction, with `sender` as the account the pool authorises.
    fn transact_as(&self, sender: &Address) -> TransactOutcome {
        PoolContractClient::new(&self.env, &self.deployment.contracts.pool).try_transact(
            &self.proof,
            &self.ext_data,
            sender,
        )
    }

    fn token(&self) -> TokenClient<'_> {
        TokenClient::new(&self.env, &self.deployment.token)
    }

    fn balance(&self, account: &Address) -> i128 {
        self.token().balance(account)
    }

    /// A second pool, in the same environment, brought to the same ledger
    /// state this spend was proved against.
    ///
    /// The nullifiers are spent per pool, so the identical proof can be sent
    /// to this one as well — which is how "the sender is not part of the
    /// proof" becomes something a test can fail.
    fn twin_pool(&self) -> FundedDeployment {
        let twin = deploy_contracts_with_real_token(&self.env);
        let mut leaves = self.state.leaves.clone();
        let roots = sync_contract_state(
            &self.env,
            &twin.contracts,
            &self.state.case,
            &mut leaves,
            &self.state.membership_trees,
            &self.state.witness,
        );
        assert_eq!(
            roots.pool_root, self.proof.root,
            "the twin pool must hold the state the proof was made against",
        );
        StellarAssetClient::new(&self.env, &twin.token).mint(&twin.contracts.pool, &FUNDED);
        twin
    }
}

/// Prove a 2-in/2-out spend of notes owned by [`OWNER_NOTE_KEY`], against a
/// pool whose token is real so balances can be read.
///
/// `ext_amount` is positive for a deposit, negative for a withdrawal and zero
/// for a private transfer; inputs + `ext_amount` must equal outputs.
fn divergent_spend(
    in_amounts: [u64; 2],
    out_amounts: [u64; 2],
    ext_amount: i32,
) -> Result<DivergentSpend> {
    let env = test_env();
    env.mock_all_auths();

    let payer = Address::generate(&env);
    let owner_account = Address::generate(&env);
    let recipient = Address::generate(&env);

    let ext_data = ExtData {
        recipient: recipient.clone(),
        ext_amount: I256::from_i32(&env, ext_amount),
        encrypted_output0: Bytes::new(&env),
        encrypted_output1: Bytes::new(&env),
    };
    let ext_data_hash_bytes = hash_ext_data(&env, &ext_data);
    let ext_data_hash_bigint = bytes32_to_bigint(&ext_data_hash_bytes);

    // Both inputs are the owner's: one key, one identity holding the notes.
    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(OWNER_NOTE_KEY),
                blinding: Scalar::from(201u64),
                amount: Scalar::from(in_amounts[0]),
            },
            InputNote {
                leaf_index: 1,
                priv_key: Scalar::from(OWNER_NOTE_KEY),
                blinding: Scalar::from(211u64),
                amount: Scalar::from(in_amounts[1]),
            },
        ],
        vec![
            OutputNote {
                pub_key: Scalar::from(501u64),
                blinding: Scalar::from(601u64),
                amount: Scalar::from(out_amounts[0]),
            },
            OutputNote {
                pub_key: Scalar::from(502u64),
                blinding: Scalar::from(602u64),
                amount: Scalar::from(out_amounts[1]),
            },
        ],
    );

    let mut leaves = prepopulated_prefix(
        0xDEAD_BEEFu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        LEAF_PREFIX,
    );
    let membership_trees = build_membership_trees(&case, |j| 0xFEED_FACEu64 ^ ((j as u64) << 40));
    let keys = case
        .inputs
        .iter()
        .map(|input| NonMembership {
            key_non_inclusion: scalar_to_bigint(derive_public_key(input.priv_key)),
        })
        .collect::<Vec<_>>();

    let witness = prepare_transaction_witness(&case, leaves.clone(), LEVELS)?;
    // A withdrawal's public amount is the field negation of what leaves the
    // pool, which is what the contract recomputes as FIELD_SIZE - |amount|
    // (pool.rs:245-260).
    let magnitude = Scalar::from(u64::from(ext_amount.unsigned_abs()));
    // Negation in the scalar field wraps by definition; there is no overflow
    // here to guard against.
    #[allow(clippy::arithmetic_side_effects)]
    let public_amount = if ext_amount < 0 {
        -magnitude
    } else {
        magnitude
    };
    let result = generate_proof(
        &case,
        leaves.clone(),
        public_amount,
        &membership_trees,
        &keys,
        Some(ext_data_hash_bigint),
    )?;
    assert!(result.verified, "the spend must prove locally");

    let deployment = deploy_contracts_with_real_token(&env);
    let roots = sync_contract_state(
        &env,
        &deployment.contracts,
        &case,
        &mut leaves,
        &membership_trees,
        &witness,
    );

    let token = StellarAssetClient::new(&env, &deployment.token);
    token.mint(&payer, &FUNDED);
    token.mint(&owner_account, &FUNDED);
    token.mint(&deployment.contracts.pool, &FUNDED);

    let mut input_nullifiers: SorobanVec<U256> = SorobanVec::new(&env);
    for nullifier in &witness.nullifiers {
        input_nullifiers.push_back(scalar_to_u256(&env, *nullifier));
    }

    let proof = Proof {
        proof: wrap_groth16_proof(&env, result),
        root: roots.pool_root,
        input_nullifiers,
        output_commitment0: scalar_to_u256(&env, output_commitment(&case, 0)),
        output_commitment1: scalar_to_u256(&env, output_commitment(&case, 1)),
        public_amount: scalar_to_u256(&env, public_amount),
        ext_data_hash: ext_data_hash_bytes,
        asp_membership_root: roots.asp_membership_root,
        asp_non_membership_root: roots.asp_non_membership_root,
    };

    Ok(DivergentSpend {
        env,
        deployment,
        proof,
        ext_data,
        payer,
        owner_account,
        recipient,
        state: SpendState {
            case,
            leaves,
            membership_trees,
            witness,
        },
    })
}

/// `Proof` is a contract type without `Clone`, and a `MockAuth` has to carry
/// the same arguments the call will make.
fn same_proof(proof: &Proof) -> Proof {
    Proof {
        proof: proof.proof.clone(),
        root: proof.root.clone(),
        input_nullifiers: proof.input_nullifiers.clone(),
        output_commitment0: proof.output_commitment0.clone(),
        output_commitment1: proof.output_commitment1.clone(),
        public_amount: proof.public_amount.clone(),
        ext_data_hash: proof.ext_data_hash.clone(),
        asp_membership_root: proof.asp_membership_root.clone(),
        asp_non_membership_root: proof.asp_non_membership_root.clone(),
    }
}

fn output_commitment(case: &TxCase, index: usize) -> Scalar {
    commitment(
        case.outputs[index].amount,
        case.outputs[index].pub_key,
        case.outputs[index].blinding,
    )
}

/// The deposit is pulled from the sender, and the note owner pays nothing.
///
/// `transact` hands `sender` to `token_client.transfer(&sender, &this, ...)`
/// (`pool.rs:448`), so funding someone else's notes costs the sender the
/// tokens while the owner's own account is never touched — the point of the
/// whole feature, stated as a balance.
#[test]
#[cfg_attr(miri, ignore)]
fn a_deposit_is_pulled_from_the_sender_not_the_note_owner() -> Result<()> {
    let spend = divergent_spend([0, 0], [13, 0], 13)?;
    let pool = spend.deployment.contracts.pool.clone();
    let pool_before = spend.balance(&pool);

    assert!(
        spend.transact_as(&spend.payer).is_ok(),
        "a payer must be able to fund the owner's notes",
    );

    assert_eq!(
        spend.balance(&spend.payer),
        FUNDED - 13,
        "the deposit must come out of the sending account",
    );
    assert_eq!(
        spend.balance(&spend.owner_account),
        FUNDED,
        "the note owner's account must be untouched: the contract never receives it",
    );
    assert_eq!(
        spend.balance(&pool),
        pool_before + 13,
        "the pool must hold the deposit",
    );
    Ok(())
}

/// A withdrawal pays `ext_data.recipient`, who is neither the note owner nor
/// the account that sent the transaction.
///
/// `internal_transact` is never given `sender` (`pool.rs:476`), so the payout
/// at `pool.rs:535` has nothing but `ext_data` to go on. Three accounts, one
/// payment, and it lands on the one named in the proof-bound external data.
#[test]
#[cfg_attr(miri, ignore)]
fn a_withdrawal_pays_the_recipient_and_neither_other_account() -> Result<()> {
    let spend = divergent_spend([13, 0], [3, 0], -10)?;
    let pool = spend.deployment.contracts.pool.clone();
    let pool_before = spend.balance(&pool);

    assert!(
        spend.transact_as(&spend.payer).is_ok(),
        "a payer must be able to send the owner's withdrawal",
    );

    assert_eq!(
        spend.balance(&spend.recipient),
        10,
        "the withdrawal must pay the recipient named in ext_data",
    );
    assert_eq!(
        spend.balance(&spend.payer),
        FUNDED,
        "the sender pays no part of a withdrawal, only its fee off-chain",
    );
    assert_eq!(
        spend.balance(&spend.owner_account),
        FUNDED,
        "the note owner's account receives nothing: the contract never learns it",
    );
    assert_eq!(
        spend.balance(&pool),
        pool_before - 10,
        "the pool must fund the payout",
    );
    Ok(())
}

/// The sender is not part of what was proved.
///
/// The same proof and external data are sent to a second, identically-stated
/// pool from a different account, and are accepted there too. Nothing in the
/// proof binds the account that carries it — which is the whole basis for one
/// account paying for another's notes.
#[test]
#[cfg_attr(miri, ignore)]
fn the_same_proof_is_accepted_from_a_different_sender() -> Result<()> {
    let spend = divergent_spend([0, 13], [13, 0], 0)?;
    let twin = spend.twin_pool();
    let other_sender = Address::generate(&spend.env);

    assert!(
        spend.transact_as(&spend.payer).is_ok(),
        "the first pool must accept the spend from the payer",
    );

    let accepted = PoolContractClient::new(&spend.env, &twin.contracts.pool)
        .try_transact(&spend.proof, &spend.ext_data, &other_sender)
        .is_ok();
    assert!(
        accepted,
        "the identical spend must be accepted from an unrelated sender",
    );
    Ok(())
}

/// The pool asks the sender to authorise, and nobody else.
///
/// `sender.require_auth()` (`pool.rs:434`) is the only authorisation in the
/// spend path. A private transfer moves no tokens, so the sender's own
/// authorisation is the entire requirement — if the contract also wanted the
/// note owner, this would fail.
#[test]
#[cfg_attr(miri, ignore)]
fn only_the_senders_authorisation_is_required() -> Result<()> {
    let spend = divergent_spend([0, 13], [13, 0], 0)?;

    spend.env.mock_auths(&[MockAuth {
        address: &spend.payer,
        invoke: &MockAuthInvoke {
            contract: &spend.deployment.contracts.pool,
            fn_name: "transact",
            args: (
                same_proof(&spend.proof),
                spend.ext_data.clone(),
                spend.payer.clone(),
            )
                .into_val(&spend.env),
            sub_invokes: &[],
        },
    }]);

    assert!(
        spend.transact_as(&spend.payer).is_ok(),
        "the sender's own authorisation must be the whole requirement",
    );
    Ok(())
}

/// Without the sender's authorisation the spend does not happen, even though
/// the notes' owner is unchanged and the proof is untouched.
#[test]
#[cfg_attr(miri, ignore)]
fn a_spend_the_sender_did_not_authorise_is_refused() -> Result<()> {
    let spend = divergent_spend([0, 13], [13, 0], 0)?;

    // The note owner's own account authorises instead. It is the wrong
    // account, and being the owner does not help.
    spend.env.mock_auths(&[MockAuth {
        address: &spend.owner_account,
        invoke: &MockAuthInvoke {
            contract: &spend.deployment.contracts.pool,
            fn_name: "transact",
            args: (
                same_proof(&spend.proof),
                spend.ext_data.clone(),
                spend.payer.clone(),
            )
                .into_val(&spend.env),
            sub_invokes: &[],
        },
    }]);

    // A host error, not a pool error: the call is stopped at `require_auth()`
    // and never reaches the proof. Asserting only `is_err()` here would pass
    // just as well if the spend were malformed, which would prove nothing.
    let outcome = spend.transact_as(&spend.payer);
    assert!(
        matches!(outcome, Err(Err(_))),
        "the spend must be refused for want of the sender's authorisation, got {outcome:?}",
    );
    Ok(())
}
