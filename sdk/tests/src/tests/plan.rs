//! PrivatePool per-step planning.

use crate::pool::{test_pool, test_recipient};
use stellar_private_payments::{Error, types::NoteAmount};

#[test]
fn transfer_two_steps() {
    let pool = test_pool(Some(&[2, 3, 5])).expect("test pool");

    let amount = NoteAmount::from(10u128);
    let recipient = test_recipient();

    let estimate = pool.estimate(amount).expect("estimate");
    assert_eq!(estimate.tx_count, 2, "expected two txs for transfer");

    let wallet = pool.spendable_notes().expect("spendable notes");
    let plan = pool
        .prepare_transfer(&wallet, recipient, amount)
        .expect("prepare transfer");
    assert_eq!(plan.tx_count(), 2);
    assert_eq!(plan.current_tx(), 0);
    assert!(!plan.is_complete());
}

#[test]
fn deposit_single_step_plan() {
    let pool = test_pool(Some(&[2, 3, 5])).expect("test pool");

    let plan = pool
        .prepare_deposit(NoteAmount::from(5u128))
        .expect("prepare deposit");

    assert_eq!(plan.tx_count(), 1);
    assert_eq!(plan.current_tx(), 0);
    assert!(!plan.is_complete());
}

#[test]
fn transfer_one_step_exact() {
    let pool = test_pool(Some(&[10])).expect("test pool");

    let amount = NoteAmount::from(10u128);
    let estimate = pool.estimate(amount).expect("estimate");
    assert_eq!(estimate.tx_count, 1);

    let wallet = pool.spendable_notes().expect("spendable notes");
    let plan = pool
        .prepare_transfer(&wallet, test_recipient(), amount)
        .expect("prepare transfer");
    assert_eq!(plan.tx_count(), 1);
    assert!(!plan.is_complete());
}

#[test]
fn withdraw_single_step() {
    let pool = test_pool(Some(&[10])).expect("test pool");

    let amount = NoteAmount::from(10u128);
    let wallet = pool.spendable_notes().expect("spendable notes");
    let plan = pool
        .prepare_withdraw(
            &wallet,
            amount,
            pool.config().user_address.as_str().to_string(),
        )
        .expect("prepare withdraw");

    assert_eq!(plan.tx_count(), 1);
    assert_eq!(plan.current_tx(), 0);
    assert!(!plan.is_complete());
}

#[test]
fn transfer_insufficient_funds() {
    let pool = test_pool(Some(&[2, 3])).expect("test pool");

    let wallet = pool.spendable_notes().expect("spendable notes");
    let err = pool
        .prepare_transfer(&wallet, test_recipient(), NoteAmount::from(100u128))
        .expect_err("transfer above wallet sum should not plan");

    assert!(matches!(err, Error::SpendSession(_)));
}

#[test]
fn estimate_empty_wallet() {
    let pool = test_pool(Some(&[])).expect("test pool");

    let err = pool
        .estimate(NoteAmount::from(10u128))
        .expect_err("empty wallet should not estimate");

    assert!(matches!(err, Error::Plan(_)));
}

#[test]
fn prepare_deposit_zero() {
    let pool = test_pool(Some(&[])).expect("test pool");

    let err = pool
        .prepare_deposit(NoteAmount::ZERO)
        .expect_err("zero deposit should not plan");

    assert!(matches!(err, Error::InvalidConfig(_)));
}

#[test]
fn withdraw_zero() {
    let pool = test_pool(Some(&[])).expect("test pool");

    let err = pool
        .prepare_withdraw(
            &[],
            NoteAmount::ZERO,
            pool.config().user_address.as_str().to_string(),
        )
        .expect_err("zero withdraw should not plan");

    assert!(matches!(err, Error::InvalidConfig(_)));
}

/// A session whose note owner and signer are different accounts: notes and key
/// material from the owner, envelope and `sender` from the signer, withdrawal
/// recipient from neither.
mod divergent_owner_and_signer {
    use crate::{
        pool::{
            DELEGATE_ADDRESS, OWNER_ADDRESS, POOL_CONTRACT_ID, WITHDRAW_RECIPIENT_ADDRESS,
            delegate_signer, delegated_test_client_and_account, test_recipient,
        },
        seed::seeded_user_public_keys,
    };
    use stellar_private_payments::{
        PreparedTransaction,
        blocking::PrivatePool,
        chain::{Limits, ReadXdr, TransactionEnvelope},
        planner::{SpendSession, SpendTarget},
        transact::PreparedTxPublic,
        types::{ExtAmount, ExtData, Field, NoteAmount, NoteOwnerAddress, SignerAddress},
    };
    use stellar_xdr::{self as xdr, ScAddress};

    #[test]
    fn withdraw_spends_the_owners_notes_and_is_sourced_by_the_signer() {
        let (client, account) =
            delegated_test_client_and_account(Some(&[10])).expect("delegated session");
        let pool = account.pool(POOL_CONTRACT_ID).expect("pool");
        assert_divergent(&pool);

        let wallet = pool.spendable_notes().expect("spendable notes");
        assert_eq!(
            wallet.iter().map(|note| note.amount).collect::<Vec<_>>(),
            [NoteAmount::from(10u128)],
        );
        assert_eq!(pool.balance().expect("balance"), NoteAmount::from(10u128));
        let signer_owned = client
            .account(
                NoteOwnerAddress::new(DELEGATE_ADDRESS),
                SignerAddress::new(DELEGATE_ADDRESS),
                delegate_signer().expect("delegate signer"),
            )
            .expect("signer-owned session")
            .pool(POOL_CONTRACT_ID)
            .expect("signer-owned pool");
        assert!(
            signer_owned
                .spendable_notes()
                .expect("signer-owned notes")
                .is_empty(),
            "the notes must be looked up for the owner, not for the signer",
        );

        // Key material is what a self-addressed change note is encrypted to.
        let (note_key, encryption_key) = account.user_public_keys().expect("session keys");
        let (owner_note_key, owner_encryption_key) =
            seeded_user_public_keys().expect("seeded owner keys");
        assert_eq!(note_key.0, owner_note_key.0);
        assert_eq!(encryption_key.0, owner_encryption_key.0);

        // The 10 note pays 4 out of the pool and leaves 6 behind as change.
        let amount = NoteAmount::from(4u128);
        let change = NoteAmount::from(6u128);
        let plan = pool
            .prepare_withdraw(&wallet, amount, WITHDRAW_RECIPIENT_ADDRESS)
            .expect("a delegated session must plan a withdrawal");
        assert_eq!(plan.tx_count(), 1);

        let paid_out = ExtAmount::try_from(amount)
            .expect("withdrawn amount fits an ext amount")
            .checked_neg()
            .expect("a withdrawal leaves the pool");

        // `PreparedTransactionPlan` does not expose its step; this is the
        // session `prepare_withdraw` builds, from the arguments it passes.
        let step = SpendSession::setup(
            wallet.clone(),
            amount,
            POOL_CONTRACT_ID.to_string(),
            SpendTarget::withdraw(WITHDRAW_RECIPIENT_ADDRESS.to_string()),
        )
        .expect("spend session")
        .step()
        .expect("materialise the step")
        .expect("a one-tx plan has a step");
        assert_eq!(step.ext_recipient, WITHDRAW_RECIPIENT_ADDRESS);
        assert_eq!(step.ext_amount, paid_out);
        assert_eq!(
            step.input_commitments,
            wallet
                .iter()
                .map(|note| note.commitment)
                .collect::<Vec<_>>(),
            "the step must spend the owner's note",
        );
        assert_eq!(step.output_amounts, [change, NoteAmount::ZERO]);
        assert!(
            step.out_recipient_note_pubkeys.iter().all(Option::is_none),
            "change must stay with the owner, not go to a named recipient",
        );

        let mut prepared = prepared_step(WITHDRAW_RECIPIENT_ADDRESS, paid_out, change);
        pool.simulate(&mut prepared).expect("simulate");
        let call = TransactCall::of(&prepared);
        assert_eq!(call.envelope_source, address(DELEGATE_ADDRESS));
        assert_eq!(call.sender, address(DELEGATE_ADDRESS));
        assert_ne!(call.envelope_source, address(OWNER_ADDRESS));

        // Weaker than the two above: this value came from `prepared_step`, not
        // from the plan, so it covers the encoding and not the hop into it.
        assert_eq!(call.ext_recipient, address(WITHDRAW_RECIPIENT_ADDRESS));
        assert_ne!(call.ext_recipient, address(DELEGATE_ADDRESS));

        pool.sign(&prepared)
            .expect("the signer must be able to sign the envelope it sources");
    }

    #[test]
    fn transfer_spends_the_owners_notes_and_is_sourced_by_the_signer() {
        let (_, account) =
            delegated_test_client_and_account(Some(&[2, 3, 5])).expect("delegated session");
        let pool = account.pool(POOL_CONTRACT_ID).expect("pool");
        assert_divergent(&pool);

        let wallet = pool.spendable_notes().expect("spendable notes");
        let mut amounts: Vec<_> = wallet.iter().map(|note| note.amount).collect();
        amounts.sort();
        assert_eq!(
            amounts,
            [
                NoteAmount::from(2u128),
                NoteAmount::from(3u128),
                NoteAmount::from(5u128),
            ],
        );

        // Same shape as `transfer_two_steps`, which signs as the owner.
        let amount = NoteAmount::from(10u128);
        let plan = pool
            .prepare_transfer(&wallet, test_recipient(), amount)
            .expect("a delegated session must plan a transfer");
        assert_eq!(plan.tx_count(), 2);

        // A transfer moves nothing out, so its ext recipient is the pool.
        let mut prepared = prepared_step(POOL_CONTRACT_ID, ExtAmount::ZERO, amount);
        pool.simulate(&mut prepared).expect("simulate");
        let call = TransactCall::of(&prepared);
        assert_eq!(call.envelope_source, address(DELEGATE_ADDRESS));
        assert_eq!(call.sender, address(DELEGATE_ADDRESS));
        assert_eq!(call.ext_recipient, address(POOL_CONTRACT_ID));

        pool.sign(&prepared)
            .expect("the signer must be able to sign the envelope it sources");
    }

    fn assert_divergent(pool: &PrivatePool) {
        let config = pool.config();
        assert_eq!(config.user_address.as_str(), OWNER_ADDRESS);
        assert_eq!(config.signer_address.as_str(), DELEGATE_ADDRESS);
        assert_ne!(
            config.user_address.as_str(),
            config.signer_address.as_str(),
            "the pair must differ or the test proves nothing",
        );
    }

    /// A `transact` step's prover output, stood in for rather than proved:
    /// nothing from here to the envelope inspects a proof.
    ///
    /// Running the real `prove_next` instead is what closes the recipient gap
    /// above. It needs the stub RPC to serve the contract-data reads and a
    /// non-membership `find`, and costs real proving time per test.
    fn prepared_step(
        recipient: &str,
        ext_amount: ExtAmount,
        change: NoteAmount,
    ) -> PreparedTransaction {
        PreparedTransaction {
            proof_uncompressed: vec![0u8; 256],
            ext_data: ExtData {
                recipient: recipient.to_string(),
                ext_amount,
                encrypted_output0: Vec::new(),
                encrypted_output1: Vec::new(),
            },
            prepared: PreparedTxPublic {
                pool_root: Field::ZERO,
                input_nullifiers: [Field::ZERO; 2],
                output_commitments: [Field::from(change), Field::ZERO],
                public_amount: Field::ZERO,
                ext_data_hash_be: [0u8; 32],
                asp_membership_root: Field::ZERO,
                asp_non_membership_root: Field::ZERO,
                output_gvk_ciphertexts: None,
                input_gvk_ciphertexts: None,
            },
            soroban_tx: Default::default(),
        }
    }

    /// The three identities in a simulated pool `transact` call.
    struct TransactCall {
        envelope_source: ScAddress,
        sender: ScAddress,
        ext_recipient: ScAddress,
    }

    impl TransactCall {
        fn of(prepared: &PreparedTransaction) -> Self {
            let envelope =
                TransactionEnvelope::from_xdr_base64(&prepared.soroban_tx.tx_xdr, Limits::none())
                    .expect("prepared envelope xdr");
            let TransactionEnvelope::Tx(v1) = envelope else {
                panic!("expected a v1 envelope");
            };
            let xdr::MuxedAccount::Ed25519(source_key) = v1.tx.source_account else {
                panic!("expected an ed25519 source account");
            };
            let xdr::OperationBody::InvokeHostFunction(invoke) = &v1.tx.operations[0].body else {
                panic!("expected an invokeHostFunction operation");
            };
            let xdr::HostFunction::InvokeContract(args) = &invoke.host_function else {
                panic!("expected a contract invocation");
            };
            assert_eq!(args.function_name.to_string(), "transact");

            // `transact(proof, ext_data, sender)`.
            let xdr::ScVal::Address(sender) = &args.args[2] else {
                panic!("the sender argument must be an address");
            };
            Self {
                envelope_source: ScAddress::Account(xdr::AccountId(
                    xdr::PublicKey::PublicKeyTypeEd25519(source_key),
                )),
                sender: sender.clone(),
                ext_recipient: ext_data_recipient(&args.args[1]),
            }
        }
    }

    fn ext_data_recipient(ext_data: &xdr::ScVal) -> ScAddress {
        let xdr::ScVal::Map(Some(map)) = ext_data else {
            panic!("expected ext_data to be a map");
        };
        for xdr::ScMapEntry { key, val } in map.iter() {
            let xdr::ScVal::Symbol(name) = key else {
                continue;
            };
            if name.to_utf8_string().expect("ext_data key") == "recipient" {
                let xdr::ScVal::Address(recipient) = val else {
                    panic!("the ext_data recipient must be an address");
                };
                return recipient.clone();
            }
        }
        panic!("ext_data has no recipient entry");
    }

    fn address(strkey: &str) -> ScAddress {
        strkey.parse().expect("address strkey")
    }
}
