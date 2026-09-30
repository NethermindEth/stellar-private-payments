use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use stellar_private_payments::{
    Client, LocalStorage,
    gvk::GvkAudit,
    types::{
        BabyJubJubPoint, ContractConfig, Field, GlobalViewKeyCiphertext, GvkAuthoritySetting,
        GvkMode, NoteAmount, PolicyFlags, TransferRecipient,
    },
};

use super::support::{TestSession, deploy, deploy_scoped, session};
use crate::{
    network::{DeploymentIdentity, LocalNetwork, lock_asp_tree},
    pool::{PoolAsset, PoolOptions},
};

async fn audit(
    contract_config: ContractConfig,
    pool_contract_id: &str,
    d_priv: Field,
) -> Result<GvkAudit> {
    let network = LocalNetwork::start().await?;

    let storage_path = std::env::temp_dir().join(format!(
        "spp-integration-tests-gvk-audit-{}-{pool_contract_id}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&storage_path);
    let storage =
        LocalStorage::open(storage_path.to_str().context("storage path is not UTF-8")?)?.into();

    let client = Client::init_readonly(network.rpc_url(), storage, contract_config, None)?;
    client.sync().await?;

    Ok(GvkAudit::new(
        client.storage().fork()?,
        pool_contract_id.to_string(),
        d_priv,
    ))
}

async fn note_pk(session: &TestSession) -> Result<Field> {
    let (note_pubkey, _) = session.account.privacy_keys().await?;
    Field::try_from_le_bytes(*note_pubkey.as_ref())
}

fn gvk_key(identity: &DeploymentIdentity) -> Field {
    identity
        .gvk_authority
        .as_ref()
        .expect("gvk pool should have an authority")
        .private_key
}

#[tokio::test]
async fn viewonly() -> Result<()> {
    let options = PoolOptions {
        gvk_mode: GvkMode::ViewOnly,
        asset: PoolAsset::Native,
        ..PoolOptions::NONE
    };
    let (config, identity) = deploy(&[options]).await?;
    let alice = session((config.clone(), identity.clone())).await?;
    let bob = session((config.clone(), identity.clone())).await?;
    let pool_contract_id = config
        .enabled_pools()
        .next()
        .context("deployment has no enabled pools")?
        .pool_contract_id
        .clone();

    alice.pool()?.deposit(NoteAmount::from(10_000_000)).await?;
    bob.pool()?.deposit(NoteAmount::from(20_000_000)).await?;

    let (bob_note_pubkey, bob_encryption_pubkey) = bob.account.privacy_keys().await?;
    alice
        .pool()?
        .transfer(
            TransferRecipient::keys(bob_note_pubkey, bob_encryption_pubkey),
            NoteAmount::from(3_000_000),
        )
        .await?;
    bob.pool()?
        .withdraw(NoteAmount::from(21_000_000), bob.wallet.address())
        .await?;

    let alice_pk = note_pk(&alice).await?;
    let bob_pk = note_pk(&bob).await?;

    let d_priv = gvk_key(&identity);
    let mut audit = audit(config, &pool_contract_id, d_priv).await?;
    let mut outputs = HashSet::new();
    while let Some(tx) = audit.next_tx().await? {
        assert!(
            tx.inputs.iter().all(|input| input.note.is_none()),
            "a view-only pool must never expose input notes"
        );
        for output in tx.outputs {
            if let Some(audited) = output.note {
                outputs.insert((audited.note.pk, audited.note.amount()?));
            }
        }
    }

    let expected_outputs = HashSet::from([
        (alice_pk, NoteAmount::from(10_000_000)),
        (bob_pk, NoteAmount::from(20_000_000)),
        (alice_pk, NoteAmount::from(7_000_000)),
        (bob_pk, NoteAmount::from(3_000_000)),
        (bob_pk, NoteAmount::from(2_000_000)),
    ]);
    assert_eq!(outputs, expected_outputs);

    Ok(())
}

#[tokio::test]
async fn traceable() -> Result<()> {
    let options = PoolOptions {
        gvk_mode: GvkMode::Traceable,
        asset: PoolAsset::Native,
        ..PoolOptions::NONE
    };
    let (config, identity) = deploy(&[options]).await?;
    let alice = session((config.clone(), identity.clone())).await?;
    let bob = session((config.clone(), identity.clone())).await?;
    let pool_contract_id = config
        .enabled_pools()
        .next()
        .context("deployment has no enabled pools")?
        .pool_contract_id
        .clone();

    alice.pool()?.deposit(NoteAmount::from(10_000_000)).await?;
    bob.pool()?.deposit(NoteAmount::from(20_000_000)).await?;

    let (bob_note_pubkey, bob_encryption_pubkey) = bob.account.privacy_keys().await?;
    alice
        .pool()?
        .transfer(
            TransferRecipient::keys(bob_note_pubkey, bob_encryption_pubkey),
            NoteAmount::from(3_000_000),
        )
        .await?;
    bob.pool()?
        .withdraw(NoteAmount::from(21_000_000), bob.wallet.address())
        .await?;

    let alice_pk = note_pk(&alice).await?;
    let bob_pk = note_pk(&bob).await?;

    let d_priv = gvk_key(&identity);
    let mut audit = audit(config, &pool_contract_id, d_priv).await?;
    let mut inputs = HashSet::new();
    let mut outputs = HashSet::new();
    let mut input_ledgers = HashMap::new();
    let mut output_ledgers = HashMap::new();
    while let Some(tx) = audit.next_tx().await? {
        let ledger = tx.ledger;
        for input in tx.inputs {
            if let Some(audited) = input.note {
                inputs.insert((audited.note.pk, audited.note.amount()?));
                input_ledgers.insert(audited.commitment, ledger);
            }
        }
        for output in tx.outputs {
            if let Some(audited) = output.note {
                outputs.insert((audited.note.pk, audited.note.amount()?));
                output_ledgers.insert(audited.commitment, ledger);
            }
        }
    }

    let expected_inputs = HashSet::from([
        (alice_pk, NoteAmount::from(10_000_000)),
        (bob_pk, NoteAmount::from(20_000_000)),
        (bob_pk, NoteAmount::from(3_000_000)),
    ]);
    assert_eq!(inputs, expected_inputs);

    let expected_outputs = HashSet::from([
        (alice_pk, NoteAmount::from(10_000_000)),
        (bob_pk, NoteAmount::from(20_000_000)),
        (alice_pk, NoteAmount::from(7_000_000)),
        (bob_pk, NoteAmount::from(3_000_000)),
        (bob_pk, NoteAmount::from(2_000_000)),
    ]);
    assert_eq!(outputs, expected_outputs);

    for (commitment, spent_ledger) in &input_ledgers {
        let created_ledger = output_ledgers
            .get(commitment)
            .context("a spent note's commitment must have appeared as an output somewhere")?;
        assert!(
            created_ledger < spent_ledger,
            "a note must be created before it is spent"
        );
    }

    Ok(())
}

#[tokio::test]
async fn non_gvk_not_auditable() -> Result<()> {
    let (config, identity) = deploy(&[
        PoolOptions::NONE,
        PoolOptions {
            gvk_mode: GvkMode::ViewOnly,
            asset: PoolAsset::Native,
            ..PoolOptions::NONE
        },
    ])
    .await?;
    let alice = session((config.clone(), identity.clone())).await?;
    let non_gvk_pool = alice.pool_at(0)?;
    let gvk_pool = alice.pool_at(1)?;
    let gvk_pool_contract_id = gvk_pool.config().pool_contract_id.clone();

    non_gvk_pool.deposit(NoteAmount::from(10_000_000)).await?;
    gvk_pool.deposit(NoteAmount::from(5_000_000)).await?;

    let alice_pk = note_pk(&alice).await?;

    let d_priv = gvk_key(&identity);
    let mut audit = audit(config, &gvk_pool_contract_id, d_priv).await?;
    let mut outputs = HashSet::new();
    while let Some(tx) = audit.next_tx().await? {
        for output in tx.outputs {
            if let Some(audited) = output.note {
                outputs.insert((audited.note.pk, audited.note.amount()?));
            }
        }
    }

    let expected_outputs = HashSet::from([(alice_pk, NoteAmount::from(5_000_000))]);
    assert_eq!(
        outputs, expected_outputs,
        "the gvk pool's audit must not surface the non-gvk pool's deposit"
    );

    Ok(())
}

#[tokio::test]
async fn wrong_key() -> Result<()> {
    let (config, identity) = deploy(&[
        PoolOptions {
            gvk_mode: GvkMode::Traceable,
            asset: PoolAsset::Native,
            ..PoolOptions::NONE
        },
        PoolOptions::NONE,
    ])
    .await?;
    let alice = session((config.clone(), identity)).await?;
    let pool_contract_id = config
        .enabled_pools()
        .next()
        .context("deployment has no enabled pools")?
        .pool_contract_id
        .clone();

    alice.pool()?.deposit(NoteAmount::from(10_000_000)).await?;
    alice
        .pool()?
        .withdraw(NoteAmount::from(4_000_000), alice.wallet.address())
        .await?;

    let wrong_key = GvkAuthoritySetting::generate()?.private_key;
    let mut audit = audit(config, &pool_contract_id, wrong_key).await?;

    let mut tx_count = 0;
    while let Some(tx) = audit.next_tx().await? {
        tx_count += 1;
        assert!(
            tx.inputs.iter().all(|input| input.note.is_none()),
            "the wrong key should not decrypt any input note"
        );
        assert!(
            tx.outputs.iter().all(|output| output.note.is_none()),
            "the wrong key should not decrypt any output note"
        );
    }
    assert_eq!(tx_count, 2, "expected the deposit and the withdraw");

    Ok(())
}

#[tokio::test]
async fn policy_auditable() -> Result<()> {
    let options = PoolOptions {
        policy_flags: PolicyFlags::BLOCKLIST,
        gvk_mode: GvkMode::Traceable,
        asset: PoolAsset::Native,
    };
    let (config, identity) = deploy(&[options]).await?;
    let alice = session((config.clone(), identity.clone())).await?;
    let pool_contract_id = config
        .enabled_pools()
        .next()
        .context("deployment has no enabled pools")?
        .pool_contract_id
        .clone();

    let _lock = lock_asp_tree(&alice.pool()?.config().contract_config.asp_non_membership).await?;

    alice.pool()?.deposit(NoteAmount::from(10_000_000)).await?;
    let alice_pk = note_pk(&alice).await?;

    let (alice_note_pubkey, _) = alice.account.privacy_keys().await?;
    let network = LocalNetwork::start().await?;
    network
        .insert_asp_non_membership_leaf(
            &alice.pool()?.config().contract_config.asp_non_membership,
            &identity.admin_secret,
            alice_note_pubkey,
        )
        .await?;

    let blocked_deposit = alice.pool()?.deposit(NoteAmount::from(6_000_000)).await;
    assert!(
        blocked_deposit.is_err(),
        "a blocked wallet should not be able to deposit"
    );

    let d_priv = gvk_key(&identity);
    let mut audit = audit(config, &pool_contract_id, d_priv).await?;

    let mut outputs = HashSet::new();
    while let Some(tx) = audit.next_tx().await? {
        for output in tx.outputs {
            if let Some(audited) = output.note {
                outputs.insert((audited.note.pk, audited.note.amount()?));
            }
        }
    }

    let expected_outputs = HashSet::from([(alice_pk, NoteAmount::from(10_000_000))]);
    assert_eq!(
        outputs, expected_outputs,
        "the rejected deposit must not appear in the audit"
    );

    Ok(())
}

#[tokio::test]
async fn audit_skips_dummy() -> Result<()> {
    let options = PoolOptions {
        gvk_mode: GvkMode::Traceable,
        asset: PoolAsset::Native,
        ..PoolOptions::NONE
    };
    let (config, identity) = deploy_scoped(&[options], "audit_skips_dummy").await?;
    let alice = session((config.clone(), identity.clone())).await?;
    let bob = session((config.clone(), identity.clone())).await?;
    let pool_contract_id = config
        .enabled_pools()
        .next()
        .context("deployment has no enabled pools")?
        .pool_contract_id
        .clone();

    // deposit, 2 dummy inputs + 1 dummy output
    alice.pool()?.deposit(NoteAmount::from(10_000_000)).await?;
    // deposit, 2 dummy inputs + 1 dummy output
    bob.pool()?.deposit(NoteAmount::from(20_000_000)).await?;

    // transfer, 1 dummy input
    let (bob_note_pubkey, bob_encryption_pubkey) = bob.account.privacy_keys().await?;
    alice
        .pool()?
        .transfer(
            TransferRecipient::keys(bob_note_pubkey, bob_encryption_pubkey),
            NoteAmount::from(3_000_000),
        )
        .await?;

    // withdraw, 1 dummy output
    bob.pool()?
        .withdraw(NoteAmount::from(21_000_000), bob.wallet.address())
        .await?;

    let alice_pk = note_pk(&alice).await?;
    let bob_pk = note_pk(&bob).await?;

    let d_priv = gvk_key(&identity);
    let mut audit = audit(config, &pool_contract_id, d_priv).await?;

    let mut input_slots = 0;
    let mut output_slots = 0;
    let mut inputs = HashSet::new();
    let mut outputs = HashSet::new();
    while let Some(tx) = audit.next_tx().await? {
        input_slots += tx.inputs.len();
        output_slots += tx.outputs.len();
        for input in tx.inputs {
            if let Some(audited) = input.note {
                inputs.insert((audited.note.pk, audited.note.amount()?));
            }
        }
        for output in tx.outputs {
            if let Some(audited) = output.note {
                outputs.insert((audited.note.pk, audited.note.amount()?));
            }
        }
    }

    assert_eq!(input_slots, 8, "4 transactions x 2 input slots each");
    assert_eq!(output_slots, 8, "4 transactions x 2 output slots each");

    let expected_inputs = HashSet::from([
        (alice_pk, NoteAmount::from(10_000_000)),
        (bob_pk, NoteAmount::from(20_000_000)),
        (bob_pk, NoteAmount::from(3_000_000)),
    ]);
    assert_eq!(inputs.len(), expected_inputs.len());
    assert_eq!(inputs, expected_inputs);

    let expected_outputs = HashSet::from([
        (alice_pk, NoteAmount::from(10_000_000)),
        (bob_pk, NoteAmount::from(20_000_000)),
        (alice_pk, NoteAmount::from(7_000_000)),
        (bob_pk, NoteAmount::from(3_000_000)),
        (bob_pk, NoteAmount::from(2_000_000)),
    ]);
    assert_eq!(outputs.len(), expected_outputs.len());
    assert_eq!(outputs, expected_outputs);

    Ok(())
}

#[tokio::test]
async fn ciphertext_field_oor() -> Result<()> {
    let options = PoolOptions {
        gvk_mode: GvkMode::ViewOnly,
        asset: PoolAsset::Native,
        ..PoolOptions::NONE
    };
    let (config, identity) = deploy(&[options]).await?;
    let alice = session((config, identity)).await?;
    let pool = alice.pool()?;

    let mut plan = pool.prepare_deposit(NoteAmount::from(10_000_000))?;
    let mut prepared = pool.prove_next(&mut plan).await?;

    // c1 element with mod
    let outputs = prepared
        .prepared
        .output_gvk_ciphertexts
        .as_mut()
        .context("view-only pool must encrypt every output note")?;
    outputs[0].c1 = Field(Field::modulus());

    let simulated = pool.simulate(&mut prepared).await;
    assert!(
        simulated.is_err(),
        "the pool must reject a non-canonical GVK ciphertext field"
    );

    Ok(())
}

#[tokio::test]
async fn viewonly_input_encrypted() -> Result<()> {
    let options = PoolOptions {
        gvk_mode: GvkMode::ViewOnly,
        asset: PoolAsset::Native,
        ..PoolOptions::NONE
    };
    let (config, identity) = deploy(&[options]).await?;
    let alice = session((config, identity)).await?;
    let pool = alice.pool()?;

    let mut plan = pool.prepare_deposit(NoteAmount::from(10_000_000))?;
    let mut prepared = pool.prove_next(&mut plan).await?;

    prepared.prepared.input_gvk_ciphertexts = Some(vec![GlobalViewKeyCiphertext {
        r: BabyJubJubPoint {
            x: Field::ONE,
            y: Field::ONE,
        },
        c1: Field::ONE,
        c2: Field::ONE,
        c3: Field::ONE,
    }]);

    let simulated = pool.simulate(&mut prepared).await;
    assert!(
        simulated.is_err(),
        "a view-only pool must reject any input ciphertext"
    );

    Ok(())
}
