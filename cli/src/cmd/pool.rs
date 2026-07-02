//! Core value operations: deposit, transfer, withdraw. Each takes the pool
//! contract id and requires a ready account.

use anyhow::Result;
use stellar_private_payments_sdk::types::TransactionResult;

use crate::{
    config::{CliConfig, validate_pool},
    explorer::Explorer,
    onboard, output,
    session::{PoolSession, parse_amount, resolve_transfer_recipient},
};

fn open(config: &CliConfig, pool: &str) -> Result<PoolSession> {
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    validate_pool(pool, &config.deployment)?;
    let network = config.resolve_network()?;
    PoolSession::open(config, &account, &network, pool)
}

pub fn deposit(config: &CliConfig, pool: &str, amount: &str, json: bool) -> Result<()> {
    let session = open(config, pool)?;
    let amount = parse_amount(amount)?;
    let result = session
        .pool()
        .deposit(amount)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    print_tx_results(
        config,
        "Deposit submitted",
        std::slice::from_ref(&result),
        json,
    )
}

pub fn transfer(
    config: &CliConfig,
    pool: &str,
    amount: &str,
    to: Option<&str>,
    note_key: Option<&str>,
    encryption_key: Option<&str>,
    json: bool,
) -> Result<()> {
    let (session, recipient) = prepare_transfer(
        config,
        pool,
        to,
        note_key,
        encryption_key,
        open,
        resolve_transfer_recipient,
    )?;
    let amount = parse_amount(amount)?;
    let results = session
        .pool()
        .transfer(recipient, amount)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    print_tx_results(config, "Transfer submitted", &results, json)
}

fn prepare_transfer<C, S, FOpen, FResolve>(
    config: &C,
    pool: &str,
    to: Option<&str>,
    note_key: Option<&str>,
    encryption_key: Option<&str>,
    open_fn: FOpen,
    resolve_fn: FResolve,
) -> Result<(S, stellar_private_payments_sdk::TransferRecipient)>
where
    FOpen: FnOnce(&C, &str) -> Result<S>,
    FResolve: FnOnce(
        &C,
        Option<&str>,
        Option<&str>,
        Option<&str>,
    ) -> Result<stellar_private_payments_sdk::TransferRecipient>,
{
    let session = open_fn(config, pool)?;
    let recipient = resolve_fn(config, to, note_key, encryption_key)?;
    Ok((session, recipient))
}

pub fn withdraw(
    config: &CliConfig,
    pool: &str,
    amount: &str,
    to: Option<&str>,
    json: bool,
) -> Result<()> {
    let recipient = match to {
        Some(address) => address.to_string(),
        None => config.require_account()?.address,
    };
    let session = open(config, pool)?;
    let amount = parse_amount(amount)?;
    let results = session
        .pool()
        .withdraw(amount, recipient)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    print_tx_results(config, "Withdraw submitted", &results, json)
}

fn print_tx_results(
    config: &CliConfig,
    title: &str,
    results: &[TransactionResult],
    json: bool,
) -> Result<()> {
    if json {
        return output::emit(results, true);
    }
    let explorer = config
        .open_storage()
        .and_then(|s| crate::explorer::base_url(&s))
        .map(Explorer::new)
        .ok();
    output::print_section(title);
    for result in results {
        match &explorer {
            Some(explorer) => output::print_kv(
                "tx_hash",
                format!("{} → {}", result.tx_hash, explorer.tx(&result.tx_hash)),
            ),
            None => output::print_kv("tx_hash", &result.tx_hash),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::prepare_transfer;
    use std::{cell::RefCell, rc::Rc};
    use stellar_private_payments_sdk::{
        TransferRecipient,
        types::{EncryptionPublicKey, NotePublicKey},
    };

    #[test]
    fn transfer_opens_before_resolving_recipient() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let open_calls = Rc::clone(&calls);
        let resolve_calls = Rc::clone(&calls);

        let (_, recipient) = prepare_transfer(
            &(),
            "pool",
            Some("GCEXAMPLE"),
            None,
            None,
            move |_, _| {
                open_calls.borrow_mut().push("open");
                Ok(())
            },
            move |_, _, _, _| {
                resolve_calls.borrow_mut().push("resolve");
                Ok(TransferRecipient {
                    note_public_key: NotePublicKey([0u8; 32]),
                    encryption_public_key: EncryptionPublicKey([1u8; 32]),
                })
            },
        )
        .unwrap();

        assert_eq!(recipient.note_public_key.0, [0u8; 32]);
        assert_eq!(calls.borrow().as_slice(), ["open", "resolve"]);
    }
}
