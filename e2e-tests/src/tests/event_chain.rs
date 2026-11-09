//! The wallet's event chain against the pool's own.
//!
//! The pool runs in the test host and records each event it publishes. The
//! wallet folds the same events from the base64 XDR an RPC would serve, and
//! must reach the hash and count the pool reports from `event_chain()`.

use super::costs::PoolFixture;
use anyhow::Result;
use pool_core::policy;
use soroban_sdk::testutils::Events as _;
use stellar_private_payments::chain::EventChain;
use stellar_xdr::{ContractEventBody, Limits, WriteXdr};

/// Folds the events the pool's last call published into `chain`, from the
/// base64 XDR an RPC serves.
fn fold_published(fixture: &PoolFixture, chain: EventChain) -> Result<EventChain> {
    let events = fixture.env.events().all().filter_by_contract(&fixture.pool);
    events.events().iter().try_fold(chain, |chain, event| {
        let ContractEventBody::V0(body) = &event.body;
        let topics = body
            .topics
            .iter()
            .map(|topic| topic.to_xdr_base64(Limits::none()))
            .collect::<Result<Vec<_>, _>>()?;
        chain.extend(&topics, &body.data.to_xdr_base64(Limits::none())?)
    })
}

fn assert_matches_the_pool(fixture: &PoolFixture, chain: EventChain) {
    let on_chain = fixture.client().event_chain();
    assert_eq!(on_chain.count, chain.count);
    assert_eq!(on_chain.hash.to_array(), chain.hash);
}

#[test]
fn the_wallet_folds_the_pools_events_to_the_pools_chain() -> Result<()> {
    let fixture = PoolFixture::new(policy::BLOCKLIST_BIT);
    let mut chain = EventChain::EMPTY;

    // A deposit, a transfer and a withdrawal: nullifiers, then commitments.
    // Each seed spends nullifiers `seed` and `seed + 1`.
    for (seed, ext_amount) in [(1, 100), (3, 0), (5, -50)] {
        let (proof, ext) = fixture.proof(fixture.client().get_root(), seed, ext_amount);
        fixture.client().transact(&proof, &ext, &fixture.sender);
        chain = fold_published(&fixture, chain)?;
        assert_matches_the_pool(&fixture, chain);
    }
    fixture.client().pause_deposits();
    chain = fold_published(&fixture, chain)?;
    assert_matches_the_pool(&fixture, chain);

    // Two nullifiers and two commitments per transact, then the pause.
    assert_eq!(chain.count, 13);
    Ok(())
}
