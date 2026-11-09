//! A running hash over every event a contract publishes.
//!
//! A client that syncs a contract's events from a source it does not trust,
//! such as a bootnode, folds them the same way and compares the result with
//! the contract's [`event_chain`]. An event withheld, altered, added or
//! reordered changes the hash.
//!
//! Each event extends the chain as
//!
//! ```text
//! count' = count + 1
//! hash'  = sha256(hash || xdr(topics) || xdr(data))
//! ```
//!
//! where `topics` is the event's topic vector as one `ScVal::Vec`, `data` its
//! data value, and `xdr` the `ScVal` XDR encoding an RPC serves in an event's
//! `topic` and `value`. XDR values delimit themselves, so the concatenation is
//! unambiguous. A contract that has published nothing reports count 0 and 32
//! zero bytes.
//!
//! The chain covers an event only if the contract publishes it with
//! [`publish_event!`](crate::publish_event).

use soroban_sdk::{Bytes, BytesN, Env, Event, contracttype, xdr::ToXdr};

/// A contract's event chain after its first `count` events.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventChain {
    /// How many events the contract has published.
    pub count: u64,
    /// The running hash after the last of them.
    pub hash: BytesN<32>,
}

impl EventChain {
    /// The chain of a contract that has published nothing.
    pub fn empty(env: &Env) -> Self {
        Self {
            count: 0,
            hash: BytesN::from_array(env, &[0; 32]),
        }
    }
}

/// The instance-storage key of the chain.
///
/// It encodes as the vector `[EventChain]`, so it does not collide with a
/// contract's own keys unless one of them is also named `EventChain`.
#[contracttype]
enum EventChainKey {
    EventChain,
}

/// Returns the calling contract's event chain.
pub fn event_chain(env: &Env) -> EventChain {
    env.storage()
        .instance()
        .get(&EventChainKey::EventChain)
        .unwrap_or_else(|| EventChain::empty(env))
}

/// Extends the calling contract's event chain with `event`.
///
/// Publish through [`publish_event!`](crate::publish_event), which calls this
/// and then publishes the event, so the two cannot drift apart.
///
/// # Panics
///
/// Panics if the contract has already published `u64::MAX` events.
pub fn extend<E: Event>(env: &Env, event: &E) {
    let EventChain { count, hash } = event_chain(env);
    let mut preimage = Bytes::from(hash);
    preimage.append(&event.topics(env).to_xdr(env));
    preimage.append(&event.data(env).to_xdr(env));
    let next = EventChain {
        count: count.checked_add(1).expect("the event count fits a u64"),
        hash: env.crypto().sha256(&preimage).to_bytes(),
    };
    env.storage()
        .instance()
        .set(&EventChainKey::EventChain, &next);
}

/// Publishes a `#[contractevent]` value and extends the calling contract's
/// event chain with it.
///
/// `publish_event!(env, event)` takes `env` as `&Env`. It publishes through
/// the event's own `publish`, which also keeps the event in the contract spec.
#[macro_export]
macro_rules! publish_event {
    ($env:expr, $event:expr $(,)?) => {{
        let env = $env;
        let event = $event;
        $crate::event_chain::extend(env, &event);
        event.publish(env);
    }};
}

/// Folds events as a client does, for tests.
#[cfg(any(test, feature = "testutils"))]
pub mod testutils {
    use super::EventChain;
    use soroban_sdk::{
        Bytes, Env,
        xdr::{ContractEvent, ContractEventBody, Limits, ScVal, ScVec, WriteXdr},
    };

    /// Folds `events` into `chain` the way a client folds the events an RPC
    /// serves: each event's topic list as one `ScVal::Vec`, then its value,
    /// in `ScVal` XDR. The events are the ones the host recorded, so this
    /// checks the contract's own encoding against the one a client sees.
    ///
    /// # Panics
    ///
    /// Panics if an event does not encode, or the count overflows.
    pub fn fold(env: &Env, chain: &EventChain, events: &[ContractEvent]) -> EventChain {
        events.iter().fold(chain.clone(), |chain, event| {
            let ContractEventBody::V0(body) = &event.body;
            let topics = ScVal::Vec(Some(ScVec(body.topics.clone())));
            let mut preimage = Bytes::from(chain.hash);
            preimage.extend_from_slice(&topics.to_xdr(Limits::none()).expect("topics encode"));
            preimage.extend_from_slice(&body.data.to_xdr(Limits::none()).expect("data encodes"));
            EventChain {
                count: chain
                    .count
                    .checked_add(1)
                    .expect("the event count fits a u64"),
                hash: env.crypto().sha256(&preimage).to_bytes(),
            }
        })
    }
}

#[cfg(test)]
mod test {
    use super::{EventChain, event_chain, testutils::fold};
    use soroban_sdk::{
        Address, Bytes, BytesN, Env, U256, contract, contractevent, testutils::Events as _,
    };

    #[contract]
    struct Emitter;

    /// Shaped like the pool's event of the same name.
    #[contractevent]
    struct NewNullifierEvent {
        #[topic]
        nullifier: U256,
    }

    /// Shaped like the pool's event of the same name.
    #[contractevent]
    struct NewCommitmentEvent {
        #[topic]
        commitment: U256,
        index: u32,
        encrypted_output: Bytes,
    }

    fn publish_sample(env: &Env, emitter: &Address) {
        env.as_contract(emitter, || {
            crate::publish_event!(
                env,
                NewNullifierEvent {
                    nullifier: U256::from_u32(env, 7),
                }
            );
            crate::publish_event!(
                env,
                NewCommitmentEvent {
                    commitment: U256::from_u32(env, 8),
                    index: 0,
                    encrypted_output: Bytes::from_array(env, &[0xab; 4]),
                }
            );
        });
    }

    #[test]
    fn a_contract_that_published_nothing_reports_the_empty_chain() {
        let env = Env::default();
        let emitter = env.register(Emitter, ());

        let chain = env.as_contract(&emitter, || event_chain(&env));

        assert_eq!(chain, EventChain::empty(&env));
        assert_eq!(chain.hash.to_array(), [0; 32]);
    }

    #[test]
    fn the_chain_matches_the_events_as_a_client_receives_them() {
        let env = Env::default();
        let emitter = env.register(Emitter, ());

        publish_sample(&env, &emitter);

        let recorded = env.events().all().filter_by_contract(&emitter);
        assert_eq!(recorded.events().len(), 2);
        assert_eq!(
            env.as_contract(&emitter, || event_chain(&env)),
            fold(&env, &EventChain::empty(&env), recorded.events())
        );
    }

    /// Clients check their fold against this vector, so a change to the
    /// encoding fails here before it reaches a deployment.
    #[test]
    fn the_sample_events_hash_to_the_pinned_vector() {
        let env = Env::default();
        let emitter = env.register(Emitter, ());

        publish_sample(&env, &emitter);

        let chain = env.as_contract(&emitter, || event_chain(&env));
        assert_eq!(chain.count, 2);
        assert_eq!(chain.hash, BytesN::from_array(&env, &PINNED_SAMPLE_HASH));
    }

    /// `561af32ec8f431764a3a12f04018cfb0e07640dc1bba75e1f5a766bf7dda8e9d`: the
    /// chain after [`publish_sample`]'s two events.
    const PINNED_SAMPLE_HASH: [u8; 32] = [
        0x56, 0x1a, 0xf3, 0x2e, 0xc8, 0xf4, 0x31, 0x76, 0x4a, 0x3a, 0x12, 0xf0, 0x40, 0x18, 0xcf,
        0xb0, 0xe0, 0x76, 0x40, 0xdc, 0x1b, 0xba, 0x75, 0xe1, 0xf5, 0xa7, 0x66, 0xbf, 0x7d, 0xda,
        0x8e, 0x9d,
    ];
}
