//! The running hash a contract keeps over every event it publishes.
//!
//! The pool, the GVK pool and the public key registry keep
//! `soroban_utils::event_chain` on chain: a count, and a SHA-256 extended by
//! each event as
//!
//! ```text
//! hash' = sha256(hash || xdr(ScVal::Vec(topics)) || xdr(value))
//! ```
//!
//! A wallet folds the events it syncs the same way and compares the result
//! with the contract's `event_chain()`. The fold works on the bytes the RPC
//! served, decoding nothing but base64, so an event withheld, altered, added
//! or reordered by whoever served it changes the hash.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use stellar_xdr::ScVal;

/// `SCV_VEC`, the `ScVal` discriminant of a vector.
const SCV_VEC: u32 = 16;

/// A contract's event chain after its first `count` events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventChain {
    /// How many events the chain covers.
    pub count: u64,
    /// The running hash after the last of them.
    pub hash: [u8; 32],
}

impl EventChain {
    /// The chain of a contract that has published nothing.
    pub const EMPTY: Self = Self {
        count: 0,
        hash: [0; 32],
    };

    /// Extends the chain with one event as the RPC serves it: each topic and
    /// the value as base64 `ScVal` XDR.
    ///
    /// The topics are hashed as the XDR of one `ScVal::Vec` holding them: its
    /// discriminant, the present flag of its optional body, its length, then
    /// each topic's XDR.
    ///
    /// # Errors
    ///
    /// Returns an error if a topic or the value is not base64, there are more
    /// than `u32::MAX` topics, or the count overflows.
    pub fn extend<T: AsRef<str>>(&self, topics: &[T], value: &str) -> Result<Self> {
        let topics = topics
            .iter()
            .map(|topic| STANDARD.decode(topic.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .context("an event topic is not base64")?;
        let value = STANDARD
            .decode(value)
            .context("an event value is not base64")?;
        let len = u32::try_from(topics.len()).context("too many event topics")?;

        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        hasher.update(SCV_VEC.to_be_bytes());
        hasher.update(1u32.to_be_bytes());
        hasher.update(len.to_be_bytes());
        for topic in &topics {
            hasher.update(topic);
        }
        hasher.update(&value);
        Ok(Self {
            count: self
                .count
                .checked_add(1)
                .context("the event count overflows")?,
            hash: hasher.finalize().into(),
        })
    }

    /// Compares this chain, which the wallet folded from the events it synced,
    /// with the chain the contract `published`.
    pub fn check(&self, published: &EventChain) -> EventChainCheck {
        let (synced, published_count) = (self.count, published.count);
        match synced.cmp(&published_count) {
            Ordering::Less => EventChainCheck::Behind {
                synced,
                published: published_count,
            },
            Ordering::Equal if self.hash == published.hash => EventChainCheck::Matches,
            _ => EventChainCheck::Differs {
                synced,
                published: published_count,
            },
        }
    }

    /// Decodes what a contract's `event_chain()` returns: a map of `count`, a
    /// `u64`, and `hash`, 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not such a map.
    pub fn from_scval(value: &ScVal) -> Result<Self> {
        let ScVal::Map(Some(entries)) = value else {
            bail!("event_chain() returned {value:?}, not a map");
        };
        let (mut count, mut hash) = (None, None);
        for entry in entries.iter() {
            match (&entry.key, &entry.val) {
                (ScVal::Symbol(key), ScVal::U64(n)) if key.0.as_slice() == b"count" => {
                    count = Some(*n);
                }
                (ScVal::Symbol(key), ScVal::Bytes(bytes)) if key.0.as_slice() == b"hash" => {
                    hash = Some(<[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                        anyhow!("event_chain() returned a hash of {} bytes", bytes.len())
                    })?);
                }
                _ => bail!("event_chain() returned an unexpected entry {entry:?}"),
            }
        }
        Ok(Self {
            count: count.context("event_chain() returned no count")?,
            hash: hash.context("event_chain() returned no hash")?,
        })
    }
}

/// How the wallet's event chain for a contract compares with the contract's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventChainCheck {
    /// The wallet holds the events the contract published, all of them.
    Matches,
    /// The wallet holds fewer events than the contract published.
    Behind { synced: u64, published: u64 },
    /// The wallet holds more events than the contract published, or as many
    /// but different ones.
    Differs { synced: u64, published: u64 },
}

#[cfg(test)]
mod tests {
    use super::{EventChain, EventChainCheck};
    use anyhow::Result;
    use stellar_xdr::{
        Limits, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal, UInt256Parts, WriteXdr,
    };

    fn b64(val: &ScVal) -> Result<String> {
        Ok(val.to_xdr_base64(Limits::none())?)
    }

    fn symbol(s: &str) -> Result<ScVal> {
        Ok(ScVal::Symbol(ScSymbol(s.try_into()?)))
    }

    fn u256(lo_lo: u64) -> ScVal {
        ScVal::U256(UInt256Parts {
            hi_hi: 0,
            hi_lo: 0,
            lo_hi: 0,
            lo_lo,
        })
    }

    /// The two events `soroban_utils::event_chain` pins its vector with, as
    /// the RPC serves them: `(topics, value)`.
    fn sample_events() -> Result<[(Vec<String>, String); 2]> {
        let commitment_data = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: symbol("encrypted_output")?,
                    val: ScVal::Bytes(ScBytes(vec![0xab; 4].try_into()?)),
                },
                ScMapEntry {
                    key: symbol("index")?,
                    val: ScVal::U32(0),
                },
            ]
            .try_into()?,
        )));
        Ok([
            (
                vec![b64(&symbol("new_nullifier_event")?)?, b64(&u256(7))?],
                b64(&ScVal::Map(Some(ScMap(Vec::new().try_into()?))))?,
            ),
            (
                vec![b64(&symbol("new_commitment_event")?)?, b64(&u256(8))?],
                b64(&commitment_data)?,
            ),
        ])
    }

    fn fold(events: &[(Vec<String>, String)]) -> Result<EventChain> {
        events
            .iter()
            .try_fold(EventChain::EMPTY, |chain, (topics, value)| {
                chain.extend(topics, value)
            })
    }

    /// The vector `soroban_utils::event_chain` pins for the contracts, so the
    /// wallet and the contracts cannot drift apart.
    #[test]
    fn the_sample_events_fold_to_the_contracts_pinned_vector() -> Result<()> {
        let chain = fold(&sample_events()?)?;

        assert_eq!(chain.count, 2);
        assert_eq!(
            hex::encode(chain.hash),
            "561af32ec8f431764a3a12f04018cfb0e07640dc1bba75e1f5a766bf7dda8e9d"
        );
        Ok(())
    }

    #[test]
    fn reordered_events_fold_to_another_hash() -> Result<()> {
        let [first, second] = sample_events()?;

        assert_ne!(
            fold(&[first.clone(), second.clone()])?.hash,
            fold(&[second, first])?.hash
        );
        Ok(())
    }

    #[test]
    fn an_event_that_is_not_base64_does_not_fold() {
        assert!(
            EventChain::EMPTY
                .extend(&["commitment"], "dGVzdA==")
                .is_err()
        );
        assert!(
            EventChain::EMPTY
                .extend::<&str>(&[], "not base64!")
                .is_err()
        );
    }

    #[test]
    fn a_chain_checks_against_the_published_one_by_count_then_hash() -> Result<()> {
        let [first, second] = sample_events()?;
        let one = fold(std::slice::from_ref(&first))?;
        let two = fold(&[first.clone(), second.clone()])?;
        let other_two = fold(&[second, first])?;

        assert_eq!(two.check(&two), EventChainCheck::Matches);
        assert_eq!(
            one.check(&two),
            EventChainCheck::Behind {
                synced: 1,
                published: 2
            }
        );
        assert_eq!(
            other_two.check(&two),
            EventChainCheck::Differs {
                synced: 2,
                published: 2
            }
        );
        assert_eq!(
            two.check(&one),
            EventChainCheck::Differs {
                synced: 2,
                published: 1
            }
        );
        Ok(())
    }

    #[test]
    fn the_contracts_return_value_decodes() -> Result<()> {
        let value = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: symbol("count")?,
                    val: ScVal::U64(2),
                },
                ScMapEntry {
                    key: symbol("hash")?,
                    val: ScVal::Bytes(ScBytes(vec![9; 32].try_into()?)),
                },
            ]
            .try_into()?,
        )));

        assert_eq!(
            EventChain::from_scval(&value)?,
            EventChain {
                count: 2,
                hash: [9; 32]
            }
        );
        assert!(EventChain::from_scval(&ScVal::U64(2)).is_err());
        Ok(())
    }
}
