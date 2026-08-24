//! Distinct types for the two account identities a spend involves.
//!
//! Until these existed, one `String` served three jobs at once: it selected
//! the notes and key material of the account that *owns* them, it became the
//! pool contract's `sender` argument, and it was the transaction envelope's
//! source account. Those are two different identities — the note owner and
//! the signer — and nothing in the type system could tell them apart, so
//! nothing could catch one being passed where the other belonged.
//!
//! `PROPOSALS.md` P-01 (decided 2026-08-24) separates them: the note owner
//! stays A, and a distinct signing account B signs the transaction, sources
//! the envelope and pays the fee. These two types are how that separation is
//! *verified* rather than merely intended — a site labelled wrongly during
//! the split fails to compile instead of silently signing as the wrong
//! account.
//!
//! **There is deliberately no conversion between them.** See the note on
//! [`SignerAddress`].

use core::fmt;

/// The account that owns the notes — **A** in the issue's vocabulary.
///
/// Selects notes and key material from storage, and feeds proof inputs. It
/// never appears in a transaction envelope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NoteOwnerAddress(String);

/// The account that signs and pays — **B** in the issue's vocabulary.
///
/// Becomes the pool contract's `sender` argument, the account whose sequence
/// number is read, the transaction envelope's source, and the address a
/// wallet is asked to sign with. It has no relationship to any note.
///
/// # Why there is no conversion to or from [`NoteOwnerAddress`]
///
/// An `impl From<NoteOwnerAddress> for SignerAddress` would be convenient and
/// would defeat the purpose of both types. The compiler's inability to
/// convert is the mechanism that proves each call site was classified
/// correctly; a conversion turns every mislabelled site back into something
/// that compiles and fails silently at runtime, signing as the note owner
/// while the caller believed otherwise. Callers that legitimately want both
/// to be the same account say so explicitly by constructing each from the
/// same string, which is visible in review.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignerAddress(String);

macro_rules! address_newtype {
    ($t:ty, $what:literal) => {
        impl $t {
            #[doc = concat!("Wraps a strkey address as ", $what, ".")]
            pub fn new(address: impl Into<String>) -> Self {
                Self(address.into())
            }

            /// The address as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the wrapper, returning the inner string.
            pub fn into_string(self) -> String {
                self.0
            }

            /// True when no address was supplied. Callers validate; this type
            /// deliberately does not, because parsing belongs where the
            /// strkey is actually used rather than at every boundary.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $t {
            fn from(address: String) -> Self {
                Self(address)
            }
        }

        impl From<&str> for $t {
            fn from(address: &str) -> Self {
                Self(address.to_string())
            }
        }

        impl AsRef<str> for $t {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

address_newtype!(NoteOwnerAddress, "the note owner");
address_newtype!(SignerAddress, "the signing account");

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    #[test]
    fn round_trips_through_str() {
        let owner = NoteOwnerAddress::new(ADDR);
        assert_eq!(owner.as_str(), ADDR);
        assert_eq!(owner.to_string(), ADDR);
        assert_eq!(owner.clone().into_string(), ADDR);
        assert!(!owner.is_empty());
        assert!(NoteOwnerAddress::new("").is_empty());
    }

    /// The two types are equal-valued but not interchangeable. This test
    /// documents the intent; the guarantee is enforced by the absence of any
    /// `From` impl between them, which a compile-fail test cannot express
    /// without a trybuild dependency this workspace does not carry.
    #[test]
    fn same_string_yields_two_unrelated_values() {
        let owner = NoteOwnerAddress::new(ADDR);
        let signer = SignerAddress::new(ADDR);
        assert_eq!(owner.as_str(), signer.as_str());
    }
}
