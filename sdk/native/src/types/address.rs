//! Distinct types for the two account identities a spend involves.
//!
//! There is deliberately no conversion between them: see [`SignerAddress`].

use core::fmt;

/// The account that owns the notes.
///
/// Selects notes and key material from storage, and feeds proof inputs. It
/// never appears in a transaction envelope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NoteOwnerAddress(String);

/// The account that signs and pays.
///
/// Becomes the pool contract's `sender` argument, the account whose sequence
/// number is read, the transaction envelope's source, and the address a
/// wallet is asked to sign with. It has no relationship to any note.
///
/// There is deliberately no conversion to or from [`NoteOwnerAddress`]: the
/// compiler's refusal is what keeps each call site classified. A caller that
/// wants both to be the same account constructs each from the same string.
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
