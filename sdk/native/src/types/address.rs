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
/// There is deliberately no conversion to or from [`NoteOwnerAddress`], and
/// neither type is constructible from a bare string by `From`. A caller that
/// wants both to be the same account names each type:
///
/// ```
/// use stellar_private_payments::types::{NoteOwnerAddress, SignerAddress};
///
/// let owner = NoteOwnerAddress::new("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF");
/// let signer = SignerAddress::new(owner.as_str());
/// assert_eq!(owner.as_str(), signer.as_str());
/// ```
///
/// Crossing without naming the destination does not compile:
///
/// ```compile_fail
/// use stellar_private_payments::types::{NoteOwnerAddress, SignerAddress};
///
/// let owner = NoteOwnerAddress::new("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF");
/// let signer: SignerAddress = owner.into_string().into();
/// ```
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

        // No `From<String>`/`From<&str>`: they let an owner-derived value
        // become a `SignerAddress` through an `.into()` naming neither type.

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

    /// `EXISTS` is true iff `T: From<F>`: inherent associated items win over
    /// trait ones, so it falls back to `NoConversion` when the bound fails.
    struct ConversionProbe<F, T>(core::marker::PhantomData<(F, T)>);

    trait NoConversion {
        const EXISTS: bool = false;
    }

    impl<F, T> NoConversion for ConversionProbe<F, T> {}

    impl<F, T: From<F>> ConversionProbe<F, T> {
        const EXISTS: bool = true;
    }

    // `const _` rather than `#[test]`: resolved at type-check, so a reinstated
    // impl fails to compile rather than reporting a test failure.
    const _: () = assert!(
        ConversionProbe::<&str, String>::EXISTS,
        "probe is broken: it fails to see String: From<&str>"
    );

    const _: () = assert!(
        !ConversionProbe::<NoteOwnerAddress, SignerAddress>::EXISTS,
        "a note owner must not convert into a signing account"
    );
    const _: () = assert!(
        !ConversionProbe::<SignerAddress, NoteOwnerAddress>::EXISTS,
        "a signing account must not convert into a note owner"
    );

    const _: () = assert!(!ConversionProbe::<String, NoteOwnerAddress>::EXISTS);
    const _: () = assert!(!ConversionProbe::<&str, NoteOwnerAddress>::EXISTS);
    const _: () = assert!(!ConversionProbe::<String, SignerAddress>::EXISTS);
    const _: () = assert!(!ConversionProbe::<&str, SignerAddress>::EXISTS);

    #[test]
    fn crossing_deliberately_still_works_and_names_the_target_type() {
        let owner = NoteOwnerAddress::new(ADDR);
        let signer = SignerAddress::new(owner.as_str());
        assert_eq!(owner.as_str(), signer.as_str());
    }
}
