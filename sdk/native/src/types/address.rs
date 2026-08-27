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

        // Deliberately NO `From<String>` or `From<&str>`. With both types
        // convertible from a string, an owner-derived value could become a
        // SignerAddress through an unremarkable `.into()` naming neither type.
        // `new` being the only constructor means every crossing writes the
        // destination type down at the site where it happens.

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

    /// Detects whether `T: From<F>` holds, on stable, with no dependency.
    ///
    /// Inherent associated items take priority over trait ones, so
    /// `ConversionProbe::<F, T>::EXISTS` resolves to the inherent `true` when
    /// the `T: From<F>` bound is satisfiable and falls back to the trait's
    /// `false` when it is not.
    ///
    /// This is what turns the invariant from a comment into a check. The
    /// test this replaced asserted only that the two types hold equal
    /// strings — it conceded in its own doc comment that the real guarantee
    /// was unenforced and would need a `trybuild` dev-dependency. It does
    /// not: nothing was added to Cargo.toml.
    struct ConversionProbe<F, T>(core::marker::PhantomData<(F, T)>);

    trait NoConversion {
        const EXISTS: bool = false;
    }

    impl<F, T> NoConversion for ConversionProbe<F, T> {}

    impl<F, T: From<F>> ConversionProbe<F, T> {
        const EXISTS: bool = true;
    }

    // The assertions below are `const _: ()` rather than `#[test]` bodies on
    // purpose. `EXISTS` is resolved during type-checking, so a violation can
    // be caught when the crate is *built* rather than when someone remembers
    // to run the suite — reinstating any of these impls fails compilation,
    // which is the same enforcement a trybuild compile-fail test would give
    // and the reason no dev-dependency was added for one. It also keeps
    // clippy::assertions_on_constants quiet without an allow: these really
    // are constants, and saying so in the syntax is more honest than
    // suppressing the lint that noticed it.

    // Guards the guards: a probe that silently stopped resolving would make
    // every assertion below vacuously true, which is the failure mode that
    // matters most for a test whose whole job is to catch a future edit.
    const _: () = assert!(
        ConversionProbe::<&str, String>::EXISTS,
        "probe is broken: it fails to see String: From<&str>"
    );

    // The invariant the whole split rests on. A `From` impl either way would
    // let a mislabelled call site compile and then sign as the wrong account
    // at runtime, which is precisely what these two types exist to prevent.
    const _: () = assert!(
        !ConversionProbe::<NoteOwnerAddress, SignerAddress>::EXISTS,
        "a note owner must not convert into a signing account"
    );
    const _: () = assert!(
        !ConversionProbe::<SignerAddress, NoteOwnerAddress>::EXISTS,
        "a signing account must not convert into a note owner"
    );

    // `From<String>`/`From<&str>` were how the two types leaked into each
    // other without either being named: `owner.as_str()` handed to anything
    // taking `impl Into<SignerAddress>` crossed the boundary in a `.into()`
    // that mentioned neither type. `new` is now the only constructor, so a
    // crossing has to write its destination down.
    const _: () = assert!(!ConversionProbe::<String, NoteOwnerAddress>::EXISTS);
    const _: () = assert!(!ConversionProbe::<&str, NoteOwnerAddress>::EXISTS);
    const _: () = assert!(!ConversionProbe::<String, SignerAddress>::EXISTS);
    const _: () = assert!(!ConversionProbe::<&str, SignerAddress>::EXISTS);

    #[test]
    fn crossing_deliberately_still_works_and_names_the_target_type() {
        // Refusing the implicit path must not refuse the legitimate one:
        // while the two are in fact the same account, callers do need to
        // build both from one string. That is allowed — it just cannot be
        // done without saying which type is being built.
        let owner = NoteOwnerAddress::new(ADDR);
        let signer = SignerAddress::new(owner.as_str());
        assert_eq!(owner.as_str(), signer.as_str());
    }
}
