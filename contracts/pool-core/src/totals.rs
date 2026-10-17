//! Notes and fees totals, kept in the pool's instance.
//!
//! The pool's token balance is the two totals plus any tokens sent to it
//! directly, and the notes total never goes below zero.

use soroban_sdk::{Address, Env, contracttype};

/// Errors from the totals functions.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A total is not stored.
    NotInitialized,
    /// A call would take the notes total below zero.
    NotesTotalExceeded,
    /// A total would overflow `i128`.
    Overflow,
    /// A claim is negative, above the fees total, or paid to the pool.
    InvalidClaimAmount,
}

/// Storage keys for the two totals, both instance keys.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TotalsDataKey {
    /// Sum of the values of the pool's unspent notes
    NotesTotal,
    /// Fees the pool has collected and not paid out
    FeesTotal,
}

/// Stores zero as both totals.
pub fn init(env: &Env) {
    let instance = env.storage().instance();
    instance.set(&TotalsDataKey::NotesTotal, &0i128);
    instance.set(&TotalsDataKey::FeesTotal, &0i128);
}

/// Adds `net` to the notes total and `fee` to the fees total.
///
/// `net` is what the call adds to notes: its `ext_amount` minus the fee.
/// Writes neither total unless both sums succeed.
///
/// # Errors
///
/// Returns [`Error::NotesTotalExceeded`] if the notes total would go below
/// zero, [`Error::Overflow`] if either sum overflows, and
/// [`Error::NotInitialized`] if a total is not stored.
pub fn record(env: &Env, net: i128, fee: i128) -> Result<(), Error> {
    let instance = env.storage().instance();
    let notes = instance
        .get::<_, i128>(&TotalsDataKey::NotesTotal)
        .ok_or(Error::NotInitialized)?
        .checked_add(net)
        .ok_or(Error::Overflow)?;
    if notes < 0 {
        return Err(Error::NotesTotalExceeded);
    }
    let fees = fees_total(env)?.checked_add(fee).ok_or(Error::Overflow)?;
    instance.set(&TotalsDataKey::NotesTotal, &notes);
    instance.set(&TotalsDataKey::FeesTotal, &fees);
    Ok(())
}

/// Subtracts `amount` from the fees total for a claim paid to `to`.
///
/// # Errors
///
/// Returns [`Error::InvalidClaimAmount`] if `amount` is negative or above the
/// fees total or `to` is the pool itself, and [`Error::NotInitialized`] if the
/// fees total is not stored.
pub fn claim(env: &Env, to: &Address, amount: i128) -> Result<(), Error> {
    if *to == env.current_contract_address() {
        return Err(Error::InvalidClaimAmount);
    }
    let fees = fees_total(env)?;
    let remaining = fees
        .checked_sub(amount)
        .filter(|_| (0..=fees).contains(&amount))
        .ok_or(Error::InvalidClaimAmount)?;
    env.storage()
        .instance()
        .set(&TotalsDataKey::FeesTotal, &remaining);
    Ok(())
}

/// Returns the fees the pool has collected and not paid out.
///
/// # Errors
///
/// Returns [`Error::NotInitialized`] if the fees total is not stored.
pub fn fees_total(env: &Env) -> Result<i128, Error> {
    env.storage()
        .instance()
        .get(&TotalsDataKey::FeesTotal)
        .ok_or(Error::NotInitialized)
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{contract, contractimpl};

    // Only ever compiled under `cfg(test)`: `pool-core` is a library and must
    // not export a contract from its production build.
    #[contract]
    struct DummyContract;

    #[contractimpl]
    impl DummyContract {
        pub fn noop() {}
    }

    /// Registers a contract holding a notes total of `notes` and a fees total
    /// of `fees`.
    fn register_with_totals(env: &Env, notes: i128, fees: i128) -> Address {
        let id = env.register(DummyContract, ());
        env.as_contract(&id, || {
            let instance = env.storage().instance();
            instance.set(&TotalsDataKey::NotesTotal, &notes);
            instance.set(&TotalsDataKey::FeesTotal, &fees);
        });
        id
    }

    /// Returns the stored notes total and fees total.
    fn totals(env: &Env) -> (Option<i128>, Option<i128>) {
        let instance = env.storage().instance();
        (
            instance.get(&TotalsDataKey::NotesTotal),
            instance.get(&TotalsDataKey::FeesTotal),
        )
    }

    /// The call also moves the notes total, so a write before both sums
    /// succeed would show in it.
    #[test]
    fn record_refuses_to_overflow_the_fees_total() {
        let env = Env::default();
        let id = register_with_totals(&env, 0, i128::MAX - 1);

        env.as_contract(&id, || {
            assert_eq!(record(&env, 7, 2), Err(Error::Overflow));
            assert_eq!(totals(&env), (Some(0), Some(i128::MAX - 1)));
        });
    }

    #[test]
    fn record_refuses_to_overflow_the_notes_total() {
        let env = Env::default();
        let id = register_with_totals(&env, i128::MAX - 1, 0);

        env.as_contract(&id, || {
            assert_eq!(record(&env, 2, 0), Err(Error::Overflow));
            assert_eq!(totals(&env), (Some(i128::MAX - 1), Some(0)));
        });
    }

    #[test]
    fn claim_refuses_the_contract_itself() {
        let env = Env::default();
        let id = register_with_totals(&env, 0, 5);

        env.as_contract(&id, || {
            assert_eq!(claim(&env, &id, 5), Err(Error::InvalidClaimAmount));
            assert_eq!(totals(&env), (Some(0), Some(5)));
        });
    }
}
