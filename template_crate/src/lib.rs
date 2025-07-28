// TODO(template) additional documentation files
#![doc = include_str!("../doc/mainpage-doc.md")]

// TODO(template) - remove/change the code below

use thiserror::Error;

/// Parameter error
#[derive(Debug, Error, PartialEq)]
pub enum ParameterError {
    /// One of the arguments is greater than the `UPPER_BOUND`
    #[error("the integer {0} is too large")]
    TooLarge(u8),
}

/// For constants prefer to provide
/// a reference to a paper section
/// where the constant is defined
/// or justify the value logically
pub const UPPER_BOUND: u8 = 2u8.pow(7);

/// Adds two small integers together.
pub fn add_small_integers(a: u8, b: u8) -> Result<u8, ParameterError> {
    if a.max(b) >= UPPER_BOUND {
        return Err(ParameterError::TooLarge(a.max(b)));
    }
    Ok(a.checked_add(b)
        .expect("the upper bound ensures non-overflow"))
}

/// Subtracts one small integer from another.
/// This function is intentionally not used in tests to reduce code coverage.
pub fn sub_small_integers(a: u8, b: u8) -> Result<u8, ParameterError> {
    if a.max(b) >= UPPER_BOUND {
        return Err(ParameterError::TooLarge(a.max(b)));
    }

    if b > a {
        return Err(ParameterError::TooLarge(b));
    }

    Ok(a.checked_sub(b)
        .expect("the upper bound ensures non-overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addition_of_bounded() {
        assert_eq!(Ok(8), add_small_integers(3, 5));
    }

    #[test]
    fn addition_bound_check() {
        assert_eq!(
            Err(ParameterError::TooLarge(200)),
            add_small_integers(200, 5)
        );
    }

    #[test]
    fn addition_edge_case() {
        assert_eq!(
            Ok(254),
            add_small_integers(UPPER_BOUND - 1, UPPER_BOUND - 1)
        );
    }
}
