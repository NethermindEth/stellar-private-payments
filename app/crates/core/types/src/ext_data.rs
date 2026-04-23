extern crate alloc;

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

use crate::ExtAmount;

/// External data associated with a pool transaction.
///
/// This mirrors the Soroban `ExtData` struct shape used on-chain for
/// `extDataHash`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtData {
    /// Recipient Stellar address / contract id (opaque here).
    pub recipient: String,
    /// Signed external amount (stroops).
    /// - Deposit: `ext_amount > 0`
    /// - Withdraw: `ext_amount < 0`
    /// - Transfer: `ext_amount = 0`
    pub ext_amount: ExtAmount,
    /// Encrypted note data for output 0 (for recipient scanning/decryption).
    pub encrypted_output0: Vec<u8>,
    /// Encrypted note data for output 1 (for recipient scanning/decryption).
    pub encrypted_output1: Vec<u8>,
}
