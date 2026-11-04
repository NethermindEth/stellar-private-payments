//! Synchronous private-pool API
//!
//! **Do not call this from inside an existing Tokio runtime**. It will
//! intentionally panic.
//! Use [`crate::PrivatePool`] with `.await` in async code instead.
//!
//! Construct sessions via [`Client`] → [`Account`] → [`PrivatePool`].

mod account;
mod client;
mod disclosure;
mod operator;
mod pool;
pub(crate) mod runtime;

pub use account::Account;
pub use client::Client;
pub use disclosure::verify_disclosure_receipt;
pub use operator::{
    AllowlistOperator, BlocklistOperator, Envelopes, GvkAudit, GvkAuthority, PoolAdmin,
};
pub use pool::PrivatePool;
