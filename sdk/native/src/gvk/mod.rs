//! Admin-side Global View Key audit over indexed pool events.
//!
//! Primary API: [`GvkAudit`]. Cryptographic primitives live in
//! [`crate::zk::gvk`].

mod audit;
mod event;

pub use audit::{
    GvkAudit, GvkOutputSlot, GvkSpentInput, GvkTxAudit, audit_commitment_event,
    audit_nullifier_event,
};
pub use event::GvkEvent;
