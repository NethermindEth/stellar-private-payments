//! Correlation ID generation and propagation for the native SDK.
//!
//! The shared implementation lives in the `types` crate so native and web
//! use one; re-exported here for `crate::correlation::…` call sites.
//! [`types::CorrelationIdLayer`] must be part of the installed subscriber
//! (see [`crate::init_tracing`]) for [`correlation_id_or_new`] to correctly
//! inherit an ambient ID instead of always minting a new one.

pub use types::correlation_id_or_new;
