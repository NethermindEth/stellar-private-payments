//! Integration Tests for Privacy Pool contracts.
//!
//! This crate contains integration tests that verify cross-contract interactions
//! between the Pool, ASP Membership, and ASP Non-Membership contracts.
//!
//! These tests deploy all contracts programmatically and verify they work together
//! as intended.

#![cfg(test)]

mod pool_asp_integration;
