//! Client traits for the contracts a pool calls into.
//!
//! `#[contractclient]` generates a caller-side struct and exports nothing, so
//! these are safe to share (see the crate docs for what is not).

use contract_types::{Groth16Error, Groth16Proof};
use soroban_sdk::{Env, U256, Vec, contractclient, crypto::bn254::Bn254Fr};

#[contractclient(crate_path = "soroban_sdk", name = "ASPMembershipClient")]
pub trait ASPMembershipInterface {
    fn get_root(env: Env) -> Result<U256, soroban_sdk::Error>;
}

#[contractclient(crate_path = "soroban_sdk", name = "ASPNonMembershipClient")]
pub trait ASPNonMembershipInterface {
    fn get_root(env: Env) -> Result<U256, soroban_sdk::Error>;
}

#[contractclient(crate_path = "soroban_sdk", name = "CircomGroth16VerifierClient")]
pub trait CircomGroth16VerifierInterface {
    fn verify(
        env: Env,
        proof: Groth16Proof,
        public_inputs: Vec<Bn254Fr>,
    ) -> Result<bool, Groth16Error>;
}
