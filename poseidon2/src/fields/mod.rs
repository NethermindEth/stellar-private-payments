#[allow(clippy::too_many_arguments)]
#[allow(clippy::derived_hash_with_manual_eq)]
#[allow(non_local_definitions)]
pub mod babybear;
#[allow(clippy::too_many_arguments)]
#[allow(clippy::derived_hash_with_manual_eq)]
#[allow(non_local_definitions)]
pub mod bls12;
#[allow(clippy::too_many_arguments)]
#[allow(clippy::derived_hash_with_manual_eq)]
#[allow(non_local_definitions)]
pub mod bn256;
#[allow(clippy::too_many_arguments)]
#[allow(clippy::derived_hash_with_manual_eq)]
#[allow(non_local_definitions)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::derived_hash_with_manual_eq)]
pub mod goldilocks;
#[allow(non_local_definitions)]
pub mod pallas;
pub mod utils;
#[allow(non_local_definitions)]
pub mod vesta;

// sage:
// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// F = GF(p)
// F.multiplicative_generator()
// F(7).is_primitive_root()
