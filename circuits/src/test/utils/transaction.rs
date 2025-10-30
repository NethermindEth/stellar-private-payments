use zkhash::fields::bn256::FpBN256 as Scalar;

use super::general::poseidon2_hash3;

/// commitment = Poseidon2(3)(amount, pubkey, blinding)
#[inline]
pub(crate) fn commitment(amount: Scalar, pubkey: Scalar, blinding: Scalar) -> Scalar {
    poseidon2_hash3(amount, pubkey, blinding)
}

/// nullifier = Poseidon2(3)(commitment, pathIndices, signature)
#[inline]
pub(crate) fn nullifier(commitment: Scalar, path_indices: Scalar, signature: Scalar) -> Scalar {
    poseidon2_hash3(commitment, path_indices, signature)
}
