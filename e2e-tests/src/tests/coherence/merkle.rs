//! Circuits merkle helpers must stay bit-identical to the SDK prover copy.
//! Coherence test guarded at production depth 10 (1024 leaves).

use circuits::core::merkle as circuits_merkle;
use stellar_private_payments::zk::merkle as prover_merkle;
use zkhash::fields::bn256::FpBN256 as Scalar;

#[test]
fn merkle_helpers_match_prover() {
    // Production Merkle tree depth is 10 (1024 leaves).
    let leaves: Vec<Scalar> = (0..1024).map(Scalar::from).collect();

    assert_eq!(
        circuits_merkle::merkle_root(leaves.clone()),
        prover_merkle::merkle_root(leaves.clone()),
        "merkle_root diverged between circuits copy and prover at depth 10 (1024 leaves)"
    );

    // Test proof generation across representative leaf indices at full depth 10
    let test_indices = [0, 1, 7, 511, 512, 1023];
    for idx in test_indices {
        let (c_path, c_indices, c_levels) = circuits_merkle::merkle_proof(&leaves, idx);
        let (p_path, p_indices, p_levels) = prover_merkle::merkle_proof_internal(&leaves, idx);
        assert_eq!(c_levels, 10, "expected production depth 10 at idx={idx}");
        assert_eq!(c_levels, p_levels, "levels diverged at idx={idx}");
        assert_eq!(c_indices, p_indices, "path indices diverged at idx={idx}");
        assert_eq!(c_path, p_path, "path elements diverged at idx={idx}");
    }

    let a = Scalar::from(11u64);
    let b = Scalar::from(22u64);
    assert_eq!(
        circuits_merkle::poseidon2_compression(a, b),
        prover_merkle::poseidon2_compression(a, b),
        "poseidon2_compression diverged"
    );
}
