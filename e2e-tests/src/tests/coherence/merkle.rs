//! Circuits merkle helpers must stay bit-identical to the SDK prover copy.
//! Dense helpers are compared over a full depth-10 tree, padded ones over a
//! depth-20 prefix.

use ark_bn254::Fr as Scalar;
use ark_ff::{BigInteger, PrimeField};
use circuits::core::merkle as circuits_merkle;
use stellar_private_payments::{types::Field, zk::merkle as prover_merkle};

fn scalar_to_field(s: Scalar) -> Field {
    let bytes = s.into_bigint().to_bytes_be();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Field::try_from_be_bytes(buf).expect("valid field element")
}

#[test]
fn merkle_helpers_match_prover() {
    let leaves: Vec<Scalar> = (0..1024).map(Scalar::from).collect();

    assert_eq!(
        circuits_merkle::merkle_root(leaves.clone()),
        prover_merkle::merkle_root(leaves.clone()),
        "merkle_root diverged between circuits copy and prover over a full depth-10 tree"
    );

    // Proof generation across representative leaf indices of the full tree
    let test_indices = [0, 1, 7, 511, 512, 1023];
    for idx in test_indices {
        let (c_path, c_indices, c_levels) = circuits_merkle::merkle_proof(&leaves, idx);
        let (p_path, p_indices, p_levels) = prover_merkle::merkle_proof_internal(&leaves, idx);
        assert_eq!(c_levels, 10, "expected a full depth-10 tree at idx={idx}");
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

#[test]
fn prefix_tree_matches_prover() {
    const DEPTH: usize = 20;

    let leaves: Vec<Scalar> = (1..=37).map(Scalar::from).collect();
    let fields: Vec<Field> = leaves.iter().copied().map(scalar_to_field).collect();

    let tree = circuits_merkle::PrefixTree::new(&leaves, DEPTH);
    let prover = prover_merkle::MerklePrefixTree::new(
        u32::try_from(DEPTH).expect("depth fits in u32"),
        &fields,
    )
    .expect("prover prefix tree")
    .into_built();

    assert_eq!(
        scalar_to_field(tree.root()),
        prover.root().expect("prover root"),
        "prefix root diverged between circuits copy and prover at depth {DEPTH}"
    );

    for idx in [0usize, 1, 2, 17, 36] {
        let (path, indices) = tree.proof(idx);
        let expected = prover
            .proof(u32::try_from(idx).expect("index fits in u32"))
            .expect("prover proof");

        assert_eq!(
            path.into_iter().map(scalar_to_field).collect::<Vec<_>>(),
            expected.path_elements(),
            "path elements diverged at idx={idx}"
        );
        assert_eq!(
            scalar_to_field(Scalar::from(indices)),
            expected.path_indices(),
            "path indices diverged at idx={idx}"
        );
    }
}

/// The root a freshly deployed pool reports.
#[test]
fn empty_prefix_tree_matches_prover() {
    const DEPTH: usize = 20;

    let tree = circuits_merkle::PrefixTree::new(&[], DEPTH);
    let prover =
        prover_merkle::MerklePrefixTree::new(u32::try_from(DEPTH).expect("depth fits in u32"), &[])
            .expect("prover prefix tree")
            .into_built();

    assert_eq!(
        scalar_to_field(tree.root()),
        prover.root().expect("prover root"),
        "empty-tree root diverged at depth {DEPTH}"
    );
}
