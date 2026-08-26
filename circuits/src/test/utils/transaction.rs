use ark_bn254::Fr as Scalar;

use super::{general::poseidon2_hash3, merkle_tree::zero_leaf};

/// Compute a commitment using Poseidon2 hash
///
/// Computes `commitment = Poseidon2(amount, pubkey, blinding)` with
/// domain separation value 1.
///
/// # Arguments
///
/// * `amount` - Transaction amount
/// * `pubkey` - Public key
/// * `blinding` - Blinding factor
///
/// # Returns
///
/// Returns the commitment scalar value.
#[inline]
pub fn commitment(amount: Scalar, pubkey: Scalar, blinding: Scalar) -> Scalar {
    poseidon2_hash3(amount, pubkey, blinding, Some(Scalar::from(1))) // We use 1 as domain separation for Commitment
}

/// Compute a nullifier using Poseidon2 hash
///
/// Computes `nullifier = Poseidon2(commitment, pathIndices, signature)` with
/// domain separation value 2.
///
/// # Arguments
///
/// * `commitment` - Commitment scalar value
/// * `path_indices` - Merkle path indices
/// * `signature` - Signature scalar value
///
/// # Returns
///
/// Returns the nullifier scalar value.
#[inline]
pub fn nullifier(commitment: Scalar, path_indices: Scalar, signature: Scalar) -> Scalar {
    poseidon2_hash3(commitment, path_indices, signature, Some(Scalar::from(2))) // We use 2 as domain separation for Nullifier
}

// --- tiny deterministic RNG (xorshift64) ---
#[derive(Clone)]
struct Rng64(u64);
impl Rng64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Generate a random-looking commitment (not tied to a real private key)
///
/// Creates a commitment using random values
/// Suitable for filler leaves in test scenarios.
///
/// # Arguments
///
/// * `rng` - Mutable reference to the random number generator
///
/// # Returns
///
/// Returns a randomly generated commitment scalar value.
fn rand_commitment(rng: &mut Rng64) -> Scalar {
    let amount = Scalar::from(rng.next() % 1_000_000); // keep small-ish
    let pubkey = Scalar::from(rng.next());
    let blinding = Scalar::from(rng.next());
    // Reuse your commitment function
    commitment(amount, pubkey, blinding)
}

/// Build a pre-populated leaves vector of length 2^levels
///
/// Creates a vector of leaves for a Merkle tree, pre-populating some positions
/// with random commitments while excluding specified indices. The excluded
/// indices are reserved for overwriting with test case inputs.
///
/// # Arguments
///
/// * `levels` - Number of tree levels
/// * `seed` - Seed value for the random number generator
/// * `exclude_indices` - Indices to leave empty (will be overwritten with test
///   inputs)
/// * `fill_count` - Number of random commitments to place in the tree for
///   testing cases
///
/// # Returns
///
/// Returns a vector of scalar values representing the leaves, with zeros for
/// empty positions and random commitments for filled positions.
pub fn prepopulated_leaves(
    levels: usize,
    seed: u64,
    exclude_indices: &[usize],
    fill_count: usize,
) -> Vec<Scalar> {
    let n = 1usize << levels;
    let mut leaves = vec![Scalar::from(0u64); n];

    let capacity = n.saturating_sub(exclude_indices.len());
    assert!(
        fill_count <= capacity,
        "prepopulated_leaves: fill_count ({fill_count}) exceeds available capacity ({capacity}), causing an infinite loop",
    );

    let mut rng = Rng64::new(seed);
    let mut placed = 0usize;

    while placed < fill_count {
        let idx = usize::try_from(rng.next())
            .expect("cast to usize failed in prepopulated_leaves")
            .checked_rem(n)
            .expect("n must not be zero");
        if exclude_indices.contains(&idx) || leaves[idx] != Scalar::from(0u64) {
            continue;
        }

        leaves[idx] = rand_commitment(&mut rng);
        placed = placed.checked_add(1).expect("placed counter overflowed");
    }

    leaves
}

/// Build the filled prefix of a Merkle tree
///
/// Every position in `0..prefix_len` gets a random commitment except
/// `exclude_indices`, which keep the zero leaf for the caller to overwrite.
///
/// # Arguments
///
/// * `seed` - Seed value for the random number generator
/// * `exclude_indices` - Indices to leave at the zero leaf
/// * `prefix_len` - Number of leaves the tree holds
///
/// # Panics
///
/// Panics if any excluded index falls outside the prefix.
pub fn prepopulated_prefix(seed: u64, exclude_indices: &[usize], prefix_len: usize) -> Vec<Scalar> {
    assert!(
        exclude_indices.iter().all(|&idx| idx < prefix_len),
        "exclude_indices must fall inside a prefix of {prefix_len} leaves",
    );

    let mut rng = Rng64::new(seed);
    (0..prefix_len)
        .map(|idx| {
            if exclude_indices.contains(&idx) {
                zero_leaf()
            } else {
                rand_commitment(&mut rng)
            }
        })
        .collect()
}
