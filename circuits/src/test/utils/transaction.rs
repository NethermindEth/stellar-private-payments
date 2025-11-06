use zkhash::fields::bn256::FpBN256 as Scalar;

use super::general::poseidon2_hash3;

/// commitment = Poseidon2(3)(amount, pubkey, blinding)
#[inline]
pub(crate) fn commitment(amount: Scalar, pubkey: Scalar, blinding: Scalar) -> Scalar {
    poseidon2_hash3(amount, pubkey, blinding, Some(Scalar::from(1))) // We use 1 as domain separation for Commitment
}

/// nullifier = Poseidon2(3)(commitment, pathIndices, signature)
#[inline]
pub(crate) fn nullifier(commitment: Scalar, path_indices: Scalar, signature: Scalar) -> Scalar {
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

// Generate a random-looking commitment (not tied to a real privkey; fine for filler leaves)
fn rand_commitment(rng: &mut Rng64) -> Scalar {
    let amount = Scalar::from(rng.next() % 1_000_000); // keep small-ish
    let pubkey = Scalar::from(rng.next());
    let blinding = Scalar::from(rng.next());
    // Reuse your commitment function
    commitment(amount, pubkey, blinding)
}

/// Build a pre-populated leaves vector of length 2^levels.
/// - `exclude_indices`: do not populate these, we’ll overwrite them with the case’s inputs.
/// - `fill_count`: how many random notes to sprinkle in.
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
