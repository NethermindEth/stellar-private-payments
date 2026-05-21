use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use prover::merkle::MerklePrefixTree;
use types::Field;

const DEPTH: u32 = 32;
const LEAF_COUNTS: [u32; 6] = [16, 64, 256, 1_024, 4_096, 16_384];

fn deterministic_leaves(count: u32) -> Vec<Field> {
    let mut leaves = Vec::with_capacity(usize::try_from(count).expect("leaf count"));

    for i in 0..count {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(u64::from(i) + 1).to_le_bytes());
        leaves.push(Field::try_from_le_bytes(bytes).expect("field"));
    }

    leaves
}

fn build_prefix_tree_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_prefix_tree_build");

    for leaf_count in LEAF_COUNTS {
        let leaves = deterministic_leaves(leaf_count);
        group.throughput(Throughput::Elements(u64::from(leaf_count)));
        group.bench_with_input(
            BenchmarkId::from_parameter(leaf_count),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let tree =
                        MerklePrefixTree::new(DEPTH, black_box(leaves)).expect("tree creation");
                    black_box(tree.into_built());
                });
            },
        );
    }

    group.finish();
}

fn proof_from_built_tree_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_prefix_tree_proof");

    for leaf_count in LEAF_COUNTS {
        let leaves = deterministic_leaves(leaf_count);
        let built = MerklePrefixTree::new(DEPTH, &leaves)
            .expect("tree creation")
            .into_built();
        let proof_index = leaf_count / 2;

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(leaf_count),
            &proof_index,
            |b, proof_index| {
                b.iter(|| {
                    black_box(built.proof(black_box(*proof_index)).expect("proof"));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    build_prefix_tree_bench,
    proof_from_built_tree_bench
);
criterion_main!(benches);
