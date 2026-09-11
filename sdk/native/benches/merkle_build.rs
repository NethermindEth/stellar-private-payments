//! What `build_membership_proof` and `build_pool_inputs` actually cost.
//!
//! Both call `MerklePrefixTree::new(depth, &leaves).into_built()` once per transaction
//! (`sdk/native/src/transact.rs:236` for the ASP membership tree, `:313` for the pool tree),
//! so the whole prefix is re-hashed every time. Issue #167 asks how many leaves correspond to
//! how much build time before deciding whether to build once and append.
//!
//! Depths are the ones the SDK actually uses, not round numbers.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use stellar_private_payments::zk::merkle::MerklePrefixTree;
use stellar_private_payments::types::Field;

/// Distinct leaves. Values do not affect the shape of the work, only the count does, but
/// making them distinct avoids any chance of a hash cache flattering the result.
fn leaves(n: usize) -> Vec<Field> {
    (0..n)
        .map(|i| {
            let mut le = [0u8; 32];
            le[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            Field::try_from_le_bytes(le).expect("field element")
        })
        .collect()
}

fn bench_build(c: &mut Criterion) {
    // ASP membership tree and pool tree depths, read from the SDK rather than assumed.
    // Depths as actually deployed, from `deployments/scripts/deploy.sh`: --asp-levels 10,
    // --pool-levels 20. Not the 8 and 10 the contract and e2e tests use.
    for (label, depth) in [("asp_membership_d10", 10u32), ("pool_d20", 20u32)] {
        let mut group = c.benchmark_group(format!("prefix_tree_build/{label}"));
        for n in [0usize, 1, 16, 256, 1_024, 4_096, 16_384] {
            let l = leaves(n);
            group.throughput(Throughput::Elements(n.max(1) as u64));
            group.bench_with_input(BenchmarkId::from_parameter(n), &l, |b, l| {
                b.iter(|| {
                    MerklePrefixTree::new(depth, l)
                        .expect("new")
                        .into_built()
                })
            });
        }
        group.finish();
    }
}

/// `new` on its own, to separate the empty-subtree chain from the level walk. If `new` is flat
/// and `into_built` is linear then caching the built tree is the only thing worth doing.
fn bench_new_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("prefix_tree_new_only");
    for n in [0usize, 1_024, 16_384] {
        let l = leaves(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &l, |b, l| {
            b.iter(|| MerklePrefixTree::new(20, l).expect("new"))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_build, bench_new_only);
criterion_main!(benches);
