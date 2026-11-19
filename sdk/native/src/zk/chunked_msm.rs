//! Groth16 proof assembly whose multi-scalar multiplications (MSMs) are split
//! over the current rayon pool.
//!
//! # Why this exists
//!
//! `ark-ec` 0.6.0 with its `parallel` feature builds a new rayon pool inside
//! every MSM and unwraps the result (`msm_bigint_wnaf` in
//! `src/scalar_mul/variable_base/mod.rs`). A pool that cannot spawn threads,
//! which is what a wasm32 thread pool is, panics there. `ark-groth16` calls
//! that MSM from private functions, so the only way to prove in parallel on
//! such a pool with unpatched crates is to leave `ark-ec` and `ark-groth16`
//! serial and assemble the proof here: each MSM is cut into chunks, every
//! chunk is a stock serial `msm_bigint`, and the chunks and the independent
//! MSMs run on the pool the caller is already in.
//!
//! **Remove this module**, the `parallel-chunked-msm` feature and the optional
//! `ark-ec` dependency once the SDK depends on an arkworks release whose MSM no
//! longer builds its own pools (fixed on the arkworks main branch after 0.6.0);
//! the `parallel` feature then works on every target.
//!
//! # What it reimplements
//!
//! The functions below follow `ark-groth16` 0.6.0 `src/prover.rs` one to one,
//! and every proof must be the one `ark-groth16` returns for the same proving
//! key, circuit, `r` and `s`:
//!
//! | here                           | `ark_groth16::Groth16`                 |
//! |--------------------------------|----------------------------------------|
//! | `create_random_proof`          | `create_random_proof_with_reduction`   |
//! | `create_proof`                 | `create_proof_with_reduction`          |
//! | `create_proof_with_assignment` | `create_proof_with_assignment`         |
//! | `calculate_coeff`              | `calculate_coeff`                      |
//!
//! The witness map is not reimplemented: it is the public
//! `R1CSToQAP::witness_map`, as in the reference.
//!
//! Differences from the reference, none of which changes a proof:
//! - MSMs go through `msm_bigint_chunked`, and the five of them run
//!   concurrently instead of one after another.
//! - The scalars are converted to big integers up front, so the `h` scalars are
//!   still alive while the other MSMs run.
//! - Three `unwrap`s that cannot fail in proving mode return the error instead.
//!
//! # With the `parallel` feature also on
//!
//! Cargo unifies features, so a build can have both `parallel` and
//! `parallel-chunked-msm`. `parallel` then wins: `prover.rs` proves through
//! `ark-groth16`, exactly as with `parallel` alone, and this module is compiled
//! but only its tests call it. That is correct on native targets. Its functions
//! stay correct there too; every chunk is then a parallel `ark-ec` MSM that
//! builds its own short-lived pools. On wasm32 the combination cannot prove,
//! for the reason above; a threaded wasm32 build must turn on
//! `parallel-chunked-msm` only.

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_groth16::{Proof, ProvingKey, r1cs_to_qap::R1CSToQAP};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_std::rand::RngCore;
use core::ops::AddAssign;
use rayon::prelude::*;

/// The big-integer form of a scalar of `G`, which is what `msm_bigint` takes.
type BigIntOf<G> = <<G as ark_ec::PrimeGroup>::ScalarField as PrimeField>::BigInt;

/// Computes `sum(bases[i] * bigints[i])` like
/// [`VariableBaseMSM::msm_bigint`], with the work split over the current rayon
/// pool: at most one chunk per pool thread, each chunk a stock `msm_bigint`.
///
/// The result is the same group element as one `msm_bigint` call over the
/// whole input, because an MSM is a sum over its terms and the chunks are
/// disjoint and cover them all. Its projective coordinates can differ; they are
/// normalized away when the proof points are converted to affine.
///
/// Like `msm_bigint`, it uses only the first `min(bases.len(),
/// bigints.len())` pairs and returns zero for an empty input.
fn msm_bigint_chunked<G: VariableBaseMSM>(bases: &[G::MulBase], bigints: &[BigIntOf<G>]) -> G {
    msm_bigint_in_chunks(bases, bigints, rayon::current_num_threads())
}

/// [`msm_bigint_chunked`] with an explicit upper bound on the number of
/// chunks. An input shorter than `max_chunks` is split into one-element
/// chunks; a length that `max_chunks` does not divide leaves a shorter last
/// chunk.
fn msm_bigint_in_chunks<G: VariableBaseMSM>(
    bases: &[G::MulBase],
    bigints: &[BigIntOf<G>],
    max_chunks: usize,
) -> G {
    // Cut both to the common length first, so chunk `i` of the bases lines up
    // with chunk `i` of the scalars.
    let size = bases.len().min(bigints.len());
    if size == 0 {
        return G::zero();
    }
    // At least 1, because `size >= 1`.
    let chunk_size = size.div_ceil(max_chunks.max(1));

    bases[..size]
        .par_chunks(chunk_size)
        .zip(bigints[..size].par_chunks(chunk_size))
        .map(|(bases, bigints)| G::msm_bigint(bases, bigints))
        .sum()
}

/// Creates a zero-knowledge Groth16 proof for `circuit`, sampling `r` and `s`
/// from `rng`.
///
/// Equal to `<Groth16<E, QAP> as SNARK>::prove`, which is
/// `Groth16::create_random_proof_with_reduction`: `r` is drawn first, then
/// `s`, both before the circuit is synthesized, so the same `rng` state gives
/// the same proof. `r` and `s` are what makes the proof zero-knowledge: they
/// are used for this proof only and never leave this module.
pub(super) fn create_random_proof<E, QAP, C, R>(
    pk: &ProvingKey<E>,
    circuit: C,
    rng: &mut R,
) -> Result<Proof<E>, SynthesisError>
where
    E: Pairing,
    QAP: R1CSToQAP,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: RngCore,
{
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    create_proof::<E, QAP, C>(circuit, pk, r, s)
}

/// Creates a Groth16 proof for `circuit` with the given randomness.
///
/// Equal to `Groth16::<E, QAP>::create_proof_with_reduction`: the same
/// constraint-system settings (optimize for constraints, proving mode with
/// matrices and without linear-combination assignments), the same witness map
/// and the same split of the assignment into instance (without the leading
/// one) and witness.
pub(super) fn create_proof<E, QAP, C>(
    circuit: C,
    pk: &ProvingKey<E>,
    r: E::ScalarField,
    s: E::ScalarField,
) -> Result<Proof<E>, SynthesisError>
where
    E: Pairing,
    QAP: R1CSToQAP,
    C: ConstraintSynthesizer<E::ScalarField>,
{
    let cs = ConstraintSystem::new_ref();

    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
        generate_lc_assignments: false,
    });

    circuit.generate_constraints(cs.clone())?;
    cs.finalize();

    // As in the reference, an unsatisfied system is only caught in builds with
    // debug assertions; otherwise it yields a proof that does not verify.
    debug_assert!(matches!(cs.is_satisfied(), Ok(true)));

    let h =
        QAP::witness_map::<E::ScalarField, GeneralEvaluationDomain<E::ScalarField>>(cs.clone())?;

    // The reference unwraps these three. None can fail here: `cs` is not
    // `None`, and both assignments exist in proving mode.
    let prover = cs.borrow().ok_or(SynthesisError::MissingCS)?;
    let instance_assignment = prover.instance_assignment()?;
    let witness_assignment = prover.witness_assignment()?;

    Ok(create_proof_with_assignment(
        pk,
        r,
        s,
        &h,
        &instance_assignment[1..],
        witness_assignment,
    ))
}

/// Computes the proof points from the QAP witness `h` and the assignment.
///
/// Equal to `Groth16::create_proof_with_assignment`. Every value is computed
/// from the same inputs by the same formula; only the scheduling differs, see
/// the module docs.
// Group and field arithmetic, as in the reference.
#[allow(clippy::arithmetic_side_effects)]
fn create_proof_with_assignment<E: Pairing>(
    pk: &ProvingKey<E>,
    r: E::ScalarField,
    s: E::ScalarField,
    h: &[E::ScalarField],
    input_assignment: &[E::ScalarField],
    aux_assignment: &[E::ScalarField],
) -> Proof<E> {
    let h_assignment = h.par_iter().map(|s| s.into_bigint()).collect::<Vec<_>>();

    // `[input_assignment, aux_assignment]` as big integers. The reference
    // converts the two parts separately and concatenates them; the `l_query`
    // MSM takes the aux part, which here is the tail of the same vector.
    let assignment = input_assignment
        .par_iter()
        .chain(aux_assignment.par_iter())
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();
    let aux_assignment = &assignment[input_assignment.len()..];

    let r_s_delta_g1 = pk.delta_g1 * (r * s);
    let r_g1 = pk.delta_g1 * r;
    let s_g2 = pk.vk.delta_g2 * s;

    // The five MSMs do not depend on each other. `rayon::join` runs them on
    // the current pool, and each one splits itself over the same pool.
    let ((h_acc, l_aux_acc), (g_a, (g1_b, g2_b))) = rayon::join(
        || {
            rayon::join(
                || msm_bigint_chunked::<E::G1>(&pk.h_query, &h_assignment),
                || msm_bigint_chunked::<E::G1>(&pk.l_query, aux_assignment),
            )
        },
        || {
            rayon::join(
                // A
                || calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment),
                || {
                    rayon::join(
                        // B in G1, needed only for `r * B`. The reference skips
                        // it the same way when `r` is zero.
                        || {
                            if r.is_zero() {
                                E::G1::zero()
                            } else {
                                let s_g1 = pk.delta_g1 * s;
                                calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment)
                            }
                        },
                        // B in G2
                        || calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment),
                    )
                },
            )
        },
    );

    let s_g_a = g_a * s;
    let r_g1_b = g1_b * r;

    let mut g_c = s_g_a;
    g_c += &r_g1_b;
    g_c -= &r_s_delta_g1;
    g_c += &l_aux_acc;
    g_c += &h_acc;

    Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    }
}

/// Computes `initial + query[0] + sum(query[1 + i] * assignment[i]) +
/// vk_param`.
///
/// Equal to `Groth16::calculate_coeff`: `query[0]` belongs to the constant-one
/// variable, whose scalar is one, so it is added as is and the MSM runs over
/// `query[1..]`. Like the reference, it panics on an empty `query`, which no
/// proving key has.
// Group arithmetic, as in the reference.
#[allow(clippy::arithmetic_side_effects)]
fn calculate_coeff<G: AffineRepr>(
    initial: G::Group,
    query: &[G],
    vk_param: G,
    assignment: &[<G::ScalarField as PrimeField>::BigInt],
) -> G::Group
where
    G::Group: VariableBaseMSM<MulBase = G>,
{
    let el = query[0];
    let acc = msm_bigint_chunked::<G::Group>(&query[1..], assignment);

    let mut res = initial;
    res.add_assign(&el);
    res += &acc;
    res.add_assign(&vk_param);

    res
}

// The tests build their own rayon pools, which wasm32 cannot do.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    // Group and field arithmetic in fixtures and oracles; the workspace deny
    // targets production integer math.
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;
    use crate::zk::circom_reduction::CircomReduction;
    use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
    use ark_ff::{AdditiveGroup, BigInteger, Field};
    use ark_groth16::Groth16;
    use ark_relations::{
        gr1cs::{ConstraintSystemRef, R1CS_PREDICATE_LABEL, Variable},
        lc,
    };
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};

    type CircomGroth16 = Groth16<Bn254, CircomReduction>;

    /// Pool sizes the tests run under: serial, an odd count, and more threads
    /// than most of the short inputs have elements.
    const POOL_SIZES: [usize; 4] = [1, 2, 3, 8];

    fn in_pool<T: Send>(threads: usize, f: impl FnOnce() -> T + Send) -> T {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("build rayon pool")
            .install(f)
    }

    /// Scalars that reach every branch of `ark-ec`'s MSM, which sorts scalars
    /// into zero, one, 8/16/32/64-bit, their negatives, and full-size ones.
    fn mixed_scalars(len: usize, rng: &mut StdRng) -> Vec<Fr> {
        let small = [
            Fr::ZERO,
            Fr::ONE,
            Fr::from(2u64),
            Fr::from(u64::from(u8::MAX)),
            Fr::from(u64::from(u16::MAX)),
            Fr::from(u64::from(u32::MAX)),
            Fr::from(u64::MAX),
        ];
        (0..len)
            .map(|i| match i % 16 {
                k @ 0..7 => small[k],
                k @ 7..13 => -small[k - 6],
                _ => Fr::rand(rng),
            })
            .collect()
    }

    fn random_bases<G: CurveGroup>(len: usize, rng: &mut StdRng) -> Vec<G::Affine> {
        let points = (0..len)
            .map(|_| G::generator() * G::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        G::normalize_batch(&points)
    }

    /// `msm_bigint_in_chunks` and `msm_bigint_chunked` return the group
    /// element stock `msm_bigint` returns, and for short inputs the one a
    /// term-by-term sum returns.
    fn check_chunked_msm<G>(seed: u64)
    where
        G: CurveGroup<ScalarField = Fr>,
    {
        let mut rng = StdRng::seed_from_u64(seed);
        // Empty, one element, fewer than the chunk and thread counts, exact
        // multiples of them, and lengths they do not divide.
        for len in [0, 1, 2, 3, 5, 7, 8, 9, 16, 17, 31, 64, 97, 257] {
            let bases = random_bases::<G>(len, &mut rng);
            let scalars = mixed_scalars(len, &mut rng);
            let bigints = scalars.iter().map(|s| s.into_bigint()).collect::<Vec<_>>();

            let expected = G::msm_bigint(&bases, &bigints);
            if len <= 64 {
                let naive: G = bases.iter().zip(&scalars).map(|(b, s)| *b * *s).sum();
                assert_eq!(expected, naive, "stock msm, len {len}");
            }

            for max_chunks in [0, 1, 2, 3, 4, 7, 8, 64, 1000] {
                assert_eq!(
                    msm_bigint_in_chunks::<G>(&bases, &bigints, max_chunks),
                    expected,
                    "len {len}, max_chunks {max_chunks}"
                );
            }
            for threads in POOL_SIZES {
                let chunked = in_pool(threads, || msm_bigint_chunked::<G>(&bases, &bigints));
                assert_eq!(chunked, expected, "len {len}, {threads} threads");
            }
        }
    }

    #[test]
    fn chunked_msm_matches_msm_bigint_g1() {
        check_chunked_msm::<G1Projective>(1);
    }

    #[test]
    fn chunked_msm_matches_msm_bigint_g2() {
        check_chunked_msm::<G2Projective>(2);
    }

    /// With slices of different lengths the chunked MSM uses the common
    /// prefix, like `msm_bigint`.
    #[test]
    fn chunked_msm_cuts_to_the_shorter_input() {
        let mut rng = StdRng::seed_from_u64(3);
        let bases = random_bases::<G1Projective>(40, &mut rng);
        let bigints = mixed_scalars(40, &mut rng)
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();

        for (n_bases, n_scalars) in [(40, 23), (23, 40), (40, 0), (0, 40), (1, 40)] {
            let (bases, bigints) = (&bases[..n_bases], &bigints[..n_scalars]);
            let expected = G1Projective::msm_bigint(bases, bigints);
            let common = n_bases.min(n_scalars);
            assert_eq!(
                expected,
                G1Projective::msm_bigint(&bases[..common], &bigints[..common])
            );
            for max_chunks in [1, 3, 8, 64] {
                assert_eq!(
                    msm_bigint_in_chunks::<G1Projective>(bases, bigints, max_chunks),
                    expected,
                    "{n_bases} bases, {n_scalars} scalars, max_chunks {max_chunks}"
                );
            }
        }
    }

    /// A circuit with several public inputs, a few hundred constraints whose
    /// rows have more than one term, and witness values of every size class,
    /// so that no MSM of its proof is trivial.
    ///
    /// Constraint `i` is `(w[i] + w[i+1] + 1) * (w[i] - 3 * w[i+2]) = p[i]`;
    /// every `PUBLIC_EVERY`-th product is also exposed as a public input.
    #[derive(Clone)]
    struct MixedCircuit {
        w: Vec<Fr>,
    }

    const PUBLIC_EVERY: usize = 61;

    impl MixedCircuit {
        fn new(constraints: usize, seed: u64) -> Self {
            let mut rng = StdRng::seed_from_u64(seed);
            Self {
                w: mixed_scalars(constraints + 2, &mut rng),
            }
        }

        fn product(&self, i: usize) -> Fr {
            (self.w[i] + self.w[i + 1] + Fr::ONE) * (self.w[i] - Fr::from(3u64) * self.w[i + 2])
        }

        fn public_inputs(&self) -> Vec<Fr> {
            (0..self.w.len() - 2)
                .step_by(PUBLIC_EVERY)
                .map(|i| self.product(i))
                .collect()
        }
    }

    impl ConstraintSynthesizer<Fr> for MixedCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let w = self
                .w
                .iter()
                .map(|v| cs.new_witness_variable(|| Ok(*v)))
                .collect::<Result<Vec<_>, _>>()?;
            for i in 0..w.len() - 2 {
                let p = cs.new_witness_variable(|| Ok(self.product(i)))?;
                cs.enforce_r1cs_constraint(
                    || lc!() + w[i] + w[i + 1] + Variable::One,
                    || lc!() + w[i] + (-Fr::from(3u64), w[i + 2]),
                    || lc!() + p,
                )?;
                if i % PUBLIC_EVERY == 0 {
                    let public = cs.new_input_variable(|| Ok(self.product(i)))?;
                    cs.enforce_r1cs_constraint(
                        || lc!() + p,
                        || lc!() + Variable::One,
                        || lc!() + public,
                    )?;
                }
            }
            Ok(())
        }
    }

    /// The proof `ark-groth16` creates from matrices and a full assignment,
    /// both taken from a constraint system set up the way
    /// `Groth16::create_proof_with_reduction` sets it up.
    fn reference_proof_from_matrices(
        pk: &ProvingKey<Bn254>,
        circuit: MixedCircuit,
        r: Fr,
        s: Fr,
    ) -> Proof<Bn254> {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
            generate_lc_assignments: false,
        });
        circuit.generate_constraints(cs.clone()).expect("synthesis");
        cs.finalize();
        assert!(cs.is_satisfied().expect("is_satisfied"));

        let matrices = cs.to_matrices().expect("matrices");
        let full_assignment = [
            cs.instance_assignment().expect("instance"),
            cs.witness_assignment().expect("witness"),
        ]
        .concat();
        CircomGroth16::create_proof_with_reduction_and_matrices(
            pk,
            r,
            s,
            &matrices[R1CS_PREDICATE_LABEL],
            cs.num_instance_variables(),
            cs.num_constraints(),
            &full_assignment,
        )
        .expect("reference proof from matrices")
    }

    fn proof_bytes(proof: &Proof<Bn254>) -> Vec<u8> {
        let mut bytes = Vec::new();
        proof
            .serialize_uncompressed(&mut bytes)
            .expect("serialize proof");
        bytes
    }

    struct Fixture {
        circuit: MixedCircuit,
        pk: ProvingKey<Bn254>,
    }

    fn fixture() -> Fixture {
        // 300 products plus 5 public-input constraints: neither count is a
        // power of two, so the evaluation domain is padded.
        let circuit = MixedCircuit::new(300, 11);
        let mut rng = StdRng::seed_from_u64(12);
        let pk =
            CircomGroth16::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
                .expect("setup");
        Fixture { circuit, pk }
    }

    /// Asserts that for this `r` and `s` the chunked assembly returns, under
    /// every pool size, exactly the proof both public `ark-groth16` entry
    /// points return, and that the proof verifies when it should.
    fn assert_same_proof_as_ark_groth16(fixture: &Fixture, r: Fr, s: Fr, label: &str) {
        let Fixture { circuit, pk } = fixture;
        let reference = CircomGroth16::create_proof_with_reduction(circuit.clone(), pk, r, s)
            .expect("reference proof");
        assert_eq!(
            reference_proof_from_matrices(pk, circuit.clone(), r, s),
            reference,
            "{label}: the two ark-groth16 entry points agree"
        );

        let pvk = CircomGroth16::process_vk(&pk.vk).expect("process vk");
        let public_inputs = circuit.public_inputs();
        assert!(public_inputs.len() > 1);
        assert!(
            CircomGroth16::verify_with_processed_vk(&pvk, &public_inputs, &reference)
                .expect("verify"),
            "{label}: the reference proof verifies"
        );

        for threads in POOL_SIZES {
            let proof = in_pool(threads, || {
                create_proof::<Bn254, CircomReduction, _>(circuit.clone(), pk, r, s)
            })
            .expect("chunked proof");
            assert_eq!(proof, reference, "{label}, {threads} threads");
            assert_eq!(
                proof_bytes(&proof),
                proof_bytes(&reference),
                "{label}, {threads} threads: serialized proof"
            );
        }
    }

    /// The proof is byte for byte the one `ark-groth16` creates for the same
    /// proving key, circuit, `r` and `s`, and it verifies.
    #[test]
    fn proof_equals_ark_groth16_for_fixed_randomness() {
        let fixture = fixture();
        let mut rng = StdRng::seed_from_u64(13);
        for i in 0..3 {
            let (r, s) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
            assert_same_proof_as_ark_groth16(&fixture, r, s, &format!("random pair {i}"));
        }
        // Scalars from the small and negated classes of the MSM.
        assert_same_proof_as_ark_groth16(&fixture, Fr::ONE, -Fr::ONE, "r = 1, s = -1");
    }

    /// The reference skips the B-in-G1 MSM when `r` is zero. That branch, and
    /// zero `s`, give the reference proof here too. The proofs still verify;
    /// they are just not zero-knowledge.
    #[test]
    fn proof_equals_ark_groth16_when_r_or_s_is_zero() {
        let fixture = fixture();
        let mut rng = StdRng::seed_from_u64(14);
        let (r, s) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        assert_same_proof_as_ark_groth16(&fixture, Fr::ZERO, s, "r = 0");
        assert_same_proof_as_ark_groth16(&fixture, r, Fr::ZERO, "s = 0");
        assert_same_proof_as_ark_groth16(&fixture, Fr::ZERO, Fr::ZERO, "r = s = 0");
    }

    /// A proof for a witness that does not satisfy the circuit is refused in
    /// builds with debug assertions and does not verify otherwise, as with
    /// the reference. Either way the chunked assembly does not make one that
    /// verifies.
    #[test]
    fn unsatisfied_witness_gives_no_valid_proof() {
        struct Tampered(MixedCircuit);
        impl ConstraintSynthesizer<Fr> for Tampered {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<Fr>,
            ) -> Result<(), SynthesisError> {
                // One more constraint the assignment breaks: `1 * 1 = w`
                // with `w = 2`.
                let w = cs.new_witness_variable(|| Ok(Fr::from(2u64)))?;
                cs.enforce_r1cs_constraint(
                    || lc!() + Variable::One,
                    || lc!() + Variable::One,
                    || lc!() + w,
                )?;
                self.0.generate_constraints(cs)
            }
        }

        let circuit = MixedCircuit::new(40, 21);
        let mut rng = StdRng::seed_from_u64(22);
        let pk = CircomGroth16::generate_random_parameters_with_reduction(
            Tampered(circuit.clone()),
            &mut rng,
        )
        .expect("setup");
        let pvk = CircomGroth16::process_vk(&pk.vk).expect("process vk");
        let public_inputs = circuit.public_inputs();

        let outcome = std::panic::catch_unwind(|| {
            let mut rng = StdRng::seed_from_u64(23);
            create_random_proof::<Bn254, CircomReduction, _, _>(&pk, Tampered(circuit), &mut rng)
        });
        match outcome {
            // Only the debug assertion may refuse the witness.
            Err(panic) => {
                if !cfg!(debug_assertions) {
                    std::panic::resume_unwind(panic);
                }
            }
            Ok(proof) => {
                let proof = proof.expect("proof");
                assert!(
                    !CircomGroth16::verify_with_processed_vk(&pvk, &public_inputs, &proof)
                        .expect("verify")
                );
            }
        }
    }

    /// `create_random_proof` draws `r` and `s` from the RNG exactly as
    /// `Groth16::prove` does: from equal RNG states both return the same
    /// proof and leave the RNG in the same state.
    #[test]
    fn random_proof_draws_r_and_s_like_ark_groth16() {
        let Fixture { circuit, pk } = fixture();
        let mut reference_rng = StdRng::seed_from_u64(15);
        let mut rng = reference_rng.clone();

        let reference =
            CircomGroth16::prove(&pk, circuit.clone(), &mut reference_rng).expect("reference");
        let proof = in_pool(3, || {
            create_random_proof::<Bn254, CircomReduction, _, _>(&pk, circuit.clone(), &mut rng)
        })
        .expect("chunked proof");

        assert_eq!(proof, reference);
        assert_eq!(proof_bytes(&proof), proof_bytes(&reference));
        assert_eq!(rng.r#gen::<[u8; 32]>(), reference_rng.r#gen::<[u8; 32]>());

        // A second proof from the advanced RNG differs: fresh `r` and `s`.
        let second =
            create_random_proof::<Bn254, CircomReduction, _, _>(&pk, circuit.clone(), &mut rng)
                .expect("second proof");
        assert_ne!(second, proof);
        let pvk = CircomGroth16::process_vk(&pk.vk).expect("process vk");
        assert!(
            CircomGroth16::verify_with_processed_vk(&pvk, &circuit.public_inputs(), &second)
                .expect("verify")
        );
    }

    /// Keeps the scalar fixture honest: it must contain every size class
    /// `ark-ec`'s MSM distinguishes.
    #[test]
    fn mixed_scalars_cover_every_msm_size_class() {
        let mut rng = StdRng::seed_from_u64(4);
        let scalars = mixed_scalars(32, &mut rng);
        let bits = |s: &Fr| s.into_bigint().num_bits();
        for (lo, hi) in [(0, 0), (1, 1), (2, 8), (9, 16), (17, 32), (33, 64)] {
            assert!(
                scalars.iter().any(|s| (lo..=hi).contains(&bits(s))),
                "no scalar with {lo}..={hi} bits"
            );
            if lo > 0 {
                assert!(
                    scalars.iter().any(|s| (lo..=hi).contains(&bits(&-*s))),
                    "no scalar whose negation has {lo}..={hi} bits"
                );
            }
        }
        assert!(
            scalars.iter().any(|s| bits(s) > 64 && bits(&-*s) > 64),
            "no full-size scalar"
        );
    }
}
