//! Circom's Groth16 QAP reduction.
//!
//! Ported logic from arkworks `circom-compat`, so we can drop the `ark-circom`
//! dependency (browser problems)
//!
//! The only deliberate change is replacing the upstream `rayon` parallel
//! iterators with serial ones. Proofs are unchanged

use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP, evaluate_constraint};
use ark_poly::EvaluationDomain;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{vec, vec::Vec};

/// Implements the witness map used by snarkjs. The arkworks witness map
/// calculates the coefficients of H through computing (AB-C)/Z in the
/// evaluation domain and going back to the coefficients domain. snarkjs instead
/// precomputes the Lagrange form of the powers of tau bases in a domain twice
/// as large and the witness map is computed as the odd coefficients of (AB-C)
/// in that domain. This serves as HZ when computing the C proof element.
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &[Vec<Vec<(F, usize)>>],
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        let zero = F::zero();
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];

        for (((a_i, b_i), at_i), bt_i) in a[..num_constraints]
            .iter_mut()
            .zip(b[..num_constraints].iter_mut())
            .zip(&matrices[0])
            .zip(&matrices[1])
        {
            *a_i = evaluate_constraint(at_i, full_assignment);
            *b_i = evaluate_constraint(bt_i, full_assignment);
        }

        {
            let start = num_constraints;
            let end = start + num_inputs;
            a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
        }

        let mut c = vec![zero; domain_size];
        for ((c_i, &a_i), &b_i) in c[..num_constraints].iter_mut().zip(&a).zip(&b) {
            *c_i = a_i * b_i;
        }

        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        let root_of_unity = {
            let domain_size_double = 2 * domain_size;
            let domain_double =
                D::new(domain_size_double).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            domain_double.element(1)
        };
        D::distribute_powers_and_mul_by_const(&mut a, root_of_unity, F::one());
        D::distribute_powers_and_mul_by_const(&mut b, root_of_unity, F::one());

        domain.fft_in_place(&mut a);
        domain.fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        domain.ifft_in_place(&mut c);
        D::distribute_powers_and_mul_by_const(&mut c, root_of_unity, F::one());
        domain.fft_in_place(&mut c);

        for (ab_i, c_i) in ab.iter_mut().zip(c) {
            *ab_i -= &c_i;
        }

        Ok(ab)
    }

    // Arithmetic here is inherent to the H-query construction.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        _: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        // the usual H query has domain-1 powers. Z has domain powers. So HZ has
        // 2*domain-1 powers.
        let mut scalars = (0..2 * max_power + 1)
            .map(|i| delta_inverse * t.pow([i as u64]))
            .collect::<Vec<_>>();
        let domain_size = scalars.len();
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        // generate the lagrange coefficients
        domain.ifft_in_place(&mut scalars);
        Ok(scalars.into_iter().skip(1).step_by(2).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::CircomReduction;
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::{Groth16, r1cs_to_qap::R1CSToQAP as _};
    use ark_relations::{
        gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
        lc,
    };
    use ark_snark::SNARK;
    use ark_std::{
        rand::{SeedableRng, rngs::StdRng},
        vec,
    };
    use core::ops::AddAssign as _;

    type CircomGroth16 = Groth16<Bn254, CircomReduction>;

    /// Minimal circuit proving knowledge of `a`, `b` with `a * b == c`
    /// (public).
    #[derive(Clone)]
    struct MulCircuit {
        a: Fr,
        b: Fr,
        c: Fr,
    }

    impl ConstraintSynthesizer<Fr> for MulCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(self.a))?;
            let b = cs.new_witness_variable(|| Ok(self.b))?;
            let c = cs.new_input_variable(|| Ok(self.c))?;
            cs.enforce_r1cs_constraint(
                || {
                    let mut l = lc!();
                    l.add_assign((Fr::from(1u64), a));
                    l
                },
                || {
                    let mut l = lc!();
                    l.add_assign((Fr::from(1u64), b));
                    l
                },
                || {
                    let mut l = lc!();
                    l.add_assign((Fr::from(1u64), c));
                    l
                },
            )
        }
    }

    /// Known-answer test: a full Groth16 setup/prove/verify round-trip through
    /// the ported reduction must accept a valid proof and reject a tampered
    /// public input. A reduction broken by an arkworks bump fails here loudly
    /// instead of silently weakening soundness.
    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn circom_reduction_round_trips() {
        let mut rng = StdRng::seed_from_u64(0);
        let a = Fr::from(3u64);
        let b = Fr::from(11u64);
        let c = a * b;
        let circuit = MulCircuit { a, b, c };

        let (pk, vk) = CircomGroth16::circuit_specific_setup(circuit.clone(), &mut rng)
            .expect("setup should succeed");
        let pvk = CircomGroth16::process_vk(&vk).expect("process vk");
        let proof = CircomGroth16::prove(&pk, circuit, &mut rng).expect("prove should succeed");

        assert!(
            CircomGroth16::verify_with_processed_vk(&pvk, &[c], &proof).expect("verify"),
            "valid proof must verify"
        );
        assert!(
            !CircomGroth16::verify_with_processed_vk(&pvk, &[c + Fr::from(1u64)], &proof)
                .expect("verify"),
            "wrong public input must not verify"
        );
    }

    /// Pin the circom-specific H-query coefficients to fixed field values, so a
    /// change in the reduction (or in the arkworks FFT/domain it relies on) is
    /// caught deterministically, independent of proving randomness.
    #[test]
    fn h_query_scalars_known_answer() {
        use ark_poly::GeneralEvaluationDomain;

        let t = Fr::from(5u64);
        let delta_inverse = Fr::from(7u64);
        let scalars = CircomReduction::h_query_scalars::<Fr, GeneralEvaluationDomain<Fr>>(
            2,
            t,
            Fr::from(0u64),
            delta_inverse,
        )
        .expect("h_query_scalars");

        let expected: vec::Vec<Fr> = [
            "7193022661598918098062353954464864857591776565882393189439146689919873452269",
            "13919056435331600773960851109981958301789492448850000962569615555631757604872",
            "9223159492280538511468992804938759570001983004527243990582506037067804749633",
            "13441247154467493061000613621128967447713476781572430544805140090532181182276",
        ]
        .iter()
        .map(|s| s.parse().expect("valid field element"))
        .collect();
        assert_eq!(scalars, expected);
    }
}
