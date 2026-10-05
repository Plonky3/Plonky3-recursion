//! Native Poly64-node interpolation for full Poly192 sumcheck messages.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::CircuitBuilder;
use p3_field::{Field, PrimeCharacteristicRing};

use super::generic_sumcheck::lagrange_coefficients;
use super::whir_plan::invalid;
use crate::verifier::binary_field_policy::BinaryPolyPolicy;
use crate::verifier::{VerificationError, VerifierLimits};

#[derive(Clone, Debug)]
pub(crate) struct Poly192SumcheckInterpolator {
    coefficients: Vec<Vec<u64>>,
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::verifier::binary_field_policy::NativePoly64Relation;
    use p3_circuit::ops::NativePoly192Target;
    use p3_sumcheck::generic_degree::RoundPolyInterpolator;

    fn scalar(b: &mut CircuitBuilder<Poly64>) -> NativePoly192Target {
        let coefficients = b.alloc_public_input_array::<3>("native Poly192 interpolation value");
        b.native_poly192_from_coefficients(coefficients)
    }
    fn dense(i: u64) -> Poly192 {
        Poly192::new(core::array::from_fn(|k| {
            Poly64::new(0x8123456789abcdefu64.wrapping_mul(i + 17 * k as u64))
        }))
    }
    #[test]
    fn native_interpolation_matches_nodes_and_full_extension_challenges() {
        for degree in [1, 2, 3, 4, 5, 7] {
            let recursive =
                Poly192SumcheckInterpolator::with_limits(degree, &VerifierLimits::default())
                    .unwrap();
            let native = RoundPolyInterpolator::<Poly192>::new(degree);
            let mut b = CircuitBuilder::<Poly64>::new();
            let claim = scalar(&mut b);
            let evaluations: Vec<_> = (0..degree).map(|_| scalar(&mut b)).collect();
            let challenge = scalar(&mut b);
            let expected = scalar(&mut b);
            assert!(
                recursive
                    .reduce_claim_using::<NativePoly64Relation, Poly64>(
                        &mut b,
                        &claim,
                        &evaluations[..degree - 1],
                        &challenge
                    )
                    .is_err()
            );
            let actual = recursive
                .reduce_claim_using::<NativePoly64Relation, Poly64>(
                    &mut b,
                    &claim,
                    &evaluations,
                    &challenge,
                )
                .unwrap();
            for (&a, &c) in actual.coefficients().iter().zip(expected.coefficients()) {
                let difference = b.sub(a, c);
                b.assert_zero(difference);
            }
            let circuit = b.build().unwrap();
            let claim = dense(11);
            let evaluations: Vec<_> = (0..degree).map(|i| dense(i as u64 + 12)).collect();
            for challenge in (0..=degree)
                .map(Poly192::interpolation_node)
                .chain([dense(53)])
            {
                let expected = native.eval(&evaluations, claim, challenge);
                let public: Vec<_> = core::iter::once(claim)
                    .chain(evaluations.iter().copied())
                    .chain([challenge, expected])
                    .flat_map(|value| value.coefficients())
                    .collect();
                let run = |public: &[Poly64]| {
                    let mut runner = circuit.runner();
                    runner
                        .set_public_inputs(public)
                        .and_then(|()| runner.run())
                        .is_ok()
                };
                assert!(run(&public));
                for coefficient in 0..3 {
                    let mut wrong = public.clone();
                    let index = wrong.len() - 3 + coefficient;
                    wrong[index] += Poly64::ONE;
                    assert!(!run(&wrong));
                }
            }
        }
    }
}

impl Poly192SumcheckInterpolator {
    pub(crate) fn with_limits(
        degree: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let native = lagrange_coefficients::<Poly192>(degree, limits)?;
        let count = native.len();
        // Native Poly192 interpolation nodes lie in Poly64. Their Lagrange
        // coefficients do too, allowing exact base scaling in the circuit.
        let mut coefficients = Vec::with_capacity(count);
        for basis in native {
            let mut row = Vec::with_capacity(count);
            for coefficient in basis {
                let [base, c1, c2] = coefficient.coefficients();
                if c1 != Poly64::ZERO || c2 != Poly64::ZERO {
                    return Err(invalid(
                        "binary Poly sumcheck interpolation left the base field",
                    ));
                }
                row.push(base.to_bits());
            }
            coefficients.push(row);
        }
        Ok(Self { coefficients })
    }

    pub(crate) fn metadata_entries(&self) -> usize {
        // The checked native constructor bounds this square before allocation.
        self.coefficients.len() * self.coefficients.len()
    }

    pub(crate) fn reduce_claim_using<P, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        claim: &P::ChallengeTarget,
        evaluations: &[P::ChallengeTarget],
        challenge: &P::ChallengeTarget,
    ) -> Result<P::ChallengeTarget, VerificationError>
    where
        EF: Field + Eq + Hash,
        P: BinaryPolyPolicy<EF>,
    {
        if evaluations.len() != self.coefficients.len() - 1 {
            return Err(invalid("binary Poly sumcheck message width mismatch"));
        }
        let mut values = Vec::with_capacity(self.coefficients.len());
        values.push(evaluations[0].clone());
        values.push(P::add(b, claim, &evaluations[0]));
        values.extend_from_slice(&evaluations[1..]);
        let zero = P::constant(b, 0)?;
        let mut polynomial = vec![zero; self.coefficients.len()];
        for (value, basis) in values.iter().zip(&self.coefficients) {
            for (coefficient, &constant) in polynomial.iter_mut().zip(basis) {
                if constant == 0 {
                    continue;
                }
                let term = if constant == 1 {
                    value.clone()
                } else {
                    P::scale_base_constant(b, value, constant)?
                };
                *coefficient = P::add(b, coefficient, &term);
                b.check_construction_limits()?;
            }
        }
        let mut iter = polynomial.into_iter().rev();
        let mut result = iter.next().expect("checked positive degree");
        for coefficient in iter {
            let product = P::mul(b, &result, challenge);
            result = P::add(b, &product, &coefficient);
            b.check_construction_limits()?;
        }
        Ok(result)
    }
}
