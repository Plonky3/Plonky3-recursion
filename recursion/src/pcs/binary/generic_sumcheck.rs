//! Division-free interpolation at the released binary generic-sumcheck nodes.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use super::RecursiveBinaryChallengeField;
use crate::verifier::binary_field_policy::{
    BinaryRelationPolicy, NativeTower128Relation, TowerRelation,
};
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{BinaryTower128Target, NativeTower128Target};
use p3_field::Field;

use super::whir_plan::invalid;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

/// Trusted Lagrange basis for one generic-degree binary sumcheck schedule.
/// The transmitted values are `h(0), h(2), ..., h(degree)` at the native
/// interpolation nodes. `h(1)` is derived from the running claimed sum.
/// Constants are prepared natively; no inverse of a private challenge is used.
#[derive(Clone, Debug)]
pub struct Binary128SumcheckInterpolator {
    coefficients: Vec<Vec<u128>>,
}

impl Binary128SumcheckInterpolator {
    pub fn new(degree: usize) -> Result<Self, VerificationError> {
        Self::with_limits(degree, &VerifierLimits::default())
    }

    /// Checks finite degree and coefficient-storage budgets before allocation.
    pub fn with_limits(degree: usize, limits: &VerifierLimits) -> Result<Self, VerificationError> {
        let coefficients = lagrange_coefficients::<BinaryField128>(degree, limits)?
            .into_iter()
            .map(|basis| basis.into_iter().map(|value| value.to_repr()).collect())
            .collect();
        Ok(Self { coefficients })
    }

    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    /// Reduces one arithmetic claim. The caller must observe the exact message
    /// and derive `challenge` through the native transcript, then close the
    /// resulting claim against its committed polynomial or AIR relation.
    /// Targets must belong to this builder.
    pub fn reduce_claim<F: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<F>,
        claim: &BinaryTower128Target,
        evaluations: &[BinaryTower128Target],
        challenge: &BinaryTower128Target,
    ) -> Result<BinaryTower128Target, VerificationError> {
        self.reduce_claim_using::<TowerRelation<BinaryField128, BinaryField128>, F>(
            b,
            claim,
            evaluations,
            challenge,
        )
    }

    /// Reduces the same claim with scalar arithmetic in the native carrier.
    pub fn reduce_claim_native(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        claim: &NativeTower128Target,
        evaluations: &[NativeTower128Target],
        challenge: &NativeTower128Target,
    ) -> Result<NativeTower128Target, VerificationError> {
        self.reduce_claim_using::<NativeTower128Relation, BinaryField128>(
            b,
            claim,
            evaluations,
            challenge,
        )
    }

    pub(crate) fn reduce_claim_using<P, F>(
        &self,
        b: &mut CircuitBuilder<F>,
        claim: &P::ChallengeTarget,
        evaluations: &[P::ChallengeTarget],
        challenge: &P::ChallengeTarget,
    ) -> Result<P::ChallengeTarget, VerificationError>
    where
        F: Field + Eq + Hash,
        P: BinaryRelationPolicy<F>,
        P::Challenge: RecursiveBinaryChallengeField,
    {
        if evaluations.len() != self.degree() {
            return Err(invalid("binary generic sumcheck message width mismatch"));
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
                    let constant = P::constant(b, constant)?;
                    P::mul(b, value, &constant)
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

/// Native interpolation constants shared by the closed binary field adapters.
/// The complete coefficient storage is bounded before constructing the nodes.
pub(super) fn lagrange_coefficients<E: Field>(
    degree: usize,
    limits: &VerifierLimits,
) -> Result<Vec<Vec<E>>, VerificationError> {
    if degree == 0 {
        return Err(invalid("binary generic sumcheck degree must be positive"));
    }
    if degree > limits.max_log_domain_or_degree {
        return Err(VerificationError::ResourceLimitExceeded {
            component: "binary generic sumcheck degree",
            actual: degree,
            limit: limits.max_log_domain_or_degree,
        });
    }
    let count = degree
        .checked_add(1)
        .ok_or(VerificationError::ResourceArithmeticOverflow {
            component: "binary generic sumcheck nodes",
        })?;
    let entries =
        count
            .checked_mul(count)
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary generic sumcheck coefficients",
            })?;
    let mut usage = InputResourceUsage::default();
    usage.add_metadata_entries(limits, entries)?;
    let nodes = (0..count).map(E::interpolation_node).collect::<Vec<_>>();
    let coefficients = nodes
        .iter()
        .enumerate()
        .map(|(i, &node)| {
            let mut polynomial = vec![E::ONE];
            let mut denominator = E::ONE;
            for (j, &other) in nodes.iter().enumerate() {
                if i == j {
                    continue;
                }
                denominator *= node + other;
                let mut next = vec![E::ZERO; polynomial.len() + 1];
                for (k, &coefficient) in polynomial.iter().enumerate() {
                    next[k] += coefficient * other;
                    next[k + 1] += coefficient;
                }
                polynomial = next;
            }
            let inverse = denominator.inverse();
            polynomial.into_iter().map(|v| v * inverse).collect()
        })
        .collect();
    Ok(coefficients)
}
