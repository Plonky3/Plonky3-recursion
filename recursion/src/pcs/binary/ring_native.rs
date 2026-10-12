//! Native Tower128 bit ring-switch verification with every sumcheck round.
//!
//! The released reduction skips one sumcheck round for each leading coordinate on which every
//! claim's point is the same bit. This verifier skips none: points of `n` coordinates take
//! `n - 7` rounds, the full-length reduction, whose soundness holds at every point. Its
//! transcript is the released one whenever the claims' first coordinates are not one common
//! bit. A column-batched trace of more than one column draws that coordinate after binding the
//! opened values, so there the two transcripts differ with probability at most `2^-127`.

use alloc::vec::Vec;

use p3_binary_field::BinaryField128;
use p3_circuit::ops::NativeTower128Target;
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::transcript::SumcheckShape;

use super::gadgets::reduce_sumcheck_using;
use super::tensor_native::equality_table;
use super::verifier::observe_seed_with_host;
use super::{
    BinaryBitRingVerifier, NativeBitTensorTarget, RecursiveBinaryTowerField, closing_weight_native,
};
use crate::BinaryTower128Challenger;
use crate::transcript::domain_separator_seed;
use crate::verifier::VerificationError;
use crate::verifier::binary_field_policy::{
    BinaryProtocolPolicy, BinaryRelationPolicy, NativeTower128Relation,
};

type F = BinaryField128;
type P = NativeTower128Relation<F>;
type H = NativeBinaryEncoding;

/// Coordinates one Tower128 element absorbs.
const ABSORBED: usize = F::RAW_BITS.ilog2() as usize;

/// One claim's committed elements in the native carrier.
#[derive(Clone, Debug)]
pub struct NativeBitRingClaimTargets {
    pub tensor: NativeBitTensorTarget,
    /// Carry and last, present exactly for a successor wider than one element.
    pub successor: Option<(NativeBitTensorTarget, NativeBitTensorTarget)>,
}

#[derive(Clone, Debug)]
pub struct NativeBitRingProofTargets {
    pub claims: Vec<NativeBitRingClaimTargets>,
    /// One message per high coordinate, since every round runs.
    pub sumcheck: Vec<[NativeTower128Target; 2]>,
    pub final_eval: NativeTower128Target,
}

/// A claim's evaluation point and the readings stated at it, both owned by the caller. The
/// reduction absorbs the point and checks the readings against the claim's columns.
#[derive(Clone, Debug)]
pub struct NativeBitRingReading {
    pub point: Vec<NativeTower128Target>,
    pub current: Option<NativeTower128Target>,
    pub next: Option<NativeTower128Target>,
}

/// The surviving packed opening and the exact transcript continuation. The caller must
/// discharge this point and value against the packed commitment.
#[derive(Clone, Debug)]
pub struct NativeBitRingOutput {
    pub point: Vec<NativeTower128Target>,
    pub value: NativeTower128Target,
    pub challenger: BinaryTower128Challenger,
}

impl BinaryBitRingVerifier<F> {
    /// Checks the committed elements and messages against this verifier's claims.
    pub(super) fn check_native_proof(
        &self,
        proof: &NativeBitRingProofTargets,
    ) -> Result<(), VerificationError> {
        if proof.claims.len() != self.specs.len()
            || proof.sumcheck.len() != self.num_variables - ABSORBED
            || proof.claims.iter().zip(&self.specs).any(|(claim, spec)| {
                claim.successor.is_some() != spec.next_rows.is_some_and(|rows| rows > ABSORBED)
            })
        {
            return Err(invalid(
                "native binary ring-switch targets do not match the verifier shape",
            ));
        }
        Ok(())
    }

    fn check_native_readings(
        &self,
        readings: &[NativeBitRingReading],
    ) -> Result<(), VerificationError> {
        if readings.len() != self.specs.len()
            || readings.iter().zip(&self.specs).any(|(reading, spec)| {
                reading.point.len() != self.num_variables
                    || reading.current.is_some() != spec.current
                    || reading.next.is_some() != spec.next_rows.is_some()
            })
        {
            return Err(invalid(
                "native binary ring-switch readings do not match the verifier shape",
            ));
        }
        Ok(())
    }

    /// Installs the complete ring-switch relation in the native carrier, running every
    /// sumcheck round (see the module documentation).
    ///
    /// Points and elements are absorbed, and challenges drawn, in the released order. Each
    /// stated reading must equal its claim's column reading at the absorbed coordinates, the
    /// starting sum is derived from the elements' rows, and the surviving value must close
    /// the final sum against the closing weight at the drawn point.
    pub fn verify_native(
        &self,
        b: &mut CircuitBuilder<F>,
        mut ch: BinaryTower128Challenger,
        readings: &[NativeBitRingReading],
        proof: &NativeBitRingProofTargets,
    ) -> Result<NativeBitRingOutput, VerificationError> {
        self.check_native_proof(proof)?;
        self.check_native_readings(readings)?;
        let high = self.num_variables - ABSORBED;
        observe_seed_with_host::<F, H, F>(b, &mut ch, &self.seed)?;
        for (reading, claim) in readings.iter().zip(&proof.claims) {
            P::observe::<H>(b, &mut ch, &reading.point)?;
            P::observe::<H>(b, &mut ch, claim.tensor.rows())?;
            if let Some((carry, last)) = &claim.successor {
                P::observe::<H>(b, &mut ch, carry.rows())?;
                P::observe::<H>(b, &mut ch, last.rows())?;
            }
        }
        let batch = (0..ABSORBED)
            .map(|_| P::sample::<H>(b, &mut ch))
            .collect::<Result<Vec<_>, _>>()?;
        let alpha = proof
            .claims
            .iter()
            .any(|claim| claim.successor.is_some())
            .then(|| P::sample::<H>(b, &mut ch))
            .transpose()?;
        let lambda = (self.specs.len() > 1)
            .then(|| P::sample::<H>(b, &mut ch))
            .transpose()?;
        let mut sums = Vec::with_capacity(readings.len());
        for ((reading, claim), spec) in readings.iter().zip(&proof.claims).zip(&self.specs) {
            let low = &reading.point[high..];
            let mut tensor = claim.tensor.clone();
            if let Some(current) = &reading.current {
                let value = tensor.evaluate_columns(b, low)?;
                P::assert_equal(b, current, &value);
            }
            if let Some(next) = &reading.next {
                let value = match &claim.successor {
                    Some((carry, last)) => {
                        tensor.successor_reading(b, low, &mut carry.clone(), &mut last.clone())?
                    }
                    None => successor_within_element(
                        b,
                        &mut tensor,
                        low,
                        spec.next_rows.expect("checked successor request"),
                    )?,
                };
                P::assert_equal(b, next, &value);
            }
            let mut sum = tensor.evaluate_rows(b, &batch)?;
            if let Some((carry, last)) = &claim.successor {
                let alpha = alpha.as_ref().expect("successor claims draw alpha");
                let carry = carry.evaluate_rows(b, &batch)?;
                let last = last.evaluate_rows(b, &batch)?;
                // alpha * carry + alpha^2 * last, as alpha * (carry + alpha * last).
                let inner = P::mul_add(b, alpha, &last, &carry);
                sum = P::mul_add(b, alpha, &inner, &sum);
            }
            sums.push(sum);
            b.check_construction_limits()?;
        }
        let mut sum = batch_claims(b, &sums, lambda.as_ref());
        if high > 0 {
            let seed = domain_separator_seed(
                &SumcheckShape::new(high, 0, Basis::Evaluation).domain_separator::<F, F>(),
            );
            observe_seed_with_host::<F, H, F>(b, &mut ch, &seed)?;
        }
        let mut point = Vec::with_capacity(high);
        for message in &proof.sumcheck {
            P::observe::<H>(b, &mut ch, message)?;
            let beta = P::sample::<H>(b, &mut ch)?;
            sum = reduce_sumcheck_using::<P, F>(b, &sum, &message[0], &message[1], &beta)?;
            point.push(beta);
            b.check_construction_limits()?;
        }
        P::observe::<H>(b, &mut ch, core::slice::from_ref(&proof.final_eval))?;
        let weights = readings
            .iter()
            .zip(&self.specs)
            .map(|(reading, spec)| {
                let successor = spec.next_rows.filter(|&rows| rows > ABSORBED).map(|rows| {
                    (
                        rows - ABSORBED,
                        alpha.as_ref().expect("successor claims draw alpha"),
                    )
                });
                closing_weight_native(b, &reading.point[..high], &point, &batch, successor)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let closing = batch_claims(b, &weights, lambda.as_ref());
        let expected = b.native_tower128_mul(&closing, &proof.final_eval);
        P::assert_equal(b, &sum, &expected);
        Ok(NativeBitRingOutput {
            point,
            value: proof.final_eval,
            challenger: ch,
        })
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

/// `sum_i lambda^i * terms[i]`, by Horner's rule from the last claim. One claim draws no
/// lambda.
fn batch_claims(
    b: &mut CircuitBuilder<F>,
    terms: &[NativeTower128Target],
    lambda: Option<&NativeTower128Target>,
) -> NativeTower128Target {
    let (&last, rest) = terms.split_last().expect("checked nonempty claims");
    let mut sum = last;
    for term in rest.iter().rev() {
        let lambda = lambda.expect("several claims draw lambda");
        sum = P::mul_add(b, lambda, &sum, term);
    }
    sum
}

/// The successor reading of a view whose `rows` trailing coordinates step inside one element.
/// Column `v` weighs `eq(low, v - 1)` when its row bits are not all zero, plus `eq(low, v)`
/// when they are all one, the repeated last row.
fn successor_within_element(
    b: &mut CircuitBuilder<F>,
    tensor: &mut NativeBitTensorTarget,
    low: &[NativeTower128Target],
    rows: usize,
) -> Result<NativeTower128Target, VerificationError> {
    let weights = equality_table(b, low);
    let last = (1usize << rows) - 1;
    let mut reading = ExprId::ZERO;
    for v in 0..weights.len() {
        let shifted = (v & last != 0).then(|| weights[v - 1]);
        let repeated = (v & last == last).then_some(weights[v]);
        let weight = match (shifted, repeated) {
            (Some(shifted), Some(repeated)) => b.add(shifted, repeated),
            (Some(weight), None) | (None, Some(weight)) => weight,
            (None, None) => continue,
        };
        let column = tensor.column(b, v)?;
        reading = b.mul_add(column.as_expr(), weight, reading);
    }
    Ok(b.native_tower128_from_expr(reading))
}
