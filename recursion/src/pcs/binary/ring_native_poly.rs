//! Native Poly64 bit ring-switch verification with every sumcheck round.
//!
//! The packed values are `Poly64` elements and the challenges `Poly192`
//! elements. One packed element absorbs six point coordinates, which index a
//! column of the sent tensor, while the batching point names eight, which
//! index its 192 rows (see `tensor_native_poly`).
//!
//! The released reduction skips one sumcheck round for each leading
//! coordinate on which every claim's point is the same bit. This verifier
//! skips none: points of `n` coordinates take `n - 6` rounds, the full-length
//! reduction, whose soundness holds at every point. Its transcript is the
//! released one whenever the claims' first coordinates are not one common bit,
//! and the native import refuses claims whose first coordinates are one common
//! bit inside the coordinates the released reduction may skip. A
//! column-batched trace of more than one column draws that coordinate after
//! binding the opened values, so there the two transcripts differ with
//! probability at most `2^-191`.

use alloc::vec::Vec;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::NativePoly192Target;
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_sumcheck::ring_switch::bits::transcript::{BitRingSwitchClaimsShape, BitRingSwitchShape};
use p3_sumcheck::ring_switch::bits::{
    BitRingSwitch, BitRingSwitchClaims, BitRingSwitchClaimsProof, BitTensor,
};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::transcript::SumcheckShape;

use super::gadgets::reduce_sumcheck_using;
use super::tensor_native_poly::equality_table;
use super::{BinaryRingClaimSpec, NativePolyBitTensorTarget, closing_weight_native_poly};
use crate::BinaryTower128Challenger;
use crate::transcript::domain_separator_seed;
use crate::verifier::binary_field_policy::{
    BinaryPolyPolicy, BinaryProtocolPolicy, NativePoly64Relation, poly_observe_seed_with_host,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

type F = Poly64;
type E = Poly192;
type P = NativePoly64Relation;
type H = NativeBinaryEncoding;

/// Point coordinates one packed Poly64 element absorbs, indexing a column.
const ABSORBED: usize = BitRingSwitch::<F, E>::ABSORBED;
/// Batching coordinates, indexing a row of the sent tensor.
const BATCHED: usize = BitRingSwitch::<F, E>::BATCHED;
/// Rows of a sent tensor, one Poly64 cell per Poly192 coordinate.
const ROWS: usize = BitTensor::<E, F>::DIMENSION;
/// Poly64 cells of one Poly192 value.
const LIMBS: usize = 3;
/// Sixteen-bit input limbs of one Poly64 cell, the unit of input accounting.
const CELL_INPUT_LIMBS: usize = 4;

/// One claim's committed elements in the native carrier.
#[derive(Clone, Debug)]
pub struct NativePolyBitRingClaimTargets {
    pub tensor: NativePolyBitTensorTarget,
    /// Carry and last, present exactly for a successor wider than one element.
    pub successor: Option<(NativePolyBitTensorTarget, NativePolyBitTensorTarget)>,
}

#[derive(Clone, Debug)]
pub struct NativePolyBitRingProofTargets {
    pub claims: Vec<NativePolyBitRingClaimTargets>,
    /// One message per high coordinate, since every round runs.
    pub sumcheck: Vec<[NativePoly192Target; 2]>,
    pub final_eval: NativePoly192Target,
}

/// A claim's evaluation point and the readings stated at it, both owned by the
/// caller. The reduction absorbs the point and checks the readings against the
/// claim's columns.
#[derive(Clone, Debug)]
pub struct NativePolyBitRingReading {
    pub point: Vec<NativePoly192Target>,
    pub current: Option<NativePoly192Target>,
    pub next: Option<NativePoly192Target>,
}

/// The surviving packed opening and the exact transcript continuation. The
/// caller must discharge this point and value against the packed commitment.
#[derive(Clone, Debug)]
pub struct NativePolyBitRingOutput {
    pub point: Vec<NativePoly192Target>,
    pub value: NativePoly192Target,
    pub challenger: BinaryTower128Challenger,
}

/// Bit ring-switch claims about a packing of Poly64 elements, reduced with
/// Poly192 challenges in the native Poly64 carrier.
#[derive(Clone, Debug)]
pub struct BinaryPolyBitRingVerifier {
    num_variables: usize,
    specs: Vec<BinaryRingClaimSpec>,
    usage: InputResourceUsage,
    seed: Vec<F>,
}

/// Shape captured solely from a resource-checked verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyRingInputShape {
    num_variables: usize,
    specs: Vec<BinaryRingClaimSpec>,
}

/// Checked native witness data. Neither this value nor its native replay is a
/// verification authority: the recursive ring and packed PCS checks are
/// required.
#[derive(Clone, Debug)]
pub struct NativeBinaryPolyRingInput {
    shape: BinaryPolyRingInputShape,
    values: Vec<F>,
}

impl BinaryPolyBitRingVerifier {
    pub fn new(
        num_variables: usize,
        specs: Vec<BinaryRingClaimSpec>,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(num_variables, specs, &VerifierLimits::default())
    }

    pub fn with_limits(
        num_variables: usize,
        specs: Vec<BinaryRingClaimSpec>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        if num_variables < ABSORBED
            || specs.is_empty()
            || specs.iter().any(|s| {
                (!s.current && s.next_rows.is_none())
                    || s.next_rows.is_some_and(|rows| rows > num_variables)
            })
        {
            return Err(invalid("Poly64 ring-switch reading geometry is invalid"));
        }
        if num_variables > limits.max_log_domain_or_degree {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "Poly64 ring-switch variables",
                actual: num_variables,
                limit: limits.max_log_domain_or_degree,
            });
        }
        let high = num_variables - ABSORBED;
        let mut usage = InputResourceUsage::default();
        usage.add_instances(limits, specs.len())?;
        usage.add_rounds(limits, high)?;
        let challenge_limbs = LIMBS * CELL_INPUT_LIMBS;
        for spec in &specs {
            let tensors = if sends_successor(spec) { 3usize } else { 1 };
            let limbs = tensors
                .checked_mul(ROWS * CELL_INPUT_LIMBS)
                .and_then(|rows| {
                    num_variables
                        .checked_add(
                            usize::from(spec.current) + usize::from(spec.next_rows.is_some()),
                        )
                        .and_then(|values| values.checked_mul(challenge_limbs))
                        .and_then(|values| rows.checked_add(values))
                })
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "Poly64 ring-switch claim limbs",
                })?;
            usage.add_scalar_elements(limits, limbs)?;
        }
        usage.add_scalar_elements(
            limits,
            high.checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .and_then(|n| n.checked_mul(challenge_limbs))
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "Poly64 ring-switch round limbs",
                })?,
        )?;
        let shapes: Vec<_> = specs
            .iter()
            .map(|spec| {
                spec.next_rows.filter(|&rows| rows > ABSORBED).map_or_else(
                    || BitRingSwitchShape::new(num_variables),
                    |rows| BitRingSwitchShape::with_successor_rows(num_variables, rows),
                )
            })
            .collect();
        let seed = if let [shape] = shapes.as_slice() {
            domain_separator_seed(&shape.domain_separator::<F, E>())
        } else {
            domain_separator_seed(
                &BitRingSwitchClaimsShape { claims: shapes }.domain_separator::<F, E>(),
            )
        };
        Ok(Self {
            num_variables,
            specs,
            usage,
            seed,
        })
    }

    /// Conservative checked input counters: every claim's elements, point and
    /// readings, and a message for every round.
    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Performs pure shape inspection, without a proof or transcript replay.
    pub fn input_shape(&self) -> BinaryPolyRingInputShape {
        BinaryPolyRingInputShape {
            num_variables: self.num_variables,
            specs: self.specs.clone(),
        }
    }

    /// The leading coordinates the released reduction may skip: the high
    /// coordinates before any successor view's rows.
    fn prefix_limit(&self) -> usize {
        let high = self.num_variables - ABSORBED;
        self.specs.iter().fold(high, |limit, spec| {
            spec.next_rows
                .map_or(limit, |rows| limit.min(self.num_variables - rows))
        })
    }

    /// Checks the released proof's structure against this verifier's claims,
    /// with a message for every high coordinate and no grinding witness.
    pub(super) fn check_native_structure(
        &self,
        proof: &BitRingSwitchClaimsProof<F, E>,
    ) -> Result<(), VerificationError> {
        if !proof.sumcheck.pow_witnesses.is_empty() {
            return Err(invalid(
                "Poly64 ring-switch sumcheck carries grinding witnesses",
            ));
        }
        if proof.claims.len() != self.specs.len()
            || proof.sumcheck.polynomial_evaluations.len() != self.num_variables - ABSORBED
            || proof.claims.iter().zip(&self.specs).any(|(claim, spec)| {
                !claim.tensor.is_well_formed()
                    || claim.successor.is_some() != sends_successor(spec)
                    || claim
                        .successor
                        .as_ref()
                        .is_some_and(|s| !s.carry.is_well_formed() || !s.last.is_well_formed())
            })
        {
            return Err(invalid("Poly64 ring-switch native structural mismatch"));
        }
        Ok(())
    }

    /// Checks native structure and readings, then replays the released ring
    /// transcript. Returns the exact native continuation for importing the
    /// packed opening.
    ///
    /// The native verifier runs every sumcheck round, so claims whose points
    /// share a Boolean first coordinate inside the coordinates the released
    /// reduction may skip are refused, before the proof's structure is checked
    /// and before the challenger is touched.
    pub fn import_native<Ch>(
        &self,
        points: &[Point<E>],
        readings: &[(Option<E>, Option<E>)],
        proof: &BitRingSwitchClaimsProof<F, E>,
        mut challenger: Ch,
    ) -> Result<(NativeBinaryPolyRingInput, Point<E>, Ch), VerificationError>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        if points.len() != self.specs.len()
            || readings.len() != self.specs.len()
            || points
                .iter()
                .zip(readings)
                .zip(&self.specs)
                .any(|((point, reading), spec)| {
                    point.num_variables() != self.num_variables
                        || reading.0.is_some() != spec.current
                        || reading.1.is_some() != spec.next_rows.is_some()
                })
        {
            return Err(invalid("Poly64 ring-switch native claim shape mismatch"));
        }
        if self.prefix_limit() > 0 {
            let first = points[0].as_slice()[0];
            if (first == E::ZERO || first == E::ONE)
                && points.iter().all(|point| point.as_slice()[0] == first)
            {
                return Err(invalid(
                    "native Poly64 ring-switch verifier runs every round, but the claims share a Boolean prefix",
                ));
            }
        }
        self.check_native_structure(proof)?;
        let reductions = points
            .iter()
            .zip(&self.specs)
            .map(|(point, spec)| {
                spec.next_rows
                    .map_or_else(
                        || BitRingSwitch::new(point),
                        |rows| BitRingSwitch::with_successor(point, rows),
                    )
                    .map_err(|_| invalid("Poly64 ring-switch native setup failed"))
            })
            .collect::<Result<_, _>>()?;
        let setup = BitRingSwitchClaims::<F, E>::new(reductions)
            .map_err(|_| invalid("Poly64 ring-switch native batch setup failed"))?;
        let (point, _) = setup
            .verify_readings(proof, readings, &mut challenger)
            .map_err(|_| invalid("Poly64 ring-switch native replay failed"))?;
        let mut values = Vec::new();
        for claim in &proof.claims {
            values.extend(claim.tensor.rows());
            if let Some(extra) = &claim.successor {
                values.extend(extra.carry.rows().iter().chain(extra.last.rows()));
            }
        }
        values.extend(
            proof
                .sumcheck
                .polynomial_evaluations
                .iter()
                .flatten()
                .flat_map(|value| value.coefficients()),
        );
        values.extend(proof.final_eval.coefficients());
        Ok((
            NativeBinaryPolyRingInput {
                shape: self.input_shape(),
                values,
            },
            point,
            challenger,
        ))
    }

    /// Checks the committed elements and messages against this verifier's
    /// claims.
    pub(super) fn check_native_proof(
        &self,
        proof: &NativePolyBitRingProofTargets,
    ) -> Result<(), VerificationError> {
        if proof.claims.len() != self.specs.len()
            || proof.sumcheck.len() != self.num_variables - ABSORBED
            || proof
                .claims
                .iter()
                .zip(&self.specs)
                .any(|(claim, spec)| claim.successor.is_some() != sends_successor(spec))
        {
            return Err(invalid(
                "native Poly64 ring-switch targets do not match the verifier shape",
            ));
        }
        Ok(())
    }

    fn check_native_readings(
        &self,
        readings: &[NativePolyBitRingReading],
    ) -> Result<(), VerificationError> {
        if readings.len() != self.specs.len()
            || readings.iter().zip(&self.specs).any(|(reading, spec)| {
                reading.point.len() != self.num_variables
                    || reading.current.is_some() != spec.current
                    || reading.next.is_some() != spec.next_rows.is_some()
            })
        {
            return Err(invalid(
                "native Poly64 ring-switch readings do not match the verifier shape",
            ));
        }
        Ok(())
    }

    /// Installs the complete ring-switch relation in the native carrier,
    /// running every sumcheck round (see the module documentation).
    ///
    /// Points are absorbed as Poly192 values and tensor rows as Poly64 cells,
    /// and challenges drawn, in the released order: eight batching
    /// coordinates, then alpha when some claim sends successor elements, then
    /// lambda for more than one claim. Each stated reading must equal its
    /// claim's column reading at the six absorbed coordinates, the starting
    /// sum is derived from the elements' rows, and the surviving value must
    /// close the final sum against the closing weight at the drawn point.
    pub fn verify_native(
        &self,
        b: &mut CircuitBuilder<F>,
        mut ch: BinaryTower128Challenger,
        readings: &[NativePolyBitRingReading],
        proof: &NativePolyBitRingProofTargets,
    ) -> Result<NativePolyBitRingOutput, VerificationError> {
        self.check_native_proof(proof)?;
        self.check_native_readings(readings)?;
        let high = self.num_variables - ABSORBED;
        poly_observe_seed_with_host::<H, F>(b, &mut ch, &self.seed)?;
        for (reading, claim) in readings.iter().zip(&proof.claims) {
            P::observe::<H>(b, &mut ch, &reading.point)?;
            P::observe_base::<H>(b, &mut ch, claim.tensor.rows())?;
            if let Some((carry, last)) = &claim.successor {
                P::observe_base::<H>(b, &mut ch, carry.rows())?;
                P::observe_base::<H>(b, &mut ch, last.rows())?;
            }
        }
        let batch = (0..BATCHED)
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
                let scaled = b.native_poly192_mul(alpha, &last);
                let inner = b.native_poly192_add(&carry, &scaled);
                let outer = b.native_poly192_mul(alpha, &inner);
                sum = b.native_poly192_add(&sum, &outer);
            }
            sums.push(sum);
            b.check_construction_limits()?;
        }
        let mut sum = batch_claims(b, &sums, lambda.as_ref());
        if high > 0 {
            let seed = domain_separator_seed(
                &SumcheckShape::new(high, 0, Basis::Evaluation).domain_separator::<F, E>(),
            );
            poly_observe_seed_with_host::<H, F>(b, &mut ch, &seed)?;
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
                closing_weight_native_poly(b, &reading.point[..high], &point, &batch, successor)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let closing = batch_claims(b, &weights, lambda.as_ref());
        let expected = b.native_poly192_mul(&closing, &proof.final_eval);
        P::assert_equal(b, &sum, &expected);
        Ok(NativePolyBitRingOutput {
            point,
            value: proof.final_eval.clone(),
            challenger: ch,
        })
    }
}

impl BinaryPolyRingInputShape {
    /// One Poly64 input per committed cell, in the native verifier's reading
    /// order: each claim's 192 tensor rows, then its carry and last rows, the
    /// three limbs of both values of every round's message, then the three
    /// limbs of the surviving value. Points and readings belong to the
    /// caller's route and are not inputs here.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<F>,
    ) -> Result<NativePolyBitRingProofTargets, VerificationError> {
        let claims = self
            .specs
            .iter()
            .map(|spec| {
                let tensor = alloc_tensor(b)?;
                let successor = if sends_successor(spec) {
                    Some((alloc_tensor(b)?, alloc_tensor(b)?))
                } else {
                    None
                };
                Ok(NativePolyBitRingClaimTargets { tensor, successor })
            })
            .collect::<Result<_, VerificationError>>()?;
        let sumcheck = (0..self.num_variables - ABSORBED)
            .map(|_| Ok([alloc_challenge(b)?, alloc_challenge(b)?]))
            .collect::<Result<_, VerificationError>>()?;
        let final_eval = alloc_challenge(b)?;
        Ok(NativePolyBitRingProofTargets {
            claims,
            sumcheck,
            final_eval,
        })
    }
}

impl NativeBinaryPolyRingInput {
    pub const fn shape(&self) -> &BinaryPolyRingInputShape {
        &self.shape
    }

    /// The native verifier's inputs, in allocation order.
    pub fn private_native_values(
        &self,
        expected: &BinaryPolyRingInputShape,
    ) -> Result<Vec<F>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "Poly64 ring-switch input belongs to a different verifier",
            ));
        }
        Ok(self.values.clone())
    }
}

/// Whether the claim's successor view outruns one element, so it sends carry
/// and last tensors.
fn sends_successor(spec: &BinaryRingClaimSpec) -> bool {
    spec.next_rows.is_some_and(|rows| rows > ABSORBED)
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

/// `sum_i lambda^i * terms[i]`, by Horner's rule from the last claim. One
/// claim draws no lambda.
fn batch_claims(
    b: &mut CircuitBuilder<F>,
    terms: &[NativePoly192Target],
    lambda: Option<&NativePoly192Target>,
) -> NativePoly192Target {
    let (last, rest) = terms.split_last().expect("checked nonempty claims");
    let mut sum = last.clone();
    for term in rest.iter().rev() {
        let lambda = lambda.expect("several claims draw lambda");
        let scaled = b.native_poly192_mul(lambda, &sum);
        sum = b.native_poly192_add(term, &scaled);
    }
    sum
}

/// The successor reading of a view whose `rows` trailing coordinates step
/// inside one element. Column `v` weighs `eq(low, v - 1)` when its row bits
/// are not all zero, plus `eq(low, v)` when they are all one, the repeated
/// last row.
fn successor_within_element(
    b: &mut CircuitBuilder<F>,
    tensor: &mut NativePolyBitTensorTarget,
    low: &[NativePoly192Target],
    rows: usize,
) -> Result<NativePoly192Target, VerificationError> {
    let weights = equality_table(b, low);
    let last = (1usize << rows) - 1;
    let mut reading: Option<NativePoly192Target> = None;
    for v in 0..weights.len() {
        let shifted = (v & last != 0).then(|| weights[v - 1]);
        let repeated = (v & last == last).then_some(weights[v]);
        let weight = match (shifted, repeated) {
            (Some(shifted), Some(repeated)) => {
                core::array::from_fn(|k| b.add(shifted[k], repeated[k]))
            }
            (Some(weight), None) | (None, Some(weight)) => weight,
            (None, None) => continue,
        };
        let weight = b.native_poly192_from_coefficients(weight);
        let column = tensor.column(b, v)?;
        let term = b.native_poly192_mul(&column, &weight);
        reading = Some(match reading {
            Some(sum) => b.native_poly192_add(&sum, &term),
            None => term,
        });
    }
    b.check_construction_limits()?;
    Ok(reading.expect("every successor view reads some column"))
}

fn alloc_cell(b: &mut CircuitBuilder<F>) -> Result<ExprId, VerificationError> {
    let value = b.alloc_private_input("native Poly64 ring-switch cell");
    b.check_construction_limits()?;
    Ok(value)
}

fn alloc_challenge(b: &mut CircuitBuilder<F>) -> Result<NativePoly192Target, VerificationError> {
    let limbs = [alloc_cell(b)?, alloc_cell(b)?, alloc_cell(b)?];
    Ok(b.native_poly192_from_coefficients(limbs))
}

fn alloc_tensor(b: &mut CircuitBuilder<F>) -> Result<NativePolyBitTensorTarget, VerificationError> {
    let rows = (0..ROWS).map(|_| alloc_cell(b)).collect::<Result<_, _>>()?;
    Ok(NativePolyBitTensorTarget::from_rows(rows)?)
}
