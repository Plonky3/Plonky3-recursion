//! Additive WHIR uses coefficient selectors and ordinary multilinear row folds.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::Field;

use super::RecursiveBinaryTowerField;
use crate::verifier::binary_field_policy::{BinaryRelationPolicy, TowerRelation};
use p3_binary_field::BinaryField128;

/// Direct coefficient-selector weight `prod(1 + r * (s + 1))` used by
/// released additive WHIR. Both points use the native big-endian coordinate
/// order. The empty product is one. Targets must belong to this builder.
pub fn binary128_select_eval<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    point: &[BinaryTower128Target],
    row: &[BinaryTower128Target],
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    select_eval_using::<TowerRelation<BinaryField128, BinaryField128>, EF>(circuit, point, row)
}
pub(crate) fn select_eval_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    point: &[P::ChallengeTarget],
    row: &[P::ChallengeTarget],
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    if point.len() != row.len() {
        return Err(arity("BinaryWhirSelect", point.len(), row.len()));
    }
    let one = P::constant(circuit, 1)?;
    let mut weight = one.clone();
    for (s, r) in point.iter().zip(row) {
        let shifted = P::add(circuit, s, &one);
        let product = P::mul(circuit, r, &shifted);
        let factor = P::add(circuit, &one, &product);
        weight = P::mul(circuit, &weight, &factor);
    }
    Ok(weight)
}

/// Evaluates a coefficient table at direct additive-domain coordinates. The
/// native coefficient order folds adjacent entries by `lo + r * hi`, from
/// the last coordinate to the first. Targets must belong to this builder.
pub fn binary128_eval_coefficients<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    coefficients: &[BinaryTower128Target],
    point: &[BinaryTower128Target],
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    eval_coefficients_using::<TowerRelation<BinaryField128, BinaryField128>, EF>(
        circuit,
        coefficients,
        point,
    )
}
pub(crate) fn eval_coefficients_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    coefficients: &[P::ChallengeTarget],
    point: &[P::ChallengeTarget],
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    eval_table_using::<P, CF>(circuit, coefficients, point, false)
}

/// Evaluates a multilinear evaluation table, as required for authenticated
/// WHIR rows and its closing polynomial. Adjacent entries fold by
/// `lo + r * (hi + lo)`, from the last coordinate to the first. The caller
/// reverses the sumcheck point first for a suffix binding strategy.
pub fn binary128_eval_multilinear<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    evaluations: &[BinaryTower128Target],
    point: &[BinaryTower128Target],
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    eval_multilinear_using::<TowerRelation<BinaryField128, BinaryField128>, EF>(
        circuit,
        evaluations,
        point,
    )
}
pub(crate) fn eval_multilinear_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    evaluations: &[P::ChallengeTarget],
    point: &[P::ChallengeTarget],
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    eval_table_using::<P, CF>(circuit, evaluations, point, true)
}

fn eval_table_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    values: &[P::ChallengeTarget],
    point: &[P::ChallengeTarget],
    multilinear: bool,
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    let expected = u32::try_from(point.len())
        .ok()
        .and_then(|bits| 1usize.checked_shl(bits));
    if expected != Some(values.len()) {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryWhirEvaluation",
            expected: alloc::format!("2^{} table entries", point.len()),
            got: values.len(),
        });
    }
    let mut layer = values.to_vec();
    for coordinate in point.iter().rev() {
        layer = layer
            .chunks_exact(2)
            .map(|pair| {
                let slope = if multilinear {
                    P::add(circuit, &pair[0], &pair[1])
                } else {
                    pair[1].clone()
                };
                let product = P::mul(circuit, coordinate, &slope);
                P::add(circuit, &pair[0], &product)
            })
            .collect();
    }
    Ok(layer[0].clone())
}

/// Reconstructs released tower-domain WHIR query coordinates
/// `[W_(n-1)(x), ..., W_0(x)]` from little-endian index bits, with
/// `x = domain_point(index)` in the alphabet's own Cantor basis. The Cantor
/// recurrence makes each coordinate the linear map of `index >> j`.
/// Every index bit is constrained even when the coordinate point is empty.
/// Targets must belong to this builder.
pub fn binary_whir_query_point<F, EF>(
    circuit: &mut CircuitBuilder<EF>,
    index_bits: &[ExprId],
    num_variables: usize,
) -> Result<Vec<BinaryTower128Target>, CircuitBuilderError>
where
    F: RecursiveBinaryTowerField,
    EF: Field + Eq + Hash,
{
    if index_bits.len() > F::RAW_BITS || num_variables > F::RAW_BITS {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryWhirQueryPoint",
            expected: alloc::format!("at most {} alphabet coordinates", F::RAW_BITS),
            got: index_bits.len().max(num_variables),
        });
    }
    // The constructor checks the carrier characteristic even for empty points.
    let zero = circuit.binary128_constant(0)?.bits()[0];
    for &bit in index_bits {
        circuit.assert_bool(bit);
    }
    let columns = (0..index_bits.len())
        .map(|i| F::cantor_basis(i).raw_coordinates())
        .collect::<Vec<_>>();
    (0..num_variables)
        .rev()
        .map(|shift| {
            let bits = core::array::from_fn(|out| {
                let mut terms = index_bits
                    .iter()
                    .skip(shift)
                    .zip(&columns)
                    .filter_map(|(&bit, &basis)| (basis >> out & 1 != 0).then_some(bit));
                terms.next().map_or(zero, |first| {
                    terms.fold(first, |sum, bit| {
                        let difference = circuit.sub(sum, bit);
                        circuit.mul(difference, difference)
                    })
                })
            });
            circuit.binary128_from_bits(bits)
        })
        .collect()
}

fn arity(op: &'static str, expected: usize, got: usize) -> CircuitBuilderError {
    CircuitBuilderError::NonPrimitiveOpArity {
        op,
        expected: alloc::format!("{expected} point coordinates"),
        got,
    }
}
