//! Polynomial-basis WHIR weights, direct query coordinates and serialization.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, TowerLevel};
use p3_circuit::ops::BinaryPoly192Target;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};

use crate::BinaryTower128Challenger;
use crate::verifier::VerificationError;

/// Evaluates the binary multilinear equality weight at two points.
/// In characteristic two each equality factor is `1 + a + b`.
/// The empty product is one. Targets must belong to this builder.
///
/// # Errors
/// Rejects a host field of characteristic two.
///
/// # Panics
/// Panics if the points have different lengths.
pub(crate) fn poly192_eq_eval<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    a: &[BinaryPoly192Target],
    b: &[BinaryPoly192Target],
) -> Result<BinaryPoly192Target, CircuitBuilderError> {
    assert_eq!(a.len(), b.len(), "binary equality point lengths differ");
    let one = circuit.binary_poly192_constant([1, 0, 0])?;
    let mut weight = one.clone();
    for (a, b) in a.iter().zip(b) {
        let sum = circuit.binary_poly192_add(a, b);
        let equal = circuit.binary_poly192_add(&one, &sum);
        weight = circuit.binary_poly192_mul(&weight, &equal);
    }
    Ok(weight)
}

/// Evaluates the repeat-last successor weight `done + omega` used by native
/// `Point::eval_next(point, row)`. Coordinates have the native big-endian
/// variable order; carry propagates from the last coordinate. The empty
/// weight is one. Targets must belong to this builder.
///
/// # Errors
/// Rejects a host field of characteristic two.
///
/// # Panics
/// Panics if the points have different lengths.
pub(super) fn poly192_next_eval<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    point: &[BinaryPoly192Target],
    row: &[BinaryPoly192Target],
) -> Result<BinaryPoly192Target, CircuitBuilderError> {
    assert_eq!(
        point.len(),
        row.len(),
        "binary successor point lengths differ"
    );
    let one = circuit.binary_poly192_constant([1, 0, 0])?;
    let mut carry = one.clone();
    let mut done = circuit.binary_poly192_constant([0; 3])?;
    let mut omega = one.clone();
    for (point, row) in point.iter().zip(row).rev() {
        let joint = circuit.binary_poly192_mul(point, row);
        let point_not_row = circuit.binary_poly192_add(point, &joint);
        let not_point_row = circuit.binary_poly192_add(row, &joint);
        let sum = circuit.binary_poly192_add(point, row);
        let equal = circuit.binary_poly192_add(&one, &sum);
        let previous_carry = carry;
        carry = circuit.binary_poly192_mul(&previous_carry, &point_not_row);
        let settled = circuit.binary_poly192_mul(&previous_carry, &not_point_row);
        let already_settled = circuit.binary_poly192_mul(&done, &equal);
        done = circuit.binary_poly192_add(&already_settled, &settled);
        omega = circuit.binary_poly192_mul(&omega, &joint);
    }
    Ok(circuit.binary_poly192_add(&done, &omega))
}

/// Reduces a compact evaluation-basis quadratic sumcheck claim at `beta`.
/// The message is `[h(0), h(infinity)]`; `h(1)` is derived from `claim`.
/// In characteristic two the updated claim is
/// `h0 + beta * (claim + hinf * (beta + 1))`.
/// This is the arithmetic step; the caller must bind the message and sample
/// `beta` through the native sumcheck transcript before using it.
/// Targets must belong to this builder.
///
/// # Errors
/// Rejects a host field of characteristic two.
pub(super) fn poly192_reduce_sumcheck_claim<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    claim: &BinaryPoly192Target,
    h0: &BinaryPoly192Target,
    hinf: &BinaryPoly192Target,
    beta: &BinaryPoly192Target,
) -> Result<BinaryPoly192Target, CircuitBuilderError> {
    let one = circuit.binary_poly192_constant([1, 0, 0])?;
    let beta_plus_one = circuit.binary_poly192_add(beta, &one);
    let leading = circuit.binary_poly192_mul(hinf, &beta_plus_one);
    let slope = circuit.binary_poly192_add(claim, &leading);
    let increment = circuit.binary_poly192_mul(beta, &slope);
    Ok(circuit.binary_poly192_add(h0, &increment))
}

/// Direct coefficient-selector weight `prod(1 + r * (s + 1))` used by
/// released additive WHIR. Both points use the native big-endian coordinate
/// order. The empty product is one. Targets must belong to this builder.
pub(super) fn poly192_select_eval<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    point: &[BinaryPoly192Target],
    row: &[BinaryPoly192Target],
) -> Result<BinaryPoly192Target, CircuitBuilderError> {
    if point.len() != row.len() {
        return Err(arity("BinaryWhirSelect", point.len(), row.len()));
    }
    let one = circuit.binary_poly192_constant([1, 0, 0])?;
    let mut weight = one.clone();
    for (s, r) in point.iter().zip(row) {
        let shifted = circuit.binary_poly192_add(s, &one);
        let product = circuit.binary_poly192_mul(r, &shifted);
        let factor = circuit.binary_poly192_add(&one, &product);
        weight = circuit.binary_poly192_mul(&weight, &factor);
    }
    Ok(weight)
}

/// Evaluates a coefficient table at direct additive-domain coordinates. The
/// native coefficient order folds adjacent entries by `lo + r * hi`, from
/// the last coordinate to the first. Targets must belong to this builder.
pub(super) fn poly192_eval_coefficients<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    coefficients: &[BinaryPoly192Target],
    point: &[BinaryPoly192Target],
) -> Result<BinaryPoly192Target, CircuitBuilderError> {
    eval_table(circuit, coefficients, point, false)
}

/// Evaluates a multilinear evaluation table, as required for authenticated
/// WHIR rows and its closing polynomial. Adjacent entries fold by
/// `lo + r * (hi + lo)`, from the last coordinate to the first. The caller
/// reverses the sumcheck point first for a suffix binding strategy.
pub(super) fn poly192_eval_multilinear<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    evaluations: &[BinaryPoly192Target],
    point: &[BinaryPoly192Target],
) -> Result<BinaryPoly192Target, CircuitBuilderError> {
    eval_table(circuit, evaluations, point, true)
}

fn eval_table<EF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    values: &[BinaryPoly192Target],
    point: &[BinaryPoly192Target],
    multilinear: bool,
) -> Result<BinaryPoly192Target, CircuitBuilderError> {
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
                    circuit.binary_poly192_add(&pair[0], &pair[1])
                } else {
                    pair[1].clone()
                };
                let product = circuit.binary_poly192_mul(coordinate, &slope);
                circuit.binary_poly192_add(&pair[0], &product)
            })
            .collect();
    }
    Ok(layer[0].clone())
}

/// Reconstructs released Poly64-domain WHIR query coordinates
/// `[W_(n-1)(x), ..., W_0(x)]` from little-endian index bits, with
/// `x = domain_point(index)` in the alphabet's own Cantor basis. The Cantor
/// recurrence makes each coordinate the linear map of `index >> j`.
/// Every index bit is constrained even when the coordinate point is empty.
/// Targets must belong to this builder.
pub(super) fn poly_whir_query_point<EF>(
    circuit: &mut CircuitBuilder<EF>,
    index_bits: &[ExprId],
    num_variables: usize,
) -> Result<Vec<BinaryPoly192Target>, CircuitBuilderError>
where
    EF: Field + Eq + Hash,
{
    if index_bits.len() > 64 || num_variables > 64 {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryWhirQueryPoint",
            expected: alloc::format!("at most {} alphabet coordinates", 64),
            got: index_bits.len().max(num_variables),
        });
    }
    // The constructor checks the carrier characteristic even for empty points.
    let zero_value = circuit.binary_poly64_constant(0)?;
    let zero = zero_value.bits()[0];
    for &bit in index_bits {
        circuit.assert_bool(bit);
    }
    let columns = (0..index_bits.len())
        .map(|i| Poly64::cantor_basis(i).to_bits())
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
            let coefficient = circuit.binary_poly64_from_bits(bits)?;
            Ok(circuit.binary_poly192_from_coefficients([
                coefficient,
                zero_value.clone(),
                zero_value.clone(),
            ]))
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

pub(crate) fn assert_equal<EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    a: &BinaryPoly192Target,
    e: &BinaryPoly192Target,
) {
    for (a, e) in a.coefficients().iter().zip(e.coefficients()) {
        for (&a, &e) in a.bits().iter().zip(e.bits()) {
            let difference = b.sub(a, e);
            b.assert_zero(difference);
        }
    }
}

pub(super) fn constrain_width<EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    value: &BinaryPoly192Target,
    bits: usize,
) {
    if bits == 64 {
        for &bit in value.coefficients()[1..]
            .iter()
            .flat_map(|coefficient| coefficient.bits())
        {
            let difference = b.sub(ExprId::ZERO, bit);
            b.assert_zero(difference);
        }
    }
}

pub(super) fn poly_bytes<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    value: &BinaryPoly192Target,
    bits: usize,
) -> Result<Vec<ExprId>, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    if !matches!(bits, 64 | 192) {
        return Err(super::whir_plan::invalid(
            "binary Poly WHIR serialization width is invalid",
        ));
    }
    value.coefficients()[..bits / 64]
        .iter()
        .flat_map(|coefficient| coefficient.bits().chunks_exact(8))
        .map(|byte| Ok(b.reconstruct_index_from_bits::<BF>(byte)?))
        .collect()
}

pub(super) fn observe_values<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    ch: &mut BinaryTower128Challenger,
    values: &[BinaryPoly192Target],
    bits: usize,
) -> Result<(), VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    for value in values {
        let bytes = poly_bytes::<BF, EF>(b, value, bits)?;
        ch.observe_bytes::<BF, EF>(b, &bytes)?;
    }
    Ok(())
}

pub(crate) fn observe_seed<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    ch: &mut BinaryTower128Challenger,
    seed: &[Poly64],
) -> Result<(), VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    for value in seed {
        let target = b.binary_poly64_constant(value.to_bits())?;
        ch.observe_poly64::<BF, EF>(b, &target)?;
    }
    Ok(())
}
