//! Multilinear weights and additive-domain folds in the Wiedemann tower.

use core::hash::Hash;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::Field;

/// Evaluates the binary multilinear equality weight at two points.
/// In characteristic two each equality factor is `1 + a + b`.
/// The empty product is one. Targets must belong to this builder.
///
/// # Errors
/// Rejects a host field of characteristic two.
///
/// # Panics
/// Panics if the points have different lengths.
pub fn binary128_eq_eval<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    a: &[BinaryTower128Target],
    b: &[BinaryTower128Target],
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    assert_eq!(a.len(), b.len(), "binary equality point lengths differ");
    let one = circuit.binary128_constant(1)?;
    let mut weight = one.clone();
    for (a, b) in a.iter().zip(b) {
        let sum = circuit.binary128_add(a, b);
        let equal = circuit.binary128_add(&one, &sum);
        weight = circuit.binary128_mul(&weight, &equal);
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
pub fn binary128_next_eval<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    point: &[BinaryTower128Target],
    row: &[BinaryTower128Target],
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    assert_eq!(
        point.len(),
        row.len(),
        "binary successor point lengths differ"
    );
    let one = circuit.binary128_constant(1)?;
    let mut carry = one.clone();
    let mut done = circuit.binary128_constant(0)?;
    let mut omega = one.clone();
    for (point, row) in point.iter().zip(row).rev() {
        let joint = circuit.binary128_mul(point, row);
        let point_not_row = circuit.binary128_add(point, &joint);
        let not_point_row = circuit.binary128_add(row, &joint);
        let sum = circuit.binary128_add(point, row);
        let equal = circuit.binary128_add(&one, &sum);
        let previous_carry = carry;
        carry = circuit.binary128_mul(&previous_carry, &point_not_row);
        let settled = circuit.binary128_mul(&previous_carry, &not_point_row);
        let already_settled = circuit.binary128_mul(&done, &equal);
        done = circuit.binary128_add(&already_settled, &settled);
        omega = circuit.binary128_mul(&omega, &joint);
    }
    Ok(circuit.binary128_add(&done, &omega))
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
pub fn binary128_reduce_sumcheck_claim<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    claim: &BinaryTower128Target,
    h0: &BinaryTower128Target,
    hinf: &BinaryTower128Target,
    beta: &BinaryTower128Target,
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    let one = circuit.binary128_constant(1)?;
    let beta_plus_one = circuit.binary128_add(beta, &one);
    let leading = circuit.binary128_mul(hinf, &beta_plus_one);
    let slope = circuit.binary128_add(claim, &leading);
    let increment = circuit.binary128_mul(beta, &slope);
    Ok(circuit.binary128_add(h0, &increment))
}

/// Folds adjacent symbols of a Cantor-domain codeword at `beta`, matching
/// native `p3_binary_pcs::fold_pair`. `index_bits` is the little-endian pair
/// index, so the lower symbol sits at `domain_point(2 * index)`. Each supplied
/// index bit is constrained to be Boolean. Narrow tower symbols widen by
/// zero-extending their raw coordinates before this operation.
/// The caller must keep the pair index within that narrower alphabet's domain.
/// Targets must belong to this builder.
///
/// # Errors
/// Rejects an index width that cannot be doubled within `usize`, then a
/// host field of characteristic two.
pub fn binary128_fold_pair<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    index_bits: &[ExprId],
    beta: &BinaryTower128Target,
    lo: &BinaryTower128Target,
    hi: &BinaryTower128Target,
) -> Result<BinaryTower128Target, CircuitBuilderError> {
    if index_bits.len() >= usize::BITS as usize {
        return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
            expected: usize::BITS as usize - 1,
            n_bits: index_bits.len(),
        });
    }
    let mut x = circuit.binary128_constant(0)?;
    let zero = circuit.define_const(F::ZERO);
    for (r, &bit) in index_bits.iter().enumerate() {
        circuit.assert_bool(bit);
        let basis = BinaryField128::cantor_basis(r + 1).to_repr();
        let term = circuit.binary128_from_bits(core::array::from_fn(|i| {
            if basis >> i & 1 == 1 { bit } else { zero }
        }))?;
        x = circuit.binary128_add(&x, &term);
    }
    let f1 = circuit.binary128_add(lo, hi);
    let x_f1 = circuit.binary128_mul(&x, &f1);
    let f0 = circuit.binary128_add(lo, &x_f1);
    let slope = circuit.binary128_add(&f0, &f1);
    let increment = circuit.binary128_mul(beta, &slope);
    Ok(circuit.binary128_add(&f0, &increment))
}
