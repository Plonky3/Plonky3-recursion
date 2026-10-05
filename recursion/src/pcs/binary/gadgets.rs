//! Multilinear weights and additive-domain folds in the Wiedemann tower.

use core::hash::Hash;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::Field;

use crate::verifier::binary_field_policy::{BinaryRelationPolicy, TowerRelation};

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
    next_eval_using::<TowerRelation<BinaryField128, BinaryField128>, F>(circuit, point, row)
}
pub(crate) fn next_eval_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    point: &[P::ChallengeTarget],
    row: &[P::ChallengeTarget],
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    assert_eq!(
        point.len(),
        row.len(),
        "binary successor point lengths differ"
    );
    let one = P::constant(circuit, 1)?;
    let mut carry = one.clone();
    let mut done = P::constant(circuit, 0)?;
    let mut omega = one.clone();
    for (point, row) in point.iter().zip(row).rev() {
        let joint = P::mul(circuit, point, row);
        let point_not_row = P::add(circuit, point, &joint);
        let not_point_row = P::add(circuit, row, &joint);
        let sum = P::add(circuit, point, row);
        let equal = P::add(circuit, &one, &sum);
        let previous_carry = carry;
        carry = P::mul(circuit, &previous_carry, &point_not_row);
        let settled = P::mul(circuit, &previous_carry, &not_point_row);
        let already_settled = P::mul(circuit, &done, &equal);
        done = P::add(circuit, &already_settled, &settled);
        omega = P::mul(circuit, &omega, &joint);
    }
    Ok(P::add(circuit, &done, &omega))
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
    reduce_sumcheck_using::<TowerRelation<BinaryField128, BinaryField128>, F>(
        circuit, claim, h0, hinf, beta,
    )
}
pub(crate) fn reduce_sumcheck_using<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    claim: &P::ChallengeTarget,
    h0: &P::ChallengeTarget,
    hinf: &P::ChallengeTarget,
    beta: &P::ChallengeTarget,
) -> Result<P::ChallengeTarget, CircuitBuilderError>
where
    CF: Field + Eq + Hash,
    P: BinaryRelationPolicy<CF>,
{
    let one = P::constant(circuit, 1)?;
    let beta_plus_one = P::add(circuit, beta, &one);
    let leading = P::mul(circuit, hinf, &beta_plus_one);
    let slope = P::add(circuit, claim, &leading);
    let increment = P::mul(circuit, beta, &slope);
    Ok(P::add(circuit, h0, &increment))
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
