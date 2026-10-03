//! Byte-hash recursive verification primitives for the binary multilinear PCS.

use alloc::format;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_pcs::BinaryPcsConfig;
use p3_binary_pcs::transcript::BinaryPcsShape;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, PrimeField64};

use crate::BinaryTower128Challenger;

mod gadgets;
mod verifier;
pub use gadgets::{
    binary128_eq_eval, binary128_fold_pair, binary128_next_eval, binary128_reduce_sumcheck_claim,
};
pub use verifier::{BinaryOracleOpeningTargets, BinaryPcs128ProofTargets, BinaryPcs128Verifier};

/// Verifies terminal binary PCS query sampling against a native configuration.
/// The challenger must already have absorbed the final codeword and checked
/// the query PoW, as in native `BinaryPcs::verify_at`. Query width and count
/// come from the verifier-owned configuration; `max_draws` is an explicit
/// operational budget. See [`verify_binary_query_indices`] for terminal-state
/// semantics and the supplied indices' representation.
///
/// # Errors
/// Rejects a query-count mismatch before adding constraints, then propagates
/// the bounded sampler's shape and challenger errors.
pub fn verify_binary_pcs_query_indices<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: BinaryTower128Challenger,
    config: &BinaryPcsConfig,
    sorted_indices: &[Vec<ExprId>],
    max_draws: usize,
) -> Result<(), CircuitBuilderError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let shape = BinaryPcsShape::new(config);
    if sorted_indices.len() != shape.num_pairs {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryQueryIndices",
            expected: format!("{} query indices", shape.num_pairs),
            got: sorted_indices.len(),
        });
    }
    verify_binary_query_indices::<BF, EF>(
        circuit,
        challenger,
        shape.pair_bits,
        sorted_indices,
        max_draws,
    )
}

/// Constrains the sorted first distinct native binary query indices.
///
/// Each supplied index consists of `bits` little-endian Boolean targets. The
/// circuit draws exactly `max_draws` candidates, requiring every candidate
/// before completion to belong to the proposed set and every proposed index
/// to appear. This accepts every native duplicate pattern completing within
/// the explicit verifier-owned draw budget, without a proof-specific shape.
/// Indices are compared bitwise, so they may exceed the host field's order.
///
/// This is a **terminal** transcript operation: it consumes the challenger
/// and exposes no continuation state. Draws after native completion are
/// ignored by the query relation. Their overdrawn state must not be used for
/// a subsequent protocol step.
///
/// # Errors
/// Rejects an empty or oversized query set, inconsistent index widths, a
/// bit width that cannot fit in `usize`, or a budget smaller than the query
/// count before adding constraints. Otherwise propagates challenger errors.
pub fn verify_binary_query_indices<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    mut challenger: BinaryTower128Challenger,
    bits: usize,
    sorted_indices: &[Vec<ExprId>],
    max_draws: usize,
) -> Result<(), CircuitBuilderError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    if bits >= usize::BITS as usize {
        return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
            expected: usize::BITS as usize - 1,
            n_bits: bits,
        });
    }
    let count = sorted_indices.len();
    if count == 0 || count > 1usize << bits {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryQueryIndices",
            expected: format!("1..=2^{bits} queries"),
            got: count,
        });
    }
    if max_draws < count {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "BinaryQueryIndices",
            expected: format!("at least {count} candidate draws"),
            got: max_draws,
        });
    }
    for index in sorted_indices {
        if index.len() != bits {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryQueryIndices",
                expected: format!("{bits} bits per index"),
                got: index.len(),
            });
        }
    }
    let zero = circuit.define_const(EF::ZERO);
    let one = circuit.define_const(EF::ONE);
    for &bit in sorted_indices.iter().flatten() {
        circuit.assert_bool(bit);
    }
    for pair in sorted_indices.windows(2) {
        let mut below = zero;
        for (&a, &b) in pair[0].iter().zip(&pair[1]) {
            let equal = equal_bit(circuit, a, b, one);
            let not_a = circuit.sub(one, a);
            let lower_here = circuit.mul(not_a, b);
            below = circuit.mul_add(equal, below, lower_here);
        }
        circuit.connect(below, one);
    }

    let mut seen = alloc::vec![zero; count];
    for _ in 0..max_draws {
        // Native uniform-bit sampling consumes eight bytes even for bits=0.
        let candidate = challenger.sample_bits::<BF, EF>(circuit, bits)?;
        let complete = circuit.mul_many(&seen);
        let active = circuit.sub(one, complete);
        let mut membership = zero;
        for (index, already_seen) in sorted_indices.iter().zip(&mut seen) {
            let factors: Vec<_> = candidate
                .iter()
                .zip(index)
                .map(|(&a, &b)| equal_bit(circuit, a, b, one))
                .collect();
            let equal = circuit.mul_many(&factors);
            membership = circuit.add(membership, equal);
            let unseen = circuit.sub(one, *already_seen);
            *already_seen = circuit.mul_add(equal, unseen, *already_seen);
        }
        // Strict ordering makes the equality events disjoint, hence this sum
        // is exactly zero or one rather than a potentially aliased integer.
        let outside = circuit.sub(one, membership);
        let invalid = circuit.mul(active, outside);
        circuit.assert_zero(invalid);
    }
    for present in seen {
        circuit.connect(present, one);
    }
    Ok(())
}

fn equal_bit<EF: p3_field::Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<EF>,
    a: ExprId,
    b: ExprId,
    one: ExprId,
) -> ExprId {
    let difference = circuit.sub(a, b);
    let different = circuit.mul(difference, difference);
    circuit.sub(one, different)
}
