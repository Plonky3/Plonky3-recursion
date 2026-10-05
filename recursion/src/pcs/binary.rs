//! Byte-hash recursive verification primitives for the binary multilinear PCS.

use alloc::format;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_pcs::BinaryPcsConfig;
use p3_binary_pcs::transcript::BinaryPcsShape;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, PrimeField64};

use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

type ByteMerkleMmcs<F, H, C> = p3_merkle_tree::MerkleTreeMmcs<F, u8, H, C, 2, 32>;
type GroupedByteMerkleMmcs<F, H, C> = p3_binary_pcs::GroupedCodewordMmcs<ByteMerkleMmcs<F, H, C>>;
type ByteMerklePcsProof<F, E, H0, C0, H1, C1> =
    p3_binary_pcs::BinaryPcsProof<F, E, ByteMerkleMmcs<F, H0, C0>, ByteMerkleMmcs<E, H1, C1>>;
type GroupedByteMerklePcsProof<F, E, H0, C0, H1, C1> = p3_binary_pcs::BinaryPcsProof<
    F,
    E,
    GroupedByteMerkleMmcs<F, H0, C0>,
    GroupedByteMerkleMmcs<E, H1, C1>,
>;
type ByteMerkleBooleanProof<E, H0, C0, H1, C1> =
    p3_binary_pcs::BooleanProof<E, ByteMerkleMmcs<E, H0, C0>, ByteMerkleMmcs<E, H1, C1>>;
type GroupedByteMerkleBooleanProof<E, H0, C0, H1, C1> = p3_binary_pcs::BooleanProof<
    E,
    GroupedByteMerkleMmcs<E, H0, C0>,
    GroupedByteMerkleMmcs<E, H1, C1>,
>;
type ByteMerkleBooleanTraceProof<E, H0, C0, H1, C1> =
    p3_binary_pcs::BooleanTraceCommitmentProof<E, ByteMerkleBooleanProof<E, H0, C0, H1, C1>>;
type GroupedByteMerkleBooleanTraceProof<E, H0, C0, H1, C1> =
    p3_binary_pcs::BooleanTraceCommitmentProof<E, GroupedByteMerkleBooleanProof<E, H0, C0, H1, C1>>;
type ByteMerkleBooleanWhirTraceProof<E, H, C> = p3_binary_pcs::BooleanTraceCommitmentProof<
    E,
    p3_binary_pcs::whir::BooleanWhirProof<E, ByteMerkleMmcs<E, H, C>>,
>;
pub(crate) type ByteMerkleMmcsPair<'base, 'round, F, E, H0, C0, H1, C1> = (
    &'base ByteMerkleMmcs<F, H0, C0>,
    &'round ByteMerkleMmcs<E, H1, C1>,
);
pub(crate) type ByteMerkleWhirParameters<'config, 'mmcs, F, E, Ch, H, C> = (
    &'config p3_whir::WhirConfig<E, F, Ch>,
    &'mmcs ByteMerkleMmcs<F, H, C>,
);
type OracleOpeningTargets<Row> = (Vec<Row>, Vec<Vec<Vec<ExprId>>>);
type WhirVerificationOutput<T> = (Vec<p3_sumcheck::OpeningBatch<T>>, BinaryTower128Challenger);

mod boolean;
mod boolean_whir;
mod fields;
mod gadgets;
mod generic_sumcheck;
mod generic_sumcheck_verifier;
mod grouped_boolean;
mod grouped_input;
mod grouped_oracle;
mod grouped_pcs;
mod grouped_trace;
mod input;
mod nonzero;
mod poly_generic_sumcheck;
mod poly_interpolation;
mod poly_nonzero;
pub(crate) use poly_interpolation::Poly192SumcheckInterpolator;
mod poly_whir_gadgets;
pub(crate) use poly_whir_gadgets::poly_whir_query_point;
mod poly_whir_input;
mod poly_whir_verifier;
pub(crate) use poly_whir_gadgets::{
    assert_equal as poly_assert_equal, observe_seed as poly_observe_seed,
    observe_values as poly_observe_values, poly192_eq_eval,
    poly192_eval_multilinear as poly_eval_multilinear,
};
mod ring;
mod ring_input;
mod tensor;
mod trace;
mod trace_native;
mod trace_plan;
mod trace_routing;
mod trace_whir;
mod verifier;
mod whir_gadgets;
mod whir_input;
mod whir_kernel;
mod whir_plan;
mod whir_queries;
mod whir_verifier;
pub use boolean::{
    BinaryBooleanInputShape, BinaryBooleanPcsVerifier, BinaryBooleanProofTargets,
    NativeBinaryBooleanInput,
};
pub use boolean_whir::{
    BinaryBooleanWhirInputShape, BinaryBooleanWhirProofTargets, BinaryBooleanWhirVerifier,
    NativeBinaryBooleanWhirInput,
};
pub use fields::{
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField, RecursiveBinaryWhirTowerField,
};
pub use gadgets::{
    binary128_eq_eval, binary128_fold_pair, binary128_next_eval, binary128_reduce_sumcheck_claim,
};
pub use generic_sumcheck::Binary128SumcheckInterpolator;
pub use generic_sumcheck_verifier::{
    BinaryGenericSumcheckInputShape, BinaryGenericSumcheckOutput,
    BinaryGenericSumcheckProofTargets, BinaryGenericSumcheckVerifier,
    NativeBinaryGenericSumcheckInput,
};
pub use grouped_boolean::{
    BinaryGroupedBooleanInputShape, BinaryGroupedBooleanPcsVerifier,
    BinaryGroupedBooleanProofTargets, NativeBinaryGroupedBooleanInput,
};
pub use grouped_input::NativeBinaryGroupedPcsInput;
pub use grouped_oracle::BinaryGroupedOraclePlan;
pub use grouped_pcs::{
    BinaryCodewordGrouping, BinaryGroupedOpeningTargets, BinaryGroupedPcsInputShape,
    BinaryGroupedPcsProofTargets, BinaryGroupedPcsVerifier,
};
pub use grouped_trace::{
    BinaryGroupedBooleanTraceInputShape, BinaryGroupedBooleanTraceProofTargets,
    BinaryGroupedBooleanTraceVerifier, NativeBinaryGroupedBooleanTraceInput,
};
pub use input::{BinaryPcsInputShape, NativeBinaryPcsInput};
pub use nonzero::{
    BinaryNonzeroChallengeOutput, BinaryNonzeroChallengePlan, BinaryNonzeroChallengeTailOutput,
    BinaryNonzeroChallengeTailPlan,
};
pub use poly_generic_sumcheck::{
    BinaryPolyGenericSumcheckInputShape, BinaryPolyGenericSumcheckOutput,
    BinaryPolyGenericSumcheckProofTargets, BinaryPolyGenericSumcheckVerifier,
    NativeBinaryPolyGenericSumcheckInput,
};
pub use poly_nonzero::{
    BinaryPolyNonzeroChallengeOutput, BinaryPolyNonzeroChallengePlan,
    BinaryPolyNonzeroChallengeTailOutput, BinaryPolyNonzeroChallengeTailPlan,
};
pub use poly_whir_input::{
    BinaryPolyWhirInputShape, BinaryPolyWhirProofTargets, BinaryPolyWhirRoundTargets,
    BinaryPolyWhirSumcheckTargets, NativeBinaryPolyWhirInput,
};
pub use poly_whir_verifier::BinaryPolyWhirVerifier;
pub use ring::{
    BinaryBitRingVerifier, BinaryRingClaimSpec, BinaryRingClaimTargets, BinaryRingOutput,
    BinaryRingProofTargets,
};
pub use ring_input::{BinaryRingInputShape, NativeBinaryRingInput};
pub use tensor::{BinaryTowerTensorTarget, binary_tensor_closing_weight};
pub use trace::{
    BinaryBooleanTraceInputShape, BinaryBooleanTraceProofTargets, BinaryBooleanTraceVerifier,
    NativeBinaryBooleanTraceInput,
};
pub use trace_whir::{
    BinaryBooleanWhirTraceInputShape, BinaryBooleanWhirTraceProofTargets,
    BinaryBooleanWhirTraceVerifier, NativeBinaryBooleanWhirTraceInput,
};
pub use verifier::{
    BinaryOracleOpeningTargets, BinaryPcs128ProofTargets, BinaryPcs128Verifier, BinaryPcsVerifier,
};
pub(crate) use verifier::{
    assert_equal, observe_cap_with_host, observe_seed, observe_seed_with_host, observe_values,
    observe_values_with_host, seed_bytes_with_host,
};
pub use whir_gadgets::{
    binary_whir_query_point, binary128_eval_coefficients, binary128_eval_multilinear,
    binary128_select_eval,
};
pub use whir_input::{
    BinaryWhirInputShape, BinaryWhirProofTargets, BinaryWhirRoundTargets,
    BinaryWhirSumcheckTargets, NativeBinaryWhirInput,
};
pub use whir_queries::BinaryWhirQueryPlan;
pub use whir_verifier::BinaryWhirVerifier;

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
    verify_binary_pcs_query_indices_with_continuation::<BF, EF>(
        circuit,
        challenger,
        config,
        sorted_indices,
        max_draws,
    )
    .map(|_| ())
}

/// Uses the trusted native PCS query geometry and retains its exact completion
/// digest. The result supports only a nonempty next native observation.
pub fn verify_binary_pcs_query_indices_with_continuation<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: BinaryTower128Challenger,
    config: &BinaryPcsConfig,
    sorted_indices: &[Vec<ExprId>],
    max_draws: usize,
) -> Result<BinaryQueryContinuation, CircuitBuilderError>
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
    verify_binary_query_indices_with_continuation::<BF, EF>(
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
    challenger: BinaryTower128Challenger,
    bits: usize,
    sorted_indices: &[Vec<ExprId>],
    max_draws: usize,
) -> Result<(), CircuitBuilderError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    verify_binary_query_indices_with_continuation::<BF, EF>(
        circuit,
        challenger,
        bits,
        sorted_indices,
        max_draws,
    )
    .map(|_| ())
}

/// Verifies the same bounded query relation and retains the native completion
/// digest under the derived first-completion selector. The opaque result can
/// only resume through a nonempty next observation; it cannot sample the
/// overdrawn transcript or expose its variable-length native output buffer.
/// Shape checks and errors match [`verify_binary_query_indices`].
pub fn verify_binary_query_indices_with_continuation<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    mut challenger: BinaryTower128Challenger,
    bits: usize,
    sorted_indices: &[Vec<ExprId>],
    max_draws: usize,
) -> Result<BinaryQueryContinuation, CircuitBuilderError>
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
    let mut retained = [zero; 32];
    let mut stop_total = zero;
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
        let complete_after = circuit.mul_many(&seen);
        let stop = circuit.sub(complete_after, complete);
        circuit.assert_bool(stop);
        stop_total = circuit.add(stop_total, stop);
        let (_, digest) = challenger.retained_query_digest()?;
        for (selected, byte) in retained.iter_mut().zip(digest) {
            *selected = circuit.mul_add(stop, byte, *selected);
        }
    }
    for present in seen {
        circuit.connect(present, one);
    }
    circuit.connect(stop_total, one);
    let (hash, _) = challenger.retained_query_digest()?;
    Ok(BinaryQueryContinuation::from_digest(hash, retained))
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
