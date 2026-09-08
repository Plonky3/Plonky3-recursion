//! Structural descriptors for native STARK inputs used by prepared recursive verifiers.

use alloc::vec::Vec;

use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::{AirVariant, RowCounts, TablePacking};

/// Allocation-relevant opened-value partitions for one STARK instance.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedValuesShape {
    pub(crate) trace_local: usize,
    pub(crate) trace_next: Option<usize>,
    pub(crate) preprocessed_local: Option<usize>,
    pub(crate) preprocessed_next: Option<usize>,
    pub(crate) quotient_chunks: Vec<usize>,
    pub(crate) random: Option<usize>,
}

/// Opened-value partitions for a batch instance, including lookup permutations.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedValuesWithLookupsShape {
    pub(crate) base: OpenedValuesShape,
    pub(crate) permutation_local: usize,
    pub(crate) permutation_next: usize,
}

/// Shapes of every commitment selected by a native proof.
#[derive(Clone, PartialEq, Eq)]
pub struct CommitmentsShape<C> {
    pub(crate) main: C,
    pub(crate) permutation: Option<C>,
    pub(crate) quotient_chunks: C,
    pub(crate) random: Option<C>,
}

/// Metadata for one matrix in a global preprocessed commitment.
#[derive(Clone, PartialEq, Eq)]
pub struct PreprocessedInstanceShape {
    pub(crate) matrix_index: usize,
    pub(crate) width: usize,
    pub(crate) degree_bits: usize,
}

/// Shape and routing metadata for global preprocessed matrices.
#[derive(Clone, PartialEq, Eq)]
pub struct GlobalPreprocessedShape<C> {
    pub(crate) commitment: C,
    pub(crate) instances: Vec<Option<PreprocessedInstanceShape>>,
    pub(crate) matrix_to_instance: Vec<usize>,
}

/// Compile-relevant manifest entry for one non-primitive table.
#[derive(Clone, PartialEq, Eq)]
pub struct NonPrimitiveContract<F> {
    pub(crate) op_type: NpoTypeId,
    pub(crate) rows: usize,
    pub(crate) lanes: usize,
    pub(crate) air_variant: AirVariant,
    pub(crate) public_values: Vec<F>,
}

/// Exact native contract for one uni-STARK input.
#[derive(Clone, PartialEq, Eq)]
pub struct UniInputContract<C, O> {
    pub(crate) degree_bits: usize,
    pub(crate) public_inputs: usize,
    pub(crate) commitments: CommitmentsShape<C>,
    pub(crate) opened_values: OpenedValuesShape,
    pub(crate) opening: O,
    pub(crate) preprocessed_commit: Option<C>,
}

/// Exact native contract for one batch-STARK input.
#[derive(Clone, PartialEq, Eq)]
pub struct BatchInputContract<F, C, O> {
    pub(crate) degree_bits: Vec<usize>,
    pub(crate) public_inputs: Vec<usize>,
    pub(crate) commitments: CommitmentsShape<C>,
    pub(crate) opened_values: Vec<OpenedValuesWithLookupsShape>,
    pub(crate) lookup_terminals: Vec<bool>,
    pub(crate) opening: O,
    pub(crate) table_packing: TablePacking,
    pub(crate) rows: RowCounts,
    pub(crate) alu_variant: AirVariant,
    pub(crate) ext_degree: usize,
    pub(crate) w_binomial: Option<F>,
    pub(crate) alu_quintic_trinomial: bool,
    pub(crate) non_primitives: Vec<NonPrimitiveContract<F>>,
    pub(crate) preprocessed: Option<GlobalPreprocessedShape<C>>,
}

/// Exact native input contract selected by a prepared verifier.
#[derive(Clone, PartialEq, Eq)]
pub enum InputContract<F, C, O> {
    /// A uni-STARK input contract.
    Uni(UniInputContract<C, O>),
    /// A batch-STARK input contract.
    Batch(BatchInputContract<F, C, O>),
}
