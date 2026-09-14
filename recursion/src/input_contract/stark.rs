//! Structural descriptors for native STARK inputs used by prepared recursive verifiers.

use alloc::boxed::Box;
use alloc::vec::Vec;

use p3_batch_stark::{BatchProof, CommonData};
use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::{AirVariant, RowCounts, TablePacking};
use p3_commit::Pcs;
use p3_uni_stark::{Proof, StarkGenericConfig};

use crate::traits::{CheckedRecursive, Recursive};
use crate::verifier::VerificationError;

/// Validate a uni-STARK proof and all commitment inputs before target allocation.
pub(crate) fn validate_uni_native<SC, Comm, Opening>(
    proof: &Proof<SC>,
    preprocessed_commit: Option<&<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig,
    Comm: CheckedRecursive<SC::Challenge>
        + Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
    Opening: CheckedRecursive<SC::Challenge>
        + Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    Comm::validate_input(&proof.commitments.trace)?;
    Comm::validate_input(&proof.commitments.quotient_chunks)?;
    if let Some(random) = &proof.commitments.random {
        Comm::validate_input(random)?;
    }
    if let Some(preprocessed) = preprocessed_commit {
        Comm::validate_input(preprocessed)?;
    }
    Opening::validate_input(&proof.opening_proof)
}

/// Validate a batch-STARK proof, commitment inputs, and basic cardinality before
/// any batch target or reconstructed-table allocation.
pub(crate) fn validate_batch_native<SC, Comm, Opening>(
    proof: &BatchProof<SC>,
    common_data: &CommonData<SC>,
    air_public_counts: &[usize],
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig,
    Comm: CheckedRecursive<SC::Challenge>
        + Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
    Opening: CheckedRecursive<SC::Challenge>
        + Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    let instances = proof.opened_values.instances.len();
    if instances == 0 {
        return Err(VerificationError::InvalidProofShape(
            "batch-STARK allocation requires at least one instance".into(),
        ));
    }
    if air_public_counts.len() != instances {
        return Err(VerificationError::InvalidProofShape(
            "batch-STARK public input count cardinality mismatch".into(),
        ));
    }
    if proof.degree_bits.len() != instances {
        return Err(VerificationError::InvalidProofShape(
            "batch-STARK degree bit cardinality mismatch".into(),
        ));
    }
    if proof.lookup_terminals.len() != instances {
        return Err(VerificationError::InvalidProofShape(
            "batch-STARK lookup terminal cardinality mismatch".into(),
        ));
    }

    Comm::validate_input(&proof.commitments.main)?;
    if let Some(permutation) = &proof.commitments.permutation {
        Comm::validate_input(permutation)?;
    }
    Comm::validate_input(&proof.commitments.quotient_chunks)?;
    if let Some(random) = &proof.commitments.random {
        Comm::validate_input(random)?;
    }
    if let Some(preprocessed) = &common_data.preprocessed {
        Comm::validate_input(&preprocessed.commitment)?;
    }
    Opening::validate_input(&proof.opening_proof)
}

/// Validate only the proof-owned parts of a batch proof. This is used by checked
/// private packing, whose API has no common-data or AIR-count arguments.
pub(crate) fn validate_batch_proof_native<SC, Comm, Opening>(
    proof: &BatchProof<SC>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig,
    Comm: CheckedRecursive<SC::Challenge>
        + Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
    Opening: CheckedRecursive<SC::Challenge>
        + Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    Comm::validate_input(&proof.commitments.main)?;
    if let Some(permutation) = &proof.commitments.permutation {
        Comm::validate_input(permutation)?;
    }
    Comm::validate_input(&proof.commitments.quotient_chunks)?;
    if let Some(random) = &proof.commitments.random {
        Comm::validate_input(random)?;
    }
    Opening::validate_input(&proof.opening_proof)
}

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
    /// Exact batch-table position whose public values are runtime-bound by an audited Statement
    /// AIR. `None` preserves the legacy expert contract's fully static NPO comparison.
    pub(crate) statement_instance: Option<usize>,
    pub(crate) preprocessed: Option<GlobalPreprocessedShape<C>>,
}

/// Exact native input contract selected by a prepared verifier.
#[derive(Clone, PartialEq, Eq)]
pub enum InputContract<F, C, O> {
    /// A uni-STARK input contract.
    Uni(UniInputContract<C, O>),
    /// A batch-STARK input contract.
    Batch(Box<BatchInputContract<F, C, O>>),
}
