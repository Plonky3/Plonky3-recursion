use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::marker::PhantomData;

use p3_challenger::{CanObserve, GrindingChallenger};
use p3_circuit::ops::PermConfig;
use p3_circuit::symbolic::RowSelectorsTargets;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, NonPrimitiveOpId};
use p3_commit::{BatchOpening, ExtensionMmcs, Mmcs, OpenedValues, PolynomialSpace};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, PackedValue, PrimeCharacteristicRing, PrimeField64,
    TwoAdicField,
};
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof, HidingFriPcs, TwoAdicFriPcs};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs, PrunedMerklePaths};
use p3_symmetric::{CryptographicHasher, MerkleCap, PseudoCompressionFunction};
use p3_uni_stark::{StarkGenericConfig, Val};
use rand::distr::{Distribution, StandardUniform};
use rand::{CryptoRng, Rng, SeedableRng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::context::{
    CheckedFriCommitment, CheckedFriOpening, ValidatedFriContext, validate_fri_context_with_caps,
};
use super::{FriVerifierParams, NativeFriParams, verify_fri_circuit};
use crate::Target;
use crate::challenger::CircuitChallenger;
use crate::input_contract::FriOpeningLayout;
use crate::input_contract::fri::{
    FriCommitStepShape, FriInputBatchShape, FriShape, HidingFriShape, HidingOpeningAdviceShape,
    MerkleCapShape,
};
use crate::traits::{
    CheckedRecursive, ComsWithOpeningsTargets, PreparedRecursive, Recursive, RecursiveChallenger,
    RecursiveExtensionMmcs, RecursiveMmcs, RecursivePcs,
};
use crate::types::{OpenedValuesTargetsWithLookups, RecursiveLagrangeSelectors};
use crate::verifier::{ObservableCommitment, VerificationError};

/// Per-query view of a shared MMCS multi-opening proof.
///
/// An MMCS authenticates a whole batch of queries into one tree with a single deduplicated
/// [`PrunedMerklePaths`], while the in-circuit MMCS gadget walks one full authentication path per
/// query. The targets a query needs are therefore built from the share of the multiproof that
/// belongs to it; the sibling digests themselves are never circuit inputs (the gadget consumes
/// them as non-primitive-op private data), so only proof components that enter the leaf preimage
/// — the hiding MMCS's salts — allocate anything here.
pub trait RecursiveMultiProofTargets<EF: Field>: Recursive<EF> {
    /// The native proof authenticating every query's rows against one commitment.
    type MultiProof;

    /// Allocates the targets one query's share of `proof` needs.
    fn new_for_query(
        circuit: &mut CircuitBuilder<EF>,
        proof: &Self::MultiProof,
        query: usize,
    ) -> Self;

    /// Public values for one query's share of `proof`, in allocation order.
    fn get_values_for_query(_proof: &Self::MultiProof, _query: usize) -> Vec<EF> {
        vec![]
    }

    /// Private values for one query's share of `proof`, in allocation order.
    fn get_private_values_for_query(_proof: &Self::MultiProof, _query: usize) -> Vec<EF> {
        vec![]
    }
}

/// Trusted native shape capture for the shared proof behind per-query MMCS targets.
///
/// This applies [`PreparedRecursive`]'s full equality and pure-inspection contract to every
/// per-query allocation, public/private extraction boundary, branch, constant, layout, loop, and
/// recursive MMCS-verification use selected by the multiproof. Native values that select compiled
/// behavior must be captured; only values that remain runtime witnesses may be omitted. A custom
/// implementation is an explicit trusted semantic opt-in.
///
/// Ordinary compressed Merkle frontier contents and `sibling_hashes` lengths remain dynamic: they
/// allocate no targets and are restored as runtime private data, and transcript query overlap may
/// change their deduplicated length without changing the prepared circuit shape.
pub trait PreparedRecursiveMultiProofTargets<EF: Field>: RecursiveMultiProofTargets<EF> {
    /// Complete reuse-relevant multiproof structure.
    type Shape: Clone + PartialEq;

    /// Purely inspect the native multiproof and validate its expected query/matrix axes.
    fn multiproof_shape(
        proof: &Self::MultiProof,
        query_matrix_counts: &[usize],
    ) -> Result<Self::Shape, VerificationError>;

    /// Validate only the borrowed axes needed before any prepared shape capture.
    /// The default is compatibility fallback for custom implementations and may allocate.
    fn validate_multiproof_raw<I>(
        proof: &Self::MultiProof,
        query_matrix_counts: I,
        required_salt_elems: Option<usize>,
    ) -> Result<(), VerificationError>
    where
        I: ExactSizeIterator<Item = usize>,
    {
        if required_salt_elems.is_some() {
            return Err(VerificationError::InvalidProofShape(
                "checked FRI salt validation is unsupported for this multiproof".into(),
            ));
        }
        let counts: Vec<_> = query_matrix_counts.collect();
        Self::multiproof_shape(proof, &counts).map(|_| ())
    }
}

/// Per-query view of the FRI input-batch openings.
///
/// Every input commitment is opened for all queries at once, so a single query's input proof is
/// the rows each batch opened at that query together with that query's share of the batch's
/// shared proof.
pub trait RecursiveFriInputOpenings<EF: Field>: Sized {
    /// The native shared openings, one entry per input batch.
    type MultiOpenings;

    /// Number of queries the batches open, or `None` when there is no input batch.
    fn num_queries(input: &Self::MultiOpenings) -> Option<usize>;

    /// Allocates the targets one query's share of `input` needs.
    fn new_for_query(
        circuit: &mut CircuitBuilder<EF>,
        input: &Self::MultiOpenings,
        query: usize,
    ) -> Self;

    /// Public values for one query's share of `input`, in allocation order.
    fn get_values_for_query(input: &Self::MultiOpenings, query: usize) -> Vec<EF>;

    /// Private values for one query's share of `input`, in allocation order.
    fn get_private_values_for_query(input: &Self::MultiOpenings, query: usize) -> Vec<EF>;
}

/// Trusted native shape capture for all FRI input-batch openings.
///
/// This applies [`PreparedRecursive`]'s full equality and pure-inspection contract to the
/// per-query target allocation, public/private extraction, and recursive FRI verification driven
/// by every input batch. Equal shapes must preserve every branch, loop count, constant, layout,
/// and extraction boundary, including native values that select compiled behavior. Dynamic
/// witness values alone may be excluded. A custom implementation is an explicit trusted semantic
/// opt-in and must compose the corresponding multiproof contract rather than assuming row totals
/// are sufficient.
pub trait PreparedRecursiveFriInputOpenings<EF: Field>: RecursiveFriInputOpenings<EF> {
    /// Complete reuse-relevant input-opening structure.
    type Shape: Clone + PartialEq;

    /// Purely inspect every input batch and capture every reuse-relevant query/matrix partition.
    fn openings_shape(input: &Self::MultiOpenings) -> Result<Self::Shape, VerificationError>;

    /// Report the query count of every input batch.
    fn query_counts(input: &Self::MultiOpenings) -> Vec<usize>;

    /// Validate borrowed input-batch/query axes before prepared shape capture.
    /// The default preserves old custom implementations and may allocate.
    fn validate_openings_raw(
        input: &Self::MultiOpenings,
    ) -> Result<Option<usize>, VerificationError> {
        let counts = Self::query_counts(input);
        if counts
            .first()
            .is_some_and(|first| counts.iter().any(|count| count != first))
        {
            return Err(VerificationError::InvalidProofShape(
                "FRI input query counts disagree".into(),
            ));
        }
        Self::openings_shape(input).map(|_| counts.first().copied())
    }
}

/// Number of queries a FRI proof opens, given the per-round and per-batch opening counts.
///
/// Every round and every batch opens the same query set, so a proof whose counts disagree is
/// malformed. Reporting the smallest count keeps the query loop inside every opening it will
/// index, leaving the disagreement to surface as a shape rejection in the verifier.
fn num_queries_from_counts(from_rounds: Option<usize>, from_batches: Option<usize>) -> usize {
    match (from_rounds, from_batches) {
        (Some(rounds), Some(batches)) => rounds.min(batches),
        (Some(count), None) | (None, Some(count)) => count,
        (None, None) => 0,
    }
}

/// Number of queries a [`TwoAdicFriPcs`] proof opens.
pub fn fri_proof_num_queries<F, EF, InputMmcs, FriMmcs, Witness>(
    proof: &FriProof<EF, FriMmcs, Witness, Vec<BatchMultiOpening<F, InputMmcs>>>,
) -> usize
where
    F: Field,
    EF: ExtensionField<F>,
    InputMmcs: Mmcs<F>,
    FriMmcs: Mmcs<EF>,
{
    num_queries_from_counts(
        proof
            .commit_phase_openings
            .iter()
            .map(|opening| opening.sibling_values.len())
            .min(),
        proof
            .input_openings
            .iter()
            .map(|batch| batch.opened_values.len())
            .min(),
    )
}

/// `Recursive` version of `FriProof`.
pub struct FriProofTargets<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF>,
    Witness: Recursive<EF>,
> {
    pub commit_phase_commits: Vec<RecMmcs::Commitment>,
    pub commit_pow_witnesses: Vec<Witness>,
    pub query_proofs: Vec<QueryProofTargets<F, EF, InputProof, RecMmcs>>,
    pub final_poly: Vec<Target>,
    pub pow_witness: Witness,
    pub log_arities: Vec<usize>,
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF> + RecursiveFriInputOpenings<EF>,
    Witness: Recursive<EF>,
> FriProofTargets<F, EF, RecMmcs, InputProof, Witness>
{
    /// Number of queries the proof opens.
    fn num_queries(
        input: &FriProof<EF, RecMmcs::Input, Witness::Input, InputProof::MultiOpenings>,
    ) -> usize {
        num_queries_from_counts(
            input
                .commit_phase_openings
                .iter()
                .map(|opening| opening.sibling_values.len())
                .min(),
            InputProof::num_queries(&input.input_openings),
        )
    }
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF> + RecursiveFriInputOpenings<EF>,
    Witness: Recursive<EF>,
> Recursive<EF> for FriProofTargets<F, EF, RecMmcs, InputProof, Witness>
where
    RecMmcs::Proof:
        RecursiveMultiProofTargets<EF, MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof>,
{
    type Input = FriProof<EF, RecMmcs::Input, Witness::Input, InputProof::MultiOpenings>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let commit_phase_commits = input
            .commit_phase_commits
            .iter()
            .map(|commitment| RecMmcs::Commitment::new(circuit, commitment))
            .collect();

        let commit_pow_witnesses = input
            .commit_pow_witnesses
            .iter()
            .map(|witness| Witness::new(circuit, witness))
            .collect();

        let query_proofs = (0..Self::num_queries(input))
            .map(|query| {
                QueryProofTargets::new_for_query(
                    circuit,
                    &input.input_openings,
                    &input.commit_phase_openings,
                    query,
                )
            })
            .collect();

        let final_poly = circuit
            .alloc_public_inputs(input.final_poly.len(), "FRI final polynomial coefficients");

        let log_arities = input
            .commit_phase_openings
            .iter()
            .map(|opening| opening.log_arity as usize)
            .collect();

        Self {
            commit_phase_commits,
            commit_pow_witnesses,
            query_proofs,
            final_poly,
            pow_witness: Witness::new(circuit, &input.query_pow_witness),
            log_arities,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        let FriProof {
            commit_phase_commits,
            commit_pow_witnesses,
            input_openings,
            commit_phase_openings,
            final_poly,
            query_pow_witness,
        } = input;

        commit_phase_commits
            .iter()
            .flat_map(|c| RecMmcs::Commitment::get_values(c))
            .chain(
                commit_pow_witnesses
                    .iter()
                    .flat_map(|w| Witness::get_values(w)),
            )
            .chain((0..Self::num_queries(input)).flat_map(|query| {
                QueryProofTargets::<F, EF, InputProof, RecMmcs>::get_values_for_query(
                    input_openings,
                    commit_phase_openings,
                    query,
                )
            }))
            .chain(final_poly.iter().copied())
            .chain(Witness::get_values(query_pow_witness))
            .collect()
    }

    fn get_private_values(input: &Self::Input) -> Vec<EF> {
        (0..Self::num_queries(input))
            .flat_map(|query| {
                QueryProofTargets::<F, EF, InputProof, RecMmcs>::get_private_values_for_query(
                    &input.input_openings,
                    &input.commit_phase_openings,
                    query,
                )
            })
            .collect()
    }
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF> + PreparedRecursiveFriInputOpenings<EF>,
    Witness: PreparedRecursive<EF>,
> PreparedRecursive<EF> for FriProofTargets<F, EF, RecMmcs, InputProof, Witness>
where
    RecMmcs::Commitment: PreparedRecursive<EF>,
    RecMmcs::Proof: PreparedRecursiveMultiProofTargets<
            EF,
            MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof,
        >,
{
    type Shape = FriShape<
        <RecMmcs::Commitment as PreparedRecursive<EF>>::Shape,
        InputProof::Shape,
        <RecMmcs::Proof as PreparedRecursiveMultiProofTargets<EF>>::Shape,
        Witness::Shape,
    >;

    fn input_shape(input: &Self::Input) -> Result<Self::Shape, VerificationError> {
        let FriProof {
            commit_phase_commits,
            commit_pow_witnesses,
            input_openings,
            commit_phase_openings,
            final_poly,
            query_pow_witness,
        } = input;

        validate_fri_structure::<F, EF, RecMmcs, InputProof, Witness>(input)?;

        let mut counts = InputProof::query_counts(input_openings);
        counts.extend(
            commit_phase_openings
                .iter()
                .map(|step| step.sibling_values.len()),
        );
        if counts
            .first()
            .is_some_and(|first| counts.iter().any(|count| count != first))
        {
            return Err(VerificationError::InvalidProofShape(
                "FRI query counts disagree".into(),
            ));
        }

        for step in commit_phase_openings {
            let siblings = 1usize
                .checked_shl(u32::from(step.log_arity))
                .and_then(|arity| arity.checked_sub(1))
                .filter(|_| step.log_arity > 0)
                .ok_or_else(|| {
                    VerificationError::InvalidProofShape("invalid FRI log_arity".into())
                })?;
            if step.sibling_values.iter().any(|row| row.len() != siblings) {
                return Err(VerificationError::InvalidProofShape(
                    "FRI sibling arity mismatch".into(),
                ));
            }
        }

        Ok(FriShape {
            commit_phase_commits: commit_phase_commits
                .iter()
                .map(RecMmcs::Commitment::input_shape)
                .collect::<Result<_, _>>()?,
            commit_pow_witnesses: commit_pow_witnesses
                .iter()
                .map(Witness::input_shape)
                .collect::<Result<_, _>>()?,
            input_openings: InputProof::openings_shape(input_openings)?,
            commit_phase_openings: commit_phase_openings
                .iter()
                .map(|step| {
                    Ok(FriCommitStepShape {
                        log_arity: step.log_arity,
                        sibling_values: step.sibling_values.iter().map(Vec::len).collect(),
                        opening_advice: RecMmcs::Proof::multiproof_shape(
                            &step.opening_proof,
                            &vec![1; step.sibling_values.len()],
                        )?,
                    })
                })
                .collect::<Result<_, VerificationError>>()?,
            final_poly: final_poly.len(),
            query_pow_witness: Witness::input_shape(query_pow_witness)?,
        })
    }
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF> + PreparedRecursiveFriInputOpenings<EF>,
    Witness: Recursive<EF>,
> CheckedRecursive<EF> for FriProofTargets<F, EF, RecMmcs, InputProof, Witness>
where
    RecMmcs::Commitment: CheckedRecursive<EF>,
    RecMmcs::Proof: PreparedRecursiveMultiProofTargets<
            EF,
            MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof,
        >,
{
    fn validate_input(input: &Self::Input) -> Result<(), VerificationError> {
        validate_fri_input::<F, EF, RecMmcs, InputProof, Witness>(input)
    }
}

/// Validate all shape choices consumed by the built-in FRI target allocator.
///
/// This is intentionally independent of verifier parameters: checks involving the
/// committed statement (query floors, final polynomial degree, and domain geometry)
/// belong to the PCS/backend boundary. The helper nevertheless covers every raw
/// relationship that the allocator and value extraction rely on.
pub(crate) fn validate_fri_input<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF> + PreparedRecursiveFriInputOpenings<EF>,
    Witness: Recursive<EF>,
>(
    input: &FriProof<EF, RecMmcs::Input, Witness::Input, InputProof::MultiOpenings>,
) -> Result<(), VerificationError>
where
    RecMmcs::Commitment: CheckedRecursive<EF>,
    RecMmcs::Proof: PreparedRecursiveMultiProofTargets<
            EF,
            MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof,
        >,
{
    validate_fri_structure::<F, EF, RecMmcs, InputProof, Witness>(input)?;
    for commitment in &input.commit_phase_commits {
        RecMmcs::Commitment::validate_input(commitment)?;
    }
    Ok(())
}

fn validate_fri_structure<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF> + PreparedRecursiveFriInputOpenings<EF>,
    Witness: Recursive<EF>,
>(
    input: &FriProof<EF, RecMmcs::Input, Witness::Input, InputProof::MultiOpenings>,
) -> Result<(), VerificationError>
where
    RecMmcs::Proof: PreparedRecursiveMultiProofTargets<
            EF,
            MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof,
        >,
{
    let phases = input.commit_phase_commits.len();
    if phases != input.commit_phase_openings.len() {
        return Err(VerificationError::InvalidProofShape(
            "FRI commitment/opening round count mismatch".into(),
        ));
    }
    if phases != input.commit_pow_witnesses.len() {
        return Err(VerificationError::InvalidProofShape(
            "FRI commitment/PoW witness round count mismatch".into(),
        ));
    }
    if input.final_poly.is_empty() {
        return Err(VerificationError::InvalidProofShape(
            "FRI proof missing final polynomial".into(),
        ));
    }

    let mut query_count = InputProof::validate_openings_raw(&input.input_openings)?;
    for step in &input.commit_phase_openings {
        let Some(arity) = (1usize)
            .checked_shl(u32::from(step.log_arity))
            .and_then(|arity| arity.checked_sub(1))
            .filter(|_| step.log_arity > 0)
        else {
            return Err(VerificationError::InvalidProofShape(
                "invalid FRI log_arity".into(),
            ));
        };
        if step.sibling_values.iter().any(|row| row.len() != arity) {
            return Err(VerificationError::InvalidProofShape(
                "FRI sibling arity mismatch".into(),
            ));
        }
        if let Some(expected) = query_count {
            if expected != step.sibling_values.len() {
                return Err(VerificationError::InvalidProofShape(
                    "FRI query counts disagree".into(),
                ));
            }
        } else {
            query_count = Some(step.sibling_values.len());
        }
        // The built-in multiproof validators check hiding salts and all matrix axes.
        let matrix_counts = core::iter::repeat_n(1usize, step.sibling_values.len());
        RecMmcs::Proof::validate_multiproof_raw(&step.opening_proof, matrix_counts, None)?;
    }

    Ok(())
}

/// Targets for the share of a FRI proof belonging to a single query.
///
/// The proof authenticates all queries together, but the in-circuit verifier walks one query at a
/// time, so it keeps the per-query view the pre-multiproof `QueryProof` had.
pub struct QueryProofTargets<
    F: Field,
    EF: ExtensionField<F>,
    InputProof: Recursive<EF>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
> {
    pub input_proof: InputProof,
    pub commit_phase_openings: Vec<CommitPhaseProofStepTargets<F, EF, RecMmcs>>,
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    InputProof: Recursive<EF> + RecursiveFriInputOpenings<EF>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
> QueryProofTargets<F, EF, InputProof, RecMmcs>
where
    RecMmcs::Proof:
        RecursiveMultiProofTargets<EF, MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof>,
{
    fn new_for_query(
        circuit: &mut CircuitBuilder<EF>,
        input_openings: &InputProof::MultiOpenings,
        commit_phase_openings: &[CommitPhaseMultiStep<EF, RecMmcs::Input>],
        query: usize,
    ) -> Self {
        let input_proof = InputProof::new_for_query(circuit, input_openings, query);
        let commit_phase_openings = commit_phase_openings
            .iter()
            .map(|opening| CommitPhaseProofStepTargets::new_for_query(circuit, opening, query))
            .collect();
        Self {
            input_proof,
            commit_phase_openings,
        }
    }

    fn get_values_for_query(
        input_openings: &InputProof::MultiOpenings,
        commit_phase_openings: &[CommitPhaseMultiStep<EF, RecMmcs::Input>],
        query: usize,
    ) -> Vec<EF> {
        InputProof::get_values_for_query(input_openings, query)
            .into_iter()
            .chain(commit_phase_openings.iter().flat_map(|opening| {
                CommitPhaseProofStepTargets::<F, EF, RecMmcs>::get_values_for_query(opening, query)
            }))
            .collect()
    }

    fn get_private_values_for_query(
        input_openings: &InputProof::MultiOpenings,
        commit_phase_openings: &[CommitPhaseMultiStep<EF, RecMmcs::Input>],
        query: usize,
    ) -> Vec<EF> {
        InputProof::get_private_values_for_query(input_openings, query)
            .into_iter()
            .chain(commit_phase_openings.iter().flat_map(|opening| {
                CommitPhaseProofStepTargets::<F, EF, RecMmcs>::get_private_values_for_query(
                    opening, query,
                )
            }))
            .collect()
    }
}

/// `Recursive` version of `CommitPhaseProofStep`.
///
/// Sibling values are stored as **lifted base field coefficients** to enable MMCS verification.
/// ExtensionMmcs commits by flattening extension elements to base field, so we need the
/// coefficients separately for hashing. Use `sibling_values_packed()` to get the packed
/// extension elements for FRI folding arithmetic.
///
/// For arity `k = 2^log_arity`, we store `k - 1` sibling values (the queried value is the
/// folded evaluation from the previous phase). Each sibling is represented by `EF::DIMENSION`
/// lifted base field coefficients, giving `(k - 1) * EF::DIMENSION` targets total.
pub struct CommitPhaseProofStepTargets<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
> {
    pub log_arity: usize,
    /// Lifted base field coefficients for all (arity - 1) sibling values, flattened.
    /// Layout: [sib0_c0, sib0_c1, .., sib0_cD, sib1_c0, .., sib{a-2}_cD]
    pub sibling_coefficients: Vec<Target>,
    pub opening_proof: RecMmcs::Proof,
    _phantom: PhantomData<(F, EF)>,
}

impl<F: Field, EF: ExtensionField<F> + BasedVectorSpace<F>, RecMmcs: RecursiveExtensionMmcs<F, EF>>
    CommitPhaseProofStepTargets<F, EF, RecMmcs>
{
    /// Pack a single sibling's lifted base field coefficients into an extension element.
    ///
    /// Uses pure ALU ops (so the coefficient private inputs satisfy the "used in ALU operand"
    /// invariant) and registers the result in the circuit builder's coefficient-provenance cache
    /// via [`CircuitBuilder::hint_ext_recompose_coeffs`]. This makes a subsequent
    /// `decompose_ext_to_base_coeffs` call on the packed value a no-op rather than allocating
    /// new witnesses (critical for D=1 MMCS hashing over higher-degree extension fields).
    fn pack_one_sibling(coeffs: &[Target], circuit: &mut CircuitBuilder<EF>) -> Target {
        let basis: Vec<EF> = (0..EF::DIMENSION)
            .map(|i| EF::from_basis_coefficients_fn(|j| if i == j { F::ONE } else { F::ZERO }))
            .collect();

        let mut result = coeffs[0];
        for (i, &basis_elem) in basis.iter().enumerate().skip(1) {
            let basis_const = circuit.define_const(basis_elem);
            result = circuit.mul_add(coeffs[i], basis_const, result);
        }
        circuit.hint_ext_recompose_coeffs(result, coeffs);
        result
    }

    /// Returns all (arity - 1) sibling values as packed extension elements.
    pub fn sibling_values_packed(&self, circuit: &mut CircuitBuilder<EF>) -> Vec<Target> {
        let d = EF::DIMENSION;
        self.sibling_coefficients
            .chunks_exact(d)
            .map(|chunk| Self::pack_one_sibling(chunk, circuit))
            .collect()
    }

    /// Returns the single sibling value as a packed extension element (arity-2 convenience).
    pub fn sibling_value_packed(&self, circuit: &mut CircuitBuilder<EF>) -> Target {
        debug_assert_eq!(
            self.log_arity, 1,
            "sibling_value_packed is for arity-2 only; use sibling_values_packed for higher arity"
        );
        Self::pack_one_sibling(&self.sibling_coefficients, circuit)
    }
}

impl<F: Field, EF: ExtensionField<F> + BasedVectorSpace<F>, RecMmcs: RecursiveExtensionMmcs<F, EF>>
    CommitPhaseProofStepTargets<F, EF, RecMmcs>
where
    RecMmcs::Proof:
        RecursiveMultiProofTargets<EF, MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof>,
{
    fn new_for_query(
        circuit: &mut CircuitBuilder<EF>,
        input: &CommitPhaseMultiStep<EF, RecMmcs::Input>,
        query: usize,
    ) -> Self {
        let log_arity = input.log_arity as usize;
        let arity = 1usize << log_arity;
        let num_siblings = arity - 1;
        let num_coeffs = num_siblings * EF::DIMENSION;
        let sibling_coefficients =
            circuit.alloc_private_inputs(num_coeffs, "FRI commit phase sibling coefficients");
        let opening_proof = RecMmcs::Proof::new_for_query(circuit, &input.opening_proof, query);
        Self {
            log_arity,
            sibling_coefficients,
            opening_proof,
            _phantom: PhantomData,
        }
    }

    fn get_values_for_query(
        input: &CommitPhaseMultiStep<EF, RecMmcs::Input>,
        query: usize,
    ) -> Vec<EF> {
        RecMmcs::Proof::get_values_for_query(&input.opening_proof, query)
    }

    fn get_private_values_for_query(
        input: &CommitPhaseMultiStep<EF, RecMmcs::Input>,
        query: usize,
    ) -> Vec<EF> {
        let mut values: Vec<EF> = Vec::new();
        for sibling_value in input.sibling_values.get(query).into_iter().flatten() {
            let coeffs = sibling_value.as_basis_coefficients_slice();
            values.extend(coeffs.iter().map(|&c| EF::from(c)));
        }
        values.extend(RecMmcs::Proof::get_private_values_for_query(
            &input.opening_proof,
            query,
        ));
        values
    }
}

/// `Recursive` version of `BatchOpening`.
///
/// Uses **lifted representation**: each base field value is represented as a single extension
/// field element `EF([v, 0, 0, 0])`. This allows 1:1 correspondence with polynomial values
/// for arithmetic verification.
pub struct BatchOpeningTargets<F: Field, EF: ExtensionField<F>, RecMmcs: RecursiveMmcs<F, EF>> {
    /// The opened row values from each matrix in the batch.
    /// Each inner vector has one target per base field value.
    pub opened_values: Vec<Vec<Target>>,
    /// The proof showing the values are valid openings.
    pub opening_proof: RecMmcs::Proof,
}

impl<F: Field, EF: ExtensionField<F>, Inner: RecursiveMmcs<F, EF>> Recursive<EF>
    for BatchOpeningTargets<F, EF, Inner>
{
    type Input = BatchOpening<F, Inner::Input>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let opened_values = input
            .opened_values
            .iter()
            .map(|values| circuit.alloc_private_inputs(values.len(), "batch opened values"))
            .collect();

        let opening_proof = Inner::Proof::new(circuit, &input.opening_proof);

        Self {
            opened_values,
            opening_proof,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        Inner::Proof::get_values(&input.opening_proof)
    }

    fn get_private_values(input: &Self::Input) -> Vec<EF> {
        input
            .opened_values
            .iter()
            .flat_map(|inner| inner.iter().map(|v| EF::from(*v)))
            .chain(Inner::Proof::get_private_values(&input.opening_proof))
            .collect()
    }
}

impl<F: Field, EF: ExtensionField<F>, Inner: RecursiveMmcs<F, EF>> BatchOpeningTargets<F, EF, Inner>
where
    Inner::Proof:
        RecursiveMultiProofTargets<EF, MultiProof = <Inner::Input as Mmcs<F>>::MultiProof>,
{
    fn new_for_query(
        circuit: &mut CircuitBuilder<EF>,
        input: &BatchMultiOpening<F, Inner::Input>,
        query: usize,
    ) -> Self {
        let opened_values = input
            .opened_values
            .get(query)
            .map(|rows| {
                rows.iter()
                    .map(|values| circuit.alloc_private_inputs(values.len(), "batch opened values"))
                    .collect()
            })
            .unwrap_or_default();

        let opening_proof = Inner::Proof::new_for_query(circuit, &input.opening_proof, query);

        Self {
            opened_values,
            opening_proof,
        }
    }

    fn get_values_for_query(input: &BatchMultiOpening<F, Inner::Input>, query: usize) -> Vec<EF> {
        Inner::Proof::get_values_for_query(&input.opening_proof, query)
    }

    fn get_private_values_for_query(
        input: &BatchMultiOpening<F, Inner::Input>,
        query: usize,
    ) -> Vec<EF> {
        input
            .opened_values
            .get(query)
            .into_iter()
            .flatten()
            .flat_map(|inner| inner.iter().map(|v| EF::from(*v)))
            .chain(Inner::Proof::get_private_values_for_query(
                &input.opening_proof,
                query,
            ))
            .collect()
    }
}

// Now, we define the commitment schemes.

/// `MerkleCapTargets` corresponds to a Merkle cap commitment with `2^cap_height` hash entries,
/// each having `DIGEST_ELEMS` digest elements.
///
/// Uses **lifted representation**: each base field hash element is stored as a separate extension
/// field target `EF([v, 0, 0, 0])`. This is consistent with Fiat-Shamir observation.
///
/// A cap of height 0 contains a single entry (the root), while a cap of height `h` contains
/// `2^h` entries. The Fiat-Shamir transcript observes all entries sequentially.
#[derive(Clone)]
pub struct MerkleCapTargets<F, const DIGEST_ELEMS: usize> {
    pub cap_targets: Vec<[Target; DIGEST_ELEMS]>,
    _phantom: PhantomData<F>,
}

impl<F, const DIGEST_ELEMS: usize> ObservableCommitment for MerkleCapTargets<F, DIGEST_ELEMS> {
    fn to_observation_targets(&self) -> Vec<Target> {
        self.cap_targets
            .iter()
            .flat_map(|entry| entry.iter().copied())
            .collect()
    }
}

type ValMmcsCommitment<F, const DIGEST_ELEMS: usize> =
    MerkleCap<<F as PackedValue>::Value, [<F as PackedValue>::Value; DIGEST_ELEMS]>;

/// Validate a borrowed built-in Merkle cap against the actual recursive
/// permutation shape and its planned tree heights.  This is value-only
/// geometry: no target rows, PCS, MMCS, RNG, or proof contents are allocated.
#[allow(dead_code, clippy::needless_pass_by_value)]
pub(crate) fn validate_merkle_cap_context<F, EF, const DIGEST_ELEMS: usize, I>(
    cap: &ValMmcsCommitment<F, DIGEST_ELEMS>,
    permutation_config: PermConfig,
    index_bit_len: usize,
    heights: I,
) -> Result<(), VerificationError>
where
    F: Field,
    EF: ExtensionField<F>,
    I: Iterator<Item = usize> + Clone,
{
    let roots = cap.num_roots();
    let mut max_height = 0usize;
    let mut has_height = false;
    let height_scan = heights.clone();
    for height in height_scan {
        if height == 0 {
            continue;
        }
        has_height = true;
        max_height = max_height.max(height);
    }
    if !has_height {
        return Err(VerificationError::InvalidProofShape(
            "MMCS commitment cap has no positive planned matrices".into(),
        ));
    }
    let (cap_height, path_bits) = if permutation_config.is_arity4_shape() {
        let path_bits = crate::pcs::mmcs::visit_arity4_path(heights, roots, |_| {})
            .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
        let cap_height = crate::pcs::mmcs::validate_commitment_cap_count(roots)
            .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
        (cap_height, path_bits)
    } else {
        let raw_heights = heights;
        for height in raw_heights {
            if height == 0 || !height.is_power_of_two() {
                return Err(VerificationError::InvalidProofShape(
                    "binary MMCS matrix heights must be positive powers of two".into(),
                ));
            }
        }
        let tree_height = max_height.trailing_zeros() as usize;
        let cap_height = crate::pcs::mmcs::validate_binary_cap_count(roots, tree_height)
            .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
        (cap_height, tree_height - cap_height)
    };
    if !permutation_config.is_arity4_shape() && cap_height > index_bit_len {
        return Err(VerificationError::InvalidProofShape(
            "binary MMCS cap needs more index bits than the checked query layout".into(),
        ));
    }
    let chunk_ext = if permutation_config.is_arity4_shape() {
        permutation_config.capacity_ext()
    } else {
        permutation_config.rate_ext()
    };
    validate_cap_packing::<DIGEST_ELEMS>(
        roots,
        chunk_ext,
        permutation_config.d() == 1 && EF::DIMENSION > 1,
        EF::DIMENSION,
        cap_height,
        path_bits,
    )?;
    Ok(())
}

fn validate_cap_packing<const DIGEST_ELEMS: usize>(
    roots: usize,
    chunk_ext: usize,
    lifted_d1: bool,
    extension_dimension: usize,
    cap_height: usize,
    path_bits: usize,
) -> Result<(), VerificationError> {
    if chunk_ext == 0 || extension_dimension == 0 {
        return Err(VerificationError::InvalidProofShape(
            "MMCS digest packing has a zero chunk or extension width".into(),
        ));
    }
    let expected_digest_elems = if lifted_d1 {
        chunk_ext
    } else {
        chunk_ext.checked_mul(extension_dimension).ok_or_else(|| {
            VerificationError::InvalidProofShape("MMCS digest width overflows".into())
        })?
    };
    if DIGEST_ELEMS != expected_digest_elems {
        return Err(VerificationError::InvalidProofShape(format!(
            "MMCS digest packing mismatch: expected {expected_digest_elems}, got {DIGEST_ELEMS}"
        )));
    }
    let flat_digest = roots.checked_mul(DIGEST_ELEMS).ok_or_else(|| {
        VerificationError::InvalidProofShape("MMCS cap digest count overflows".into())
    })?;
    let flat_chunk = roots.checked_mul(chunk_ext).ok_or_else(|| {
        VerificationError::InvalidProofShape("MMCS cap chunk count overflows".into())
    })?;
    let target_size = core::mem::size_of::<Target>();
    if roots
        .checked_mul(core::mem::size_of::<Vec<Target>>())
        .and_then(|bytes| (bytes <= isize::MAX as usize).then_some(bytes))
        .is_none()
    {
        return Err(VerificationError::InvalidProofShape(
            "MMCS cap outer target vector size overflows".into(),
        ));
    }
    for (label, elements) in [("digest", flat_digest), ("chunk", flat_chunk)] {
        if elements
            .checked_mul(target_size)
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .is_none()
        {
            return Err(VerificationError::InvalidProofShape(format!(
                "MMCS cap {label} target size overflows"
            )));
        }
    }
    cap_height.checked_add(path_bits).ok_or_else(|| {
        VerificationError::InvalidProofShape("MMCS cap and path bits overflow".into())
    })?;
    Ok(())
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize> Recursive<EF>
    for MerkleCapTargets<F, DIGEST_ELEMS>
{
    type Input = ValMmcsCommitment<F, DIGEST_ELEMS>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let cap_targets = (0..input.num_roots())
            .map(|_| circuit.alloc_public_input_array("MMCS commitment cap entry"))
            .collect();
        Self {
            cap_targets,
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        input
            .roots()
            .iter()
            .flat_map(|entry: &[<F as PackedValue>::Value; DIGEST_ELEMS]| {
                entry.iter().map(|v| EF::from(*v))
            })
            .collect()
    }
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize> PreparedRecursive<EF>
    for MerkleCapTargets<F, DIGEST_ELEMS>
{
    type Shape = MerkleCapShape;

    fn input_shape(input: &Self::Input) -> Result<Self::Shape, VerificationError> {
        Ok(MerkleCapShape {
            roots: input.num_roots(),
        })
    }
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize> CheckedRecursive<EF>
    for MerkleCapTargets<F, DIGEST_ELEMS>
{
    fn validate_input(input: &Self::Input) -> Result<(), VerificationError> {
        let roots = input.num_roots();
        if roots == 0 || !roots.is_power_of_two() {
            return Err(VerificationError::InvalidProofShape(
                "MMCS commitment cap must have a non-empty power-of-two root count".into(),
            ));
        }
        Ok(())
    }
}

/// `HashProofTargets` corresponds to a Merkle tree `Proof` in the form of a vector of hashes with `DIGEST_ELEMS` digest elements.
pub struct HashProofTargets<F, const DIGEST_ELEMS: usize> {
    pub hash_proof_targets: Vec<[Target; DIGEST_ELEMS]>,
    _phantom: PhantomData<F>,
}

type ValMmcsProof<PW, const DIGEST_ELEMS: usize> = Vec<[<PW as PackedValue>::Value; DIGEST_ELEMS]>;

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize> Recursive<EF>
    for HashProofTargets<F, DIGEST_ELEMS>
{
    type Input = ValMmcsProof<F, DIGEST_ELEMS>;

    fn new(_circuit: &mut CircuitBuilder<EF>, _input: &Self::Input) -> Self {
        // Merkle proof hashes are not allocated as circuit inputs.
        Self {
            hash_proof_targets: vec![],
            _phantom: PhantomData,
        }
    }

    fn get_values(_input: &Self::Input) -> Vec<EF> {
        vec![]
    }
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize> RecursiveMultiProofTargets<EF>
    for HashProofTargets<F, DIGEST_ELEMS>
{
    type MultiProof = PrunedMerklePaths<<F as PackedValue>::Value, DIGEST_ELEMS>;

    fn new_for_query(
        _circuit: &mut CircuitBuilder<EF>,
        _proof: &Self::MultiProof,
        _query: usize,
    ) -> Self {
        // Merkle proof hashes are not allocated as circuit inputs.
        Self {
            hash_proof_targets: vec![],
            _phantom: PhantomData,
        }
    }
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize>
    PreparedRecursiveMultiProofTargets<EF> for HashProofTargets<F, DIGEST_ELEMS>
{
    type Shape = ();

    fn multiproof_shape(
        _proof: &Self::MultiProof,
        _query_matrix_counts: &[usize],
    ) -> Result<Self::Shape, VerificationError> {
        Ok(())
    }

    fn validate_multiproof_raw<I>(
        _proof: &Self::MultiProof,
        _query_matrix_counts: I,
        required_salt_elems: Option<usize>,
    ) -> Result<(), VerificationError>
    where
        I: ExactSizeIterator<Item = usize>,
    {
        if required_salt_elems.is_some() {
            return Err(VerificationError::InvalidProofShape(
                "ordinary FRI multiproof cannot carry salts".into(),
            ));
        }
        Ok(())
    }
}

/// In TwoAdicFriPcs, the POW witness is just a base field element.
pub struct Witness<F> {
    pub witness: Target,
    _phantom: PhantomData<F>,
}

impl<F: Field, EF: ExtensionField<F>> Recursive<EF> for Witness<F> {
    type Input = F;

    fn new(circuit: &mut CircuitBuilder<EF>, _input: &Self::Input) -> Self {
        Self {
            witness: circuit.alloc_public_input("FRI proof-of-work witness"),
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        vec![EF::from(*input)]
    }
}

impl<F: Field, EF: ExtensionField<F>> PreparedRecursive<EF> for Witness<F> {
    type Shape = ();

    fn input_shape(_input: &Self::Input) -> Result<Self::Shape, VerificationError> {
        Ok(())
    }
}

/// `Recursive` version of a `MerkleTreeMmcs` where the leaf and digest elements are base field values.
pub struct RecValMmcs<F: Field, const DIGEST_ELEMS: usize, H, C>
where
    H: CryptographicHasher<F, [F; DIGEST_ELEMS]>
        + CryptographicHasher<F::Packing, [F::Packing; DIGEST_ELEMS]>
        + Sync,
{
    pub hash: H,
    pub compress: C,
    _phantom: PhantomData<F>,
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize, H, C> RecursiveMmcs<F, EF>
    for RecValMmcs<F, DIGEST_ELEMS, H, C>
where
    H: CryptographicHasher<F, [F; DIGEST_ELEMS]>
        + CryptographicHasher<F::Packing, [F::Packing; DIGEST_ELEMS]>
        + Sync,
    C: PseudoCompressionFunction<[F; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<[F::Packing; DIGEST_ELEMS], 2>
        + Sync,
    [F; DIGEST_ELEMS]: Serialize + for<'a> Deserialize<'a>,
{
    type Input = MerkleTreeMmcs<F::Packing, F::Packing, H, C, 2, DIGEST_ELEMS>;

    type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;

    type Proof = HashProofTargets<F, DIGEST_ELEMS>;
}

/// Arity-4 counterpart of [`RecValMmcs`].
///
/// Binds `Input` to `MerkleTreeMmcs<…, 4, DIGEST_ELEMS>` so the recursive verifier can target
/// proofs committed with the 4-to-1 native MMCS. Requires the compression function `C` to
/// implement `PseudoCompressionFunction<…, 4>` (an arity-4 [`p3_symmetric::TruncatedPermutation`]);
/// the leaf hasher `H` is unchanged.
pub struct RecValMmcsArity4<F: Field, const DIGEST_ELEMS: usize, H, C>
where
    H: CryptographicHasher<F, [F; DIGEST_ELEMS]>
        + CryptographicHasher<F::Packing, [F::Packing; DIGEST_ELEMS]>
        + Sync,
{
    pub hash: H,
    pub compress: C,
    _phantom: PhantomData<F>,
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize, H, C> RecursiveMmcs<F, EF>
    for RecValMmcsArity4<F, DIGEST_ELEMS, H, C>
where
    H: CryptographicHasher<F, [F; DIGEST_ELEMS]>
        + CryptographicHasher<F::Packing, [F::Packing; DIGEST_ELEMS]>
        + Sync,
    C: PseudoCompressionFunction<[F; DIGEST_ELEMS], 4>
        + PseudoCompressionFunction<[F::Packing; DIGEST_ELEMS], 4>
        + Sync,
    [F; DIGEST_ELEMS]: Serialize + for<'a> Deserialize<'a>,
{
    type Input = MerkleTreeMmcs<F::Packing, F::Packing, H, C, 4, DIGEST_ELEMS>;

    type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;

    type Proof = HashProofTargets<F, DIGEST_ELEMS>;
}

/// `Recursive` version of an `ExtensionFieldMmcs` where the inner `Mmcs` is a `MerkleTreeMmcs`.
pub struct RecExtensionValMmcs<
    F: Field,
    EF: ExtensionField<F>,
    const DIGEST_ELEMS: usize,
    MyMmcs: RecursiveMmcs<F, EF>,
> {
    _phantom: PhantomData<F>,
    _phantom_ef: PhantomData<EF>,
    _phantom_val: PhantomData<MyMmcs>,
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize, RecValMmcs: RecursiveMmcs<F, EF>>
    RecursiveExtensionMmcs<F, EF> for RecExtensionValMmcs<F, EF, DIGEST_ELEMS, RecValMmcs>
{
    type Input = ExtensionMmcs<F, EF, RecValMmcs::Input>;

    type Commitment = RecValMmcs::Commitment;

    type Proof = RecValMmcs::Proof;
}

/// Arity-4 counterpart of [`RecExtensionValMmcs`]. The inner MMCS is the 4-to-1
/// `MerkleTreeMmcs<…, 4, DIGEST_ELEMS>`.
pub struct RecExtensionValMmcsArity4<
    F: Field,
    EF: ExtensionField<F>,
    const DIGEST_ELEMS: usize,
    MyMmcs: RecursiveMmcs<F, EF>,
> {
    _phantom: PhantomData<F>,
    _phantom_ef: PhantomData<EF>,
    _phantom_val: PhantomData<MyMmcs>,
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize, RecValMmcs: RecursiveMmcs<F, EF>>
    RecursiveExtensionMmcs<F, EF> for RecExtensionValMmcsArity4<F, EF, DIGEST_ELEMS, RecValMmcs>
{
    type Input = ExtensionMmcs<F, EF, RecValMmcs::Input>;

    type Commitment = RecValMmcs::Commitment;

    type Proof = RecValMmcs::Proof;
}

/// Access to per-leaf salt targets carried by an MMCS opening proof.
///
/// `MerkleTreeMmcs` openings carry no salts (returns an empty slice), while
/// `MerkleTreeHidingMmcs` openings carry `SALT_ELEMS` salt targets per matrix that must be
/// appended to the leaf preimage when recomputing the Merkle path in-circuit.
pub trait MmcsProofTargets {
    /// Per-matrix salt targets, in the same matrix order as the batch opened values.
    /// Empty when the underlying MMCS is non-hiding.
    fn salt_targets(&self) -> &[Vec<Target>];
}

impl<F, const DIGEST_ELEMS: usize> MmcsProofTargets for HashProofTargets<F, DIGEST_ELEMS> {
    fn salt_targets(&self) -> &[Vec<Target>] {
        &[]
    }
}

/// `Recursive` proof targets for a `MerkleTreeHidingMmcs` opening.
///
/// The native proof is `(salts, siblings)`. The sibling digests are supplied as MMCS
/// non-primitive-op private data (exactly like the non-hiding `HashProofTargets`), while the
/// per-matrix salts are allocated as circuit private inputs because they enter the leaf hash.
pub struct HidingHashProofTargets<F, const DIGEST_ELEMS: usize> {
    /// Per-matrix salt targets (circuit private inputs), one inner vec per opened matrix.
    pub salts: Vec<Vec<Target>>,
    _phantom: PhantomData<F>,
}

type HidingValMmcsProof<F, const DIGEST_ELEMS: usize> = (
    Vec<Vec<<F as PackedValue>::Value>>,
    Vec<[<F as PackedValue>::Value; DIGEST_ELEMS]>,
);

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize> Recursive<EF>
    for HidingHashProofTargets<F, DIGEST_ELEMS>
{
    type Input = HidingValMmcsProof<F, DIGEST_ELEMS>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let salts = input
            .0
            .iter()
            .map(|salt| circuit.alloc_private_inputs(salt.len(), "hiding MMCS leaf salt"))
            .collect();
        Self {
            salts,
            _phantom: PhantomData,
        }
    }

    fn get_values(_input: &Self::Input) -> Vec<EF> {
        vec![]
    }

    fn get_private_values(input: &Self::Input) -> Vec<EF> {
        input
            .0
            .iter()
            .flat_map(|salt| salt.iter().map(|&v| EF::from(v)))
            .collect()
    }
}

impl<F, const DIGEST_ELEMS: usize> MmcsProofTargets for HidingHashProofTargets<F, DIGEST_ELEMS> {
    fn salt_targets(&self) -> &[Vec<Target>] {
        &self.salts
    }
}

/// Native hiding MMCS multiproof: `(per-query per-matrix salts, shared pruned paths)`.
type HidingValMmcsMultiProof<F, const DIGEST_ELEMS: usize> = (
    Vec<Vec<Vec<<F as PackedValue>::Value>>>,
    PrunedMerklePaths<<F as PackedValue>::Value, DIGEST_ELEMS>,
);

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize> RecursiveMultiProofTargets<EF>
    for HidingHashProofTargets<F, DIGEST_ELEMS>
{
    type MultiProof = HidingValMmcsMultiProof<F, DIGEST_ELEMS>;

    fn new_for_query(
        circuit: &mut CircuitBuilder<EF>,
        proof: &Self::MultiProof,
        query: usize,
    ) -> Self {
        let salts = proof
            .0
            .get(query)
            .map(|per_matrix| {
                per_matrix
                    .iter()
                    .map(|salt| circuit.alloc_private_inputs(salt.len(), "hiding MMCS leaf salt"))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            salts,
            _phantom: PhantomData,
        }
    }

    fn get_private_values_for_query(proof: &Self::MultiProof, query: usize) -> Vec<EF> {
        proof
            .0
            .get(query)
            .into_iter()
            .flatten()
            .flat_map(|salt| salt.iter().map(|&v| EF::from(v)))
            .collect()
    }
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize>
    PreparedRecursiveMultiProofTargets<EF> for HidingHashProofTargets<F, DIGEST_ELEMS>
{
    type Shape = HidingOpeningAdviceShape;

    fn multiproof_shape(
        proof: &Self::MultiProof,
        query_matrix_counts: &[usize],
    ) -> Result<Self::Shape, VerificationError> {
        <Self as PreparedRecursiveMultiProofTargets<EF>>::validate_multiproof_raw(
            proof,
            query_matrix_counts.iter().copied(),
            None,
        )?;
        if proof.0.len() != query_matrix_counts.len()
            || proof
                .0
                .iter()
                .zip(query_matrix_counts)
                .any(|(matrices, &expected)| matrices.len() != expected)
        {
            return Err(VerificationError::InvalidProofShape(
                "hiding FRI salt query/matrix shape mismatch".into(),
            ));
        }
        Ok(HidingOpeningAdviceShape {
            salts: proof
                .0
                .iter()
                .map(|matrices| matrices.iter().map(Vec::len).collect())
                .collect(),
        })
    }

    fn validate_multiproof_raw<I>(
        proof: &Self::MultiProof,
        query_matrix_counts: I,
        required_salt_elems: Option<usize>,
    ) -> Result<(), VerificationError>
    where
        I: ExactSizeIterator<Item = usize>,
    {
        if proof.0.len() != query_matrix_counts.len() {
            return Err(VerificationError::InvalidProofShape(
                "hiding FRI salt query count mismatch".into(),
            ));
        }
        for (salts, expected) in proof.0.iter().zip(query_matrix_counts) {
            if salts.len() != expected {
                return Err(VerificationError::InvalidProofShape(
                    "hiding FRI salt matrix count mismatch".into(),
                ));
            }
            if let Some(salt_width) = required_salt_elems
                && salts.iter().any(|salt| salt.len() != salt_width)
            {
                return Err(VerificationError::InvalidProofShape(
                    "hiding FRI salt width mismatch".into(),
                ));
            }
        }
        Ok(())
    }
}

/// `Recursive` version of a `MerkleTreeHidingMmcs` where leaf and digest elements are base
/// field values. Mirrors [`RecValMmcs`] but the leaves are salted (hiding commitment).
pub struct RecValHidingMmcs<F: Field, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize, H, C, R>
where
    H: CryptographicHasher<F, [F; DIGEST_ELEMS]>
        + CryptographicHasher<F::Packing, [F::Packing; DIGEST_ELEMS]>
        + Sync,
{
    pub hash: H,
    pub compress: C,
    _phantom: PhantomData<(F, R)>,
}

impl<
    F: Field + Serialize + DeserializeOwned,
    EF: ExtensionField<F>,
    const DIGEST_ELEMS: usize,
    const SALT_ELEMS: usize,
    H,
    C,
    R,
> RecursiveMmcs<F, EF> for RecValHidingMmcs<F, DIGEST_ELEMS, SALT_ELEMS, H, C, R>
where
    H: CryptographicHasher<F, [F; DIGEST_ELEMS]>
        + CryptographicHasher<F::Packing, [F::Packing; DIGEST_ELEMS]>
        + Sync,
    C: PseudoCompressionFunction<[F; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<[F::Packing; DIGEST_ELEMS], 2>
        + Sync,
    R: Rng + Send + SeedableRng + CryptoRng,
    StandardUniform: Distribution<F>,
    [F; DIGEST_ELEMS]: Serialize + for<'a> Deserialize<'a>,
{
    type Input = MerkleTreeHidingMmcs<F::Packing, F::Packing, H, C, R, 2, DIGEST_ELEMS, SALT_ELEMS>;

    type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;

    type Proof = HidingHashProofTargets<F, DIGEST_ELEMS>;
}

pub type InputProofTargets<F, EF, Inner> = Vec<BatchOpeningTargets<F, EF, Inner>>;

/// Static salt metadata carried by the native MMCS input type.
///
/// The recursive hiding proof target intentionally erases its salt width, while
/// the native MMCS type retains it in its const parameters.  Checked FRI
/// validation uses this capability without cloning an MMCS or touching its
/// prover state.
pub(crate) trait NativeFriSaltWidth {
    const SALT_ELEMS: Option<usize>;
}

impl<P, PW, H, C, const ARITY: usize, const DIGEST_ELEMS: usize> NativeFriSaltWidth
    for MerkleTreeMmcs<P, PW, H, C, ARITY, DIGEST_ELEMS>
{
    const SALT_ELEMS: Option<usize> = None;
}

impl<P, PW, H, C, R, const ARITY: usize, const DIGEST_ELEMS: usize, const SALT_ELEMS: usize>
    NativeFriSaltWidth for MerkleTreeHidingMmcs<P, PW, H, C, R, ARITY, DIGEST_ELEMS, SALT_ELEMS>
{
    const SALT_ELEMS: Option<usize> = Some(SALT_ELEMS);
}

impl<F, EF, M: NativeFriSaltWidth> NativeFriSaltWidth for ExtensionMmcs<F, EF, M> {
    const SALT_ELEMS: Option<usize> = M::SALT_ELEMS;
}

pub type TwoAdicFriProofTargets<F, EF, RecMmcs, Inner> =
    FriProofTargets<F, EF, RecMmcs, InputProofTargets<F, EF, Inner>, Target>;

#[allow(clippy::type_complexity)]
fn validate_builtin_fri_raw<F, EF, RF, RI, W>(
    input: &FriProof<EF, RF::Input, W::Input, Vec<BatchMultiOpening<F, RI::Input>>>,
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
) -> Result<(), VerificationError>
where
    F: Field,
    EF: ExtensionField<F>,
    RF: RecursiveExtensionMmcs<F, EF>,
    RI: RecursiveMmcs<F, EF>,
    W: Recursive<EF>,
    RI::Proof:
        PreparedRecursiveMultiProofTargets<EF, MultiProof = <RI::Input as Mmcs<F>>::MultiProof>,
    RF::Proof:
        PreparedRecursiveMultiProofTargets<EF, MultiProof = <RF::Input as Mmcs<EF>>::MultiProof>,
{
    let query_count = InputProofTargets::<F, EF, RI>::validate_openings_raw(&input.input_openings)?;
    for batch in &input.input_openings {
        <RI::Proof as PreparedRecursiveMultiProofTargets<EF>>::validate_multiproof_raw(
            &batch.opening_proof,
            batch.opened_values.iter().map(Vec::len),
            input_salt_elems,
        )?;
    }
    for step in &input.commit_phase_openings {
        if query_count.is_some_and(|count| count != step.sibling_values.len()) {
            return Err(VerificationError::InvalidProofShape(
                "FRI query counts disagree".into(),
            ));
        }
        <RF::Proof as PreparedRecursiveMultiProofTargets<EF>>::validate_multiproof_raw(
            &step.opening_proof,
            core::iter::repeat_n(1usize, step.sibling_values.len()),
            phase_salt_elems,
        )?;
    }
    Ok(())
}

impl<F, EF, RF, RI, W> CheckedFriOpening<EF, RI::Commitment>
    for FriProofTargets<F, EF, RF, InputProofTargets<F, EF, RI>, W>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    RF: RecursiveExtensionMmcs<F, EF>,
    RI: RecursiveMmcs<F, EF>,
    W: Recursive<EF>,
    RI::Input: NativeFriSaltWidth,
    RF::Input: NativeFriSaltWidth,
    RI::Commitment: CheckedFriCommitment<EF, Input = <RI::Input as Mmcs<F>>::Commitment>,
    RF::Commitment: CheckedFriCommitment<EF, Input = <RF::Input as Mmcs<EF>>::Commitment>,
    RI::Proof:
        PreparedRecursiveMultiProofTargets<EF, MultiProof = <RI::Input as Mmcs<F>>::MultiProof>,
    RF::Proof:
        PreparedRecursiveMultiProofTargets<EF, MultiProof = <RF::Input as Mmcs<EF>>::MultiProof>,
{
    type PhaseCommitment = RF::Commitment;

    fn validate_fri_context(
        input: &Self::Input,
        native: &NativeFriParams,
        recursive: &FriVerifierParams,
        layout: FriOpeningLayout<'_>,
        input_caps: &[&<RI::Commitment as Recursive<EF>>::Input],
    ) -> Result<ValidatedFriContext, VerificationError> {
        validate_builtin_fri_raw::<F, EF, RF, RI, W>(
            input,
            <RI::Input as NativeFriSaltWidth>::SALT_ELEMS,
            <RF::Input as NativeFriSaltWidth>::SALT_ELEMS,
        )?;
        let phase_caps: Vec<_> = input.commit_phase_commits.iter().collect();
        validate_fri_context_with_caps::<
            F,
            EF,
            RI::Input,
            RF::Input,
            W::Input,
            RI::Commitment,
            RF::Commitment,
        >(
            input,
            native,
            recursive,
            layout,
            input_caps,
            &phase_caps,
            <RI::Input as NativeFriSaltWidth>::SALT_ELEMS,
            <RF::Input as NativeFriSaltWidth>::SALT_ELEMS,
            None,
        )
    }

    fn validate_fri_replacement(
        input: &Self::Input,
        expected: &ValidatedFriContext,
        candidate_layout: FriOpeningLayout<'_>,
        input_caps: &[&<RI::Commitment as Recursive<EF>>::Input],
    ) -> Result<(), VerificationError> {
        if candidate_layout.to_owned_layout() != *expected.layout() {
            return Err(VerificationError::InvalidProofShape(
                "FRI retained layout mismatch".into(),
            ));
        }
        let candidate = Self::validate_fri_context(
            input,
            &expected.native_params(),
            &expected.recursive_params(),
            candidate_layout,
            input_caps,
        )?;
        if candidate.log_arities() != expected.log_arities()
            || candidate.input_cap_roots() != expected.input_cap_roots()
            || candidate.phase_cap_roots() != expected.phase_cap_roots()
            || candidate.input_salt_elems() != expected.input_salt_elems()
            || candidate.phase_salt_elems() != expected.phase_salt_elems()
            || candidate.hiding_tail_shape() != expected.hiding_tail_shape()
        {
            return Err(VerificationError::InvalidProofShape(
                "FRI retained schedule or cap metadata mismatch".into(),
            ));
        }
        Ok(())
    }
}

impl<F, EF, RF, RI, W> CheckedFriOpening<EF, RI::Commitment>
    for HidingFriProofTargets<F, EF, RF, InputProofTargets<F, EF, RI>, W>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    RF: RecursiveExtensionMmcs<F, EF>,
    RI: RecursiveMmcs<F, EF>,
    W: Recursive<EF>,
    RI::Input: NativeFriSaltWidth,
    RF::Input: NativeFriSaltWidth,
    RI::Commitment: CheckedFriCommitment<EF, Input = <RI::Input as Mmcs<F>>::Commitment>,
    RF::Commitment: CheckedFriCommitment<EF, Input = <RF::Input as Mmcs<EF>>::Commitment>,
    RI::Proof:
        PreparedRecursiveMultiProofTargets<EF, MultiProof = <RI::Input as Mmcs<F>>::MultiProof>,
    RF::Proof:
        PreparedRecursiveMultiProofTargets<EF, MultiProof = <RF::Input as Mmcs<EF>>::MultiProof>,
{
    type PhaseCommitment = RF::Commitment;

    fn validate_fri_context(
        input: &Self::Input,
        native: &NativeFriParams,
        recursive: &FriVerifierParams,
        layout: FriOpeningLayout<'_>,
        input_caps: &[&<RI::Commitment as Recursive<EF>>::Input],
    ) -> Result<ValidatedFriContext, VerificationError> {
        validate_builtin_fri_raw::<F, EF, RF, RI, W>(
            &input.1,
            <RI::Input as NativeFriSaltWidth>::SALT_ELEMS,
            <RF::Input as NativeFriSaltWidth>::SALT_ELEMS,
        )?;
        let phase_caps: Vec<_> = input.1.commit_phase_commits.iter().collect();
        validate_fri_context_with_caps::<
            F,
            EF,
            RI::Input,
            RF::Input,
            W::Input,
            RI::Commitment,
            RF::Commitment,
        >(
            &input.1,
            native,
            recursive,
            layout,
            input_caps,
            &phase_caps,
            <RI::Input as NativeFriSaltWidth>::SALT_ELEMS,
            <RF::Input as NativeFriSaltWidth>::SALT_ELEMS,
            Some(&input.0),
        )
    }

    fn validate_fri_replacement(
        input: &Self::Input,
        expected: &ValidatedFriContext,
        candidate_layout: FriOpeningLayout<'_>,
        input_caps: &[&<RI::Commitment as Recursive<EF>>::Input],
    ) -> Result<(), VerificationError> {
        if candidate_layout.to_owned_layout() != *expected.layout() {
            return Err(VerificationError::InvalidProofShape(
                "FRI retained layout mismatch".into(),
            ));
        }
        let candidate = Self::validate_fri_context(
            input,
            &expected.native_params(),
            &expected.recursive_params(),
            candidate_layout,
            input_caps,
        )?;
        if candidate.log_arities() != expected.log_arities()
            || candidate.input_cap_roots() != expected.input_cap_roots()
            || candidate.phase_cap_roots() != expected.phase_cap_roots()
            || candidate.input_salt_elems() != expected.input_salt_elems()
            || candidate.phase_salt_elems() != expected.phase_salt_elems()
            || candidate.hiding_tail_shape() != expected.hiding_tail_shape()
        {
            return Err(VerificationError::InvalidProofShape(
                "FRI retained schedule or cap metadata mismatch".into(),
            ));
        }
        Ok(())
    }
}

impl<F: Field, EF: ExtensionField<F>, Inner: RecursiveMmcs<F, EF>> Recursive<EF>
    for InputProofTargets<F, EF, Inner>
{
    type Input = Vec<BatchOpening<F, Inner::Input>>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let num_batch_openings = input.len();
        let mut batch_openings = Self::with_capacity(num_batch_openings);
        for batch_opening in input.iter() {
            batch_openings.push(BatchOpeningTargets::new(circuit, batch_opening));
        }

        batch_openings
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        input
            .iter()
            .flat_map(|batch_opening| {
                BatchOpeningTargets::<F, EF, Inner>::get_values(batch_opening)
            })
            .collect()
    }

    fn get_private_values(input: &Self::Input) -> Vec<EF> {
        input
            .iter()
            .flat_map(|batch_opening| {
                BatchOpeningTargets::<F, EF, Inner>::get_private_values(batch_opening)
            })
            .collect()
    }
}

impl<F: Field, EF: ExtensionField<F>, Inner: RecursiveMmcs<F, EF>> RecursiveFriInputOpenings<EF>
    for InputProofTargets<F, EF, Inner>
where
    Inner::Proof:
        RecursiveMultiProofTargets<EF, MultiProof = <Inner::Input as Mmcs<F>>::MultiProof>,
{
    type MultiOpenings = Vec<BatchMultiOpening<F, Inner::Input>>;

    fn num_queries(input: &Self::MultiOpenings) -> Option<usize> {
        input.iter().map(|batch| batch.opened_values.len()).min()
    }

    fn new_for_query(
        circuit: &mut CircuitBuilder<EF>,
        input: &Self::MultiOpenings,
        query: usize,
    ) -> Self {
        input
            .iter()
            .map(|batch| BatchOpeningTargets::new_for_query(circuit, batch, query))
            .collect()
    }

    fn get_values_for_query(input: &Self::MultiOpenings, query: usize) -> Vec<EF> {
        input
            .iter()
            .flat_map(|batch| {
                BatchOpeningTargets::<F, EF, Inner>::get_values_for_query(batch, query)
            })
            .collect()
    }

    fn get_private_values_for_query(input: &Self::MultiOpenings, query: usize) -> Vec<EF> {
        input
            .iter()
            .flat_map(|batch| {
                BatchOpeningTargets::<F, EF, Inner>::get_private_values_for_query(batch, query)
            })
            .collect()
    }
}

impl<F: Field, EF: ExtensionField<F>, Inner: RecursiveMmcs<F, EF>>
    PreparedRecursiveFriInputOpenings<EF> for InputProofTargets<F, EF, Inner>
where
    Inner::Proof:
        PreparedRecursiveMultiProofTargets<EF, MultiProof = <Inner::Input as Mmcs<F>>::MultiProof>,
{
    type Shape =
        Vec<FriInputBatchShape<<Inner::Proof as PreparedRecursiveMultiProofTargets<EF>>::Shape>>;

    fn openings_shape(input: &Self::MultiOpenings) -> Result<Self::Shape, VerificationError> {
        Self::validate_openings_raw(input)?;
        input
            .iter()
            .map(|batch| {
                let query_matrix_counts =
                    batch.opened_values.iter().map(Vec::len).collect::<Vec<_>>();
                Ok(FriInputBatchShape {
                    opened_values: batch
                        .opened_values
                        .iter()
                        .map(|matrices| matrices.iter().map(Vec::len).collect())
                        .collect(),
                    opening_advice: Inner::Proof::multiproof_shape(
                        &batch.opening_proof,
                        &query_matrix_counts,
                    )?,
                })
            })
            .collect()
    }

    fn query_counts(input: &Self::MultiOpenings) -> Vec<usize> {
        input
            .iter()
            .map(|batch| batch.opened_values.len())
            .collect()
    }

    fn validate_openings_raw(
        input: &Self::MultiOpenings,
    ) -> Result<Option<usize>, VerificationError> {
        let mut query_count = None;
        for batch in input {
            let count = batch.opened_values.len();
            if let Some(expected) = query_count {
                if expected != count {
                    return Err(VerificationError::InvalidProofShape(
                        "FRI input query counts disagree".into(),
                    ));
                }
            } else {
                query_count = Some(count);
            }
            Inner::Proof::validate_multiproof_raw(
                &batch.opening_proof,
                batch.opened_values.iter().map(Vec::len),
                None,
            )?;
        }
        Ok(query_count)
    }
}

// Recursive type for the `FriProof` of `TwoAdicFriPcs`.
type RecursiveFriProof<SC, RecursiveFriMmcs, RecursiveInputProof> = FriProofTargets<
    Val<SC>,
    <SC as StarkGenericConfig>::Challenge,
    RecursiveFriMmcs,
    RecursiveInputProof,
    Witness<Val<SC>>,
>;

// Implement `RecursivePcs` for `TwoAdicFriPcs`.
impl<SC, Dft, Comm, InputMmcs, RecursiveInputMmcs, RecursiveFriMmcs, FriMmcs>
    RecursivePcs<
        SC,
        InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
        RecursiveFriProof<
            SC,
            RecursiveFriMmcs,
            InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
        >,
        Comm,
        TwoAdicMultiplicativeCoset<Val<SC>>,
    > for TwoAdicFriPcs<Val<SC>, Dft, InputMmcs, FriMmcs>
where
    SC: StarkGenericConfig,
    Val<SC>: TwoAdicField + PrimeField64,
    InputMmcs: Mmcs<Val<SC>>,
    FriMmcs: Mmcs<SC::Challenge>,
    Comm: Recursive<SC::Challenge> + ObservableCommitment,
    RecursiveInputMmcs: RecursiveMmcs<Val<SC>, SC::Challenge, Input = InputMmcs>,
    RecursiveInputMmcs::Proof: MmcsProofTargets
        + RecursiveMultiProofTargets<
            SC::Challenge,
            MultiProof = <InputMmcs as Mmcs<Val<SC>>>::MultiProof,
        >,
    RecursiveFriMmcs: RecursiveExtensionMmcs<Val<SC>, SC::Challenge, Input = FriMmcs>,
    RecursiveFriMmcs::Commitment: ObservableCommitment,
    RecursiveFriMmcs::Proof: MmcsProofTargets
        + RecursiveMultiProofTargets<
            SC::Challenge,
            MultiProof = <FriMmcs as Mmcs<SC::Challenge>>::MultiProof,
        >,
    SC::Challenger: GrindingChallenger + CanObserve<FriMmcs::Commitment>,
{
    type VerifierParams = FriVerifierParams;
    type RecursiveProof = RecursiveFriProof<
        SC,
        RecursiveFriMmcs,
        InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
    >;

    /// Observes all opened values and derives PCS-specific challenges.
    fn get_challenges_circuit<
        const WIDTH: usize,
        const RATE: usize,
        C: crate::ChallengerPermConfig,
    >(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenger: &mut CircuitChallenger<WIDTH, RATE, C>,
        fri_proof: &RecursiveFriProof<
            SC,
            RecursiveFriMmcs,
            InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
        >,
        _opened_values: &OpenedValuesTargetsWithLookups<SC>,
        params: &Self::VerifierParams,
    ) -> Result<Vec<Target>, CircuitBuilderError>
    where
        Val<SC>: PrimeField64,
        SC::Challenge: ExtensionField<Val<SC>>,
    {
        // NOTE: Opened values must be observed by the caller BEFORE calling this function.
        // For batch-STARK, the caller must observe in per-instance order to match native.
        // For single-STARK, the caller can use opened_values.observe() directly.

        // Sample FRI alpha (for batch opening reduction) - extension field
        let fri_alpha = challenger.sample_ext(circuit);

        // Sample FRI betas: one per commit phase
        // For each FRI commitment, observe it and sample beta
        let mut betas = Vec::with_capacity(fri_proof.commit_phase_commits.len());
        for (commit, pow) in fri_proof
            .commit_phase_commits
            .iter()
            .zip(fri_proof.commit_pow_witnesses.iter())
        {
            let commit_targets = commit.to_observation_targets();
            challenger.observe_slice(circuit, &commit_targets);
            // Check commit-phase PoW witness.
            challenger.check_pow_witness(circuit, params.commit_pow_bits, pow.witness)?;
            // Sample beta - extension field
            let beta = challenger.sample_ext(circuit);
            betas.push(beta);
        }

        // Observe final polynomial coefficients (extension field values)
        challenger.observe_ext_slice(circuit, &fri_proof.final_poly);

        // Bind the variable-arity schedule into the transcript before query grinding,
        // matching the native FRI verifier in Plonky3.
        for &log_arity in &fri_proof.log_arities {
            let log_arity_target =
                circuit.alloc_const(SC::Challenge::from_usize(log_arity), "FRI log_arity");
            challenger.observe(circuit, log_arity_target);
        }

        // Check query PoW witness.
        challenger.check_pow_witness(
            circuit,
            params.query_pow_bits,
            fri_proof.pow_witness.witness,
        )?;

        // Query indices are sampled in-circuit by verify_circuit from the challenger
        // (which is left in the correct state here) to ensure soundness.
        let mut challenges = Vec::with_capacity(1 + betas.len());
        challenges.push(fri_alpha);
        challenges.extend(betas);
        Ok(challenges)
    }

    fn verify_circuit<const WIDTH: usize, const RATE: usize, C: crate::ChallengerPermConfig>(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenges: &[Target],
        challenger: &mut CircuitChallenger<WIDTH, RATE, C>,
        commitments_with_opening_points: &ComsWithOpeningsTargets<
            Comm,
            TwoAdicMultiplicativeCoset<Val<SC>>,
        >,
        opening_proof: &Self::RecursiveProof,
        params: &Self::VerifierParams,
    ) -> Result<Vec<NonPrimitiveOpId>, VerificationError> {
        let FriVerifierParams {
            log_blowup,
            log_final_poly_len,
            commit_pow_bits: _,
            query_pow_bits: _,
            num_queries: required_num_queries,
            permutation_config,
        } = *params;
        let num_betas = opening_proof.commit_phase_commits.len();
        let num_queries = opening_proof.query_proofs.len();

        if num_queries < required_num_queries {
            return Err(VerificationError::InvalidProofShape(format!(
                "FRI proof has {num_queries} queries but verifier params require at least {required_num_queries}"
            )));
        }

        let alpha = challenges[0];
        let betas = &challenges[1..1 + num_betas];

        let total_log_reduction: usize = opening_proof.log_arities.iter().sum();
        let log_max_height = total_log_reduction + log_final_poly_len + log_blowup;

        let max_query_index_bits = Val::<SC>::bits();
        if log_max_height > max_query_index_bits {
            return Err(VerificationError::InvalidProofShape(format!(
                "log_max_height {log_max_height} exceeds base field bit width {max_query_index_bits}"
            )));
        }

        let index_bits_per_query: Vec<Vec<Target>> = (0..num_queries)
            .map(|_| challenger.sample_bits(circuit, log_max_height))
            .collect::<Result<Vec<_>, _>>()?;

        verify_fri_circuit(
            circuit,
            opening_proof,
            alpha,
            betas,
            &index_bits_per_query,
            commitments_with_opening_points,
            log_blowup,
            permutation_config,
        )
    }

    fn selectors_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        point: &Target,
    ) -> RecursiveLagrangeSelectors {
        // Constants that we will need.
        let shift_inv =
            circuit.alloc_const(SC::Challenge::from(domain.shift_inverse()), "shift_inv");
        let one = circuit.alloc_const(SC::Challenge::from(Val::<SC>::ONE), "1");
        let subgroup_gen_inv = circuit.alloc_const(
            SC::Challenge::from(domain.subgroup_generator().inverse()),
            "subgroup_gen_inv",
        );

        // Unshifted and z_h
        let unshifted_point = circuit.alloc_mul(shift_inv, *point, "unshifted_point");
        let us_exp = circuit.exp_power_of_2(unshifted_point, domain.log_size());
        let z_h = circuit.alloc_sub(us_exp, one, "z_h");

        // Denominators
        let us_minus_one = circuit.alloc_sub(unshifted_point, one, "us_minus_one");
        let us_minus_gen_inv =
            circuit.alloc_sub(unshifted_point, subgroup_gen_inv, "us_minus_gen_inv");

        // Selectors
        let is_first_row = circuit.alloc_div(z_h, us_minus_one, "is_first_row");
        let is_last_row = circuit.alloc_div(z_h, us_minus_gen_inv, "is_last_row");
        let is_transition = us_minus_gen_inv;
        let inv_vanishing = circuit.alloc_div(one, z_h, "inv_vanishing");

        let row_selectors = RowSelectorsTargets {
            is_first_row,
            is_last_row,
            is_transition,
        };
        RecursiveLagrangeSelectors {
            row_selectors,
            inv_vanishing,
        }
    }

    fn evaluate_periodic_columns_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        periodic_columns: &[Vec<Val<SC>>],
        point: Target,
    ) -> Result<Vec<Target>, VerificationError> {
        crate::verifier::evaluate_periodic_columns_circuit(circuit, domain, periodic_columns, point)
    }

    fn create_disjoint_domain(
        &self,
        trace_domain: TwoAdicMultiplicativeCoset<Val<SC>>,
        degree: usize,
    ) -> TwoAdicMultiplicativeCoset<Val<SC>> {
        trace_domain.create_disjoint_domain(degree)
    }

    fn split_domains(
        &self,
        trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        degree: usize,
    ) -> Vec<TwoAdicMultiplicativeCoset<Val<SC>>> {
        trace_domain.split_domains(degree)
    }

    fn log_size(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> usize {
        trace_domain.log_size()
    }

    fn first_point(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> SC::Challenge {
        trace_domain.first_point().into()
    }

    // This is not used for non-ZK FRI proofs.
    fn get_fri_random_opened_values(
        _proof: &RecursiveFriProof<
            SC,
            RecursiveFriMmcs,
            InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
        >,
    ) -> &[Vec<Vec<Vec<Target>>>] {
        &[]
    }
}

/// Recursive targets for the extra random opened values carried by `HidingFriPcs`.
pub struct HidingOpenedValuesTargets<EF: Field> {
    /// Layout: rounds -> matrices -> points -> values.
    pub rounds: Vec<Vec<Vec<Vec<Target>>>>,
    _phantom: PhantomData<EF>,
}

impl<EF: Field> Recursive<EF> for HidingOpenedValuesTargets<EF> {
    type Input = OpenedValues<EF>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let rounds = input
            .iter()
            .map(|round| {
                round
                    .iter()
                    .map(|matrix| {
                        matrix
                            .iter()
                            .map(|point_vals| {
                                circuit.alloc_private_inputs(
                                    point_vals.len(),
                                    "hiding random opened values",
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        Self {
            rounds,
            _phantom: PhantomData,
        }
    }

    fn get_values(_input: &Self::Input) -> Vec<EF> {
        vec![]
    }

    fn get_private_values(input: &Self::Input) -> Vec<EF> {
        input
            .iter()
            .flat_map(|round| round.iter())
            .flat_map(|matrix| matrix.iter())
            .flat_map(|point_vals| point_vals.iter().copied())
            .collect()
    }
}

impl<EF: Field> PreparedRecursive<EF> for HidingOpenedValuesTargets<EF> {
    type Shape = Vec<Vec<Vec<usize>>>;

    fn input_shape(input: &Self::Input) -> Result<Self::Shape, VerificationError> {
        Ok(input
            .iter()
            .map(|round| {
                round
                    .iter()
                    .map(|matrix| matrix.iter().map(Vec::len).collect())
                    .collect()
            })
            .collect())
    }
}

/// Recursive proof targets for `HidingFriPcs`.
///
/// This wraps:
/// 1. Random opened values split out by `HidingFriPcs`
/// 2. The inner FRI proof (same structure as `TwoAdicFriPcs`)
pub struct HidingFriProofTargets<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF>,
    PowWitness: Recursive<EF>,
> {
    pub random_opened_values: HidingOpenedValuesTargets<EF>,
    pub inner_proof: FriProofTargets<F, EF, RecMmcs, InputProof, PowWitness>,
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF> + RecursiveFriInputOpenings<EF>,
    PowWitness: Recursive<EF>,
> Recursive<EF> for HidingFriProofTargets<F, EF, RecMmcs, InputProof, PowWitness>
where
    RecMmcs::Proof:
        RecursiveMultiProofTargets<EF, MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof>,
{
    type Input = (
        OpenedValues<EF>,
        FriProof<EF, RecMmcs::Input, PowWitness::Input, InputProof::MultiOpenings>,
    );

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        Self {
            random_opened_values: HidingOpenedValuesTargets::new(circuit, &input.0),
            inner_proof: FriProofTargets::new(circuit, &input.1),
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        FriProofTargets::<F, EF, RecMmcs, InputProof, PowWitness>::get_values(&input.1)
    }

    fn get_private_values(input: &Self::Input) -> Vec<EF> {
        HidingOpenedValuesTargets::<EF>::get_private_values(&input.0)
            .into_iter()
            .chain(
                FriProofTargets::<F, EF, RecMmcs, InputProof, PowWitness>::get_private_values(
                    &input.1,
                ),
            )
            .collect()
    }
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF> + PreparedRecursiveFriInputOpenings<EF>,
    PowWitness: PreparedRecursive<EF>,
> PreparedRecursive<EF> for HidingFriProofTargets<F, EF, RecMmcs, InputProof, PowWitness>
where
    RecMmcs::Commitment: PreparedRecursive<EF>,
    RecMmcs::Proof: PreparedRecursiveMultiProofTargets<
            EF,
            MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof,
        >,
{
    type Shape = HidingFriShape<
        <FriProofTargets<F, EF, RecMmcs, InputProof, PowWitness> as PreparedRecursive<EF>>::Shape,
    >;

    fn input_shape(input: &Self::Input) -> Result<Self::Shape, VerificationError> {
        let (random_opened_values, inner_proof) = input;
        Ok(HidingFriShape {
            random_openings: HidingOpenedValuesTargets::<EF>::input_shape(random_opened_values)?,
            inner: FriProofTargets::<F, EF, RecMmcs, InputProof, PowWitness>::input_shape(
                inner_proof,
            )?,
        })
    }
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF> + PreparedRecursiveFriInputOpenings<EF>,
    PowWitness: Recursive<EF>,
> CheckedRecursive<EF> for HidingFriProofTargets<F, EF, RecMmcs, InputProof, PowWitness>
where
    RecMmcs::Commitment: CheckedRecursive<EF>,
    RecMmcs::Proof: PreparedRecursiveMultiProofTargets<
            EF,
            MultiProof = <RecMmcs::Input as Mmcs<EF>>::MultiProof,
        >,
{
    fn validate_input(input: &Self::Input) -> Result<(), VerificationError> {
        FriProofTargets::<F, EF, RecMmcs, InputProof, PowWitness>::validate_input(&input.1)
    }
}

type RecursiveHidingFriProof<SC, RecursiveFriMmcs, RecursiveInputProof> = HidingFriProofTargets<
    Val<SC>,
    <SC as StarkGenericConfig>::Challenge,
    RecursiveFriMmcs,
    RecursiveInputProof,
    Witness<Val<SC>>,
>;

/// Merged commitments with opening points and random opened values.
type HidingMergedCommitments<SC, Comm> = (
    Comm,
    Vec<(
        TwoAdicMultiplicativeCoset<Val<SC>>,
        Vec<(Target, Vec<Target>)>,
    )>,
);

fn merge_hiding_random_openings<SC, Comm>(
    commitments_with_opening_points: &ComsWithOpeningsTargets<
        Comm,
        TwoAdicMultiplicativeCoset<Val<SC>>,
    >,
    random_opened_values: &[Vec<Vec<Vec<Target>>>],
) -> Result<Vec<HidingMergedCommitments<SC, Comm>>, VerificationError>
where
    SC: StarkGenericConfig,
    Val<SC>: TwoAdicField,
    Comm: Clone,
{
    if commitments_with_opening_points.len() != random_opened_values.len() {
        return Err(VerificationError::InvalidProofShape(
            "Hiding FRI proof shape mismatch: random rounds count does not match commitments"
                .to_string(),
        ));
    }

    let mut merged = Vec::with_capacity(commitments_with_opening_points.len());

    for ((commitment, mats), rand_round) in commitments_with_opening_points
        .iter()
        .zip(random_opened_values.iter())
    {
        if mats.len() != rand_round.len() {
            return Err(VerificationError::InvalidProofShape(
                "Hiding FRI proof shape mismatch: random matrices count does not match".to_string(),
            ));
        }

        let mut merged_mats = Vec::with_capacity(mats.len());
        for ((domain, points), rand_mat) in mats.iter().zip(rand_round.iter()) {
            if points.len() != rand_mat.len() {
                return Err(VerificationError::InvalidProofShape(
                    "Hiding FRI proof shape mismatch: random points count does not match"
                        .to_string(),
                ));
            }

            let mut merged_points = Vec::with_capacity(points.len());
            for ((point, vals), rand_point) in points.iter().zip(rand_mat.iter()) {
                let mut merged_vals = vals.clone();
                merged_vals.extend(rand_point.iter().copied());
                merged_points.push((*point, merged_vals));
            }

            merged_mats.push((*domain, merged_points));
        }

        merged.push((commitment.clone(), merged_mats));
    }

    Ok(merged)
}

impl<SC, Dft, Comm, InputMmcs, RecursiveInputMmcs, RecursiveFriMmcs, FriMmcs, R>
    RecursivePcs<
        SC,
        InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
        RecursiveHidingFriProof<
            SC,
            RecursiveFriMmcs,
            InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
        >,
        Comm,
        TwoAdicMultiplicativeCoset<Val<SC>>,
    > for HidingFriPcs<Val<SC>, Dft, InputMmcs, FriMmcs, R>
where
    SC: StarkGenericConfig,
    Val<SC>: TwoAdicField + PrimeField64,
    InputMmcs: Mmcs<Val<SC>>,
    FriMmcs: Mmcs<SC::Challenge>,
    Comm: Recursive<SC::Challenge> + ObservableCommitment + Clone,
    RecursiveInputMmcs: RecursiveMmcs<Val<SC>, SC::Challenge, Input = InputMmcs>,
    RecursiveInputMmcs::Proof: MmcsProofTargets
        + RecursiveMultiProofTargets<
            SC::Challenge,
            MultiProof = <InputMmcs as Mmcs<Val<SC>>>::MultiProof,
        >,
    RecursiveFriMmcs: RecursiveExtensionMmcs<Val<SC>, SC::Challenge, Input = FriMmcs>,
    RecursiveFriMmcs::Commitment: ObservableCommitment,
    RecursiveFriMmcs::Proof: MmcsProofTargets
        + RecursiveMultiProofTargets<
            SC::Challenge,
            MultiProof = <FriMmcs as Mmcs<SC::Challenge>>::MultiProof,
        >,
    SC::Challenger: GrindingChallenger + CanObserve<FriMmcs::Commitment>,
{
    type VerifierParams = FriVerifierParams;
    type RecursiveProof = RecursiveHidingFriProof<
        SC,
        RecursiveFriMmcs,
        InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
    >;

    fn get_challenges_circuit<
        const WIDTH: usize,
        const RATE: usize,
        C: crate::ChallengerPermConfig,
    >(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenger: &mut CircuitChallenger<WIDTH, RATE, C>,
        proof_targets: &Self::RecursiveProof,
        _opened_values: &OpenedValuesTargetsWithLookups<SC>,
        params: &Self::VerifierParams,
    ) -> Result<Vec<Target>, CircuitBuilderError>
    where
        Val<SC>: PrimeField64,
        SC::Challenge: ExtensionField<Val<SC>>,
    {
        let fri_proof = &proof_targets.inner_proof;

        let fri_alpha = challenger.sample_ext(circuit);

        let mut betas = Vec::with_capacity(fri_proof.commit_phase_commits.len());
        for (commit, pow) in fri_proof
            .commit_phase_commits
            .iter()
            .zip(fri_proof.commit_pow_witnesses.iter())
        {
            let commit_targets = commit.to_observation_targets();
            challenger.observe_slice(circuit, &commit_targets);
            challenger.check_pow_witness(circuit, params.commit_pow_bits, pow.witness)?;
            let beta = challenger.sample_ext(circuit);
            betas.push(beta);
        }

        challenger.observe_ext_slice(circuit, &fri_proof.final_poly);

        for &log_arity in &fri_proof.log_arities {
            let log_arity_target =
                circuit.alloc_const(SC::Challenge::from_usize(log_arity), "FRI log_arity");
            challenger.observe(circuit, log_arity_target);
        }

        challenger.check_pow_witness(
            circuit,
            params.query_pow_bits,
            fri_proof.pow_witness.witness,
        )?;

        let mut challenges = Vec::with_capacity(1 + betas.len());
        challenges.push(fri_alpha);
        challenges.extend(betas);
        Ok(challenges)
    }

    fn verify_circuit<const WIDTH: usize, const RATE: usize, C: crate::ChallengerPermConfig>(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenges: &[Target],
        challenger: &mut CircuitChallenger<WIDTH, RATE, C>,
        commitments_with_opening_points: &ComsWithOpeningsTargets<
            Comm,
            TwoAdicMultiplicativeCoset<Val<SC>>,
        >,
        opening_proof: &Self::RecursiveProof,
        params: &Self::VerifierParams,
    ) -> Result<Vec<NonPrimitiveOpId>, VerificationError> {
        let FriVerifierParams {
            log_blowup,
            log_final_poly_len,
            commit_pow_bits: _,
            query_pow_bits: _,
            num_queries: required_num_queries,
            permutation_config,
        } = *params;
        let fri_proof = &opening_proof.inner_proof;
        let num_betas = fri_proof.commit_phase_commits.len();
        let num_queries = fri_proof.query_proofs.len();

        if num_queries < required_num_queries {
            return Err(VerificationError::InvalidProofShape(format!(
                "FRI proof has {num_queries} queries but verifier params require at least {required_num_queries}"
            )));
        }

        let alpha = challenges[0];
        let betas = &challenges[1..1 + num_betas];

        let total_log_reduction: usize = fri_proof.log_arities.iter().sum();
        let log_max_height = total_log_reduction + log_final_poly_len + log_blowup;

        let max_query_index_bits = Val::<SC>::bits();
        if log_max_height > max_query_index_bits {
            return Err(VerificationError::InvalidProofShape(format!(
                "log_max_height {log_max_height} exceeds base field bit width {max_query_index_bits}"
            )));
        }

        let index_bits_per_query: Vec<Vec<Target>> = (0..num_queries)
            .map(|_| challenger.sample_bits(circuit, log_max_height))
            .collect::<Result<Vec<_>, _>>()?;

        let merged_commitments = merge_hiding_random_openings::<SC, Comm>(
            commitments_with_opening_points,
            &opening_proof.random_opened_values.rounds,
        )?;

        verify_fri_circuit(
            circuit,
            fri_proof,
            alpha,
            betas,
            &index_bits_per_query,
            &merged_commitments,
            log_blowup,
            permutation_config,
        )
    }

    fn selectors_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        point: &Target,
    ) -> RecursiveLagrangeSelectors {
        let shift_inv =
            circuit.alloc_const(SC::Challenge::from(domain.shift_inverse()), "shift_inv");
        let one = circuit.alloc_const(SC::Challenge::from(Val::<SC>::ONE), "1");
        let subgroup_gen_inv = circuit.alloc_const(
            SC::Challenge::from(domain.subgroup_generator().inverse()),
            "subgroup_gen_inv",
        );

        let unshifted_point = circuit.alloc_mul(shift_inv, *point, "unshifted_point");
        let us_exp = circuit.exp_power_of_2(unshifted_point, domain.log_size());
        let z_h = circuit.alloc_sub(us_exp, one, "z_h");

        let us_minus_one = circuit.alloc_sub(unshifted_point, one, "us_minus_one");
        let us_minus_gen_inv =
            circuit.alloc_sub(unshifted_point, subgroup_gen_inv, "us_minus_gen_inv");

        let is_first_row = circuit.alloc_div(z_h, us_minus_one, "is_first_row");
        let is_last_row = circuit.alloc_div(z_h, us_minus_gen_inv, "is_last_row");
        let is_transition = us_minus_gen_inv;
        let inv_vanishing = circuit.alloc_div(one, z_h, "inv_vanishing");

        let row_selectors = RowSelectorsTargets {
            is_first_row,
            is_last_row,
            is_transition,
        };
        RecursiveLagrangeSelectors {
            row_selectors,
            inv_vanishing,
        }
    }

    fn evaluate_periodic_columns_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        periodic_columns: &[Vec<Val<SC>>],
        point: Target,
    ) -> Result<Vec<Target>, VerificationError> {
        crate::verifier::evaluate_periodic_columns_circuit(circuit, domain, periodic_columns, point)
    }

    fn create_disjoint_domain(
        &self,
        trace_domain: TwoAdicMultiplicativeCoset<Val<SC>>,
        degree: usize,
    ) -> TwoAdicMultiplicativeCoset<Val<SC>> {
        trace_domain.create_disjoint_domain(degree)
    }

    fn split_domains(
        &self,
        trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        degree: usize,
    ) -> Vec<TwoAdicMultiplicativeCoset<Val<SC>>> {
        trace_domain.split_domains(degree)
    }

    fn log_size(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> usize {
        trace_domain.log_size()
    }

    fn first_point(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> SC::Challenge {
        trace_domain.first_point().into()
    }

    fn get_fri_random_opened_values(
        proof: &RecursiveHidingFriProof<
            SC,
            RecursiveFriMmcs,
            InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
        >,
    ) -> &[Vec<Vec<Vec<Target>>>] {
        &proof.random_opened_values.rounds
    }
}

#[cfg(test)]
mod prepared_shape_tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};
    use p3_merkle_tree::{MerkleTreeHidingMmcs, PrunedMerklePaths};
    use p3_symmetric::MerkleCap;
    use p3_test_utils::koala_bear_params::{
        Challenge, ChallengeMmcs, DIGEST_ELEMS, F, MyCompress, MyHash, MyMmcs,
    };
    use rand::rngs::StdRng;

    use super::*;
    use crate::input_contract::fri::FriShape;
    use crate::traits::PreparedRecursive;

    type RecInputMmcs = RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>;
    type RecFriMmcs = RecExtensionValMmcs<F, Challenge, DIGEST_ELEMS, RecInputMmcs>;
    type OpeningTargets = FriProofTargets<
        F,
        Challenge,
        RecFriMmcs,
        InputProofTargets<F, Challenge, RecInputMmcs>,
        Witness<F>,
    >;
    type Opening = <OpeningTargets as Recursive<Challenge>>::Input;

    type NativeHidingMmcs = MerkleTreeHidingMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        StdRng,
        2,
        DIGEST_ELEMS,
        4,
    >;
    type RecHidingMmcs = RecValHidingMmcs<F, DIGEST_ELEMS, 4, MyHash, MyCompress, StdRng>;
    type RecHidingFriMmcs = RecExtensionValMmcs<F, Challenge, DIGEST_ELEMS, RecHidingMmcs>;
    type HidingOpeningTargets = HidingFriProofTargets<
        F,
        Challenge,
        RecHidingFriMmcs,
        InputProofTargets<F, Challenge, RecHidingMmcs>,
        Witness<F>,
    >;
    type HidingOpening = <HidingOpeningTargets as Recursive<Challenge>>::Input;

    fn cap(roots: usize) -> MerkleCap<F, [F; DIGEST_ELEMS]> {
        MerkleCap::new(vec![[F::ZERO; DIGEST_ELEMS]; roots])
    }

    #[test]
    fn borrowed_cap_context_checks_binary_packing_and_height() {
        let one_root_cap = cap(1);
        let perm = PermConfig::poseidon2(crate::ops::Poseidon2Config::KOALA_BEAR_D4_W16);
        assert!(
            validate_merkle_cap_context::<F, Challenge, DIGEST_ELEMS, _>(
                &one_root_cap,
                perm,
                1,
                [2usize].into_iter(),
            )
            .is_ok()
        );
        assert!(
            validate_merkle_cap_context::<F, Challenge, DIGEST_ELEMS, _>(
                &one_root_cap,
                perm,
                1,
                [0usize].into_iter(),
            )
            .is_err()
        );
        let too_tall = cap(4);
        assert!(
            validate_merkle_cap_context::<F, Challenge, DIGEST_ELEMS, _>(
                &too_tall,
                perm,
                2,
                [2usize].into_iter(),
            )
            .is_err()
        );

        let arity4 = PermConfig::poseidon2(crate::ops::Poseidon2Config::KOALA_BEAR_D4_W32);
        let arity4_cap = cap(1);
        assert!(
            validate_merkle_cap_context::<F, Challenge, DIGEST_ELEMS, _>(
                &arity4_cap,
                arity4,
                4,
                [16usize, 8].into_iter(),
            )
            .is_ok()
        );
        let surplus_cap = cap(8);
        assert!(
            validate_merkle_cap_context::<F, Challenge, DIGEST_ELEMS, _>(
                &surplus_cap,
                arity4,
                4,
                [16usize, 8].into_iter(),
            )
            .is_ok()
        );
    }

    #[test]
    fn cap_packing_covers_d2_d4_and_lifted_d5_lanes() {
        let d4_binary = PermConfig::poseidon2(crate::ops::Poseidon2Config::KOALA_BEAR_D4_W16);
        assert!(
            validate_cap_packing::<DIGEST_ELEMS>(
                1,
                d4_binary.rate_ext(),
                false,
                <Challenge as BasedVectorSpace<F>>::DIMENSION,
                0,
                0,
            )
            .is_ok()
        );

        let d4_arity4 = PermConfig::poseidon2(crate::ops::Poseidon2Config::KOALA_BEAR_D4_W32);
        assert!(
            validate_cap_packing::<DIGEST_ELEMS>(
                1,
                d4_arity4.capacity_ext(),
                false,
                <Challenge as BasedVectorSpace<F>>::DIMENSION,
                0,
                0,
            )
            .is_ok()
        );

        // These metadata-only controls cover the supported degree-2 and
        // D=1-permutation-over-degree-5 packing lanes without allocating a
        // giant native cap.
        assert!(validate_cap_packing::<8>(1, 4, false, 2, 0, 0).is_ok());
        assert!(validate_cap_packing::<8>(1, 8, true, 5, 0, 0).is_ok());
        assert!(validate_cap_packing::<7>(1, 2, false, 4, 0, 0).is_err());
    }

    #[test]
    fn cap_packing_overflow_boundaries_are_typed_errors() {
        assert!(validate_cap_packing::<1>(1, 0, false, 1, 0, 0).is_err());
        assert!(validate_cap_packing::<1>(1, 1, false, 0, 0, 0).is_err());
        assert!(validate_cap_packing::<1>(1, usize::MAX, false, 2, 0, 0).is_err());
        assert!(validate_cap_packing::<8>(usize::MAX, 1, false, 8, 0, 0).is_err());
        assert!(
            validate_cap_packing::<1>(
                usize::MAX / core::mem::size_of::<Target>() + 1,
                1,
                false,
                1,
                0,
                0,
            )
            .is_err()
        );
        assert!(validate_cap_packing::<1>(1, 1, false, 1, usize::MAX, 1).is_err());

        // Keep the outer `Vec<Target>` header bound distinct from the flat
        // digest-byte bound: both are checked before any allocation.
        let outer_header_roots =
            (isize::MAX as usize / core::mem::size_of::<Vec<Target>>()).saturating_add(1);
        let outer_error = validate_cap_packing::<1>(outer_header_roots, 1, false, 1, 0, 0)
            .expect_err("outer target-vector bytes must be rejected");
        assert!(matches!(
            outer_error,
            VerificationError::InvalidProofShape(message)
                if message.contains("outer target vector")
        ));

        let flat_digest_roots =
            (isize::MAX as usize / (8 * core::mem::size_of::<Target>())).saturating_add(1);
        let flat_error = validate_cap_packing::<8>(flat_digest_roots, 2, false, 4, 0, 0)
            .expect_err("flat digest target bytes must be rejected");
        assert!(matches!(
            flat_error,
            VerificationError::InvalidProofShape(message)
                if message.contains("digest target size")
        ));
    }

    fn frontier(count: usize) -> PrunedMerklePaths<F, DIGEST_ELEMS> {
        PrunedMerklePaths {
            sibling_hashes: vec![[F::ZERO; DIGEST_ELEMS]; count],
        }
    }

    #[test]
    fn contextual_fri_validator_accepts_a_tiny_native_shape() {
        use crate::input_contract::stark_layout::{InstanceLayout, NativeStarkLayout};
        use crate::pcs::fri::context::validate_fri_context_core;
        use crate::pcs::fri::{FriVerifierParams, NativeFriParams};

        let params = p3_fri::FriParameters {
            log_blowup: 1,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: 1,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs: (),
        };
        let native = NativeFriParams::try_from_native::<F, _>(&params).unwrap();
        let recursive = FriVerifierParams::with_mmcs(
            1,
            0,
            0,
            0,
            1,
            crate::ops::Poseidon2Config::KOALA_BEAR_D4_W16,
        );
        let proof = FriProof::<Challenge, ChallengeMmcs, F, Vec<BatchMultiOpening<F, MyMmcs>>> {
            commit_phase_commits: vec![cap(1)],
            commit_pow_witnesses: vec![F::ZERO],
            input_openings: vec![
                BatchMultiOpening {
                    opened_values: vec![vec![vec![F::ZERO]]],
                    opening_proof: frontier(0),
                },
                BatchMultiOpening {
                    opened_values: vec![vec![vec![F::ZERO]]],
                    opening_proof: frontier(0),
                },
            ],
            commit_phase_openings: vec![CommitPhaseMultiStep {
                log_arity: 1,
                sibling_values: vec![vec![Challenge::ZERO]],
                opening_proof: frontier(0),
            }],
            final_poly: vec![Challenge::ZERO],
            query_pow_witness: F::ZERO,
        };
        let layout = NativeStarkLayout::new(
            vec![InstanceLayout {
                challenge_width: 1,
                ext_log: 1,
                base_log: 1,
                trace_width: 1,
                trace_next: false,
                pre_width: 0,
                pre_next: false,
                quotient_log: 0,
                quotient_chunks: 1,
                permutation_width: 0,
            }],
            &[],
            false,
            false,
            false,
        )
        .unwrap();
        assert!(
            validate_fri_context_core(
                &proof,
                &native,
                &recursive,
                layout.opening_view(),
                PermConfig::poseidon2(crate::ops::Poseidon2Config::KOALA_BEAR_D4_W16),
                None,
            )
            .is_ok()
        );

        let mut malformed = proof.clone();
        malformed.commit_phase_openings[0].sibling_values[0].clear();
        assert!(
            validate_fri_context_core(
                &malformed,
                &native,
                &recursive,
                layout.opening_view(),
                PermConfig::poseidon2(crate::ops::Poseidon2Config::KOALA_BEAR_D4_W16),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn checked_context_requires_and_validates_actual_caps() {
        use crate::input_contract::stark_layout::{InstanceLayout, NativeStarkLayout};
        use crate::pcs::fri::context::CheckedFriOpening;
        use crate::pcs::fri::{FriVerifierParams, NativeFriParams};

        let params = p3_fri::FriParameters {
            log_blowup: 1,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: 1,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs: (),
        };
        let native = NativeFriParams::try_from_native::<F, _>(&params).unwrap();
        let recursive = FriVerifierParams::with_mmcs(
            1,
            0,
            0,
            0,
            1,
            crate::ops::Poseidon2Config::KOALA_BEAR_D4_W16,
        );
        let mut proof = ordinary_opening(&[1]);
        proof.input_openings.push(BatchMultiOpening::<F, MyMmcs> {
            opened_values: vec![vec![vec![F::ZERO]]],
            opening_proof: frontier(0),
        });
        let layout = NativeStarkLayout::new(
            vec![InstanceLayout {
                challenge_width: 1,
                ext_log: 1,
                base_log: 1,
                trace_width: 1,
                trace_next: false,
                pre_width: 0,
                pre_next: false,
                quotient_log: 0,
                quotient_chunks: 1,
                permutation_width: 0,
            }],
            &[],
            false,
            false,
            false,
        )
        .unwrap();
        let input_cap0 = cap(1);
        let input_cap1 = cap(1);
        let input_caps = [&input_cap0, &input_cap1];
        let result = <OpeningTargets as CheckedFriOpening<
            Challenge,
            <RecInputMmcs as RecursiveMmcs<F, Challenge>>::Commitment,
        >>::validate_fri_context(
            &proof,
            &native,
            &recursive,
            layout.opening_view(),
            &input_caps,
        );
        let context = result.expect("actual input and phase cap geometry should pass");
        assert!(
            <OpeningTargets as CheckedFriOpening<
                Challenge,
                <RecInputMmcs as RecursiveMmcs<F, Challenge>>::Commitment,
            >>::validate_fri_replacement(
                &proof, &context, layout.opening_view(), &input_caps,
            )
            .is_ok()
        );

        let altered_layout = NativeStarkLayout::new(
            vec![InstanceLayout {
                trace_width: 2,
                ..layout.instances[0]
            }],
            &[],
            false,
            false,
            false,
        )
        .unwrap();
        assert!(
            <OpeningTargets as CheckedFriOpening<
                Challenge,
                <RecInputMmcs as RecursiveMmcs<F, Challenge>>::Commitment,
            >>::validate_fri_replacement(
                &proof,
                &context,
                altered_layout.opening_view(),
                &input_caps,
            )
            .is_err()
        );

        let mut wrong_phase = proof.clone();
        wrong_phase.commit_phase_commits[0] = cap(2);
        assert!(
            <OpeningTargets as CheckedFriOpening<
                Challenge,
                <RecInputMmcs as RecursiveMmcs<F, Challenge>>::Commitment,
            >>::validate_fri_context(
                &wrong_phase,
                &native,
                &recursive,
                layout.opening_view(),
                &input_caps,
            )
            .is_err()
        );
    }

    #[test]
    fn checked_hiding_context_checks_static_salt_width_and_tail_partition() {
        use crate::input_contract::stark_layout::{InstanceLayout, NativeStarkLayout};
        use crate::pcs::fri::context::CheckedFriOpening;

        let params = p3_fri::FriParameters {
            log_blowup: 1,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: 1,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs: (),
        };
        let native = NativeFriParams::try_from_native::<F, _>(&params).unwrap();
        let recursive = FriVerifierParams::with_mmcs(
            1,
            0,
            0,
            0,
            1,
            crate::ops::Poseidon2Config::KOALA_BEAR_D4_W16,
        );
        let mut proof = hiding_opening(&[4], &[1]);
        proof
            .1
            .input_openings
            .push(BatchMultiOpening::<F, NativeHidingMmcs> {
                opened_values: vec![vec![vec![F::ZERO]]],
                opening_proof: hiding_frontier(vec![vec![vec![F::ZERO; 4]]], 0),
            });
        let tails = vec![
            vec![vec![vec![Challenge::ZERO]]],
            vec![vec![vec![Challenge::ZERO]]],
        ];
        proof.0 = tails;
        let layout = NativeStarkLayout::new(
            vec![InstanceLayout {
                challenge_width: 1,
                ext_log: 1,
                base_log: 1,
                trace_width: 1,
                trace_next: false,
                pre_width: 0,
                pre_next: false,
                quotient_log: 0,
                quotient_chunks: 1,
                permutation_width: 0,
            }],
            &[],
            false,
            false,
            false,
        )
        .unwrap();
        let input_cap0 = cap(1);
        let input_cap1 = cap(1);
        let input_caps = [&input_cap0, &input_cap1];
        let result = <HidingOpeningTargets as CheckedFriOpening<
            Challenge,
            <RecHidingMmcs as RecursiveMmcs<F, Challenge>>::Commitment,
        >>::validate_fri_context(
            &proof,
            &native,
            &recursive,
            layout.opening_view(),
            &input_caps,
        );
        assert!(
            result.is_ok(),
            "hiding salt/tail metadata should pass: {result:?}"
        );

        let mut bad = proof.clone();
        bad.1.input_openings[1].opening_proof.0[0][0] = vec![F::ZERO; 3];
        let bad_result = <HidingOpeningTargets as CheckedFriOpening<
            Challenge,
            <RecHidingMmcs as RecursiveMmcs<F, Challenge>>::Commitment,
        >>::validate_fri_context(
            &bad,
            &native,
            &recursive,
            layout.opening_view(),
            &input_caps,
        );
        assert!(bad_result.is_err(), "last input salt width must be exact");
    }

    fn ordinary_opening(widths: &[usize]) -> Opening {
        FriProof {
            commit_phase_commits: vec![cap(1)],
            commit_pow_witnesses: vec![F::ZERO],
            input_openings: vec![BatchMultiOpening::<F, MyMmcs> {
                opened_values: vec![widths.iter().map(|&width| vec![F::ZERO; width]).collect()],
                opening_proof: frontier(0),
            }],
            commit_phase_openings: vec![CommitPhaseMultiStep {
                log_arity: 1,
                sibling_values: vec![vec![Challenge::ZERO]],
                opening_proof: frontier(0),
            }],
            final_poly: vec![Challenge::ZERO],
            query_pow_witness: F::ZERO,
        }
    }

    fn hiding_frontier(
        salts: Vec<Vec<Vec<F>>>,
        count: usize,
    ) -> <NativeHidingMmcs as Mmcs<F>>::MultiProof {
        (salts, frontier(count))
    }

    fn hiding_opening(salt_widths: &[usize], random_widths: &[usize]) -> HidingOpening {
        let inner = FriProof {
            commit_phase_commits: vec![cap(1)],
            commit_pow_witnesses: vec![F::ZERO],
            input_openings: vec![BatchMultiOpening::<F, NativeHidingMmcs> {
                opened_values: vec![salt_widths.iter().map(|_| vec![F::ZERO]).collect()],
                opening_proof: hiding_frontier(
                    vec![
                        salt_widths
                            .iter()
                            .map(|&width| vec![F::ZERO; width])
                            .collect(),
                    ],
                    0,
                ),
            }],
            commit_phase_openings: vec![CommitPhaseMultiStep {
                log_arity: 1,
                sibling_values: vec![vec![Challenge::ZERO]],
                opening_proof: hiding_frontier(vec![vec![vec![F::ZERO; 4]]], 0),
            }],
            final_poly: vec![Challenge::ZERO],
            query_pow_witness: F::ZERO,
        };
        let random_opened_values = vec![vec![
            random_widths
                .iter()
                .map(|&width| vec![Challenge::ZERO; width])
                .collect(),
        ]];
        (random_opened_values, inner)
    }

    fn assert_different_shapes<Fld: Field, T: PreparedRecursive<Fld>>(
        left: &T::Input,
        right: &T::Input,
    ) {
        assert!(T::input_shape(left).unwrap() != T::input_shape(right).unwrap());
    }

    #[test]
    fn prepared_fri_equal_total_matrix_partition_differs() {
        let left = ordinary_opening(&[1, 3]);
        let right = ordinary_opening(&[2, 2]);

        assert_different_shapes::<Challenge, OpeningTargets>(&left, &right);
    }

    #[test]
    fn prepared_fri_rejects_nonminimum_query_tail() {
        let mut input = ordinary_opening(&[1, 3]);
        input.input_openings.push(BatchMultiOpening::<F, MyMmcs> {
            opened_values: vec![vec![vec![F::ZERO]], vec![vec![F::ZERO]]],
            opening_proof: frontier(0),
        });

        assert!(matches!(
            OpeningTargets::input_shape(&input),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_fri_rejects_bad_sibling_arity() {
        let mut input = ordinary_opening(&[1, 3]);
        input.commit_phase_openings[0].log_arity = 2;

        assert!(matches!(
            OpeningTargets::input_shape(&input),
            Err(VerificationError::InvalidProofShape(_))
        ));

        let mut zero_arity = ordinary_opening(&[1, 3]);
        zero_arity.commit_phase_openings[0].log_arity = 0;
        assert!(matches!(
            OpeningTargets::input_shape(&zero_arity),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_fri_rejects_commitment_round_cardinality_mismatch() {
        let mut input = ordinary_opening(&[1, 3]);
        input.commit_phase_openings.push(CommitPhaseMultiStep {
            log_arity: 1,
            sibling_values: vec![vec![Challenge::ZERO]],
            opening_proof: frontier(0),
        });

        assert!(matches!(
            OpeningTargets::input_shape(&input),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_fri_cap_and_final_poly_lengths_bind() {
        let baseline = ordinary_opening(&[1, 3]);
        let mut wider_cap = ordinary_opening(&[1, 3]);
        wider_cap.commit_phase_commits[0] = cap(2);
        let mut longer_final_poly = ordinary_opening(&[1, 3]);
        longer_final_poly.final_poly.push(Challenge::ONE);

        assert_different_shapes::<Challenge, OpeningTargets>(&baseline, &wider_cap);
        assert_different_shapes::<Challenge, OpeningTargets>(&baseline, &longer_final_poly);
    }

    #[test]
    fn prepared_hiding_fri_salt_partition_binds() {
        let left = hiding_opening(&[1, 3], &[1, 3]);
        let right = hiding_opening(&[2, 2], &[1, 3]);

        assert_different_shapes::<Challenge, HidingOpeningTargets>(&left, &right);

        let mut malformed = hiding_opening(&[1, 3], &[1, 3]);
        malformed.1.input_openings[0].opening_proof.0[0].pop();
        assert!(matches!(
            HidingOpeningTargets::input_shape(&malformed),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_hiding_fri_random_point_partition_binds() {
        let left = hiding_opening(&[1, 3], &[1, 3]);
        let right = hiding_opening(&[1, 3], &[2, 2]);

        assert_different_shapes::<Challenge, HidingOpeningTargets>(&left, &right);
    }

    #[test]
    fn prepared_fri_frontier_length_is_dynamic() {
        let left = ordinary_opening(&[1, 3]);
        let mut right = ordinary_opening(&[1, 3]);
        right.input_openings[0].opening_proof = frontier(5);

        let left_shape: FriShape<_, _, _, _> = OpeningTargets::input_shape(&left).unwrap();
        let right_shape = OpeningTargets::input_shape(&right).unwrap();
        assert!(left_shape == right_shape);
    }
}
