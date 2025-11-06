use alloc::vec::Vec;
use alloc::{format, vec};
use core::marker::PhantomData;

use p3_challenger::{CanObserve, GrindingChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::utils::{RowSelectorsTargets, decompose_to_bits};
use p3_commit::{BatchOpening, ExtensionMmcs, Mmcs, PolynomialSpace};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, Field, PackedValue, PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};
use p3_uni_stark::{StarkGenericConfig, Val};
use serde::{Deserialize, Serialize};

use super::{FriVerifierParams, MAX_QUERY_INDEX_BITS, verify_fri_circuit};
use crate::Target;
use crate::challenger::CircuitChallenger;
use crate::traits::{
    ComsWithOpeningsTargets, Recursive, RecursiveChallenger, RecursiveExtensionMmcs, RecursiveMmcs,
    RecursivePcs,
};
use crate::types::{OpenedValuesTargets, ProofTargets, RecursiveLagrangeSelectors};
use crate::verifier::{ObservableCommitment, VerificationError};

/// `Recursive` version of `FriProof`.
pub struct FriProofTargets<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF>,
    Witness: Recursive<EF>,
> {
    pub commit_phase_commits: Vec<RecMmcs::Commitment>,
    pub query_proofs: Vec<QueryProofTargets<F, EF, InputProof, RecMmcs>>,
    pub final_poly: Vec<Target>,
    pub pow_witness: Witness,
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF>,
    Witness: Recursive<EF>,
> Recursive<EF> for FriProofTargets<F, EF, RecMmcs, InputProof, Witness>
{
    type Input = FriProof<EF, RecMmcs::Input, Witness::Input, InputProof::Input>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let commit_phase_commits = input
            .commit_phase_commits
            .iter()
            .map(|commitment| RecMmcs::Commitment::new(circuit, commitment))
            .collect();

        let query_proofs = input
            .query_proofs
            .iter()
            .map(|query| QueryProofTargets::new(circuit, query))
            .collect();

        let final_poly = circuit
            .alloc_public_inputs(input.final_poly.len(), "FRI final polynomial coefficients");

        Self {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness: Witness::new(circuit, &input.pow_witness),
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        let FriProof {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        } = input;

        commit_phase_commits
            .iter()
            .flat_map(|c| RecMmcs::Commitment::get_values(c))
            .chain(
                query_proofs
                    .iter()
                    .flat_map(|c| QueryProofTargets::<F, EF, InputProof, RecMmcs>::get_values(c)),
            )
            .chain(final_poly.iter().copied())
            .chain(Witness::get_values(pow_witness))
            .collect()
    }
}

/// `Recursive` version of `QueryProof`.
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
    InputProof: Recursive<EF>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
> Recursive<EF> for QueryProofTargets<F, EF, InputProof, RecMmcs>
{
    type Input = QueryProof<EF, RecMmcs::Input, InputProof::Input>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        // Note that the iterator `lens` is updated by each call to `new`. So we can always pass the same `lens` for all structures.
        let input_proof = InputProof::new(circuit, &input.input_proof);
        let commit_phase_openings = input
            .commit_phase_openings
            .iter()
            .map(|commitment| CommitPhaseProofStepTargets::new(circuit, commitment))
            .collect();
        Self {
            input_proof,
            commit_phase_openings,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        InputProof::get_values(&input.input_proof)
            .into_iter()
            .chain(
                input
                    .commit_phase_openings
                    .iter()
                    .flat_map(|o| CommitPhaseProofStepTargets::<_, _, RecMmcs>::get_values(o)),
            )
            .collect()
    }
}

/// `Recursive` version of `CommitPhaseProofStepTargets`.
pub struct CommitPhaseProofStepTargets<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
> {
    pub sibling_value: Target,
    pub opening_proof: RecMmcs::Proof,
    // This is necessary because the `Input` type can include the extension field element.
    _phantom: PhantomData<EF>,
}

impl<F: Field, EF: ExtensionField<F>, RecMmcs: RecursiveExtensionMmcs<F, EF>> Recursive<EF>
    for CommitPhaseProofStepTargets<F, EF, RecMmcs>
{
    // This is used with an extension field element, since it is part of `FriProof`, not a base field element.
    type Input = CommitPhaseProofStep<EF, RecMmcs::Input>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let sibling_value = circuit.alloc_public_input("FRI commit phase sibling value");
        let opening_proof = RecMmcs::Proof::new(circuit, &input.opening_proof);
        Self {
            sibling_value,
            opening_proof,
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        let CommitPhaseProofStep {
            sibling_value,
            opening_proof,
        } = input;

        let mut values = vec![*sibling_value];
        values.extend(RecMmcs::Proof::get_values(opening_proof));
        values
    }
}

/// `Recursive` version of `BatchOpening`.
pub struct BatchOpeningTargets<F: Field, EF: ExtensionField<F>, RecMmcs: RecursiveMmcs<F, EF>> {
    /// The opened row values from each matrix in the batch.
    /// Each inner vector corresponds to one matrix.
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
            .map(|values| circuit.alloc_public_inputs(values.len(), "batch opened values"))
            .collect();

        let opening_proof = Inner::Proof::new(circuit, &input.opening_proof);

        Self {
            opened_values,
            opening_proof,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        let BatchOpening {
            opened_values,
            opening_proof,
        } = input;

        opened_values
            .iter()
            .flat_map(|inner| inner.iter().map(|v| EF::from(*v)))
            .chain(Inner::Proof::get_values(opening_proof))
            .collect()
    }
}

// Now, we define the commitment schemes.

/// `HashTargets` corresponds to a commitment in the form of hashes with `DIGEST_ELEMS` digest elements.
#[derive(Clone)]
pub struct HashTargets<F, const DIGEST_ELEMS: usize> {
    pub hash_targets: [Target; DIGEST_ELEMS],
    _phantom: PhantomData<F>,
}

impl<F, const DIGEST_ELEMS: usize> ObservableCommitment for HashTargets<F, DIGEST_ELEMS> {
    fn to_observation_targets(&self) -> Vec<Target> {
        self.hash_targets.to_vec()
    }
}

type ValMmcsCommitment<F, const DIGEST_ELEMS: usize> =
    Hash<<F as PackedValue>::Value, <F as PackedValue>::Value, DIGEST_ELEMS>;

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize> Recursive<EF>
    for HashTargets<F, DIGEST_ELEMS>
{
    type Input = ValMmcsCommitment<F, DIGEST_ELEMS>;

    fn new(circuit: &mut CircuitBuilder<EF>, _input: &Self::Input) -> Self {
        Self {
            hash_targets: circuit.alloc_public_input_array("MMCS commitment digest"),
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        input.into_iter().map(|v| EF::from(v)).collect()
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

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let proof_len = input.len();
        let mut proof = Vec::with_capacity(proof_len);
        for _ in 0..proof_len {
            proof.push(circuit.alloc_public_input_array("Merkle proof hash"));
        }

        Self {
            hash_proof_targets: proof,
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        input
            .iter()
            .flat_map(|h| h.iter().map(|v| EF::from(*v)))
            .collect()
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
    type Input = MerkleTreeMmcs<F::Packing, F::Packing, H, C, DIGEST_ELEMS>;

    type Commitment = HashTargets<F, DIGEST_ELEMS>;

    type Proof = HashProofTargets<F, DIGEST_ELEMS>;
}

/// `Recursive` version of an `ExtensionFieldMmcs` where the inner `Mmcs` is a `MerkleTreeMmcs`.
pub struct RecExtensionValMmcs<
    F: Field,
    EF: ExtensionField<F>,
    const DIGEST_ELEMS: usize,
    ValMmcs: RecursiveMmcs<F, EF>,
> {
    _phantom: PhantomData<F>,
    _phantom_ef: PhantomData<EF>,
    _phantom_val: PhantomData<ValMmcs>,
}

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize, RecValMmcs: RecursiveMmcs<F, EF>>
    RecursiveExtensionMmcs<F, EF> for RecExtensionValMmcs<F, EF, DIGEST_ELEMS, RecValMmcs>
{
    type Input = ExtensionMmcs<F, EF, RecValMmcs::Input>;

    type Commitment = RecValMmcs::Commitment;

    type Proof = RecValMmcs::Proof;
}

pub type InputProofTargets<F, EF, Inner> = Vec<BatchOpeningTargets<F, EF, Inner>>;

pub type TwoAdicFriProofTargets<F, EF, RecMmcs, Inner> =
    FriProofTargets<F, EF, RecMmcs, InputProofTargets<F, EF, Inner>, Target>;

impl<F: Field, EF: ExtensionField<F>, Inner: RecursiveMmcs<F, EF>> Recursive<EF>
    for InputProofTargets<F, EF, Inner>
{
    type Input = Vec<BatchOpening<F, Inner::Input>>;

    fn new(circuit: &mut CircuitBuilder<EF>, input: &Self::Input) -> Self {
        let num_batch_openings = input.len();
        let mut batch_openings = Vec::with_capacity(num_batch_openings);
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
    Val<SC>: TwoAdicField,
    InputMmcs: Mmcs<Val<SC>>,
    FriMmcs: Mmcs<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    RecursiveInputMmcs: RecursiveMmcs<Val<SC>, SC::Challenge, Input = InputMmcs>,
    RecursiveFriMmcs: RecursiveExtensionMmcs<Val<SC>, SC::Challenge, Input = FriMmcs>,
    RecursiveFriMmcs::Commitment: ObservableCommitment,
    SC::Challenger: GrindingChallenger,
    SC::Challenger: CanObserve<FriMmcs::Commitment>,
{
    type VerifierParams = FriVerifierParams;
    type RecursiveProof = RecursiveFriProof<
        SC,
        RecursiveFriMmcs,
        InputProofTargets<Val<SC>, SC::Challenge, RecursiveInputMmcs>,
    >;

    fn get_challenges_circuit<const RATE: usize>(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenger: &mut CircuitChallenger<RATE>,
        proof_targets: &ProofTargets<SC, Comm, Self::RecursiveProof>,
        opened_values: &OpenedValuesTargets<SC>,
        params: &Self::VerifierParams,
    ) -> Vec<Target> {
        let fri_proof = &proof_targets.opening_proof;

        // Observe all opened values (trace, quotient chunks, random)
        opened_values.observe(circuit, challenger);

        // Sample FRI alpha (for batch opening reduction)
        let fri_alpha = challenger.sample(circuit);

        // Sample FRI betas: one per commit phase
        // For each FRI commitment, observe it and sample beta
        let mut betas = Vec::with_capacity(fri_proof.commit_phase_commits.len());
        for commit in &fri_proof.commit_phase_commits {
            let commit_targets = commit.to_observation_targets();
            challenger.observe_slice(circuit, &commit_targets);
            let beta = challenger.sample(circuit);
            betas.push(beta);
        }

        // Observe final polynomial coefficients
        challenger.observe_slice(circuit, &fri_proof.final_poly);

        // Check PoW witness.
        challenger.check_witness(
            circuit,
            params.pow_bits,
            fri_proof.pow_witness.witness,
            Val::<SC>::bits(),
        );

        // Sample query indices
        let num_queries = fri_proof.query_proofs.len();
        let mut query_indices = Vec::with_capacity(num_queries);
        for _ in 0..num_queries {
            let index = challenger.sample(circuit);
            query_indices.push(index);
        }

        // Return challenges in order: [fri_alpha, betas..., query_indices...]
        let mut challenges = Vec::with_capacity(1 + betas.len() + num_queries);
        challenges.push(fri_alpha);
        challenges.extend(betas);
        challenges.extend(query_indices);
        challenges
    }

    fn verify_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenges: &[Target],
        commitments_with_opening_points: &ComsWithOpeningsTargets<
            Comm,
            TwoAdicMultiplicativeCoset<Val<SC>>,
        >,
        opening_proof: &Self::RecursiveProof,
        params: &Self::VerifierParams,
    ) -> Result<(), VerificationError> {
        let FriVerifierParams {
            log_blowup,
            log_final_poly_len,
            pow_bits: _,
        } = *params;
        // Extract FRI challenges from the challenges slice.
        // Layout: [alpha, beta_0, ..., beta_{n-1}, query_0, ..., query_{m-1}]
        // where:
        //   - alpha: FRI batch combination challenge
        //   - betas: one challenge per FRI folding round
        //   - query indices: sampled indices for FRI queries (as field elements)
        let num_betas = opening_proof.commit_phase_commits.len();
        let num_queries = opening_proof.query_proofs.len();

        let alpha = challenges[0];
        let betas = &challenges[1..1 + num_betas];

        let query_indices = &challenges[1 + num_betas..1 + num_betas + num_queries];

        // Calculate the maximum height of the FRI proof tree.
        let log_max_height = num_betas + log_final_poly_len + log_blowup;

        if log_max_height > MAX_QUERY_INDEX_BITS {
            return Err(VerificationError::InvalidProofShape(format!(
                "log_max_height {log_max_height} exceeds MAX_QUERY_INDEX_BITS {MAX_QUERY_INDEX_BITS}"
            )));
        }

        let index_bits_per_query: Vec<Vec<Target>> = query_indices
            .iter()
            .map(|&index_target| {
                let all_bits = decompose_to_bits(circuit, index_target, MAX_QUERY_INDEX_BITS);
                all_bits.into_iter().take(log_max_height).collect()
            })
            .collect();

        verify_fri_circuit(
            circuit,
            opening_proof,
            alpha,
            betas,
            &index_bits_per_query,
            commitments_with_opening_points,
            log_blowup,
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
}
