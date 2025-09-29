//! In this file, we define all the structures required to have a recursive version of `TwoAdicFriPcs`.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::{array, iter};

use p3_challenger::GrindingChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::utils::RowSelectorsTargets;
use p3_commit::{BatchOpening, ExtensionMmcs, Mmcs, PolynomialSpace};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, Field, PackedValue, PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};
use p3_uni_stark::{StarkGenericConfig, Val};
use serde::{Deserialize, Serialize};

use crate::Target;
use crate::recursive_traits::{
    ComsWithOpeningsTargets, Recursive, RecursiveExtensionMmcs, RecursiveLagrangeSelectors,
    RecursiveMmcs, RecursivePcs,
};

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

    fn new(
        circuit: &mut CircuitBuilder<EF>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        // Note that the iterator `lens` is updated by each call to `new`. So we can always pass the same `lens` for all structures.
        let num_commit_phase_commits = lens.next().unwrap();
        let mut commit_phase_commits = Vec::with_capacity(num_commit_phase_commits);
        for _ in 0..num_commit_phase_commits {
            commit_phase_commits.push(RecMmcs::Commitment::new(circuit, lens, degree_bits));
        }

        let num_query_proofs = lens.next().unwrap();
        let mut query_proofs = Vec::with_capacity(num_query_proofs);
        for _ in 0..num_query_proofs {
            query_proofs.push(QueryProofTargets::<F, EF, InputProof, RecMmcs>::new(
                circuit,
                lens,
                degree_bits,
            ));
        }

        let final_poly_len = lens.next().unwrap();
        let mut final_poly = Vec::with_capacity(final_poly_len);
        for _ in 0..final_poly_len {
            final_poly.push(circuit.add_public_input());
        }
        Self {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness: Witness::new(circuit, lens, degree_bits),
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

    fn num_challenges(&self) -> usize {
        1 // `alpha`: FRI batch combination challenge
        + self.commit_phase_commits.len() // `beta` challenges for the FRI rounds
        + self.query_proofs.len() // Indices for all query proofs
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let FriProof {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        } = input;

        let mut all_lens = vec![commit_phase_commits.len()];
        all_lens.extend(
            commit_phase_commits
                .iter()
                .flat_map(|c| RecMmcs::Commitment::lens(c)),
        );
        all_lens.push(query_proofs.len());
        all_lens.extend(
            query_proofs
                .iter()
                .flat_map(|q| QueryProofTargets::<F, EF, InputProof, RecMmcs>::lens(q)),
        );
        all_lens.push(final_poly.len());
        all_lens.extend(Witness::lens(pow_witness));

        all_lens.into_iter()
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

    fn new(
        circuit: &mut CircuitBuilder<EF>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        // Note that the iterator `lens` is updated by each call to `new`. So we can always pass the same `lens` for all structures.
        let input_proof = InputProof::new(circuit, lens, degree_bits);
        let num_commit_phase_openings = lens.next().unwrap();
        let mut commit_phase_openings = Vec::with_capacity(num_commit_phase_openings);
        for _ in 0..num_commit_phase_openings {
            commit_phase_openings.push(CommitPhaseProofStepTargets::<F, EF, RecMmcs>::new(
                circuit,
                lens,
                degree_bits,
            ));
        }
        Self {
            input_proof,
            commit_phase_openings,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        let QueryProof {
            input_proof,
            commit_phase_openings,
        } = input;

        let mut all_values = vec![];
        all_values.extend(InputProof::get_values(input_proof));
        all_values.extend(
            commit_phase_openings
                .iter()
                .flat_map(|o| CommitPhaseProofStepTargets::<F, EF, RecMmcs>::get_values(o)),
        );
        all_values
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let QueryProof {
            input_proof,
            commit_phase_openings,
        } = input;

        let mut all_lens = vec![];
        all_lens.extend(InputProof::lens(input_proof));
        all_lens.push(commit_phase_openings.len());
        for opening in commit_phase_openings {
            all_lens.extend(CommitPhaseProofStepTargets::<F, EF, RecMmcs>::lens(opening));
        }

        all_lens.into_iter()
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

    fn new(
        circuit: &mut CircuitBuilder<EF>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let sibling_value = circuit.add_public_input();
        let opening_proof = RecMmcs::Proof::new(circuit, lens, degree_bits);
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

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let CommitPhaseProofStep {
            sibling_value: _,
            opening_proof,
        } = input;

        RecMmcs::Proof::lens(opening_proof)
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

    fn new(
        circuit: &mut CircuitBuilder<EF>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let opened_vals_len = lens.next().unwrap();
        let mut opened_values = Vec::with_capacity(opened_vals_len);
        for _ in 0..opened_vals_len {
            let num_opened_values = lens.next().unwrap();
            let mut inner_opened_vals = Vec::with_capacity(num_opened_values);
            for _ in 0..num_opened_values {
                inner_opened_vals.push(circuit.add_public_input());
            }
            opened_values.push(inner_opened_vals);
        }

        let opening_proof = Inner::Proof::new(circuit, lens, degree_bits);

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

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let BatchOpening {
            opened_values,
            opening_proof,
        } = input;

        let mut all_lens = vec![opened_values.len()];
        all_lens.extend(opened_values.iter().map(|inner| inner.len()));
        all_lens.extend(Inner::Proof::lens(opening_proof));

        all_lens.into_iter()
    }
}

// Now, we define the commitment schemes.

/// `HashTargets` corresponds to a commitment in the form of hashes with `DIGEST_ELEMS` digest elements.
#[derive(Clone)]
pub struct HashTargets<F, const DIGEST_ELEMS: usize> {
    pub hash_targets: [Target; DIGEST_ELEMS],
    _phantom: PhantomData<F>,
}

type ValMmcsCommitment<F, const DIGEST_ELEMS: usize> =
    Hash<<F as PackedValue>::Value, <F as PackedValue>::Value, DIGEST_ELEMS>;

impl<F: Field, EF: ExtensionField<F>, const DIGEST_ELEMS: usize> Recursive<EF>
    for HashTargets<F, DIGEST_ELEMS>
{
    type Input = ValMmcsCommitment<F, DIGEST_ELEMS>;

    fn new(
        circuit: &mut CircuitBuilder<EF>,
        _lens: &mut impl Iterator<Item = usize>,
        _degree_bits: usize,
    ) -> Self {
        Self {
            hash_targets: array::from_fn(|_| circuit.add_public_input()),
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        input.into_iter().map(|v| EF::from(v)).collect()
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(_input: &Self::Input) -> impl Iterator<Item = usize> {
        iter::empty()
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

    fn new(
        circuit: &mut CircuitBuilder<EF>,
        lens: &mut impl Iterator<Item = usize>,
        _degree_bits: usize,
    ) -> Self {
        let proof_len = lens.next().unwrap();
        let mut proof = Vec::with_capacity(proof_len);
        for _ in 0..proof_len {
            proof.push(array::from_fn(|_| circuit.add_public_input()));
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

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        iter::once(input.len())
    }
}

/// In TwoAdicFriPcs, the POW witness is just a base field element.
pub struct Witness<F> {
    pub witness: Target,
    _phantom: PhantomData<F>,
}

impl<F: Field, EF: ExtensionField<F>> Recursive<EF> for Witness<F> {
    type Input = F;

    fn new(
        circuit: &mut CircuitBuilder<EF>,
        _lens: &mut impl Iterator<Item = usize>,
        _degree_bits: usize,
    ) -> Self {
        Self {
            witness: circuit.add_public_input(),
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<EF> {
        vec![EF::from(*input)]
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(_input: &Self::Input) -> impl Iterator<Item = usize> {
        iter::empty()
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

pub type InputProof<F, InputMmcs> = Vec<BatchOpening<F, InputMmcs>>;

impl<F: Field, EF: ExtensionField<F>, Inner: RecursiveMmcs<F, EF>> Recursive<EF>
    for InputProofTargets<F, EF, Inner>
{
    type Input = Vec<BatchOpening<F, Inner::Input>>;

    fn new(
        circuit: &mut CircuitBuilder<EF>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let num_batch_openings = lens.next().unwrap();
        let mut batch_openings = Vec::with_capacity(num_batch_openings);
        for _ in 0..num_batch_openings {
            batch_openings.push(BatchOpeningTargets::new(circuit, lens, degree_bits));
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

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let mut all_lens = vec![input.len()];
        for batch_opening in input {
            all_lens.extend(BatchOpeningTargets::<F, EF, Inner>::lens(batch_opening));
        }
        all_lens.into_iter()
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
impl<SC, Dft, Comm, InputMmcs, RecursiveInputProof, InputProof, RecursiveFriMmcs, FriMmcs>
    RecursivePcs<
        SC,
        RecursiveInputProof,
        RecursiveFriProof<SC, RecursiveFriMmcs, RecursiveInputProof>,
        Comm,
        TwoAdicMultiplicativeCoset<Val<SC>>,
    > for TwoAdicFriPcs<Val<SC>, Dft, InputMmcs, FriMmcs>
where
    SC: StarkGenericConfig,
    Val<SC>: TwoAdicField,
    InputMmcs: Mmcs<Val<SC>>,
    FriMmcs: Mmcs<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    RecursiveInputProof: Recursive<SC::Challenge, Input = InputProof>,
    RecursiveFriMmcs: RecursiveExtensionMmcs<Val<SC>, SC::Challenge, Input = FriMmcs>,
    SC::Challenger: GrindingChallenger,
    SC::Challenger: p3_challenger::CanObserve<FriMmcs::Commitment>,
{
    type RecursiveProof = RecursiveFriProof<SC, RecursiveFriMmcs, RecursiveInputProof>;

    fn get_challenges_circuit(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        proof_targets: &crate::recursive_traits::ProofTargets<SC, Comm, Self::RecursiveProof>,
    ) -> Vec<Target> {
        proof_targets.opening_proof.get_challenges(circuit)
    }

    fn verify_circuit(
        &self,
        _circuit: &mut CircuitBuilder<SC::Challenge>,
        _challenges: &[Target],
        _commitments_with_opening_points: &ComsWithOpeningsTargets<
            Comm,
            TwoAdicMultiplicativeCoset<Val<SC>>,
        >,
        _opening_proof: &Self::RecursiveProof,
    ) {
        // TODO
    }

    fn selectors_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        point: &Target,
    ) -> RecursiveLagrangeSelectors {
        // Constants that we will need.
        let shift_inv = circuit.add_const(SC::Challenge::from(domain.shift_inverse()));
        let one = circuit.add_const(SC::Challenge::from(Val::<SC>::ONE));
        let subgroup_gen_inv =
            circuit.add_const(SC::Challenge::from(domain.subgroup_generator().inverse()));

        // Unshifted and z_h
        let unshifted_point = circuit.mul(shift_inv, *point);
        let us_exp = circuit.exp_power_of_2(unshifted_point, domain.log_size());
        let z_h = circuit.sub(us_exp, one);

        // Denominators
        let us_minus_one = circuit.sub(unshifted_point, one);
        let us_minus_gen_inv = circuit.sub(unshifted_point, subgroup_gen_inv);

        // Selectors
        let is_first_row = circuit.div(z_h, us_minus_one);
        let is_last_row = circuit.div(z_h, us_minus_gen_inv);
        let is_transition = us_minus_gen_inv;
        let inv_vanishing = circuit.div(one, z_h);

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
        SC::Challenge::from(trace_domain.first_point())
    }
}
