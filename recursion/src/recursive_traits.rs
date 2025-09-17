use std::marker::PhantomData;

use p3_circuit::{CircuitBuilder, ExprId};
use p3_commit::{Mmcs, Pcs};
use p3_field::{ExtensionField, Field};
use p3_uni_stark::{Commitments, OpenedValues, Proof, StarkGenericConfig};

/// Structure representing all the wires necessary for an input proof.
#[derive(Clone)]
pub struct ProofTargets<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
> {
    pub commitments_wires: CommitmentTargets<SC::Challenge, Comm>,
    pub opened_values_wires: OpenedValuesTargets<SC>,
    pub opening_proof: OpeningProof,
    pub degree_bits: usize,
}

#[derive(Clone)]
pub struct CommitmentTargets<F: Field, Comm: Recursive<F>> {
    pub trace_wires: Comm,
    pub quotient_chunks_wires: Comm,
    pub random_commit: Option<Comm>,
    pub _phantom: PhantomData<F>,
}

// TODO: Move these structures to their respective crates.
#[derive(Clone)]
pub struct OpenedValuesTargets<SC: StarkGenericConfig> {
    pub trace_local_wires: Vec<ExprId>,
    pub trace_next_wires: Vec<ExprId>,
    pub quotient_chunks_wires: Vec<Vec<ExprId>>,
    pub random_wires: Option<Vec<ExprId>>,
    _phantom: PhantomData<SC>,
}

pub trait Recursive<F: Field> {
    /// The nonrecursive type associated with the recursive type implementing the trait.
    type Input: Clone;

    /// Creates a new instance of the recursive type. `lens` corresponds to all the vector lengths necessary to build the structure.
    /// TODO: They can actually be deduced from StarkGenericConfig and `degree_bits`.
    fn new(
        circuit: &mut CircuitBuilder<F>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self;

    /// Returns a vec of field elements representing the private elements of the Input. Used to populate private inputs.
    /// Default implementation returns an empty vec.
    fn get_private_values(_input: &Self::Input) -> Vec<F> {
        vec![]
    }
    /// Returns a vec of field elements representing the elements of the Input. Used to populate public inputs.
    fn get_values(input: &Self::Input) -> Vec<F>;

    /// Returns the number of challenges necessary.
    /// TODO: Should we move this to Pcs instead?
    fn num_challenges(&self) -> usize;

    /// Creates new wires for all the necessary challenges.
    /// TODO: Should we move this to Pcs instead?
    fn get_challenges(&self, circuit: &mut CircuitBuilder<F>) -> Vec<ExprId> {
        let num_challenges = self.num_challenges();

        let mut challenges = Vec::with_capacity(num_challenges);
        for _ in 0..num_challenges {
            challenges.push(circuit.add_public_input());
        }

        challenges
    }

    // Temporary method used for testing for now. This should be changed into something more generic which relies as little as possible on the actual proof.
    fn lens(input: &Self::Input) -> impl Iterator<Item = usize>;
}

/// Trait representing the `Commitment` and `Proof` of an `Input` with type `Mmcs`.
pub trait RecursiveMmcs<F: Field, EF: ExtensionField<F>> {
    type Input: Mmcs<F>;
    type Commitment: Recursive<EF, Input = <Self::Input as Mmcs<F>>::Commitment> + Clone;
    type Proof: Recursive<EF, Input = <Self::Input as Mmcs<F>>::Proof> + Clone;
}

/// Extension version of `RecursiveMmcs`.
pub trait RecursiveExtensionMmcs<F: Field, EF: ExtensionField<F>> {
    type Input: Mmcs<EF>;

    type Commitment: Recursive<EF, Input = <Self::Input as Mmcs<EF>>::Commitment> + Clone;
    type Proof: Recursive<EF, Input = <Self::Input as Mmcs<EF>>::Proof> + Clone;
}

type Commitment<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;

type ComsWithOpenings<Comm, Domain> = [(Comm, Vec<(Domain, Vec<(ExprId, Vec<ExprId>)>)>)];

type ComsToVerify<SC> = [(
    Commitment<SC>,
    Vec<
        Vec<(
            <SC as StarkGenericConfig>::Challenge,
            Vec<<SC as StarkGenericConfig>::Challenge>,
        )>,
    >,
)];

/// Trait which defines the methods necessary
/// for a Pcs to generate values for associated wires.
/// Generalize
pub trait PcsGeneration<SC: StarkGenericConfig, OpeningProof> {
    fn generate_challenges<InputProof: Recursive<SC::Challenge>, const D: usize>(
        config: &SC,
        challenger: &mut SC::Challenger,
        coms_to_verify: &ComsToVerify<SC>,
        opening_proof: &OpeningProof,
    ) -> Vec<SC::Challenge>;
}

/// Trait including the methods necessary for the recursive version of Pcs.
/// Prepend Recursive
pub trait RecursivePcs<
    SC: StarkGenericConfig,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    Domain,
>
{
    type RecursiveProof;

    /// Creates new wires for all the challenges necessary when computing the Pcs.
    fn get_challenges_circuit(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        proof_wires: &ProofTargets<SC, Comm, OpeningProof>,
    ) -> Vec<ExprId>;

    /// Adds the circuit which verifies the Pcs computation.
    fn verify_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenges: &[ExprId],
        commitments_with_opening_points: &ComsWithOpenings<Comm, Domain>,
        opening_proof: &OpeningProof,
    );

    /// Computes wire selectors at `point` in the circuit.
    fn selectors_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &Domain,
        point: &ExprId,
    ) -> RecursiveLagrangeSelectors;

    /// Computes a disjoint domain given the degree and the current domain. This is the same as the original method in Pcs, but is also used in the verifier circuit.
    fn create_disjoint_domain(&self, trace_domain: Domain, degree: usize) -> Domain;

    /// Split a domain given the degree and the current domain. This is the same as the original method in Pcs, but is also used in the verifier circuit.
    fn split_domains(&self, trace_domain: &Domain, degree: usize) -> Vec<Domain>;

    /// Returns the size of the domain. This is the same as the original method in Pcs, but is also used in the verifier circuit.
    fn size(&self, trace_domain: &Domain) -> usize;

    /// Returns the first point in the domain. This is the same as the original method in Pcs, but is also used in the verifier circuit.
    fn first_point(&self, trace_domain: &Domain) -> SC::Challenge;
}

/// Circuit version of the `LagrangeSelectors`.
pub struct RecursiveLagrangeSelectors {
    pub is_first_row: ExprId,
    pub is_last_row: ExprId,
    pub is_transition: ExprId,
    pub inv_vanishing: ExprId,
}

/// Trait including methods necessary to compute the verification of an AIR's constraints,
/// as well as AIR-specific methods used in the full verification circuit.
#[allow(clippy::too_many_arguments)]
pub trait RecursiveAir<F: Field> {
    /// Number of AIR columns.
    fn width(&self) -> usize;

    /// Circuit version of the AIR constraints.
    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &ExprId,
        local_prep_values: &[ExprId],
        next_prep_values: &[ExprId],
        local_values: &[ExprId],
        next_values: &[ExprId],
        public_values: &[ExprId],
    ) -> ExprId;

    /// Infers log of constraint degree.
    fn get_log_quotient_degree(&self, num_public_values: usize, is_zk: usize) -> usize;
}

// Implemeting `Recursive` for the `ProofTargets`, `CommitmentTargets` and `OpenedValuesTargets` base structures.
impl<
    SC: StarkGenericConfig + Clone,
    Comm: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    OpeningProof: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
> Recursive<SC::Challenge> for ProofTargets<SC, Comm, OpeningProof>
{
    type Input = Proof<SC>;

    fn new(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let commitments_wires = CommitmentTargets::new(circuit, lens, degree_bits);
        let opened_values_wires = OpenedValuesTargets::new(circuit, lens, degree_bits);
        let opening_proof = OpeningProof::new(circuit, lens, degree_bits);

        Self {
            commitments_wires,
            opened_values_wires,
            opening_proof,
            degree_bits,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let Proof {
            commitments,
            opened_values,
            opening_proof,
            degree_bits: _,
        } = input;
        let mut values = vec![];
        values.extend::<Vec<SC::Challenge>>(CommitmentTargets::<SC::Challenge, Comm>::get_values(
            commitments,
        ));
        values.extend(OpenedValuesTargets::<SC>::get_values(opened_values));
        values.extend(OpeningProof::get_values(opening_proof));
        values
    }

    fn num_challenges(&self) -> usize {
        self.commitments_wires.num_challenges()
            + self.opened_values_wires.num_challenges()
            + self.opening_proof.num_challenges()
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let Proof {
            commitments,
            opened_values,
            opening_proof,
            degree_bits: _,
        } = input;
        let mut all_lens = vec![];
        all_lens.extend(CommitmentTargets::<SC::Challenge, Comm>::lens(commitments));
        all_lens.extend(OpenedValuesTargets::<SC>::lens(opened_values));
        all_lens.extend(OpeningProof::lens(opening_proof));
        all_lens.into_iter()
    }
}

impl<F: Field, Comm> Recursive<F> for CommitmentTargets<F, Comm>
where
    Comm: Recursive<F>,
{
    type Input = Commitments<Comm::Input>;

    fn new(
        circuit: &mut CircuitBuilder<F>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let trace_wires = Comm::new(circuit, lens, degree_bits);
        let quotient_chunks_wires = Comm::new(circuit, lens, degree_bits);
        let random_commit_len = lens.next().unwrap();
        let random_commit = if random_commit_len > 0 {
            Some(Comm::new(circuit, lens, degree_bits))
        } else {
            None
        };
        Self {
            trace_wires,
            quotient_chunks_wires,
            random_commit,
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<F> {
        let Commitments {
            trace,
            quotient_chunks,
            random,
        } = input;

        let mut values = vec![];
        values.extend(Comm::get_values(trace));
        values.extend(Comm::get_values(quotient_chunks));
        if let Some(random) = random {
            values.extend(Comm::get_values(random));
        }
        values
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let Commitments {
            trace,
            quotient_chunks,
            random,
        } = input;

        let mut all_lens = vec![];
        all_lens.extend(Comm::lens(trace));
        all_lens.extend(Comm::lens(quotient_chunks));
        if let Some(random) = random {
            all_lens.extend(Comm::lens(random));
        } else {
            all_lens.push(0);
        }
        all_lens.into_iter()
    }
}

impl<SC: StarkGenericConfig> Recursive<SC::Challenge> for OpenedValuesTargets<SC> {
    type Input = OpenedValues<SC::Challenge>;

    fn new(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        lens: &mut impl Iterator<Item = usize>,
        _degree_bits: usize,
    ) -> Self {
        let trace_local_len = lens.next().unwrap();
        let mut trace_local_wires = Vec::with_capacity(trace_local_len);
        for _ in 0..trace_local_len {
            trace_local_wires.push(circuit.add_public_input());
        }
        let trace_next_len = lens.next().unwrap();
        let mut trace_next_wires = Vec::with_capacity(trace_next_len);
        for _ in 0..trace_next_len {
            trace_next_wires.push(circuit.add_public_input());
        }
        let quotient_chunks_len = lens.next().unwrap();
        let mut quotient_chunks_wires = Vec::with_capacity(quotient_chunks_len);
        for _ in 0..quotient_chunks_len {
            let quotient_chunks_cols_len = lens.next().unwrap();
            let mut quotient_col = Vec::with_capacity(quotient_chunks_cols_len);
            for _ in 0..quotient_chunks_cols_len {
                quotient_col.push(circuit.add_public_input());
            }
            quotient_chunks_wires.push(quotient_col);
        }
        let random_len = lens.next().unwrap();
        let random_wires = if random_len > 0 {
            let mut r = Vec::with_capacity(random_len);
            for _ in 0..random_len {
                r.push(circuit.add_public_input());
            }
            Some(r)
        } else {
            None
        };

        Self {
            trace_local_wires,
            trace_next_wires,
            quotient_chunks_wires,
            random_wires,
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let OpenedValues {
            trace_local,
            trace_next,
            quotient_chunks,
            random,
        } = input;

        let mut values = vec![];
        values.extend(trace_local);
        values.extend(trace_next);
        for chunk in quotient_chunks {
            values.extend(chunk);
        }
        if let Some(random) = random {
            values.extend(random);
        }

        values
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let OpenedValues {
            trace_local,
            trace_next,
            quotient_chunks,
            random,
        } = input;

        let mut all_lens = vec![];
        all_lens.push(trace_local.len());
        all_lens.push(trace_next.len());

        all_lens.push(quotient_chunks.len());
        for chunk in quotient_chunks {
            all_lens.push(chunk.len());
        }

        if let Some(random) = random {
            all_lens.push(random.len());
        } else {
            all_lens.push(0);
        }

        all_lens.into_iter()
    }
}
