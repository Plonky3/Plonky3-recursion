use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::Air;
use p3_circuit::utils::{ColumnsTargets, RowSelectorsTargets, symbolic_to_circuit};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, NonPrimitiveOpId};
use p3_commit::{Mmcs, Pcs};
use p3_field::{ExtensionField, Field};
use p3_matrix::Dimensions;
use p3_uni_stark::{
    Commitments, OpenedValues, Proof, StarkGenericConfig, SymbolicAirBuilder,
    get_log_quotient_degree, get_symbolic_constraints,
};

use crate::Target;

/// Structure representing all the targets necessary for an input proof.
pub struct ProofTargets<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
> {
    pub commitments_targets: CommitmentTargets<SC::Challenge, Comm>,
    pub opened_values_targets: OpenedValuesTargets<SC>,
    pub opening_proof: OpeningProof,
    pub degree_bits: usize,
}

pub struct CommitmentTargets<F: Field, Comm: Recursive<F>> {
    pub trace_targets: Comm,
    pub quotient_chunks_targets: Comm,
    pub random_commit: Option<Comm>,
    pub _phantom: PhantomData<F>,
}

// TODO: Move these structures to their respective crates.
pub struct OpenedValuesTargets<SC: StarkGenericConfig> {
    pub trace_local_targets: Vec<Target>,
    pub trace_next_targets: Vec<Target>,
    pub quotient_chunks_targets: Vec<Vec<Target>>,
    pub random_targets: Option<Vec<Target>>,
    _phantom: PhantomData<SC>,
}

pub trait Recursive<F: Field> {
    /// The nonrecursive type associated with the recursive type implementing the trait.
    type Input;

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

    /// Creates new targets for all the necessary challenges.
    /// TODO: Should we move this to Pcs instead?
    fn get_challenges(&self, circuit: &mut CircuitBuilder<F>) -> Vec<Target> {
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
    type Commitment: Recursive<EF, Input = <Self::Input as Mmcs<F>>::Commitment>;
    type Proof: Recursive<EF, Input = <Self::Input as Mmcs<F>>::Proof>;

    /// Recursive verison of `verify_circuit_batch`. Adds a ircuit that verifies an opened batch of rows with respect to a given commitment.
    ///
    /// - `circuit`: The circuit builder to which we add the verify_batch circuit
    /// - `commit`: The merkle root of the tree.
    /// - `dimensions`: A vector of the dimensions of the matrices committed to.
    /// - `directions`: The binary decomposition of the index of a leaf in the tree.
    /// - `opened_values`: A vector of matrix rows. Assume that the tallest matrix committed
    ///   to has height `2^n >= M_tall.height() > 2^{n - 1}` and the `j`th matrix has height
    ///   `2^m >= Mj.height() > 2^{m - 1}`. Then `j`'th value of opened values must be the row `Mj[index >> (m - n)]`.
    /// - `proof`: A vector of sibling nodes. The `i`th element should be the node at level `i`
    ///   with index `(index << i) ^ 1`.
    ///
    /// Returns the new merkle_verify gate, otherwise returns an error.
    fn verify_batch_circuit(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        directions: &[Target],
        opened_values: &[Vec<Target>],
        proof: &Self::Proof,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;
}

/// Extension version of `RecursiveMmcs`.
pub trait RecursiveExtensionMmcs<F: Field, EF: ExtensionField<F>> {
    type Input: Mmcs<EF>;

    type Commitment: Recursive<EF, Input = <Self::Input as Mmcs<EF>>::Commitment>;
    type Proof: Recursive<EF, Input = <Self::Input as Mmcs<EF>>::Proof>;
}

/// A collection of Mmcs commitments such that for each one we have:
/// - The commitment itself.
/// - For each matrix:
///     - The domain of the matrix.
///     - A vector of pairs (point, values), where `values` are the rows of the matrix at `point`.
pub(crate) type ComsWithOpeningsTargets<Comm, Domain> =
    [(Comm, Vec<(Domain, Vec<(Target, Vec<Target>)>)>)];

/// Trait including the methods necessary for the recursive version of Pcs.
pub trait RecursivePcs<
    SC: StarkGenericConfig,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    Domain,
>
{
    type VerifierParams;

    type RecursiveProof;

    /// Creates new targets for all the challenges necessary when computing the Pcs.
    fn get_challenges_circuit(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
        params: &Self::VerifierParams,
    ) -> Vec<Target>;

    /// Adds the circuit which verifies the Pcs computation.
    fn verify_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenges: &[Target],
        commitments_with_opening_points: &ComsWithOpeningsTargets<Comm, Domain>,
        opening_proof: &OpeningProof,
        params: &Self::VerifierParams,
    );

    /// Computes target selectors at `point` in the circuit.
    fn selectors_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &Domain,
        point: &Target,
    ) -> RecursiveLagrangeSelectors;

    /// Computes a disjoint domain given the degree and the current domain. This is the same as the original method in Pcs, but is also used in the verifier circuit.
    fn create_disjoint_domain(&self, trace_domain: Domain, degree: usize) -> Domain;

    /// Split a domain given the degree and the current domain. This is the same as the original method in Pcs, but is also used in the verifier circuit.
    fn split_domains(&self, trace_domain: &Domain, degree: usize) -> Vec<Domain>;

    /// Returns the log of the domain's size. This is the same as the original method in Pcs, but is also used in the verifier circuit.
    fn log_size(&self, trace_domain: &Domain) -> usize;

    /// Returns the size of the domain. This is the same as the original method in Pcs, but is also used in the verifier circuit.
    fn size(&self, trace_domain: &Domain) -> usize {
        1 << self.log_size(trace_domain)
    }

    /// Returns the first point in the domain. This is the same as the original method in Pcs, but is also used in the verifier circuit.
    fn first_point(&self, trace_domain: &Domain) -> SC::Challenge;
}

/// Circuit version of the `LagrangeSelectors`.
pub struct RecursiveLagrangeSelectors {
    pub row_selectors: RowSelectorsTargets,
    pub inv_vanishing: Target,
}

/// Trait including methods necessary to compute the verification of an AIR's constraints,
/// as well as AIR-specific methods used in the full verification circuit.
pub trait RecursiveAir<F: Field> {
    /// Number of AIR columns.
    fn width(&self) -> usize;

    /// Circuit version of the AIR constraints.
    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &Target,
        columns: ColumnsTargets,
    ) -> Target;

    /// Infers log of constraint degree.
    fn get_log_quotient_degree(&self, num_public_values: usize, is_zk: usize) -> usize;
}

impl<F: Field, A> RecursiveAir<F> for A
where
    A: Air<SymbolicAirBuilder<F>>,
{
    fn width(&self) -> usize {
        Self::width(self)
    }

    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &Target,
        columns: ColumnsTargets,
    ) -> Target {
        let symbolic_constraints = get_symbolic_constraints(self, 0, columns.public_values.len());

        let mut acc = builder.add_const(F::ZERO);
        for s_c in symbolic_constraints {
            let mul_prev = builder.mul(acc, *alpha);
            let constraints = symbolic_to_circuit(sels.row_selectors, &columns, &s_c, builder);
            acc = builder.add(mul_prev, constraints);
        }

        acc
    }

    fn get_log_quotient_degree(&self, num_public_values: usize, is_zk: usize) -> usize {
        get_log_quotient_degree(self, 0, num_public_values, is_zk)
    }
}

// Implemeting `Recursive` for the `ProofTargets`, `CommitmentTargets` and `OpenedValuesTargets` base structures.
impl<
    SC: StarkGenericConfig,
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
        let commitments_targets = CommitmentTargets::new(circuit, lens, degree_bits);
        let opened_values_targets = OpenedValuesTargets::new(circuit, lens, degree_bits);
        let opening_proof = OpeningProof::new(circuit, lens, degree_bits);

        Self {
            commitments_targets,
            opened_values_targets,
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

        CommitmentTargets::<SC::Challenge, Comm>::get_values(commitments)
            .into_iter()
            .chain(OpenedValuesTargets::<SC>::get_values(opened_values))
            .chain(OpeningProof::get_values(opening_proof))
            .collect()
    }

    fn num_challenges(&self) -> usize {
        self.commitments_targets.num_challenges()
            + self.opened_values_targets.num_challenges()
            + self.opening_proof.num_challenges()
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let Proof {
            commitments,
            opened_values,
            opening_proof,
            degree_bits: _,
        } = input;

        CommitmentTargets::<SC::Challenge, Comm>::lens(commitments)
            .chain(OpenedValuesTargets::<SC>::lens(opened_values))
            .chain(OpeningProof::lens(opening_proof))
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
        let trace_targets = Comm::new(circuit, lens, degree_bits);
        let quotient_chunks_targets = Comm::new(circuit, lens, degree_bits);
        let random_commit_len = lens.next().unwrap();
        let random_commit = if random_commit_len > 0 {
            Some(Comm::new(circuit, lens, degree_bits))
        } else {
            None
        };
        Self {
            trace_targets,
            quotient_chunks_targets,
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
        let mut trace_local_targets = Vec::with_capacity(trace_local_len);
        for _ in 0..trace_local_len {
            trace_local_targets.push(circuit.add_public_input());
        }
        let trace_next_len = lens.next().unwrap();
        let mut trace_next_targets = Vec::with_capacity(trace_next_len);
        for _ in 0..trace_next_len {
            trace_next_targets.push(circuit.add_public_input());
        }
        let quotient_chunks_len = lens.next().unwrap();
        let mut quotient_chunks_targets = Vec::with_capacity(quotient_chunks_len);
        for _ in 0..quotient_chunks_len {
            let quotient_chunks_cols_len = lens.next().unwrap();
            let mut quotient_col = Vec::with_capacity(quotient_chunks_cols_len);
            for _ in 0..quotient_chunks_cols_len {
                quotient_col.push(circuit.add_public_input());
            }
            quotient_chunks_targets.push(quotient_col);
        }
        let random_len = lens.next().unwrap();
        let random_targets = if random_len > 0 {
            let mut r = Vec::with_capacity(random_len);
            for _ in 0..random_len {
                r.push(circuit.add_public_input());
            }
            Some(r)
        } else {
            None
        };

        Self {
            trace_local_targets,
            trace_next_targets,
            quotient_chunks_targets,
            random_targets,
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
