//! Target structures for STARK proofs in recursive circuits.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_circuit::CircuitBuilder;
use p3_commit::Pcs;
use p3_field::Field;
use p3_uni_stark::{Commitments, OpenedValues, Proof, StarkGenericConfig};

use crate::Target;
use crate::traits::{Recursive, RecursiveChallenger};

/// Structure representing all the targets necessary for an input proof.
///
/// This contains the circuit representation of a STARK proof, with all
/// commitments, opened values, and the opening proof as targets.
#[derive(Clone)]
pub struct ProofTargets<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
> {
    /// Commitments to trace, quotient chunks, and optional random polynomial
    pub commitments_targets: CommitmentTargets<SC::Challenge, Comm>,
    /// Opened values at evaluation points (zeta, zeta_next)
    pub opened_values_targets: OpenedValuesTargets<SC>,
    /// PCS opening proof
    pub opening_proof: OpeningProof,
    /// Log₂ of the trace domain size
    pub degree_bits: usize,
}

/// Target structure for STARK commitments.
#[derive(Clone)]
pub struct CommitmentTargets<F: Field, Comm: Recursive<F>> {
    /// Commitment to the trace polynomial
    pub trace_targets: Comm,
    /// Commitment to the quotient polynomial chunks
    pub quotient_chunks_targets: Comm,
    /// Optional commitment to random polynomial (ZK mode)
    pub random_commit: Option<Comm>,
    pub _phantom: PhantomData<F>,
}

/// Target structure for opened polynomial values.
#[derive(Clone)]
pub struct OpenedValuesTargets<SC: StarkGenericConfig> {
    /// Trace values at point zeta
    pub trace_local_targets: Vec<Target>,
    /// Trace values at point zeta * g (next row)
    pub trace_next_targets: Vec<Target>,
    /// Quotient chunk values at zeta
    pub quotient_chunks_targets: Vec<Vec<Target>>,
    /// Optional random polynomial values (ZK mode)
    pub random_targets: Option<Vec<Target>>,
    pub _phantom: PhantomData<SC>,
}

impl<SC: StarkGenericConfig> OpenedValuesTargets<SC> {
    /// Observe all opened values in the Fiat-Shamir transcript.
    ///
    /// This method absorbs all opened values into the challenger state,
    /// which is necessary before sampling PCS challenges.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder
    /// - `challenger`: Running challenger state
    pub fn observe<F: Field>(
        &self,
        circuit: &mut CircuitBuilder<F>,
        challenger: &mut impl RecursiveChallenger<F>,
    ) {
        // Observe trace values at zeta and zeta_next
        challenger.observe_slice(circuit, &self.trace_local_targets);
        challenger.observe_slice(circuit, &self.trace_next_targets);

        // Observe quotient chunk values
        for chunk_values in &self.quotient_chunks_targets {
            challenger.observe_slice(circuit, chunk_values);
        }

        // Observe random values if in ZK mode
        if let Some(random_vals) = &self.random_targets {
            challenger.observe_slice(circuit, random_vals);
        }
    }
}

impl<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    OpeningProof: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
> Recursive<SC::Challenge> for ProofTargets<SC, Comm, OpeningProof>
{
    type Input = Proof<SC>;

    /// Allocates the necessary circuit targets for storing the proof's public data.
    fn new(circuit: &mut CircuitBuilder<SC::Challenge>, input: &Self::Input) -> Self {
        let commitments_targets = CommitmentTargets::new(circuit, &input.commitments);
        let opened_values_targets = OpenedValuesTargets::new(circuit, &input.opened_values);
        let opening_proof = OpeningProof::new(circuit, &input.opening_proof);

        Self {
            commitments_targets,
            opened_values_targets,
            opening_proof,
            degree_bits: input.degree_bits,
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
}

impl<F: Field, Comm> Recursive<F> for CommitmentTargets<F, Comm>
where
    Comm: Recursive<F>,
{
    type Input = Commitments<Comm::Input>;

    fn new(circuit: &mut CircuitBuilder<F>, input: &Self::Input) -> Self {
        let trace_targets = Comm::new(circuit, &input.trace);
        let quotient_chunks_targets = Comm::new(circuit, &input.quotient_chunks);
        let random_commit = input
            .random
            .as_ref()
            .map(|random| Comm::new(circuit, random));

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
}

impl<SC: StarkGenericConfig> Recursive<SC::Challenge> for OpenedValuesTargets<SC> {
    type Input = OpenedValues<SC::Challenge>;

    fn new(circuit: &mut CircuitBuilder<SC::Challenge>, input: &Self::Input) -> Self {
        let trace_local_len = input.trace_local.len();
        let trace_local_targets =
            circuit.alloc_public_inputs(trace_local_len, "trace local values");

        let trace_next_len = input.trace_next.len();
        let trace_next_targets = circuit.alloc_public_inputs(trace_next_len, "trace next values");

        let quotient_chunks_len = input.quotient_chunks.len();
        let mut quotient_chunks_targets = Vec::with_capacity(quotient_chunks_len);
        for quotient_chunk in input.quotient_chunks.iter() {
            let quotient_chunks_cols_len = quotient_chunk.len();
            let quotient_col =
                circuit.alloc_public_inputs(quotient_chunks_cols_len, "quotient chunk columns");
            quotient_chunks_targets.push(quotient_col);
        }

        let random_targets = input
            .random
            .as_ref()
            .map(|random| circuit.alloc_public_inputs(random.len(), "random values (ZK mode)"));

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
}
