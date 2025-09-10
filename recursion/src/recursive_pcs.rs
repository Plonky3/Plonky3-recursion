//! In this file, we define all the structures required to have a recursive version of `TwoAdicFriPcs`.

use std::{array, iter, marker::PhantomData};

use crate::{
    circuit_builder::{CircuitBuilder, ExtensionWireId, WireId},
    gates::arith_gates::{MulExtensionGate, SubExtensionGate},
    recursive_traits::{
        Recursive, RecursiveExtensionMmcs, RecursiveLagrangeSels, RecursiveMmcs, RecursivePcs,
    },
};
use p3_fri::TwoAdicFriPcs;

use p3_commit::{BatchOpening, ExtensionMmcs, PolynomialSpace};
use p3_field::{
    ExtensionField, Field, PackedValue, TwoAdicField, coset::TwoAdicMultiplicativeCoset,
};
use p3_field::{PrimeCharacteristicRing, extension::BinomiallyExtendable};
use p3_fri::{CommitPhaseProofStep, FriProof, QueryProof};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};
use p3_uni_stark::{Domain, StarkGenericConfig, Val};
use serde::{Deserialize, Serialize};

/// `Recursive` version of `FriProof`.
#[derive(Clone)]
pub struct FriProofWires<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF, D>,
    InputProof: Recursive<F, D>,
    Witness: Recursive<F, D>,
    const D: usize,
> {
    pub commit_phase_commits: Vec<RecMmcs::Commitment>,
    pub query_proofs: Vec<QueryProofWires<F, EF, InputProof, RecMmcs, D>>,
    pub final_poly: Vec<ExtensionWireId<D>>,
    pub pow_witness: Witness,
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF, D>,
    InputProof: Recursive<F, D>,
    Witness: Recursive<F, D>,
    const D: usize,
> Recursive<F, D> for FriProofWires<F, EF, RecMmcs, InputProof, Witness, D>
{
    type Input = FriProof<EF, RecMmcs::Input, Witness::Input, InputProof::Input>;

    fn new(
        circuit: &mut CircuitBuilder<F, D>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let num_commit_phase_commits = lens.next().unwrap();
        let mut commit_phase_commits = Vec::with_capacity(num_commit_phase_commits);
        for _ in 0..num_commit_phase_commits {
            commit_phase_commits.push(RecMmcs::Commitment::new(circuit, lens, degree_bits));
        }

        let num_query_proofs = lens.next().unwrap();
        let mut query_proofs = Vec::with_capacity(num_query_proofs);
        for _ in 0..num_query_proofs {
            query_proofs.push(QueryProofWires::<F, EF, InputProof, RecMmcs, D>::new(
                circuit,
                lens,
                degree_bits,
            ));
        }
        // `lens` has been updated by the other structures. So the first element is indeed the length of the final polynomial.
        let final_poly_len = lens.next().unwrap();
        let mut final_poly = Vec::with_capacity(final_poly_len);
        for _ in 0..final_poly_len {
            final_poly.push(circuit.new_extension_wires());
        }
        Self {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness: Witness::new(circuit, lens, degree_bits),
        }
    }

    fn get_values(input: Self::Input) -> Vec<F> {
        let FriProof {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        } = input;

        commit_phase_commits
            .iter()
            .flat_map(|c| {
                <<RecMmcs as RecursiveExtensionMmcs<F, EF, D>>::Commitment as Recursive<F, D>>::get_values(
                    c.clone(),
                )
            })
            .chain(query_proofs.iter().flat_map(|c| {
                <QueryProofWires<F, EF, InputProof, RecMmcs, D> as Recursive<F, D>>::get_values(
                    c.clone(),
                )
            }))
            .chain(final_poly.into_iter().flat_map(|f| {
                f.as_basis_coefficients_slice().to_vec()
            }))
            .chain(<Witness as Recursive<F, D>>::get_values(pow_witness))
            .collect()
    }

    fn set_wires(
        &self,
        circuit: &mut CircuitBuilder<F, D>,
        input: Self::Input,
    ) -> Result<(), crate::circuit_builder::CircuitError> {
        let FriProof {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        } = input;

        let FriProofWires {
            commit_phase_commits: commit_phase_commits_wires,
            query_proofs: query_proofs_wires,
            final_poly: final_poly_wires,
            pow_witness: pow_witness_wires,
            ..
        } = self;

        for (c, w) in commit_phase_commits
            .iter()
            .zip(commit_phase_commits_wires.iter())
        {
            w.set_wires(circuit, c.clone())?;
        }
        for (q, w) in query_proofs.iter().zip(query_proofs_wires.iter()) {
            w.set_wires(circuit, q.clone())?;
        }
        for (f, w) in final_poly.iter().zip(final_poly_wires.iter()) {
            let f_ext: [F; D] = f.as_basis_coefficients_slice().try_into().unwrap();
            circuit.set_extension_wires(*w, &f_ext)?;
        }
        pow_witness_wires.set_wires(circuit, pow_witness)?;

        Ok(())
    }

    fn num_challenges(&self) -> usize {
        1 // alpha
        + self.commit_phase_commits.len() // Observe each commit and sample a beta challenge
        + self.final_poly.len() // Observe the final polynomial coefficients
        + self.query_proofs.len() // Sample an index for each query proof.
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
                .flat_map(|q| QueryProofWires::<F, EF, InputProof, RecMmcs, D>::lens(q)),
        );
        all_lens.push(final_poly.len());
        all_lens.extend(Witness::lens(pow_witness));

        all_lens.into_iter()
    }
}

/// `Recursive` version of `QueryProof`.
#[derive(Clone)]
pub struct QueryProofWires<
    F: Field,
    EF: ExtensionField<F>,
    InputProof: Recursive<F, D>,
    RecMmcs: RecursiveExtensionMmcs<F, EF, D>,
    const D: usize,
> {
    pub input_proof: InputProof,
    pub commit_phase_openings: Vec<CommitPhaseProofStepWires<F, EF, RecMmcs, D>>,
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    InputProof: Recursive<F, D>,
    RecMmcs: RecursiveExtensionMmcs<F, EF, D>,
    const D: usize,
> Recursive<F, D> for QueryProofWires<F, EF, InputProof, RecMmcs, D>
{
    type Input = QueryProof<EF, RecMmcs::Input, InputProof::Input>;

    fn new(
        circuit: &mut CircuitBuilder<F, D>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let input_proof = InputProof::new(circuit, lens, degree_bits);
        let num_commit_phase_openings = lens.next().unwrap();
        let mut commit_phase_openings = Vec::with_capacity(num_commit_phase_openings);
        for _ in 0..num_commit_phase_openings {
            commit_phase_openings.push(CommitPhaseProofStepWires::<F, EF, RecMmcs, D>::new(
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

    fn get_values(input: Self::Input) -> Vec<F> {
        let QueryProof {
            input_proof,
            commit_phase_openings,
        } = input;

        let mut all_values = vec![];
        all_values.extend(<InputProof as Recursive<F, D>>::get_values(input_proof));
        all_values.extend(commit_phase_openings.iter().flat_map(|o| {
            <CommitPhaseProofStepWires<F, EF, RecMmcs, D> as Recursive<F, D>>::get_values(o.clone())
        }));
        all_values
    }

    fn set_wires(
        &self,
        circuit: &mut CircuitBuilder<F, D>,
        input: Self::Input,
    ) -> Result<(), crate::circuit_builder::CircuitError> {
        let QueryProof {
            input_proof,
            commit_phase_openings,
        } = input;

        let QueryProofWires {
            input_proof: input_proof_wires,
            commit_phase_openings: commit_phase_openings_wires,
        } = self;

        <InputProof as Recursive<F, D>>::set_wires(&input_proof_wires, circuit, input_proof)?;
        for (cpo, w) in commit_phase_openings
            .iter()
            .zip(commit_phase_openings_wires.iter())
        {
            <CommitPhaseProofStepWires<F, EF, RecMmcs, D> as Recursive<F, D>>::set_wires(
                w,
                circuit,
                cpo.clone(),
            )?;
        }

        Ok(())
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
        all_lens.extend(InputProof::lens(&input_proof));
        all_lens.push(commit_phase_openings.len());
        for opening in commit_phase_openings {
            all_lens.extend(CommitPhaseProofStepWires::<F, EF, RecMmcs, D>::lens(
                opening,
            ));
        }

        all_lens.into_iter()
    }
}

/// `Recursive` version of `CommitPhaseProofStepWires`.
#[derive(Clone)]
pub struct CommitPhaseProofStepWires<
    F: Field,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF, D>,
    const D: usize,
> {
    pub sibling_value: ExtensionWireId<D>,
    pub opening_proof: RecMmcs::Proof,
    // This is necessary because the `Input` type can include the extension field element.
    _phantom: PhantomData<EF>,
}

impl<F: Field, EF: ExtensionField<F>, RecMmcs: RecursiveExtensionMmcs<F, EF, D>, const D: usize>
    Recursive<F, D> for CommitPhaseProofStepWires<F, EF, RecMmcs, D>
{
    // This is used with an extension field element, since it is part of `FriProof`, not a base field element.
    type Input = CommitPhaseProofStep<EF, RecMmcs::Input>;

    fn new(
        circuit: &mut CircuitBuilder<F, D>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let sibling_value = circuit.new_extension_wires();
        let opening_proof = <RecMmcs::Proof as Recursive<F, D>>::new(circuit, lens, degree_bits);
        Self {
            sibling_value,
            opening_proof,
            _phantom: PhantomData,
        }
    }

    fn get_values(input: Self::Input) -> Vec<F> {
        let CommitPhaseProofStep {
            sibling_value,
            opening_proof,
        } = input;

        let mut values = sibling_value.as_basis_coefficients_slice().to_vec();
        values.extend(<RecMmcs::Proof as Recursive<F, D>>::get_values(
            opening_proof,
        ));
        values
    }

    fn set_wires(
        &self,
        circuit: &mut CircuitBuilder<F, D>,
        input: Self::Input,
    ) -> Result<(), crate::circuit_builder::CircuitError> {
        let CommitPhaseProofStep {
            sibling_value,
            opening_proof,
        } = input;

        let CommitPhaseProofStepWires {
            sibling_value: sibling_value_wire,
            opening_proof: opening_proof_wires,
            _phantom,
        } = self;

        circuit.set_extension_wires(
            *sibling_value_wire,
            sibling_value
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap(),
        )?;
        <RecMmcs::Proof as Recursive<F, D>>::set_wires(
            opening_proof_wires,
            circuit,
            opening_proof,
        )?;

        Ok(())
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
#[derive(Clone)]
pub struct BatchOpeningWires<F: Field, RecMmcs: RecursiveMmcs<F, D>, const D: usize> {
    /// The opened row values from each matrix in the batch.
    /// Each inner vector corresponds to one matrix.
    pub opened_values: Vec<Vec<WireId>>,
    /// The proof showing the values are valid openings.
    pub opening_proof: RecMmcs::Proof,
    _phantom: PhantomData<F>,
}

impl<F: Field, Inner: RecursiveMmcs<F, D>, const D: usize> Recursive<F, D>
    for BatchOpeningWires<F, Inner, D>
{
    type Input = BatchOpening<F, Inner::Input>;

    fn new(
        circuit: &mut CircuitBuilder<F, D>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let opened_vals_len = lens.next().unwrap();
        let mut opened_values = Vec::with_capacity(opened_vals_len);
        for _ in 0..opened_vals_len {
            let num_opened_values = lens.next().unwrap();
            let mut inner_opened_vals = Vec::with_capacity(num_opened_values);
            for _ in 0..num_opened_values {
                inner_opened_vals.push(circuit.new_wire());
            }
            opened_values.push(inner_opened_vals);
        }

        let opening_proof = Inner::Proof::new(circuit, lens, degree_bits);

        Self {
            opened_values,
            opening_proof,
            _phantom: PhantomData,
        }
    }

    fn get_values(input: Self::Input) -> Vec<F> {
        let BatchOpening {
            opened_values,
            opening_proof,
        } = input;

        opened_values
            .into_iter()
            .flat_map(|inner| inner.into_iter())
            .chain(<Inner::Proof as Recursive<F, D>>::get_values(opening_proof))
            .collect()
    }

    fn set_wires(
        &self,
        circuit: &mut CircuitBuilder<F, D>,
        input: Self::Input,
    ) -> Result<(), crate::circuit_builder::CircuitError> {
        let BatchOpening {
            opened_values,
            opening_proof,
        } = input;

        let BatchOpeningWires {
            opened_values: opened_values_wires,
            opening_proof: opening_proof_wires,
            ..
        } = self;

        for (inner_vals, inner_wires) in opened_values.iter().zip(opened_values_wires.iter()) {
            for (val, wire) in inner_vals.iter().zip(inner_wires.iter()) {
                circuit.set_wire_value(*wire, *val)?;
            }
        }

        <Inner::Proof as Recursive<F, D>>::set_wires(opening_proof_wires, circuit, opening_proof)?;

        Ok(())
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
type ValMmcsCommitment<F, const DIGEST_ELEMS: usize> =
    Hash<<F as PackedValue>::Value, <F as PackedValue>::Value, DIGEST_ELEMS>;
/// `HashWires` corresponds to a commitment in the form of hashes with `DIGEST_ELEMS` digest elements.
pub type HashWires<const DIGEST_ELEMS: usize> = [WireId; DIGEST_ELEMS];

impl<F: Field, const D: usize, const DIGEST_ELEMS: usize> Recursive<F, D>
    for HashWires<DIGEST_ELEMS>
{
    type Input = ValMmcsCommitment<F, DIGEST_ELEMS>;

    fn new(
        circuit: &mut CircuitBuilder<F, D>,
        _lens: &mut impl Iterator<Item = usize>,
        _degree_bits: usize,
    ) -> Self {
        array::from_fn(|_| circuit.new_wire())
    }

    fn get_values(input: Self::Input) -> Vec<F> {
        input.into_iter().collect()
    }

    fn set_wires(
        &self,
        circuit: &mut CircuitBuilder<F, D>,
        input: Self::Input,
    ) -> Result<(), crate::circuit_builder::CircuitError> {
        for (wire, val) in self.iter().zip(input.into_iter()) {
            circuit.set_wire_value(*wire, val)?;
        }
        Ok(())
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(_input: &Self::Input) -> impl Iterator<Item = usize> {
        iter::empty()
    }
}

/// `HashProofWires` corresponds to a Merkle tree `Proof` in the form of a vector of hashes with `DIGEST_ELEMS` digest elements.
pub type HashProofWires<const DIGEST_ELEMS: usize> = Vec<[WireId; DIGEST_ELEMS]>;
type ValMmcsProof<PW, const DIGEST_ELEMS: usize> = Vec<[<PW as PackedValue>::Value; DIGEST_ELEMS]>;

impl<F: Field, const D: usize, const DIGEST_ELEMS: usize> Recursive<F, D>
    for HashProofWires<DIGEST_ELEMS>
{
    type Input = ValMmcsProof<F, DIGEST_ELEMS>;

    fn new(
        circuit: &mut CircuitBuilder<F, D>,
        lens: &mut impl Iterator<Item = usize>,
        _degree_bits: usize,
    ) -> Self {
        let proof_len = lens.next().unwrap();
        let mut proof = Vec::with_capacity(proof_len);
        for _ in 0..proof_len {
            proof.push(array::from_fn(|_| circuit.new_wire()));
        }
        proof
    }

    fn get_values(input: Self::Input) -> Vec<F> {
        input.into_iter().flat_map(|h| h.into_iter()).collect()
    }

    fn set_wires(
        &self,
        circuit: &mut CircuitBuilder<F, D>,
        input: Self::Input,
    ) -> Result<(), crate::circuit_builder::CircuitError> {
        for (h_wires, h_vals) in self.iter().zip(input.into_iter()) {
            for (wire, val) in h_wires.iter().zip(h_vals.into_iter()) {
                circuit.set_wire_value(*wire, val)?;
            }
        }
        Ok(())
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        iter::once(input.len())
    }
}

type Witness = WireId;

impl<F: Field, const D: usize> Recursive<F, D> for Witness {
    type Input = F;

    fn new(
        circuit: &mut CircuitBuilder<F, D>,
        _lens: &mut impl Iterator<Item = usize>,
        _degree_bits: usize,
    ) -> Self {
        circuit.new_wire()
    }

    fn get_values(input: Self::Input) -> Vec<F> {
        vec![input]
    }

    fn set_wires(
        &self,
        circuit: &mut CircuitBuilder<F, D>,
        input: Self::Input,
    ) -> Result<(), crate::circuit_builder::CircuitError> {
        circuit.set_wire_value(*self, input)?;
        Ok(())
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(_input: &Self::Input) -> impl Iterator<Item = usize> {
        iter::empty()
    }
}

#[derive(Clone)]
/// `Recursive` version of a `MerkleTreeMmcs` where the leaf and digest elements are base field values.
pub struct RecValMmcs<F: Field, const DIGEST_ELEMS: usize, H, C>
where
    H: CryptographicHasher<F, [F; DIGEST_ELEMS]>
        + CryptographicHasher<<F as Field>::Packing, [<F as Field>::Packing; DIGEST_ELEMS]>
        + Sync,
{
    pub hash: H,
    pub compress: C,
    _phantom: PhantomData<F>,
}

impl<F: Field, const DIGEST_ELEMS: usize, const D: usize, H, C> RecursiveMmcs<F, D>
    for RecValMmcs<F, DIGEST_ELEMS, H, C>
where
    H: CryptographicHasher<F, [F; DIGEST_ELEMS]>
        + CryptographicHasher<<F as Field>::Packing, [<F as Field>::Packing; DIGEST_ELEMS]>
        + Sync,
    C: PseudoCompressionFunction<[F; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<[<F as Field>::Packing; DIGEST_ELEMS], 2>
        + Sync,
    [F; DIGEST_ELEMS]: Serialize + for<'a> Deserialize<'a>,
{
    type Input = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, H, C, DIGEST_ELEMS>;

    type Commitment = HashWires<DIGEST_ELEMS>;

    type Proof = HashProofWires<DIGEST_ELEMS>;
}

#[derive(Clone)]
/// `Recursive` version of an `ExtensionFieldMmcs` where the inner `Mmcs` is a `MerkleTreeMmcs`.
pub struct RecExtensionValMmcs<
    F: Field,
    EF: ExtensionField<F>,
    const DIGEST_ELEMS: usize,
    const D: usize,
    ValMmcs: RecursiveMmcs<F, D>,
> {
    _phantom: PhantomData<F>,
    _phantom_ef: PhantomData<EF>,
    _phantom_val: PhantomData<ValMmcs>,
}

impl<
    F: Field,
    EF: ExtensionField<F>,
    const DIGEST_ELEMS: usize,
    const D: usize,
    RecValMmcs: RecursiveMmcs<F, D>,
> RecursiveExtensionMmcs<F, EF, D> for RecExtensionValMmcs<F, EF, DIGEST_ELEMS, D, RecValMmcs>
{
    type Input = ExtensionMmcs<F, EF, RecValMmcs::Input>;

    type Commitment = RecValMmcs::Commitment;

    type Proof = RecValMmcs::Proof;
}

pub type InputProofWires<F, Inner, const D: usize> = Vec<BatchOpeningWires<F, Inner, D>>;

pub type TwoAdicFriProofWires<F, EF, RecMmcs, Inner, const D: usize> =
    FriProofWires<F, EF, RecMmcs, InputProofWires<F, Inner, D>, WireId, D>;

pub type InputProof<F, InputMmcs> = Vec<BatchOpening<F, InputMmcs>>;

impl<F: Field, Inner: RecursiveMmcs<F, D>, const D: usize> Recursive<F, D>
    for InputProofWires<F, Inner, D>
{
    type Input = Vec<BatchOpening<F, Inner::Input>>;

    fn new(
        circuit: &mut CircuitBuilder<F, D>,
        lens: &mut impl Iterator<Item = usize>,
        degree_bits: usize,
    ) -> Self {
        let num_batch_openings = lens.next().unwrap();
        let mut batch_openings = Vec::with_capacity(num_batch_openings);
        for _ in 0..num_batch_openings {
            batch_openings.push(BatchOpeningWires::new(circuit, lens, degree_bits));
        }

        batch_openings
    }

    fn get_values(input: Self::Input) -> Vec<F> {
        input
            .into_iter()
            .flat_map(|batch_opening| BatchOpeningWires::<F, Inner, D>::get_values(batch_opening))
            .collect()
    }

    fn set_wires(
        &self,
        circuit: &mut CircuitBuilder<F, D>,
        input: Self::Input,
    ) -> Result<(), crate::circuit_builder::CircuitError> {
        for (batch_opening, wires) in self.iter().zip(input) {
            batch_opening.set_wires(circuit, wires)?;
        }
        Ok(())
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn lens(input: &Self::Input) -> impl Iterator<Item = usize> {
        let mut all_lens = vec![input.len()];
        for batch_opening in input {
            all_lens.extend(BatchOpeningWires::<F, Inner, D>::lens(batch_opening));
        }
        all_lens.into_iter()
    }
}

//Implement RecursivePcs for TwoAdicFriPcs.
impl<
    SC: StarkGenericConfig,
    Dft,
    Comm: Recursive<Val<SC>, D>,
    // OpeningProof: Recursive<Val<SC>, D>,
    InputMmcs,
    RecursiveInputProof: Recursive<Val<SC>, D, Input = InputProof>,
    InputProof,
    RecursiveFriMmcs: RecursiveExtensionMmcs<Val<SC>, SC::Challenge, D, Input = FriMmcs>,
    FriMmcs,
    const D: usize,
>
    RecursivePcs<
        SC,
        RecursiveInputProof,
        FriProofWires<Val<SC>, SC::Challenge, RecursiveFriMmcs, RecursiveInputProof, WireId, D>,
        Comm,
        TwoAdicMultiplicativeCoset<Val<SC>>,
        D,
    > for TwoAdicFriPcs<Val<SC>, Dft, InputMmcs, FriMmcs>
where
    Domain<SC>: PolynomialSpace,
    Val<SC>: TwoAdicField + BinomiallyExtendable<D>,
{
    type RecursiveProof =
        FriProofWires<Val<SC>, SC::Challenge, RecursiveFriMmcs, RecursiveInputProof, WireId, D>;

    fn get_challenges_circuit(
        circuit: &mut CircuitBuilder<p3_uni_stark::Val<SC>, D>,
        proof_wires: &crate::recursive_traits::ProofWires<SC, Comm, Self::RecursiveProof, D>,
    ) -> Vec<ExtensionWireId<D>> {
        proof_wires.opened_values_wires.get_challenges(circuit)
    }

    fn verify_circuit(
        &self,
        _circuit: &mut CircuitBuilder<p3_uni_stark::Val<SC>, D>,
        _challenges: &[ExtensionWireId<D>],
        _commitments_with_opening_points: &[(
            &Comm,
            Vec<(
                TwoAdicMultiplicativeCoset<Val<SC>>,
                Vec<([usize; D], Vec<[usize; D]>)>,
            )>,
        )],
        _opening_proof: &Self::RecursiveProof,
    ) {
        // TODO
    }

    fn selectors_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<p3_uni_stark::Val<SC>, D>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        point: &ExtensionWireId<D>,
    ) -> crate::recursive_traits::RecursiveLagrangeSels<D> {
        // Constants that we will need.
        let shift_inv = circuit.add_extension_constant(SC::Challenge::from(domain.shift_inverse()));
        let one = circuit.add_extension_constant(SC::Challenge::from(Val::<SC>::ONE));
        let subgroup_gen_inv = circuit
            .add_extension_constant(SC::Challenge::from(domain.subgroup_generator().inverse()));
        let exp = circuit.add_extension_constant(SC::Challenge::from_usize(domain.size()));

        // Unshifted and z_h
        let unshifted_point: [usize; D] = circuit.new_extension_wires();
        MulExtensionGate::add_to_circuit(circuit, shift_inv, *point, unshifted_point);
        let us_exp = circuit.new_extension_wires();
        MulExtensionGate::add_to_circuit(circuit, unshifted_point, exp, us_exp);
        let z_h = circuit.new_extension_wires();
        SubExtensionGate::add_to_circuit(circuit, us_exp, one, z_h);

        // Denominators
        let us_minus_one = circuit.new_extension_wires();
        SubExtensionGate::add_to_circuit(circuit, unshifted_point, one, us_minus_one);
        let us_minus_gen_inv = circuit.new_extension_wires();
        SubExtensionGate::add_to_circuit(
            circuit,
            unshifted_point,
            subgroup_gen_inv,
            us_minus_gen_inv,
        );

        // Selectors
        let is_first_row = circuit.new_extension_wires();
        MulExtensionGate::add_to_circuit(circuit, us_minus_one, is_first_row, z_h);
        let is_last_row = circuit.new_extension_wires();
        MulExtensionGate::add_to_circuit(circuit, us_minus_gen_inv, is_last_row, z_h);
        let is_transition = us_minus_gen_inv;
        let inv_vanishing = circuit.new_extension_wires();
        MulExtensionGate::add_to_circuit(circuit, z_h, inv_vanishing, one);

        RecursiveLagrangeSels {
            is_first_row,
            is_last_row,
            is_transition,
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

    fn size(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> usize {
        trace_domain.size()
    }

    fn first_point(
        &self,
        trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
    ) -> p3_uni_stark::Val<SC> {
        trace_domain.first_point()
    }
}
