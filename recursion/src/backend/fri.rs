//! FRI PCS backend for the unified recursion API.

use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::BatchStarkProver;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_commit::Pcs;
use p3_field::extension::BinomiallyExtendable;
use p3_field::{BasedVectorSpace, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};

use crate::ops::Poseidon2Config;
use crate::public_inputs::{BatchStarkVerifierInputsBuilder, StarkVerifierInputsBuilder};
use crate::recursion::{
    PcsRecursionBackend, RecursionInput, RegisterPoseidon2ForDegree, VerifierCircuitResult,
};
use crate::traits::RecursiveAir;
use crate::verifier::{
    ObservableCommitment, VerificationError, verify_p3_batch_proof_circuit,
    verify_p3_uni_proof_circuit,
};
use crate::{Recursive, RecursivePcs};

/// Config that uses FRI with Merkle-tree MMCS and fixed constants (WIDTH, RATE, DIGEST_ELEMS).
/// Implement this for your StarkConfig to use [`FriRecursionBackend`].
pub trait FriRecursionConfig: StarkGenericConfig + Sized
where
    Self::Pcs: RecursivePcs<
            Self,
            Self::InputProof,
            Self::OpeningProof,
            Self::Commitment,
            <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Domain,
        >,
{
    /// Commitment type used in the verifier circuit (e.g. HashTargets).
    type Commitment: Recursive<
            Self::Challenge,
            Input = <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment;

    /// Input proof type for the PCS (e.g. batch opening targets for FRI).
    type InputProof: Recursive<Self::Challenge>;

    /// Opening proof type used in the verifier circuit (e.g. FRI proof targets).
    type OpeningProof: Recursive<
            Self::Challenge,
            Input = <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Proof,
        >;

    /// Raw FRI opening proof type (value type, not circuit targets). Used to set private data.
    type RawOpeningProof;

    const DIGEST_ELEMS: usize;

    /// Invoke a closure with the FRI opening proof extracted from the recursion input.
    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>;

    /// Enable Poseidon2 permutation on the circuit (for MMCS verification). Called by the backend before building the verifier.
    fn enable_poseidon2_on_circuit(
        &self,
        circuit: &mut CircuitBuilder<Self::Challenge>,
    ) -> Result<(), VerificationError>;

    /// Return the PCS verifier params (e.g. FRI params). The config must hold these and return a reference.
    #[allow(clippy::type_complexity)]
    fn pcs_verifier_params(
        &self,
    ) -> &<Self::Pcs as RecursivePcs<
        Self,
        Self::InputProof,
        Self::OpeningProof,
        Self::Commitment,
        <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Domain,
    >>::VerifierParams;

    /// Set FRI Merkle path private data on the runner. Implement by calling
    /// [`crate::pcs::set_fri_mmcs_private_data`] with your concrete MMCS/hasher types.
    fn set_fri_private_data(
        runner: &mut CircuitRunner<Self::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str>;
}

/// FRI-based recursion backend. Holds Poseidon2 config; verifier params come from the config via [`FriRecursionConfig::pcs_verifier_params`].
/// `WIDTH` and `RATE` are the Poseidon2 circuit parameters (typically 16 and 8).
#[derive(Clone)]
pub struct FriRecursionBackend<const WIDTH: usize = 16, const RATE: usize = 8> {
    pub poseidon2_config: Poseidon2Config,
}

impl<const WIDTH: usize, const RATE: usize> FriRecursionBackend<WIDTH, RATE> {
    pub const fn new(poseidon2_config: Poseidon2Config) -> Self {
        Self { poseidon2_config }
    }
}

/// Verifier result from the FRI backend: either uni-stark or batch-stark builder + op_ids.
pub enum FriVerifierResult<SC>
where
    SC: FriRecursionConfig,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    UniStark(
        StarkVerifierInputsBuilder<SC, SC::Commitment, SC::OpeningProof>,
        Vec<NonPrimitiveOpId>,
    ),
    BatchStark(
        BatchStarkVerifierInputsBuilder<SC, SC::Commitment, SC::OpeningProof>,
        Vec<NonPrimitiveOpId>,
    ),
}

impl<SC, A> VerifierCircuitResult<SC, A> for FriVerifierResult<SC>
where
    SC: FriRecursionConfig,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>,
{
    fn pack_public_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        match (self, prev) {
            (
                Self::UniStark(builder, _),
                RecursionInput::UniStark {
                    proof,
                    public_inputs,
                    preprocessed_commit,
                    ..
                },
            ) => Ok(builder.pack_values(public_inputs, proof, preprocessed_commit)),
            (
                Self::BatchStark(builder, _),
                RecursionInput::BatchStark {
                    proof,
                    common_data,
                    table_public_inputs,
                },
            ) => Ok(builder.pack_values(table_public_inputs, &proof.proof, common_data)),
            _ => Err(VerificationError::InvalidProofShape(
                alloc::string::ToString::to_string(
                    "RecursionInput variant does not match verifier result",
                ),
            )),
        }
    }

    fn op_ids(&self) -> &[NonPrimitiveOpId] {
        match self {
            Self::UniStark(_, ids) | Self::BatchStark(_, ids) => ids,
        }
    }
}

impl<SC, A, const WIDTH: usize, const RATE: usize> PcsRecursionBackend<SC, A>
    for FriRecursionBackend<WIDTH, RATE>
where
    SC: FriRecursionConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + p3_field::ExtensionField<Val<SC>>
        + p3_field::PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Clone,
    p3_uni_stark::SymbolicExpression<SC::Challenge>:
        From<p3_uni_stark::SymbolicExpression<Val<SC>>>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    type VerifierResult = FriVerifierResult<SC>;

    fn prepare_circuit(
        &self,
        config: &SC,
        circuit: &mut CircuitBuilder<SC::Challenge>,
    ) -> Result<(), VerificationError> {
        config.enable_poseidon2_on_circuit(circuit)
    }

    fn build_verifier_circuit(
        &self,
        prev: &RecursionInput<'_, SC, A>,
        config: &SC,
        circuit: &mut CircuitBuilder<SC::Challenge>,
    ) -> Result<Self::VerifierResult, VerificationError> {
        match prev {
            RecursionInput::UniStark {
                proof,
                air,
                public_inputs,
                preprocessed_commit,
            } => {
                let verifier_inputs =
                    StarkVerifierInputsBuilder::<SC, SC::Commitment, SC::OpeningProof>::allocate(
                        circuit,
                        proof,
                        preprocessed_commit.as_ref(),
                        public_inputs.len(),
                    );
                let op_ids = verify_p3_uni_proof_circuit::<
                    A,
                    SC,
                    SC::Commitment,
                    SC::InputProof,
                    SC::OpeningProof,
                    WIDTH,
                    RATE,
                >(
                    config,
                    air,
                    circuit,
                    &verifier_inputs.proof_targets,
                    &verifier_inputs.air_public_targets,
                    &verifier_inputs.preprocessed_commit,
                    config.pcs_verifier_params(),
                    self.poseidon2_config,
                )?;
                Ok(FriVerifierResult::UniStark(verifier_inputs, op_ids))
            }
            RecursionInput::BatchStark {
                proof,
                common_data,
                table_public_inputs,
            } => {
                let lookup_gadget = p3_lookup::logup::LogUpGadget::new();
                let (verifier_inputs, op_ids) = match proof.ext_degree {
                    1 => verify_p3_batch_proof_circuit::<
                        SC,
                        SC::Commitment,
                        SC::InputProof,
                        SC::OpeningProof,
                        _,
                        WIDTH,
                        RATE,
                        1,
                    >(
                        config,
                        circuit,
                        proof,
                        config.pcs_verifier_params(),
                        common_data,
                        &lookup_gadget,
                        self.poseidon2_config,
                    )?,
                    2 => verify_p3_batch_proof_circuit::<
                        SC,
                        SC::Commitment,
                        SC::InputProof,
                        SC::OpeningProof,
                        _,
                        WIDTH,
                        RATE,
                        2,
                    >(
                        config,
                        circuit,
                        proof,
                        config.pcs_verifier_params(),
                        common_data,
                        &lookup_gadget,
                        self.poseidon2_config,
                    )?,
                    4 => verify_p3_batch_proof_circuit::<
                        SC,
                        SC::Commitment,
                        SC::InputProof,
                        SC::OpeningProof,
                        _,
                        WIDTH,
                        RATE,
                        4,
                    >(
                        config,
                        circuit,
                        proof,
                        config.pcs_verifier_params(),
                        common_data,
                        &lookup_gadget,
                        self.poseidon2_config,
                    )?,
                    d => {
                        return Err(VerificationError::InvalidProofShape(alloc::format!(
                            "unsupported batch proof ext_degree {}",
                            d
                        )));
                    }
                };
                let _ = table_public_inputs;
                Ok(FriVerifierResult::BatchStark(verifier_inputs, op_ids))
            }
        }
    }

    fn set_private_data(
        &self,
        config: &SC,
        runner: &mut CircuitRunner<SC::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str> {
        let _ = config;
        SC::with_fri_opening_proof(prev, |opening_proof| {
            SC::set_fri_private_data(runner, op_ids, opening_proof)
        })
    }

    fn poseidon2_config_for_circuit(&self) -> Option<Poseidon2Config> {
        Some(self.poseidon2_config)
    }
}

impl<SC, const WIDTH: usize, const RATE: usize> RegisterPoseidon2ForDegree<SC, 2>
    for FriRecursionBackend<WIDTH, RATE>
where
    SC: FriRecursionConfig + Send + Sync,
    Val<SC>: BinomiallyExtendable<2> + p3_circuit_prover::config::StarkField,
    p3_uni_stark::SymbolicExpression<SC::Challenge>:
        From<p3_uni_stark::SymbolicExpression<Val<SC>>>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    fn register_poseidon2(&self, prover: &mut BatchStarkProver<SC>, config: Poseidon2Config) {
        prover.register_poseidon2_table_d2(config);
    }
}

impl<SC, const WIDTH: usize, const RATE: usize> RegisterPoseidon2ForDegree<SC, 4>
    for FriRecursionBackend<WIDTH, RATE>
where
    SC: FriRecursionConfig + Send + Sync,
    Val<SC>: BinomiallyExtendable<4> + p3_circuit_prover::config::StarkField,
    p3_uni_stark::SymbolicExpression<SC::Challenge>:
        From<p3_uni_stark::SymbolicExpression<Val<SC>>>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    fn register_poseidon2(&self, prover: &mut BatchStarkProver<SC>, config: Poseidon2Config) {
        prover.register_poseidon2_table(config);
    }
}
