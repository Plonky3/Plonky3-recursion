use alloc::string::ToString;
use alloc::{vec, vec::Vec};

use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier};
use p3_commit::Pcs;
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{Proof, StarkGenericConfig, Val};

use super::prover::{PreparedProver, prepare_prover};
use super::{
    NativeCommitment, PreparedInput, PreparedPcsRecursionBackend, TrustedPcsRecursionBackend,
};
use crate::recursion::{
    BatchOnly, PcsRecursionBackend, ProveNextLayerParams, RecursionInput, RecursionOutput,
    VerifierCircuitResult,
};
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

/// Trusted construction source for a child relation fixed inside a recursive verifier circuit.
///
/// The configuration and preprocessing commitment are owned by the source. A batch source owns
/// the verifier-authoritative descriptor/common handle, not independently supplied common data.
pub enum TrustedPreparedSource<'air, 'p, SC, A>
where
    SC: StarkGenericConfig + 'static,
{
    /// Trusted uni-STARK authority and one representative proof used to fix allocation shape.
    UniStark {
        config: SC,
        air: &'air A,
        preprocessed_commit: Option<NativeCommitment<SC>>,
        proof: &'p Proof<SC>,
        public_inputs: &'p [Val<SC>],
    },
    /// Trusted batch verifier descriptor and one representative proof/statement.
    BatchStark {
        verifier: CircuitVerifier<SC>,
        proof: &'p BatchStarkProof<SC>,
        statement: &'p [Val<SC>],
    },
}

/// Witness-only input accepted by a trusted prepared owner.
///
/// It intentionally contains no configuration, AIR, preprocessing commitment, or batch common
/// data. Those remain fixed by [`TrustedPreparedSource`].
#[derive(Clone, Copy)]
pub enum TrustedPreparedInput<'p, SC>
where
    SC: StarkGenericConfig + 'static,
{
    UniStark {
        proof: &'p Proof<SC>,
        public_inputs: &'p [Val<SC>],
    },
    BatchStark {
        proof: &'p BatchStarkProof<SC>,
        statement: &'p [Val<SC>],
    },
}

enum TrustedChildAuthority<'air, SC, A>
where
    SC: StarkGenericConfig + 'static,
{
    Uni {
        config: SC,
        air: &'air A,
        preprocessed_commit: Option<NativeCommitment<SC>>,
    },
    Batch {
        verifier: CircuitVerifier<SC>,
        table_public_inputs: Vec<Vec<Val<SC>>>,
    },
}

struct TrustedConstruction<'air, 'p, SC, A>
where
    SC: StarkGenericConfig + 'static,
{
    authority: TrustedChildAuthority<'air, SC, A>,
    input: TrustedPreparedInput<'p, SC>,
}

impl<'air, 'p, SC, A> TrustedConstruction<'air, 'p, SC, A>
where
    SC: StarkGenericConfig + 'static,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn new(source: TrustedPreparedSource<'air, 'p, SC, A>) -> Result<Self, VerificationError> {
        match source {
            TrustedPreparedSource::UniStark {
                config,
                air,
                preprocessed_commit,
                proof,
                public_inputs,
            } => Ok(Self {
                authority: TrustedChildAuthority::Uni {
                    config,
                    air,
                    preprocessed_commit,
                },
                input: TrustedPreparedInput::UniStark {
                    proof,
                    public_inputs,
                },
            }),
            TrustedPreparedSource::BatchStark {
                verifier,
                proof,
                statement,
            } => {
                verifier
                    .verify(proof, statement)
                    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
                let mut table_public_inputs = vec![Vec::new(); 3];
                table_public_inputs.extend(
                    verifier
                        .relation()
                        .non_primitives()
                        .iter()
                        .map(|entry| entry.public_values().to_vec()),
                );
                Ok(Self {
                    authority: TrustedChildAuthority::Batch {
                        verifier,
                        table_public_inputs,
                    },
                    input: TrustedPreparedInput::BatchStark { proof, statement },
                })
            }
        }
    }
}

impl<'air, SC, A> TrustedChildAuthority<'air, SC, A>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64 + StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn config(&self) -> &SC {
        match self {
            Self::Uni { config, .. } => config,
            Self::Batch { verifier, .. } => verifier.config(),
        }
    }

    fn expected_preprocessed(&self) -> Option<&NativeCommitment<SC>> {
        match self {
            Self::Uni {
                preprocessed_commit,
                ..
            } => preprocessed_commit.as_ref(),
            Self::Batch { verifier, .. } => verifier
                .common_data()
                .preprocessed
                .as_ref()
                .map(|global| &global.commitment),
        }
    }

    fn prepared_input<'a, 'p: 'a>(
        &'a self,
        input: &'a TrustedPreparedInput<'p, SC>,
    ) -> Result<PreparedInput<'a, SC>, VerificationError> {
        match (self, input) {
            (
                Self::Uni {
                    preprocessed_commit,
                    ..
                },
                TrustedPreparedInput::UniStark {
                    proof,
                    public_inputs,
                },
            ) => Ok(PreparedInput::UniStark {
                proof,
                public_inputs,
                preprocessed_commit: preprocessed_commit.as_ref(),
            }),
            (
                Self::Batch {
                    verifier,
                    table_public_inputs,
                },
                TrustedPreparedInput::BatchStark { proof, statement },
            ) => {
                verifier
                    .verify(proof, statement)
                    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
                Ok(PreparedInput::BatchStark {
                    proof,
                    common_data: verifier.common_data(),
                    table_public_inputs,
                })
            }
            _ => Err(VerificationError::PreparedInputMismatch {
                component: "input.kind",
            }),
        }
    }

    fn recursion_input<'a, 'p: 'a>(
        &'a self,
        input: &'a TrustedPreparedInput<'p, SC>,
    ) -> Result<RecursionInput<'a, SC, A>, VerificationError>
    where
        NativeCommitment<SC>: Clone,
    {
        match (self, input) {
            (
                Self::Uni {
                    air,
                    preprocessed_commit,
                    ..
                },
                TrustedPreparedInput::UniStark {
                    proof,
                    public_inputs,
                },
            ) => Ok(RecursionInput::UniStark {
                proof,
                air,
                public_inputs: public_inputs.to_vec(),
                preprocessed_commit: preprocessed_commit.clone(),
            }),
            (
                Self::Batch {
                    verifier,
                    table_public_inputs,
                },
                TrustedPreparedInput::BatchStark { proof, statement },
            ) => {
                verifier
                    .verify(proof, statement)
                    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
                Ok(RecursionInput::BatchStark {
                    proof,
                    common_data: verifier.common_data(),
                    table_public_inputs: table_public_inputs.clone(),
                })
            }
            _ => Err(VerificationError::PreparedInputMismatch {
                component: "input.kind",
            }),
        }
    }
}

/// A trusted single-child recursive verifier with independently retained input and output
/// configurations.
pub struct TrustedPreparedLayer<'air, InSC, OutSC, A, B, const D: usize>
where
    InSC: StarkGenericConfig + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + 'static,
    A: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<InSC, A, D>,
{
    child: TrustedChildAuthority<'air, InSC, A>,
    contract: B::InputContract,
    circuit: Circuit<InSC::Challenge>,
    result: B::VerifierResult,
    backend: B,
    params: ProveNextLayerParams,
    prep: PreparedProver<OutSC>,
}

impl<'air, InSC, OutSC, A, B, const D: usize> TrustedPreparedLayer<'air, InSC, OutSC, A, B, D>
where
    InSC: StarkGenericConfig + Send + Sync + Clone + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<InSC, A, D> + PcsRecursionBackend<OutSC, BatchOnly, D>,
    Val<InSC>: PrimeField64 + StarkField,
    Val<OutSC>: PrimeField64 + StarkField,
    InSC::Challenge: BasedVectorSpace<Val<InSC>>
        + BasedVectorSpace<Val<OutSC>>
        + From<Val<InSC>>
        + From<Val<OutSC>>
        + ExtensionField<Val<InSC>>
        + ExtensionField<Val<OutSC>>
        + ExtractBinomialW<Val<InSC>>
        + ExtractBinomialW<Val<OutSC>>,
    SymbolicExpressionExt<Val<InSC>, InSC::Challenge>:
        Algebra<SymbolicExpression<Val<InSC>>> + Algebra<InSC::Challenge>,
    SymbolicExpressionExt<Val<OutSC>, OutSC::Challenge>:
        Algebra<SymbolicExpression<Val<OutSC>>> + Algebra<OutSC::Challenge>,
    <InSC::Pcs as Pcs<InSC::Challenge, InSC::Challenger>>::Commitment: Clone,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Domain: Send + Sync,
    OutSC::Pcs: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::ProverData: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Commitment: Sync,
{
    pub fn new(
        source: TrustedPreparedSource<'air, '_, InSC, A>,
        output_config: OutSC,
        backend: B,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError> {
        let source = TrustedConstruction::<InSC, A>::new(source)?;
        let prepared = source.authority.prepared_input(&source.input)?;
        <B as PreparedPcsRecursionBackend<InSC, A, D>>::preflight_input(
            &backend,
            source.authority.config(),
            &prepared,
        )?;
        let prev = source.authority.recursion_input(&source.input)?;
        let contract = backend.capture_input_contract(source.authority.config(), &prev)?;

        let mut builder = CircuitBuilder::new();
        <B as PcsRecursionBackend<InSC, A, D>>::prepare_circuit(
            &backend,
            source.authority.config(),
            &mut builder,
        )?;
        let result = match (&source.authority, &source.input) {
            (TrustedChildAuthority::Uni { .. }, TrustedPreparedInput::UniStark { .. }) => {
                backend.build_verifier_circuit(&prev, source.authority.config(), &mut builder)?
            }
            (
                TrustedChildAuthority::Batch { verifier, .. },
                TrustedPreparedInput::BatchStark { proof, statement },
            ) => backend.build_trusted_batch_verifier_circuit(
                verifier,
                proof,
                statement,
                &mut builder,
            )?,
            _ => unreachable!(),
        };
        backend.constrain_trusted_preprocessing(
            &mut builder,
            &result,
            source.authority.expected_preprocessed(),
        )?;
        let circuit = builder.build().map_err(VerificationError::CircuitBuilder)?;
        let prep =
            prepare_prover::<OutSC, BatchOnly, B, D>(&circuit, &output_config, &backend, &params)?;
        Ok(Self {
            child: source.authority,
            contract,
            circuit,
            result,
            backend,
            params,
            prep,
        })
    }

    pub fn check_input(
        &self,
        input: &TrustedPreparedInput<'_, InSC>,
    ) -> Result<(), VerificationError> {
        let prepared = self.child.prepared_input(input)?;
        self.backend
            .validate_prepared_input(self.child.config(), &self.contract, &prepared)
    }

    pub fn prove(
        &self,
        input: TrustedPreparedInput<'_, InSC>,
    ) -> Result<RecursionOutput<OutSC>, VerificationError> {
        self.check_input(&input)?;
        let prev = self.child.recursion_input(&input)?;
        let public = self.result.pack_public_inputs(&prev)?;
        let private = self.result.pack_private_inputs(&prev)?;
        let mut runner = self.circuit.runner();
        runner
            .set_public_inputs(&public)
            .map_err(VerificationError::Circuit)?;
        runner
            .set_private_inputs(&private)
            .map_err(VerificationError::Circuit)?;
        match (&self.child, &input) {
            (TrustedChildAuthority::Uni { .. }, TrustedPreparedInput::UniStark { .. }) => {
                <B as PcsRecursionBackend<InSC, A, D>>::set_private_data_for_result(
                    &self.backend,
                    self.child.config(),
                    &mut runner,
                    &self.result,
                    &prev,
                )
                .map_err(|message| VerificationError::InvalidProofShape(message.into()))?
            }
            (
                TrustedChildAuthority::Batch { verifier, .. },
                TrustedPreparedInput::BatchStark { proof, statement },
            ) => self.backend.set_private_data_for_trusted_batch(
                verifier,
                proof,
                statement,
                &mut runner,
                self.result.op_ids(),
            )?,
            _ => unreachable!(),
        }
        let traces = runner.run().map_err(VerificationError::Circuit)?;
        self.prep.prove(&traces)
    }

    pub const fn params(&self) -> &ProveNextLayerParams {
        &self.params
    }

    pub fn verifier(&self) -> CircuitVerifier<OutSC> {
        self.prep.verifier()
    }
}
