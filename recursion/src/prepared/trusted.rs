use alloc::string::ToString;
use alloc::vec;

use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_circuit::{Circuit, CircuitBuilder, StatementField, StatementSchema};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier, StatementPreprocessor};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{Proof, StarkGenericConfig, Val};

use super::prover::{PreparedProver, prepare_prover_with_statement};
use super::{
    NativeCommitment, PreparedInput, PreparedPcsRecursionBackend, TrustedChildStatementLayout,
    TrustedPcsRecursionBackend, VerifiedStatementTargets,
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

impl<SC> Clone for TrustedPreparedInput<'_, SC>
where
    SC: StarkGenericConfig + 'static,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<SC> Copy for TrustedPreparedInput<'_, SC> where SC: StarkGenericConfig + 'static {}

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
            } => Ok(Self {
                authority: TrustedChildAuthority::Batch { verifier },
                input: TrustedPreparedInput::BatchStark { proof, statement },
            }),
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
            (Self::Batch { verifier }, TrustedPreparedInput::BatchStark { proof, statement }) => {
                verifier
                    .verify(proof, statement)
                    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
                let table_public_inputs = verifier
                    .table_public_values(statement)
                    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
                Ok(RecursionInput::BatchStark {
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
    StatementPreprocessor: p3_circuit_prover::common::NpoPreprocessor<Val<OutSC>>,
{
    #[allow(
        clippy::needless_pass_by_value,
        reason = "prepared-owner constructors deliberately consume output configuration authority"
    )]
    pub fn new(
        source: TrustedPreparedSource<'air, '_, InSC, A>,
        output_config: OutSC,
        backend: B,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError> {
        match &source {
            TrustedPreparedSource::UniStark {
                config,
                proof,
                public_inputs,
                preprocessed_commit,
                ..
            } => <B as PreparedPcsRecursionBackend<InSC, A, D>>::preflight_input(
                &backend,
                config,
                &PreparedInput::UniStark {
                    proof,
                    public_inputs,
                    preprocessed_commit: preprocessed_commit.as_ref(),
                },
            )?,
            TrustedPreparedSource::BatchStark {
                verifier, proof, ..
            } => backend.preflight_trusted_batch(verifier, proof)?,
        }
        let statement_layout = match &source {
            TrustedPreparedSource::UniStark { public_inputs, .. } => {
                let schema =
                    StatementSchema::try_new(vec![StatementField::Base; public_inputs.len()])
                        .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
                super::TrustedChildStatementLayout::uni(public_inputs.len(), schema)?
            }
            TrustedPreparedSource::BatchStark { verifier, .. } => {
                super::TrustedChildStatementLayout::batch(verifier.statement_layout())
            }
        };
        let source = TrustedConstruction::<InSC, A>::new(source)?;
        let prev = source.authority.recursion_input(&source.input)?;
        let contract = capture_trusted_input_contract::<InSC, A, B, D>(
            &backend,
            &source.authority,
            &source.input,
            &prev,
        )?;

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
        backend
            .verified_statement_targets(&result, &statement_layout, &builder)?
            .install::<Val<OutSC>>(&mut builder)?;
        let circuit = builder.build().map_err(VerificationError::CircuitBuilder)?;
        let prep = prepare_prover_with_statement::<OutSC, BatchOnly, B, D>(
            &circuit,
            &output_config,
            &backend,
            &params,
            statement_layout.schema(),
        )?;
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
        preflight_trusted_input::<InSC, A, B, D>(&self.backend, &self.child, input)?;
        validate_trusted_input_contract::<InSC, A, B, D>(
            &self.backend,
            &self.child,
            &self.contract,
            input,
        )
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
                .map_err(|message| VerificationError::InvalidProofShape(message.into()))?;
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

/// A trusted two-child recursive verifier whose two input authorities and output configuration
/// are retained independently.
pub struct TrustedPreparedAggregation<'left_air, 'right_air, InSC, OutSC, A1, A2, B, const D: usize>
where
    InSC: StarkGenericConfig + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + 'static,
    A1: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<InSC, A1, D> + TrustedPcsRecursionBackend<InSC, A2, D>,
{
    left: TrustedChildAuthority<'left_air, InSC, A1>,
    right: TrustedChildAuthority<'right_air, InSC, A2>,
    left_contract: <B as PreparedPcsRecursionBackend<InSC, A1, D>>::InputContract,
    right_contract: <B as PreparedPcsRecursionBackend<InSC, A2, D>>::InputContract,
    circuit: Circuit<InSC::Challenge>,
    left_result: <B as PcsRecursionBackend<InSC, A1, D>>::VerifierResult,
    right_result: <B as PcsRecursionBackend<InSC, A2, D>>::VerifierResult,
    backend: B,
    params: ProveNextLayerParams,
    prep: PreparedProver<OutSC>,
}

impl<'left_air, 'right_air, InSC, OutSC, A1, A2, B, const D: usize>
    TrustedPreparedAggregation<'left_air, 'right_air, InSC, OutSC, A1, A2, B, D>
where
    InSC: StarkGenericConfig + Send + Sync + Clone + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<InSC, A1, D>
        + TrustedPcsRecursionBackend<InSC, A2, D>
        + PcsRecursionBackend<OutSC, BatchOnly, D>,
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
    <InSC::Pcs as Pcs<InSC::Challenge, InSC::Challenger>>::Domain:
        PolynomialSpace<Val = Val<OutSC>>,
    <InSC::Pcs as Pcs<InSC::Challenge, InSC::Challenger>>::Commitment: Clone,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Domain: Send + Sync,
    OutSC::Pcs: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::ProverData: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Commitment: Sync,
    StatementPreprocessor: p3_circuit_prover::common::NpoPreprocessor<Val<OutSC>>,
{
    /// Preflight both unmaterialized sources before cloning or natively verifying either child.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "prepared-owner constructors deliberately consume output configuration authority"
    )]
    pub fn new(
        left: TrustedPreparedSource<'left_air, '_, InSC, A1>,
        right: TrustedPreparedSource<'right_air, '_, InSC, A2>,
        output_config: OutSC,
        backend: B,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError> {
        preflight_trusted_source::<InSC, A1, B, D>(&backend, &left)?;
        preflight_trusted_source::<InSC, A2, B, D>(&backend, &right)?;

        let left = TrustedConstruction::<InSC, A1>::new(left)?;
        let right = TrustedConstruction::<InSC, A2>::new(right)?;
        let left_statement = trusted_child_statement_layout(&left.authority)?;
        let right_statement = trusted_child_statement_layout(&right.authority)?;
        let left_prev = left.authority.recursion_input(&left.input)?;
        let right_prev = right.authority.recursion_input(&right.input)?;
        let left_contract = capture_trusted_input_contract::<InSC, A1, B, D>(
            &backend,
            &left.authority,
            &left.input,
            &left_prev,
        )?;
        let right_contract = capture_trusted_input_contract::<InSC, A2, B, D>(
            &backend,
            &right.authority,
            &right.input,
            &right_prev,
        )?;

        let mut builder = CircuitBuilder::new();
        <B as PcsRecursionBackend<InSC, A1, D>>::prepare_circuit(
            &backend,
            left.authority.config(),
            &mut builder,
        )?;
        <B as PcsRecursionBackend<InSC, A2, D>>::prepare_circuit(
            &backend,
            right.authority.config(),
            &mut builder,
        )?;
        let left_result = build_trusted_child::<InSC, A1, B, D>(
            &backend,
            &left.authority,
            &left.input,
            &left_prev,
            &mut builder,
        )?;
        let right_result = build_trusted_child::<InSC, A2, B, D>(
            &backend,
            &right.authority,
            &right.input,
            &right_prev,
            &mut builder,
        )?;
        <B as TrustedPcsRecursionBackend<InSC, A1, D>>::constrain_trusted_preprocessing(
            &backend,
            &mut builder,
            &left_result,
            left.authority.expected_preprocessed(),
        )?;
        <B as TrustedPcsRecursionBackend<InSC, A2, D>>::constrain_trusted_preprocessing(
            &backend,
            &mut builder,
            &right_result,
            right.authority.expected_preprocessed(),
        )?;
        let left_targets =
            <B as TrustedPcsRecursionBackend<InSC, A1, D>>::verified_statement_targets(
                &backend,
                &left_result,
                &left_statement,
                &builder,
            )?;
        let right_targets =
            <B as TrustedPcsRecursionBackend<InSC, A2, D>>::verified_statement_targets(
                &backend,
                &right_result,
                &right_statement,
                &builder,
            )?;
        let aggregation_layout = VerifiedStatementTargets::install_ordered_aggregation::<Val<InSC>>(
            left_targets,
            right_targets,
            &mut builder,
        )?;
        let circuit = builder.build().map_err(VerificationError::CircuitBuilder)?;
        let prep = prepare_prover_with_statement::<OutSC, BatchOnly, B, D>(
            &circuit,
            &output_config,
            &backend,
            &params,
            aggregation_layout.output(),
        )?;

        Ok(Self {
            left: left.authority,
            right: right.authority,
            left_contract,
            right_contract,
            circuit,
            left_result,
            right_result,
            backend,
            params,
            prep,
        })
    }

    /// Validate both witness-only inputs before either result packs witness values.
    pub fn check_inputs(
        &self,
        left: &TrustedPreparedInput<'_, InSC>,
        right: &TrustedPreparedInput<'_, InSC>,
    ) -> Result<(), VerificationError> {
        preflight_trusted_input::<InSC, A1, B, D>(&self.backend, &self.left, left)?;
        preflight_trusted_input::<InSC, A2, B, D>(&self.backend, &self.right, right)?;
        validate_trusted_input_contract::<InSC, A1, B, D>(
            &self.backend,
            &self.left,
            &self.left_contract,
            left,
        )?;
        validate_trusted_input_contract::<InSC, A2, B, D>(
            &self.backend,
            &self.right,
            &self.right_contract,
            right,
        )
    }

    /// Prove one aggregation layer under the retained child authorities and output config.
    pub fn prove(
        &self,
        left: TrustedPreparedInput<'_, InSC>,
        right: TrustedPreparedInput<'_, InSC>,
    ) -> Result<RecursionOutput<OutSC>, VerificationError> {
        self.check_inputs(&left, &right)?;
        let left_prev = self.left.recursion_input(&left)?;
        let right_prev = self.right.recursion_input(&right)?;
        let mut public = self.left_result.pack_public_inputs(&left_prev)?;
        public.extend(self.right_result.pack_public_inputs(&right_prev)?);
        let mut private = self.left_result.pack_private_inputs(&left_prev)?;
        private.extend(self.right_result.pack_private_inputs(&right_prev)?);
        let mut runner = self.circuit.runner();
        runner
            .set_public_inputs(&public)
            .map_err(VerificationError::Circuit)?;
        runner
            .set_private_inputs(&private)
            .map_err(VerificationError::Circuit)?;
        set_trusted_child_private::<InSC, A1, B, D>(
            &self.backend,
            &self.left,
            &left,
            &left_prev,
            &self.left_result,
            &mut runner,
        )?;
        set_trusted_child_private::<InSC, A2, B, D>(
            &self.backend,
            &self.right,
            &right,
            &right_prev,
            &self.right_result,
            &mut runner,
        )?;
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

fn trusted_child_statement_layout<SC, A>(
    authority: &TrustedChildAuthority<'_, SC, A>,
) -> Result<TrustedChildStatementLayout, VerificationError>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64 + StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    match authority {
        TrustedChildAuthority::Uni { air, .. } => {
            let public_values_len = air.expected_public_input_count().ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "trusted uni-STARK AIR does not declare an exact public input count".into(),
                )
            })?;
            let schema = StatementSchema::try_new(vec![StatementField::Base; public_values_len])
                .map_err(|error| {
                    VerificationError::InvalidProofShape(alloc::format!(
                        "trusted uni statement schema is invalid: {error}"
                    ))
                })?;
            TrustedChildStatementLayout::uni(public_values_len, schema)
        }
        TrustedChildAuthority::Batch { verifier } => Ok(TrustedChildStatementLayout::batch(
            verifier.statement_layout(),
        )),
    }
}

fn capture_trusted_input_contract<'air, 'p, SC, A, B, const D: usize>(
    backend: &B,
    authority: &TrustedChildAuthority<'air, SC, A>,
    input: &TrustedPreparedInput<'p, SC>,
    recursion_input: &RecursionInput<'_, SC, A>,
) -> Result<B::InputContract, VerificationError>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    match (authority, input) {
        (TrustedChildAuthority::Uni { .. }, TrustedPreparedInput::UniStark { .. }) => {
            backend.capture_input_contract(authority.config(), recursion_input)
        }
        (
            TrustedChildAuthority::Batch { verifier },
            TrustedPreparedInput::BatchStark { proof, statement },
        ) => backend.capture_trusted_batch_input_contract(verifier, proof, statement),
        _ => Err(VerificationError::PreparedInputMismatch {
            component: "input.kind",
        }),
    }
}

fn validate_trusted_input_contract<'air, 'p, SC, A, B, const D: usize>(
    backend: &B,
    authority: &TrustedChildAuthority<'air, SC, A>,
    contract: &B::InputContract,
    input: &TrustedPreparedInput<'p, SC>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    match (authority, input) {
        (
            TrustedChildAuthority::Uni {
                preprocessed_commit,
                ..
            },
            TrustedPreparedInput::UniStark {
                proof,
                public_inputs,
            },
        ) => backend.validate_prepared_input(
            authority.config(),
            contract,
            &PreparedInput::UniStark {
                proof,
                public_inputs,
                preprocessed_commit: preprocessed_commit.as_ref(),
            },
        ),
        (
            TrustedChildAuthority::Batch { verifier },
            TrustedPreparedInput::BatchStark { proof, statement },
        ) => backend.validate_trusted_batch_input(verifier, contract, proof, statement),
        _ => Err(VerificationError::PreparedInputMismatch {
            component: "input.kind",
        }),
    }
}

fn preflight_trusted_input<'air, 'p, SC, A, B, const D: usize>(
    backend: &B,
    authority: &TrustedChildAuthority<'air, SC, A>,
    input: &TrustedPreparedInput<'p, SC>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    match (authority, input) {
        (
            TrustedChildAuthority::Uni {
                preprocessed_commit,
                ..
            },
            TrustedPreparedInput::UniStark {
                proof,
                public_inputs,
            },
        ) => <B as PreparedPcsRecursionBackend<SC, A, D>>::preflight_input(
            backend,
            authority.config(),
            &PreparedInput::UniStark {
                proof,
                public_inputs,
                preprocessed_commit: preprocessed_commit.as_ref(),
            },
        ),
        (
            TrustedChildAuthority::Batch { verifier },
            TrustedPreparedInput::BatchStark { proof, .. },
        ) => backend.preflight_trusted_batch(verifier, proof),
        _ => Err(VerificationError::PreparedInputMismatch {
            component: "input.kind",
        }),
    }
}

fn preflight_trusted_source<SC, A, B, const D: usize>(
    backend: &B,
    source: &TrustedPreparedSource<'_, '_, SC, A>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    match source {
        TrustedPreparedSource::UniStark {
            config,
            proof,
            public_inputs,
            preprocessed_commit,
            ..
        } => <B as PreparedPcsRecursionBackend<SC, A, D>>::preflight_input(
            backend,
            config,
            &PreparedInput::UniStark {
                proof,
                public_inputs,
                preprocessed_commit: preprocessed_commit.as_ref(),
            },
        ),
        TrustedPreparedSource::BatchStark {
            verifier, proof, ..
        } => backend.preflight_trusted_batch(verifier, proof),
    }
}

fn build_trusted_child<'air, 'p, SC, A, B, const D: usize>(
    backend: &B,
    authority: &TrustedChildAuthority<'air, SC, A>,
    input: &TrustedPreparedInput<'p, SC>,
    prev: &RecursionInput<'_, SC, A>,
    builder: &mut CircuitBuilder<SC::Challenge>,
) -> Result<B::VerifierResult, VerificationError>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    match (authority, input) {
        (TrustedChildAuthority::Uni { .. }, TrustedPreparedInput::UniStark { .. }) => {
            backend.build_verifier_circuit(prev, authority.config(), builder)
        }
        (
            TrustedChildAuthority::Batch { verifier, .. },
            TrustedPreparedInput::BatchStark { proof, statement },
        ) => backend.build_trusted_batch_verifier_circuit(verifier, proof, statement, builder),
        _ => unreachable!(),
    }
}

fn set_trusted_child_private<'air, 'p, SC, A, B, const D: usize>(
    backend: &B,
    authority: &TrustedChildAuthority<'air, SC, A>,
    input: &TrustedPreparedInput<'p, SC>,
    prev: &RecursionInput<'_, SC, A>,
    result: &B::VerifierResult,
    runner: &mut p3_circuit::CircuitRunner<'_, SC::Challenge>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: TrustedPcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    match (authority, input) {
        (TrustedChildAuthority::Uni { .. }, TrustedPreparedInput::UniStark { .. }) => {
            <B as PcsRecursionBackend<SC, A, D>>::set_private_data_for_result(
                backend,
                authority.config(),
                runner,
                result,
                prev,
            )
            .map_err(|message| VerificationError::InvalidProofShape(message.into()))
        }
        (
            TrustedChildAuthority::Batch { verifier, .. },
            TrustedPreparedInput::BatchStark { proof, statement },
        ) => backend.set_private_data_for_trusted_batch(
            verifier,
            proof,
            statement,
            runner,
            result.op_ids(),
        ),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use std::any::Any;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::string::String;

    use p3_circuit::tables::WitnessTrace;
    use p3_circuit_prover::BatchStarkProverError;
    use p3_field::PrimeCharacteristicRing;
    use p3_test_utils::corpus::{CaseRng, CorpusSpec, derive_family_seed, for_each_case};
    use p3_test_utils::koala_bear_params::{Challenge, DIGEST_ELEMS, F};
    use p3_test_utils::rejection_oracle::classify_debug_diagnostic;

    use super::*;
    use crate::pcs::fri::MerkleCapTargets;
    use crate::prepared::test_common;
    use crate::traits::Recursive;
    use crate::verifier::VerifierLimits;

    const MAX_ASSURANCE_PROOF_CASES: u32 = 8;

    fn assurance_proof_corpus_from_env() -> CorpusSpec {
        let start_seed = std::env::var("P3_ASSURANCE_START_SEED")
            .ok()
            .map(|raw| {
                raw.parse::<u64>().unwrap_or_else(|_| {
                    panic!("P3_ASSURANCE_START_SEED must be a u64, got {raw:?}")
                })
            })
            .unwrap_or(0);
        let cases = std::env::var("P3_ASSURANCE_PROOF_CASES")
            .ok()
            .map(|raw| {
                raw.parse::<u32>().unwrap_or_else(|_| {
                    panic!(
                        "P3_ASSURANCE_PROOF_CASES must be a u32 in 1..={MAX_ASSURANCE_PROOF_CASES}, got {raw:?}"
                    )
                })
            })
            .unwrap_or(1);
        assert!(
            (1..=MAX_ASSURANCE_PROOF_CASES).contains(&cases),
            "P3_ASSURANCE_PROOF_CASES must be in 1..={MAX_ASSURANCE_PROOF_CASES}, got {cases}"
        );
        CorpusSpec { start_seed, cases }
    }

    #[test]
    fn fri_trusted_layer_reuses_one_child_relation_for_two_runtime_statements() {
        let fixture = test_common::KoalaBearD4StatementFixture::new();
        let first_statement = [F::from_u64(7), F::from_u64(9)];
        let second_statement = [F::from_u64(11), F::from_u64(13)];
        let first_proof = fixture.prove([7, 9]);
        let second_proof = fixture.prove([11, 13]);
        let child_verifier = fixture.verifier();
        child_verifier
            .verify(&first_proof, &first_statement)
            .unwrap();
        child_verifier
            .verify(&second_proof, &second_statement)
            .unwrap();

        let owner = TrustedPreparedLayer::<_, _, BatchOnly, _, 4>::new(
            TrustedPreparedSource::BatchStark {
                verifier: child_verifier,
                proof: &first_proof,
                statement: &first_statement,
            },
            fixture.layer_config.clone(),
            fixture.backend,
            ProveNextLayerParams::default(),
        )
        .unwrap();
        let first = owner
            .prove(TrustedPreparedInput::BatchStark {
                proof: &first_proof,
                statement: &first_statement,
            })
            .unwrap();
        let second = owner
            .prove(TrustedPreparedInput::BatchStark {
                proof: &second_proof,
                statement: &second_statement,
            })
            .unwrap();

        let parent_verifier = owner.verifier();
        parent_verifier.verify(&first.0, &first_statement).unwrap();
        parent_verifier
            .verify(&second.0, &second_statement)
            .unwrap();
    }

    #[test]
    fn trusted_layer_preflights_an_over_limit_replacement_before_native_validation() {
        type SC = test_common::KoalaBearD4RecursionConfig;

        let fixture = test_common::KoalaBearD4StatementFixture::new();
        let statement = [F::from_u64(7), F::from_u64(9)];
        let proof = fixture.prove([7, 9]);
        let exact_final_poly = proof.proof.opening_proof.final_poly.len();
        let backend = fixture.backend.clone().with_limits(VerifierLimits {
            max_final_poly_evaluations: exact_final_poly,
            ..VerifierLimits::default()
        });
        let owner = TrustedPreparedLayer::<SC, SC, BatchOnly, _, 4>::new(
            TrustedPreparedSource::BatchStark {
                verifier: fixture.verifier(),
                proof: &proof,
                statement: &statement,
            },
            fixture.layer_config,
            backend,
            ProveNextLayerParams::default(),
        )
        .unwrap();

        let encoded = postcard::to_allocvec(&proof).unwrap();
        let mut oversized: BatchStarkProof<SC> = postcard::from_bytes(&encoded).unwrap();
        oversized
            .proof
            .opening_proof
            .final_poly
            .push(Challenge::ZERO);
        let error = owner
            .check_input(&TrustedPreparedInput::BatchStark {
                proof: &oversized,
                statement: &statement,
            })
            .unwrap_err();
        assert!(matches!(
            error,
            VerificationError::ResourceLimitExceeded {
                component: "final polynomial evaluations",
                ..
            }
        ));
    }

    #[test]
    fn trusted_aggregation_preflights_right_before_validating_left() {
        type SC = test_common::KoalaBearD4RecursionConfig;

        let fixture = test_common::KoalaBearD4StatementFixture::new();
        let statement = [F::from_u64(7), F::from_u64(9)];
        let wrong_left_statement = [F::from_u64(9), F::from_u64(7)];
        let proof = fixture.prove([7, 9]);
        let exact_final_poly = proof.proof.opening_proof.final_poly.len();
        let backend = fixture.backend.clone().with_limits(VerifierLimits {
            max_final_poly_evaluations: exact_final_poly,
            ..VerifierLimits::default()
        });
        let owner = TrustedPreparedAggregation::<SC, SC, BatchOnly, BatchOnly, _, 4>::new(
            TrustedPreparedSource::BatchStark {
                verifier: fixture.verifier(),
                proof: &proof,
                statement: &statement,
            },
            TrustedPreparedSource::BatchStark {
                verifier: fixture.verifier(),
                proof: &proof,
                statement: &statement,
            },
            fixture.layer_config,
            backend,
            ProveNextLayerParams::default(),
        )
        .unwrap();

        let encoded = postcard::to_allocvec(&proof).unwrap();
        let mut oversized_right: BatchStarkProof<SC> = postcard::from_bytes(&encoded).unwrap();
        oversized_right
            .proof
            .opening_proof
            .final_poly
            .push(Challenge::ZERO);
        let error = owner
            .check_inputs(
                &TrustedPreparedInput::BatchStark {
                    proof: &proof,
                    statement: &wrong_left_statement,
                },
                &TrustedPreparedInput::BatchStark {
                    proof: &oversized_right,
                    statement: &statement,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            VerificationError::ResourceLimitExceeded {
                component: "final polynomial evaluations",
                ..
            }
        ));
    }

    #[test]
    fn fri_trusted_layer_rejects_wrong_statement_value_order_length_and_metadata() {
        type SC = test_common::KoalaBearD4RecursionConfig;

        let fixture = test_common::KoalaBearD4StatementFixture::new();
        let statement = [F::from_u64(7), F::from_u64(9)];
        let proof = fixture.prove([7, 9]);
        let owner = TrustedPreparedLayer::<_, _, BatchOnly, _, 4>::new(
            TrustedPreparedSource::BatchStark {
                verifier: fixture.verifier(),
                proof: &proof,
                statement: &statement,
            },
            fixture.layer_config.clone(),
            fixture.backend,
            ProveNextLayerParams::default(),
        )
        .unwrap();

        for wrong in [
            vec![F::from_u64(8), F::from_u64(9)],
            vec![F::from_u64(9), F::from_u64(7)],
            vec![F::from_u64(7)],
        ] {
            let error = owner
                .check_input(&TrustedPreparedInput::BatchStark {
                    proof: &proof,
                    statement: &wrong,
                })
                .unwrap_err();
            assert!(matches!(error, VerificationError::InvalidProofShape(_)));
        }

        let bytes = postcard::to_allocvec(&proof).unwrap();
        let mut replaced_metadata: BatchStarkProof<SC> = postcard::from_bytes(&bytes).unwrap();
        replaced_metadata
            .non_primitives
            .iter_mut()
            .find(|entry| entry.op_type == p3_circuit::ops::NpoTypeId::statement())
            .unwrap()
            .public_values = vec![F::from_u64(11), F::from_u64(13)];
        let error = owner
            .check_input(&TrustedPreparedInput::BatchStark {
                proof: &replaced_metadata,
                statement: &statement,
            })
            .unwrap_err();
        assert!(matches!(error, VerificationError::InvalidProofShape(_)));
    }

    #[test]
    fn fri_fixed_parent_rejects_wrong_packed_statement_after_host_bypass() {
        type SC = test_common::KoalaBearD4RecursionConfig;

        let fixture = test_common::KoalaBearD4StatementFixture::new();
        let statement = [F::from_u64(7), F::from_u64(9)];
        let proof = fixture.prove([7, 9]);
        let owner = TrustedPreparedLayer::<SC, SC, BatchOnly, _, 4>::new(
            TrustedPreparedSource::BatchStark {
                verifier: fixture.verifier(),
                proof: &proof,
                statement: &statement,
            },
            fixture.layer_config.clone(),
            fixture.backend,
            ProveNextLayerParams::default(),
        )
        .unwrap();
        let input = TrustedPreparedInput::BatchStark {
            proof: &proof,
            statement: &statement,
        };
        let prev = owner.child.recursion_input(&input).unwrap();
        let public = owner.result.pack_public_inputs(&prev).unwrap();
        let private = owner.result.pack_private_inputs(&prev).unwrap();
        let mut runner = owner.circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        runner.set_private_inputs(&private).unwrap();
        set_trusted_child_private::<SC, BatchOnly, _, 4>(
            &owner.backend,
            &owner.child,
            &input,
            &prev,
            &owner.result,
            &mut runner,
        )
        .unwrap();
        let mut forged_traces = runner.run().unwrap();
        let honest = owner.prep.prove(&forged_traces).unwrap();
        let fixed_parent = owner.verifier();
        fixed_parent.verify(&honest.0, &statement).unwrap();

        let TrustedChildAuthority::Batch { verifier } = &owner.child else {
            unreachable!()
        };
        let wrong_statement = [F::from_u64(9), F::from_u64(7)];
        let wrong_prev: RecursionInput<'_, SC, BatchOnly> = RecursionInput::BatchStark {
            proof: &proof,
            common_data: verifier.common_data(),
            table_public_inputs: verifier.table_public_values(&wrong_statement).unwrap(),
        };
        let wrong_public = owner.result.inner.pack_public_inputs(&wrong_prev).unwrap();
        assert_eq!(wrong_public.len(), public.len());
        assert_ne!(wrong_public, public);

        let mut witness_values = (0..forged_traces.witness_trace.num_rows())
            .map(|index| {
                *forged_traces
                    .witness_trace
                    .get_value(p3_circuit::WitnessId(index as u32))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for (position, value) in wrong_public.iter().copied().enumerate() {
            witness_values[owner.circuit.public_rows[position].0 as usize] = value;
        }
        forged_traces.witness_trace = WitnessTrace::new(witness_values);
        forged_traces.public_trace.values = wrong_public;

        let attempt = catch_unwind(AssertUnwindSafe(|| owner.prep.prove(&forged_traces)));
        match attempt {
            Ok(Ok(forged)) => assert!(
                fixed_parent.verify(&forged.0, &statement).is_err(),
                "the original parent key must reject the directly packed wrong statement"
            ),
            Ok(Err(error)) => panic!("forged trace must reach proof construction: {error:?}"),
            Err(payload) => assert!(
                classify_panic(payload.as_ref()).is_some(),
                "debug rejection must be an exact strict constraint/lookup failure"
            ),
        }
    }

    fn check_trusted_aggregation_rejects_seeded_statement_boundary_and_output_substitutions(
        corpus: CorpusSpec,
        fixed_values: Option<([u64; 2], [u64; 2])>,
    ) {
        type SC = test_common::KoalaBearD4RecursionConfig;

        let fixture = test_common::KoalaBearD4StatementFixture::new();
        let representative_left_statement = [F::from_u64(7), F::from_u64(9)];
        let representative_right_statement = [F::from_u64(11), F::from_u64(13)];
        let representative_left_proof = fixture.prove([7, 9]);
        let representative_right_proof = fixture.prove([11, 13]);
        let params = ProveNextLayerParams::default();
        let owner = TrustedPreparedAggregation::<SC, SC, BatchOnly, BatchOnly, _, 4>::new(
            TrustedPreparedSource::BatchStark {
                verifier: fixture.verifier(),
                proof: &representative_left_proof,
                statement: &representative_left_statement,
            },
            TrustedPreparedSource::BatchStark {
                verifier: fixture.verifier(),
                proof: &representative_right_proof,
                statement: &representative_right_statement,
            },
            fixture.layer_config.clone(),
            fixture.backend.clone(),
            params,
        )
        .unwrap();
        let parent_verifier = owner.verifier();
        let layout = parent_verifier
            .aggregation_statement_layout()
            .expect("the trusted parent retains the ordered child boundary");
        assert_eq!(
            layout.left().base_len(),
            2,
            "family=trusted-ordered field=KoalaBear/D4 mutation=none expected-stage=layout-left"
        );
        assert_eq!(
            layout.right().base_len(),
            2,
            "family=trusted-ordered field=KoalaBear/D4 mutation=none expected-stage=layout-right"
        );
        assert_eq!(
            layout.split_at(),
            2,
            "family=trusted-ordered field=KoalaBear/D4 mutation=none expected-stage=layout-boundary"
        );
        assert_eq!(
            layout.output().base_len(),
            4,
            "family=trusted-ordered field=KoalaBear/D4 mutation=none expected-stage=layout-output"
        );

        for_each_case(corpus, |seed| {
            let mut rng = CaseRng::new(derive_family_seed(seed, 0x4f52_4445_5245_445f));
            let (left_values, right_values) = fixed_values.unwrap_or_else(|| {
                (
                    [1 + (rng.next_u64() % 1000), 1001 + (rng.next_u64() % 1000)],
                    [
                        2001 + (rng.next_u64() % 1000),
                        3001 + (rng.next_u64() % 1000),
                    ],
                )
            });
            let left_statement = left_values.map(F::from_u64);
            let right_statement = right_values.map(F::from_u64);
            let left_proof = fixture.prove(left_values);
            let right_proof = fixture.prove(right_values);
            let child_verifier = fixture.verifier();
            child_verifier
                .verify(&left_proof, &left_statement)
                .unwrap_or_else(|error| {
                    panic!(
                        "family=trusted-ordered field=KoalaBear/D4 seed={seed} mutation=none expected-stage=native-left-accept error={error:?}"
                    )
                });
            child_verifier
                .verify(&right_proof, &right_statement)
                .unwrap_or_else(|error| {
                    panic!(
                        "family=trusted-ordered field=KoalaBear/D4 seed={seed} mutation=none expected-stage=native-right-accept error={error:?}"
                    )
                });

            let left_input = TrustedPreparedInput::BatchStark {
                proof: &left_proof,
                statement: &left_statement,
            };
            let right_input = TrustedPreparedInput::BatchStark {
                proof: &right_proof,
                statement: &right_statement,
            };
            owner
                .check_inputs(&left_input, &right_input)
                .unwrap_or_else(|error| {
                    panic!(
                        "family=trusted-ordered field=KoalaBear/D4 seed={seed} mutation=none expected-stage=trusted-replay-accept error={error:?}"
                    )
                });
            let output = owner
                .prove(left_input, right_input)
                .unwrap_or_else(|error| {
                    panic!(
                        "family=trusted-ordered field=KoalaBear/D4 seed={seed} mutation=none expected-stage=circuit-prove-accept error={error:?}"
                    )
                });
            let expected = [
                left_statement[0],
                left_statement[1],
                right_statement[0],
                right_statement[1],
            ];
            parent_verifier
                .verify(&output.0, &expected)
                .unwrap_or_else(|error| {
                    panic!(
                        "family=trusted-ordered field=KoalaBear/D4 seed={seed} mutation=none expected-stage=parent-native-accept error={error:?}"
                    )
                });

            if fixed_values.is_some() {
                let duplicated_left_output = owner
                    .prove(
                        TrustedPreparedInput::BatchStark {
                            proof: &left_proof,
                            statement: &left_statement,
                        },
                        TrustedPreparedInput::BatchStark {
                            proof: &left_proof,
                            statement: &left_statement,
                        },
                    )
                    .expect("identical authorized slots may reuse the same relation and statement");
                let duplicated_expected = [
                    left_statement[0],
                    left_statement[1],
                    left_statement[0],
                    left_statement[1],
                ];
                parent_verifier
                    .verify(&duplicated_left_output.0, &duplicated_expected)
                    .unwrap();
                assert!(
                    parent_verifier
                        .verify(&duplicated_left_output.0, &expected)
                        .is_err(),
                    "a valid left || left output must not satisfy an independently requested left || right"
                );
            }

            let mut wrong_boundary = [
                right_statement[0],
                right_statement[1],
                left_statement[0],
                left_statement[1],
            ];
            let error = parent_verifier
                .verify(&output.0, &wrong_boundary)
                .unwrap_err();
            assert!(
                matches!(error, BatchStarkProverError::RelationMismatch(_)),
                "family=trusted-ordered field=KoalaBear/D4 seed={seed} mutation=child-boundary-swap expected-stage=relation-mismatch error={error:?}"
            );

            wrong_boundary = expected;
            wrong_boundary[layout.split_at()] = wrong_boundary[layout.split_at()] + F::ONE;
            let error = parent_verifier
                .verify(&output.0, &wrong_boundary)
                .unwrap_err();
            assert!(
                matches!(error, BatchStarkProverError::RelationMismatch(_)),
                "family=trusted-ordered field=KoalaBear/D4 seed={seed} mutation=right-output-scalar expected-stage=relation-mismatch error={error:?}"
            );
            let error = parent_verifier
                .verify(&output.0, &expected[..expected.len() - 1])
                .unwrap_err();
            assert!(
                matches!(error, BatchStarkProverError::RelationMismatch(_)),
                "family=trusted-ordered field=KoalaBear/D4 seed={seed} mutation=output-length expected-stage=relation-mismatch error={error:?}"
            );

            let error = owner
                .check_inputs(
                    &TrustedPreparedInput::BatchStark {
                        proof: &left_proof,
                        statement: &right_statement,
                    },
                    &TrustedPreparedInput::BatchStark {
                        proof: &right_proof,
                        statement: &left_statement,
                    },
                )
                .unwrap_err();
            assert!(
                matches!(error, VerificationError::InvalidProofShape(_)),
                "family=trusted-ordered field=KoalaBear/D4 seed={seed} mutation=swapped-input-statements expected-stage=invalid-proof-shape error={error:?}"
            );
        });
    }

    #[test]
    fn trusted_aggregation_keeps_left_and_right_runtime_statements_in_input_order() {
        check_trusted_aggregation_rejects_seeded_statement_boundary_and_output_substitutions(
            CorpusSpec {
                start_seed: 0,
                cases: 1,
            },
            Some(([7, 9], [11, 13])),
        );
    }

    #[test]
    fn assurance_trusted_aggregation_rejects_seeded_statement_boundary_and_output_substitutions() {
        check_trusted_aggregation_rejects_seeded_statement_boundary_and_output_substitutions(
            assurance_proof_corpus_from_env(),
            None,
        );
    }

    #[test]
    fn fri_fixed_parent_rejects_actual_wrong_child_root_after_host_bypass() {
        type SC = test_common::KoalaBearD4RecursionConfig;

        let child_a = test_common::build_koala_bear_d4_first_layer_input();
        let child_b =
            test_common::build_koala_bear_d4_first_layer_input_with_different_alu_relation();
        child_b
            .verifier
            .verify(&child_b.base_proof, &[])
            .expect("child B is valid under its own native verifier");
        assert_ne!(
            child_a
                .verifier
                .common_data()
                .preprocessed
                .as_ref()
                .map(|group| &group.commitment),
            child_b
                .verifier
                .common_data()
                .preprocessed
                .as_ref()
                .map(|group| &group.commitment),
            "the negative requires a different actual child preprocessing root"
        );

        let owner = TrustedPreparedLayer::<SC, SC, BatchOnly, _, 4>::new(
            TrustedPreparedSource::BatchStark {
                verifier: child_a.verifier.clone(),
                proof: &child_a.base_proof,
                statement: &[],
            },
            child_a.layer_config.clone(),
            child_a.backend.clone(),
            ProveNextLayerParams::default(),
        )
        .expect("the original parent A circuit and preparation are created once");

        let input_a = TrustedPreparedInput::BatchStark {
            proof: &child_a.base_proof,
            statement: &[],
        };
        let prev_a = owner.child.recursion_input(&input_a).unwrap();
        let public_a = owner.result.pack_public_inputs(&prev_a).unwrap();
        let private_a = owner.result.pack_private_inputs(&prev_a).unwrap();
        let mut runner = owner.circuit.runner();
        runner.set_public_inputs(&public_a).unwrap();
        runner.set_private_inputs(&private_a).unwrap();
        set_trusted_child_private::<SC, BatchOnly, _, 4>(
            &owner.backend,
            &owner.child,
            &input_a,
            &prev_a,
            &owner.result,
            &mut runner,
        )
        .unwrap();
        let honest_traces = runner.run().unwrap();
        let honest = owner.prep.prove(&honest_traces).unwrap();
        let fixed_parent = owner.verifier();
        fixed_parent
            .verify(&honest.0, &[])
            .expect("honest A passes the exact low-level fixed-parent route");

        // Deliberately bypass TrustedPreparedLayer::check_input. Packing through the raw verifier
        // result preserves B's actual proof commitment; no A root is substituted here.
        let source_b =
            TrustedConstruction::<SC, BatchOnly>::new(TrustedPreparedSource::BatchStark {
                verifier: child_b.verifier.clone(),
                proof: &child_b.base_proof,
                statement: &[],
            })
            .unwrap();
        let prev_b = source_b.authority.recursion_input(&source_b.input).unwrap();
        let public_b = owner.result.inner.pack_public_inputs(&prev_b).unwrap();
        assert_eq!(public_b.len(), public_a.len(), "child B must be same-shape");
        let actual_b_root = &child_b
            .verifier
            .common_data()
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment;
        let encoded_b_root =
            <MerkleCapTargets<F, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(actual_b_root);
        assert!(
            public_b
                .windows(encoded_b_root.len())
                .any(|window| window == encoded_b_root),
            "the bypass packing must contain child B's complete actual cap encoding"
        );
        assert_ne!(
            public_b, public_a,
            "packing child B must carry its actual differing public commitment"
        );

        let mut forged_traces = honest_traces;
        let mut witness_values = (0..forged_traces.witness_trace.num_rows())
            .map(|index| {
                *forged_traces
                    .witness_trace
                    .get_value(p3_circuit::WitnessId(index as u32))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for (position, value) in public_b.iter().copied().enumerate() {
            witness_values[owner.circuit.public_rows[position].0 as usize] = value;
        }
        forged_traces.witness_trace = WitnessTrace::new(witness_values);
        forged_traces.public_trace.values = public_b;

        let attempt = catch_unwind(AssertUnwindSafe(|| owner.prep.prove(&forged_traces)));
        match attempt {
            Ok(Ok(forged)) => assert!(
                fixed_parent.verify(&forged.0, &[]).is_err(),
                "the original parent A verifier must reject child B's actual root"
            ),
            Ok(Err(error)) => panic!("forged trace must reach proof construction: {error:?}"),
            Err(payload) => assert!(
                classify_panic(payload.as_ref()).is_some(),
                "debug rejection must match the shared strict constraint/lookup oracle"
            ),
        }
    }

    #[test]
    fn fri_aggregation_fixed_parent_rejects_each_foreign_child_after_host_bypass() {
        type SC = test_common::KoalaBearD4RecursionConfig;

        let child_a = test_common::build_koala_bear_d4_first_layer_input();
        let child_b =
            test_common::build_koala_bear_d4_first_layer_input_with_different_alu_relation();
        child_a.verifier.verify(&child_a.base_proof, &[]).unwrap();
        child_b.verifier.verify(&child_b.base_proof, &[]).unwrap();
        assert_ne!(
            child_a
                .verifier
                .common_data()
                .preprocessed
                .as_ref()
                .map(|group| &group.commitment),
            child_b
                .verifier
                .common_data()
                .preprocessed
                .as_ref()
                .map(|group| &group.commitment),
            "the two valid children must have distinct preprocessing roots"
        );

        let owner = TrustedPreparedAggregation::<SC, SC, BatchOnly, BatchOnly, _, 4>::new(
            TrustedPreparedSource::BatchStark {
                verifier: child_a.verifier.clone(),
                proof: &child_a.base_proof,
                statement: &[],
            },
            TrustedPreparedSource::BatchStark {
                verifier: child_b.verifier.clone(),
                proof: &child_b.base_proof,
                statement: &[],
            },
            child_a.layer_config.clone(),
            child_a.backend.clone(),
            ProveNextLayerParams::default(),
        )
        .expect("the original ordered child pair prepares exactly once");

        let input_a = TrustedPreparedInput::BatchStark {
            proof: &child_a.base_proof,
            statement: &[],
        };
        let input_b = TrustedPreparedInput::BatchStark {
            proof: &child_b.base_proof,
            statement: &[],
        };
        let honest = owner
            .prove(input_a, input_b)
            .expect("the exact retained child pair proves");
        let fixed_parent = owner.verifier();
        fixed_parent
            .verify(&honest.0, &[])
            .expect("the exact retained child pair verifies");

        let prev_a = owner.left.recursion_input(&input_a).unwrap();
        let prev_b = owner.right.recursion_input(&input_b).unwrap();
        let mut honest_public = owner.left_result.pack_public_inputs(&prev_a).unwrap();
        honest_public.extend(owner.right_result.pack_public_inputs(&prev_b).unwrap());
        let mut honest_private = owner.left_result.pack_private_inputs(&prev_a).unwrap();
        honest_private.extend(owner.right_result.pack_private_inputs(&prev_b).unwrap());
        let run_honest_pair = || {
            let mut runner = owner.circuit.runner();
            runner.set_public_inputs(&honest_public).unwrap();
            runner.set_private_inputs(&honest_private).unwrap();
            set_trusted_child_private::<SC, BatchOnly, _, 4>(
                &owner.backend,
                &owner.left,
                &input_a,
                &prev_a,
                &owner.left_result,
                &mut runner,
            )
            .unwrap();
            set_trusted_child_private::<SC, BatchOnly, _, 4>(
                &owner.backend,
                &owner.right,
                &input_b,
                &prev_b,
                &owner.right_result,
                &mut runner,
            )
            .unwrap();
            runner.run().unwrap()
        };
        let encoded_a_root =
            <MerkleCapTargets<F, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(
                &child_a
                    .verifier
                    .common_data()
                    .preprocessed
                    .as_ref()
                    .unwrap()
                    .commitment,
            );
        let encoded_b_root =
            <MerkleCapTargets<F, DIGEST_ELEMS> as Recursive<Challenge>>::get_values(
                &child_b
                    .verifier
                    .common_data()
                    .preprocessed
                    .as_ref()
                    .unwrap()
                    .commitment,
            );

        // Replace only the left child with the valid foreign B proof, retaining the exact A/B
        // aggregation circuit and parent preparation. The raw result packer carries B's actual
        // root; no host-side expected-root substitution or trusted-input check is involved.
        let mut left_foreign_public = owner.left_result.inner.pack_public_inputs(&prev_b).unwrap();
        let left_public_len = left_foreign_public.len();
        assert!(
            left_foreign_public
                .windows(encoded_b_root.len())
                .any(|window| window == encoded_b_root),
            "the raw left pack must contain foreign child B's complete actual cap"
        );
        left_foreign_public.extend(owner.right_result.pack_public_inputs(&prev_b).unwrap());
        assert_eq!(left_public_len, honest_public.len() - left_public_len);
        let mut left_foreign_traces = run_honest_pair();
        replace_public_values(
            &owner.circuit,
            &mut left_foreign_traces,
            left_foreign_public,
        );
        let left_attempt =
            catch_unwind(AssertUnwindSafe(|| owner.prep.prove(&left_foreign_traces)));
        assert_fixed_parent_rejects(left_attempt, &fixed_parent, "left");

        // Symmetrically replace only the right child with valid foreign A inputs while retaining
        // the same A/B parent circuit and preparation.
        let mut right_foreign_public = owner.left_result.pack_public_inputs(&prev_a).unwrap();
        let right_offset = right_foreign_public.len();
        right_foreign_public.extend(
            owner
                .right_result
                .inner
                .pack_public_inputs(&prev_a)
                .unwrap(),
        );
        assert!(
            right_foreign_public[right_offset..]
                .windows(encoded_a_root.len())
                .any(|window| window == encoded_a_root),
            "the raw right pack must contain foreign child A's complete actual cap"
        );
        let mut right_foreign_traces = run_honest_pair();
        replace_public_values(
            &owner.circuit,
            &mut right_foreign_traces,
            right_foreign_public,
        );
        let right_attempt =
            catch_unwind(AssertUnwindSafe(|| owner.prep.prove(&right_foreign_traces)));
        assert_fixed_parent_rejects(right_attempt, &fixed_parent, "right");
    }

    fn replace_public_values(
        circuit: &Circuit<Challenge>,
        traces: &mut p3_circuit::tables::Traces<Challenge>,
        values: Vec<Challenge>,
    ) {
        let mut witness_values = (0..traces.witness_trace.num_rows())
            .map(|index| {
                *traces
                    .witness_trace
                    .get_value(p3_circuit::WitnessId(index as u32))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for (position, value) in values.iter().copied().enumerate() {
            witness_values[circuit.public_rows[position].0 as usize] = value;
        }
        traces.witness_trace = WitnessTrace::new(witness_values);
        traces.public_trace.values = values;
    }

    fn assert_fixed_parent_rejects(
        attempt: std::thread::Result<
            Result<RecursionOutput<test_common::KoalaBearD4RecursionConfig>, VerificationError>,
        >,
        fixed_parent: &CircuitVerifier<test_common::KoalaBearD4RecursionConfig>,
        side: &str,
    ) {
        match attempt {
            Ok(Ok(forged)) => assert!(
                fixed_parent.verify(&forged.0, &[]).is_err(),
                "the fixed parent must reject the foreign {side} child"
            ),
            Ok(Err(error)) => {
                panic!("forged {side} trace must reach proof construction: {error:?}")
            }
            Err(payload) => assert!(
                classify_panic(payload.as_ref()).is_some(),
                "debug rejection for the foreign {side} child must match the strict oracle"
            ),
        }
    }

    fn classify_panic(
        payload: &(dyn Any + Send),
    ) -> Option<p3_test_utils::rejection_oracle::DebugRejectionKind> {
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())?;
        classify_debug_diagnostic(message)
    }
}
