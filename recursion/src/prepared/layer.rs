use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_circuit::Circuit;
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_commit::Pcs;
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};

use super::input::legacy_input;
use super::prover::{PreparedProver, prepare_prover};
use super::{PreparedInput, PreparedPcsRecursionBackend, PreparedSource};
use crate::profile::RecursionLayerProfile;
use crate::recursion::{
    PcsRecursionBackend, ProveNextLayerParams, RecursionOutput, VerifierCircuitResult,
    build_next_layer_circuit,
};
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

/// An owned single-layer verifier whose proving method accepts witness data only.
///
/// The construction proof is borrowed only for the duration of [`Self::new`]; the returned owner
/// retains the AIR borrow separately:
///
/// ```
/// # use p3_air::{SymbolicExpression, SymbolicExpressionExt};
/// # use p3_circuit_prover::config::StarkField;
/// # use p3_circuit_prover::field_params::ExtractBinomialW;
/// # use p3_commit::Pcs;
/// # use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{PreparedLayer, PreparedPcsRecursionBackend, PreparedSource, ProveNextLayerParams, RecursiveAir, VerificationError};
/// # use p3_uni_stark::{Proof, StarkGenericConfig, Val};
/// # fn prepare<'air, SC, A, B, const D: usize>(air: &'air A, proof: Proof<SC>, public_inputs: Vec<Val<SC>>, config: SC, backend: B) -> Result<PreparedLayer<'air, SC, A, B, D>, VerificationError>
/// # where
/// #   SC: StarkGenericConfig + Send + Sync + Clone + 'static,
/// #   A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
/// #   B: PreparedPcsRecursionBackend<SC, A, D>,
/// #   Val<SC>: PrimeField64 + StarkField,
/// #   SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>> + ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
/// #   SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
/// #   SC::Pcs: Sync,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
/// # {
/// PreparedLayer::new(
///     PreparedSource::UniStark {
///         air,
///         proof: &proof,
///         public_inputs: &public_inputs,
///         preprocessed_commit: None,
///     },
///     config,
///     backend,
///     ProveNextLayerParams::default(),
/// )
/// # }
/// ```
///
/// A replacement AIR cannot be supplied while proving:
///
/// ```compile_fail,E0061
/// # use p3_air::{SymbolicExpression, SymbolicExpressionExt};
/// # use p3_circuit_prover::config::StarkField;
/// # use p3_circuit_prover::field_params::ExtractBinomialW;
/// # use p3_commit::Pcs;
/// # use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{PreparedInput, PreparedLayer, PreparedPcsRecursionBackend, RecursiveAir};
/// # use p3_uni_stark::{StarkGenericConfig, Val};
/// # fn wrong<SC, A, B, const D: usize>(owner: &PreparedLayer<'_, SC, A, B, D>, input: PreparedInput<'_, SC>, replacement_air: &A)
/// # where
/// #   SC: StarkGenericConfig + Send + Sync + Clone + 'static,
/// #   A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>, B: PreparedPcsRecursionBackend<SC, A, D>, Val<SC>: PrimeField64 + StarkField,
/// #   SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>> + ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
/// #   SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync, SC::Pcs: Sync,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
/// # {
/// let _ = owner.prove(input, replacement_air);
/// # }
/// ```
///
/// Configuration, backend, and parameters are also fixed at construction:
///
/// ```compile_fail,E0061
/// # use p3_air::{SymbolicExpression, SymbolicExpressionExt};
/// # use p3_circuit_prover::config::StarkField;
/// # use p3_circuit_prover::field_params::ExtractBinomialW;
/// # use p3_commit::Pcs;
/// # use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{PreparedInput, PreparedLayer, PreparedPcsRecursionBackend, ProveNextLayerParams, RecursiveAir};
/// # use p3_uni_stark::{StarkGenericConfig, Val};
/// # fn wrong<SC, A, B, const D: usize>(owner: &PreparedLayer<'_, SC, A, B, D>, input: PreparedInput<'_, SC>, config: SC, backend: B, params: ProveNextLayerParams)
/// # where
/// #   SC: StarkGenericConfig + Send + Sync + Clone + 'static,
/// #   A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>, B: PreparedPcsRecursionBackend<SC, A, D>, Val<SC>: PrimeField64 + StarkField,
/// #   SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>> + ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
/// #   SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync, SC::Pcs: Sync,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
/// # {
/// let _ = owner.prove(input, config, backend, params);
/// # }
/// ```
///
/// The circuit and preparation internals are private:
///
/// ```compile_fail,E0616
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{PreparedLayer, PreparedPcsRecursionBackend, RecursiveAir};
/// # use p3_uni_stark::{StarkGenericConfig, Val};
/// # fn inspect<SC, A, B, const D: usize>(owner: &PreparedLayer<'_, SC, A, B, D>) where SC: StarkGenericConfig, A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>, B: PreparedPcsRecursionBackend<SC, A, D> {
/// let _ = &owner.circuit;
/// # }
/// ```
///
/// ```compile_fail,E0616
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{PreparedLayer, PreparedPcsRecursionBackend, RecursiveAir};
/// # use p3_uni_stark::{StarkGenericConfig, Val};
/// # fn inspect<SC, A, B, const D: usize>(owner: &PreparedLayer<'_, SC, A, B, D>) where SC: StarkGenericConfig, A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>, B: PreparedPcsRecursionBackend<SC, A, D> {
/// let _ = &owner.prep;
/// # }
/// ```
///
/// An owner cannot be reconstructed from another owner's private parts:
///
/// ```compile_fail,E0451
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{PreparedLayer, PreparedPcsRecursionBackend, RecursiveAir};
/// # use p3_uni_stark::{StarkGenericConfig, Val};
/// # fn rebuild<SC, A, B, const D: usize>(owner: PreparedLayer<'_, SC, A, B, D>) where SC: StarkGenericConfig, A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>, B: PreparedPcsRecursionBackend<SC, A, D> {
/// let _ = PreparedLayer { ..owner };
/// # }
/// ```
pub struct PreparedLayer<'air, SC, A, B, const D: usize>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PreparedPcsRecursionBackend<SC, A, D>,
{
    air: Option<&'air A>,
    contract: B::InputContract,
    circuit: Circuit<SC::Challenge>,
    verifier_result: B::VerifierResult,
    config: SC,
    backend: B,
    params: ProveNextLayerParams,
    profile: Option<RecursionLayerProfile>,
    prep: PreparedProver<SC>,
}

impl<'air, SC, A, B, const D: usize> PreparedLayer<'air, SC, A, B, D>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PreparedPcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
{
    /// Capture a trusted native input contract, build its verifier circuit, and prepare proving.
    pub fn new(
        source: PreparedSource<'air, '_, SC, A>,
        config: SC,
        backend: B,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError> {
        let air = match &source {
            PreparedSource::UniStark { air, .. } => Some(*air),
            PreparedSource::BatchStark { .. } => None,
        };
        let input = source.as_input();
        let prev = legacy_input(air, &input)?;
        let contract = backend.capture_input_contract(&config, &prev)?;
        let (circuit, verifier_result) =
            build_next_layer_circuit::<SC, A, B, D>(&prev, &config, &backend)?;
        let prep = prepare_prover::<SC, A, B, D>(&circuit, &config, &backend, &params)?;
        Ok(Self {
            air,
            contract,
            circuit,
            verifier_result,
            config,
            backend,
            params,
            profile: None,
            prep,
        })
    }

    /// Validate a witness input before any packing, runner creation, or backend setup.
    pub fn check_input(&self, input: &PreparedInput<'_, SC>) -> Result<(), VerificationError> {
        self.backend
            .validate_prepared_input(&self.config, &self.contract, input)
    }

    /// Prove one recursion layer using only a native witness matching the captured contract.
    #[tracing::instrument(name = "prove_next_layer", skip_all)]
    pub fn prove(
        &self,
        input: PreparedInput<'_, SC>,
    ) -> Result<RecursionOutput<SC>, VerificationError> {
        self.check_input(&input)?;
        let prev = legacy_input(self.air, &input)?;
        let public = self.verifier_result.pack_public_inputs(&prev)?;
        let private = self.verifier_result.pack_private_inputs(&prev)?;
        let mut runner = self.circuit.runner();
        runner
            .set_public_inputs(&public)
            .map_err(VerificationError::Circuit)?;
        runner
            .set_private_inputs(&private)
            .map_err(VerificationError::Circuit)?;
        <B as PcsRecursionBackend<SC, A, D>>::set_private_data(
            &self.backend,
            &self.config,
            &mut runner,
            self.verifier_result.op_ids(),
            &prev,
        )
        .map_err(|message| VerificationError::InvalidProofShape(message.into()))?;
        let traces = runner.run().map_err(VerificationError::Circuit)?;
        self.prep.prove(&traces)
    }

    /// Parameters fixed when this verifier was prepared.
    pub const fn params(&self) -> &ProveNextLayerParams {
        &self.params
    }

    /// Profile label fixed at construction, if profile-based preparation was requested.
    pub const fn profile(&self) -> Option<&RecursionLayerProfile> {
        self.profile.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::Cell;

    use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
    use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
    use p3_circuit_prover::batch_stark_prover::TableProver;
    use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
    use p3_field::PrimeCharacteristicRing;
    use p3_test_utils::koala_bear_params::F;
    use p3_uni_stark::{StarkGenericConfig, Val, prove, verify};

    use super::*;
    use crate::prepared::test_common;

    type Config = test_common::KoalaBearD4RecursionConfig;
    type Backend = test_common::KoalaBearD4Backend;

    struct CountingVerifierResult<R> {
        inner: R,
        pack_calls: Rc<Cell<usize>>,
    }

    impl<SC, A, R> VerifierCircuitResult<SC, A> for CountingVerifierResult<R>
    where
        SC: StarkGenericConfig,
        A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
        R: VerifierCircuitResult<SC, A>,
    {
        fn pack_public_inputs(
            &self,
            prev: &crate::recursion::RecursionInput<'_, SC, A>,
        ) -> Result<Vec<SC::Challenge>, VerificationError>
        where
            Val<SC>: PrimeField64,
            SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>,
        {
            self.pack_calls.set(self.pack_calls.get() + 1);
            self.inner.pack_public_inputs(prev)
        }

        fn pack_private_inputs(
            &self,
            prev: &crate::recursion::RecursionInput<'_, SC, A>,
        ) -> Result<Vec<SC::Challenge>, VerificationError>
        where
            Val<SC>: PrimeField64,
            SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>,
        {
            self.pack_calls.set(self.pack_calls.get() + 1);
            self.inner.pack_private_inputs(prev)
        }

        fn op_ids(&self) -> &[NonPrimitiveOpId] {
            self.inner.op_ids()
        }
    }

    #[derive(Clone)]
    struct CountingBackend<B> {
        inner: B,
        pack_calls: Rc<Cell<usize>>,
        setup_calls: Rc<Cell<usize>>,
        build_calls: Rc<Cell<usize>>,
    }

    impl<B> CountingBackend<B> {
        fn new(inner: B) -> Self {
            Self {
                inner,
                pack_calls: Rc::new(Cell::new(0)),
                setup_calls: Rc::new(Cell::new(0)),
                build_calls: Rc::new(Cell::new(0)),
            }
        }
    }

    impl<SC, A, B, const D: usize> PcsRecursionBackend<SC, A, D> for CountingBackend<B>
    where
        SC: StarkGenericConfig,
        A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
        B: PcsRecursionBackend<SC, A, D>,
    {
        type VerifierResult = CountingVerifierResult<B::VerifierResult>;

        fn prepare_circuit(
            &self,
            config: &SC,
            circuit: &mut CircuitBuilder<SC::Challenge>,
        ) -> Result<(), VerificationError> {
            self.build_calls.set(self.build_calls.get() + 1);
            self.inner.prepare_circuit(config, circuit)
        }

        fn build_verifier_circuit(
            &self,
            prev: &crate::recursion::RecursionInput<'_, SC, A>,
            config: &SC,
            circuit: &mut CircuitBuilder<SC::Challenge>,
        ) -> Result<Self::VerifierResult, VerificationError> {
            Ok(CountingVerifierResult {
                inner: self.inner.build_verifier_circuit(prev, config, circuit)?,
                pack_calls: Rc::clone(&self.pack_calls),
            })
        }

        fn set_private_data(
            &self,
            config: &SC,
            runner: &mut CircuitRunner<'_, SC::Challenge>,
            op_ids: &[NonPrimitiveOpId],
            prev: &crate::recursion::RecursionInput<'_, SC, A>,
        ) -> Result<(), &'static str> {
            self.setup_calls.set(self.setup_calls.get() + 1);
            self.inner.set_private_data(config, runner, op_ids, prev)
        }

        fn non_primitive_preprocessors(&self) -> Vec<Box<dyn NpoPreprocessor<Val<SC>>>> {
            self.inner.non_primitive_preprocessors()
        }

        fn non_primitive_provers(&self, ext_degree: usize) -> Vec<Box<dyn TableProver<SC>>> {
            self.inner.non_primitive_provers(ext_degree)
        }

        fn non_primitive_air_builders(&self) -> Vec<Box<dyn NpoAirBuilder<SC, D>>> {
            self.inner.non_primitive_air_builders()
        }
    }

    impl<SC, A, B, const D: usize> PreparedPcsRecursionBackend<SC, A, D> for CountingBackend<B>
    where
        SC: StarkGenericConfig,
        A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
        B: PreparedPcsRecursionBackend<SC, A, D>,
    {
        type InputContract = B::InputContract;

        fn capture_input_contract(
            &self,
            config: &SC,
            source: &crate::recursion::RecursionInput<'_, SC, A>,
        ) -> Result<Self::InputContract, VerificationError> {
            self.inner.capture_input_contract(config, source)
        }

        fn validate_prepared_input(
            &self,
            config: &SC,
            contract: &Self::InputContract,
            input: &PreparedInput<'_, SC>,
        ) -> Result<(), VerificationError> {
            self.inner.validate_prepared_input(config, contract, input)
        }
    }

    #[derive(Clone)]
    struct ShapeOnlyBackend {
        pack_calls: Rc<Cell<usize>>,
        setup_calls: Rc<Cell<usize>>,
    }

    struct ShapeOnlyVerifierResult {
        pack_calls: Rc<Cell<usize>>,
    }

    impl VerifierCircuitResult<Config, FibonacciAir> for ShapeOnlyVerifierResult {
        fn pack_public_inputs(
            &self,
            _prev: &crate::recursion::RecursionInput<'_, Config, FibonacciAir>,
        ) -> Result<Vec<<Config as StarkGenericConfig>::Challenge>, VerificationError> {
            self.pack_calls.set(self.pack_calls.get() + 1);
            Ok(Vec::new())
        }

        fn pack_private_inputs(
            &self,
            _prev: &crate::recursion::RecursionInput<'_, Config, FibonacciAir>,
        ) -> Result<Vec<<Config as StarkGenericConfig>::Challenge>, VerificationError> {
            self.pack_calls.set(self.pack_calls.get() + 1);
            Ok(Vec::new())
        }

        fn op_ids(&self) -> &[NonPrimitiveOpId] {
            &[]
        }
    }

    impl PcsRecursionBackend<Config, FibonacciAir, 4> for ShapeOnlyBackend {
        type VerifierResult = ShapeOnlyVerifierResult;

        fn prepare_circuit(
            &self,
            _config: &Config,
            _circuit: &mut CircuitBuilder<<Config as StarkGenericConfig>::Challenge>,
        ) -> Result<(), VerificationError> {
            Ok(())
        }

        fn build_verifier_circuit(
            &self,
            _prev: &crate::recursion::RecursionInput<'_, Config, FibonacciAir>,
            _config: &Config,
            circuit: &mut CircuitBuilder<<Config as StarkGenericConfig>::Challenge>,
        ) -> Result<Self::VerifierResult, VerificationError> {
            circuit.define_const(<Config as StarkGenericConfig>::Challenge::ZERO);
            Ok(ShapeOnlyVerifierResult {
                pack_calls: Rc::clone(&self.pack_calls),
            })
        }

        fn set_private_data(
            &self,
            _config: &Config,
            _runner: &mut CircuitRunner<'_, <Config as StarkGenericConfig>::Challenge>,
            _op_ids: &[NonPrimitiveOpId],
            _prev: &crate::recursion::RecursionInput<'_, Config, FibonacciAir>,
        ) -> Result<(), &'static str> {
            self.setup_calls.set(self.setup_calls.get() + 1);
            Ok(())
        }
    }

    impl PreparedPcsRecursionBackend<Config, FibonacciAir, 4> for ShapeOnlyBackend {
        type InputContract = usize;

        fn capture_input_contract(
            &self,
            _config: &Config,
            source: &crate::recursion::RecursionInput<'_, Config, FibonacciAir>,
        ) -> Result<Self::InputContract, VerificationError> {
            match source {
                crate::recursion::RecursionInput::UniStark { public_inputs, .. } => {
                    Ok(public_inputs.len())
                }
                crate::recursion::RecursionInput::BatchStark { .. } => {
                    Err(VerificationError::PreparedInputMismatch {
                        component: "input.kind",
                    })
                }
            }
        }

        fn validate_prepared_input(
            &self,
            _config: &Config,
            contract: &Self::InputContract,
            input: &PreparedInput<'_, Config>,
        ) -> Result<(), VerificationError> {
            match input {
                PreparedInput::UniStark { public_inputs, .. }
                    if public_inputs.len() == *contract =>
                {
                    Ok(())
                }
                PreparedInput::UniStark { .. } => Err(VerificationError::PreparedInputMismatch {
                    component: "input.public_inputs",
                }),
                PreparedInput::BatchStark { .. } => Err(VerificationError::PreparedInputMismatch {
                    component: "input.kind",
                }),
            }
        }
    }

    fn honest_fri_reference(
        config: &Config,
        air: &FibonacciAir,
    ) -> (p3_uni_stark::Proof<Config>, Vec<F>) {
        let n = 1 << 10;
        let mut a = F::ZERO;
        let mut b = F::ONE;
        for _ in 1..n {
            let next = a + b;
            a = b;
            b = next;
        }
        let output = b;
        let pis = vec![F::ZERO, F::ONE, output];
        let proof = prove(config, air, generate_trace_rows::<F>(0, 1, n), &pis);
        verify(config, air, &proof, &pis).unwrap();
        (proof, pis)
    }

    #[test]
    fn custom_contract_mismatch_stops_before_pack_or_backend_setup() {
        let (config, _) = test_common::koala_bear_d4_recursion_config_and_backend();
        let air = FibonacciAir {};
        let (proof, pis) = honest_fri_reference(&config, &air);
        let backend = ShapeOnlyBackend {
            pack_calls: Rc::new(Cell::new(0)),
            setup_calls: Rc::new(Cell::new(0)),
        };
        let prepared = PreparedLayer::<Config, FibonacciAir, _, 4>::new(
            PreparedSource::UniStark {
                air: &air,
                proof: &proof,
                public_inputs: &pis,
                preprocessed_commit: None,
            },
            config,
            backend.clone(),
            ProveNextLayerParams::default(),
        )
        .unwrap();

        let error = prepared
            .prove(PreparedInput::UniStark {
                proof: &proof,
                public_inputs: &pis[..2],
                preprocessed_commit: None,
            })
            .err()
            .unwrap();
        assert!(matches!(
            error,
            VerificationError::PreparedInputMismatch {
                component: "input.public_inputs"
            }
        ));
        assert_eq!(backend.pack_calls.get(), 0);
        assert_eq!(backend.setup_calls.get(), 0);
    }

    #[test]
    fn builtin_equal_total_metadata_mismatch_stops_before_pack_or_backend_setup() {
        let first = test_common::build_koala_bear_d4_first_layer_input_with_starts(0, 1);
        let mut changed = test_common::build_koala_bear_d4_first_layer_input_with_starts(2, 3);
        let table_public_inputs =
            vec![vec![]; first.base_proof.proof.opened_values.instances.len()];
        let backend = CountingBackend::new(first.backend.clone());
        let prepared = PreparedLayer::<Config, crate::recursion::BatchOnly, _, 4>::new(
            PreparedSource::batch(
                &first.base_proof,
                &first.base_proof.stark_common,
                &table_public_inputs,
            ),
            first.layer_config.clone(),
            backend.clone(),
            ProveNextLayerParams::default(),
        )
        .unwrap();
        let public_lanes = changed.base_proof.table_packing.public_lanes();
        let alu_lanes = changed.base_proof.table_packing.alu_lanes();
        changed.base_proof.table_packing = changed
            .base_proof
            .table_packing
            .clone()
            .with_public_alu_lanes(public_lanes + 1, alu_lanes - 1);

        let error = prepared
            .prove(PreparedInput::BatchStark {
                proof: &changed.base_proof,
                common_data: &changed.base_proof.stark_common,
                table_public_inputs: &table_public_inputs,
            })
            .err()
            .unwrap();
        assert!(matches!(
            error,
            VerificationError::PreparedInputMismatch {
                component: "input.metadata"
            }
        ));
        assert_eq!(backend.pack_calls.get(), 0);
        assert_eq!(backend.setup_calls.get(), 0);
    }

    #[test]
    fn trusted_public_arity_is_rejected_before_backend_build() {
        let (config, inner) = test_common::koala_bear_d4_recursion_config_and_backend();
        let air = FibonacciAir {};
        let (proof, pis) = honest_fri_reference(&config, &air);
        for public_inputs in [&pis[..2], &[pis[0], pis[1], pis[2], F::ZERO][..]] {
            let backend = CountingBackend::new(inner.clone());
            let result = PreparedLayer::<Config, FibonacciAir, CountingBackend<Backend>, 4>::new(
                PreparedSource::UniStark {
                    air: &air,
                    proof: &proof,
                    public_inputs,
                    preprocessed_commit: None,
                },
                config.clone(),
                backend.clone(),
                ProveNextLayerParams::default(),
            );
            assert!(matches!(
                result,
                Err(VerificationError::InvalidProofShape(_))
            ));
            assert_eq!(backend.build_calls.get(), 0);
            assert_eq!(backend.pack_calls.get(), 0);
            assert_eq!(backend.setup_calls.get(), 0);
        }
    }
}
