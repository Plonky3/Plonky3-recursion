//! Prepared-verifier native input contracts and borrowed input views.

mod aggregation;
pub(crate) mod input;
mod layer;
pub(crate) mod prover;
mod trusted;

#[cfg(test)]
#[path = "../../tests/common/mod.rs"]
pub(crate) mod test_common;

pub use aggregation::{PreparedAggregation, PreparedAggregationCross};
pub use input::{NativeCommitment, PreparedInput, PreparedSource};
pub use layer::PreparedLayer;
use p3_circuit::CircuitBuilder;
use p3_circuit::{CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier};
use p3_field::Field;
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};
pub use trusted::{
    TrustedPreparedAggregation, TrustedPreparedInput, TrustedPreparedLayer, TrustedPreparedSource,
};

use crate::recursion::{PcsRecursionBackend, RecursionInput};
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

/// Explicit opt-in for recursive commitment targets whose complete native identity can be
/// constrained to constants.
///
/// [`crate::verifier::ObservableCommitment`] is deliberately insufficient: transcript
/// observation does not promise that the exposed targets are a complete, injective commitment
/// encoding. Trusted recursion backends require this stronger audited capability.
pub trait ConstrainConstantCommitment<F: Field>: crate::traits::Recursive<F> {
    /// Constrain every target encoding `self` to the corresponding limb of `expected`.
    fn constrain_constant(
        &self,
        circuit: &mut CircuitBuilder<F>,
        expected: &Self::Input,
    ) -> Result<(), VerificationError>;
}

/// Explicit backend opt-in for safe prepared-verifier circuit reuse.
///
/// Implementations are trusted to capture every native input property that can affect target
/// allocation or compiled verifier behavior. A backend implementing only
/// [`PcsRecursionBackend`] continues to work with uncached APIs and is deliberately excluded from
/// prepared owners.
///
/// ```compile_fail
/// use p3_lookup::logup::LogUpGadget;
/// use p3_recursion::{PcsRecursionBackend, PreparedPcsRecursionBackend, RecursiveAir};
/// use p3_uni_stark::{StarkGenericConfig, Val};
///
/// fn generic_backend_is_not_implicitly_prepared<SC, A, B, const D: usize>()
/// where
///     SC: StarkGenericConfig,
///     A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
///     B: PcsRecursionBackend<SC, A, D>,
/// {
///     fn needs_opt_in<SC, A, B, const D: usize>()
///     where
///         SC: StarkGenericConfig,
///         A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
///         B: PreparedPcsRecursionBackend<SC, A, D>,
///     {}
///     needs_opt_in::<SC, A, B, D>();
/// }
/// ```
///
/// A generic caller that requests the explicit prepared-backend contract compiles:
///
/// ```
/// use p3_lookup::logup::LogUpGadget;
/// use p3_recursion::{PreparedPcsRecursionBackend, RecursiveAir};
/// use p3_uni_stark::{StarkGenericConfig, Val};
///
/// fn accepts_explicit_opt_in<SC, A, B, const D: usize>()
/// where
///     SC: StarkGenericConfig,
///     A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
///     B: PreparedPcsRecursionBackend<SC, A, D>,
/// {
/// }
/// ```
pub trait PreparedPcsRecursionBackend<SC, A, const D: usize>:
    PcsRecursionBackend<SC, A, D>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    /// Complete native contract used to authorize reuse.
    type InputContract;

    /// Borrowed resource preflight hook for prepared owners. Implementations
    /// should run it before shape capture or any source cloning.
    fn preflight_input(
        &self,
        _config: &SC,
        _input: &PreparedInput<'_, SC>,
    ) -> Result<(), VerificationError> {
        Ok(())
    }

    /// Capture and validate the trusted construction reference.
    fn capture_input_contract(
        &self,
        config: &SC,
        source: &RecursionInput<'_, SC, A>,
    ) -> Result<Self::InputContract, VerificationError>;

    /// Validate a later witness-only input against a captured contract.
    fn validate_prepared_input(
        &self,
        config: &SC,
        contract: &Self::InputContract,
        input: &PreparedInput<'_, SC>,
    ) -> Result<(), VerificationError>;
}

/// Explicit backend opt-in for prepared circuits that pin a child verifier's trusted
/// preprocessing commitment inside the recursive circuit.
///
/// This contract deliberately has no default implementation and is not blanket-implemented for
/// prepared backends. An implementation must identify the preprocessing target for every input
/// branch and constrain its complete encoding to the retained native commitment.
pub trait TrustedPcsRecursionBackend<SC, A, const D: usize>:
    PreparedPcsRecursionBackend<SC, A, D>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    /// Walk all adversarial batch witness resources before descriptor-derived allocation, cloning,
    /// native verification, plugin construction, or packing.
    fn preflight_trusted_batch(
        &self,
        verifier: &CircuitVerifier<SC>,
        proof: &BatchStarkProof<SC>,
    ) -> Result<(), VerificationError>;

    /// Build the batch verifier branch from retained descriptor/common authority.
    fn build_trusted_batch_verifier_circuit(
        &self,
        verifier: &CircuitVerifier<SC>,
        proof: &BatchStarkProof<SC>,
        statement: &[Val<SC>],
        circuit: &mut CircuitBuilder<SC::Challenge>,
    ) -> Result<Self::VerifierResult, VerificationError>;

    /// Populate backend-private witness data using transcript replay under the retained child
    /// verifier descriptor/common data.
    fn set_private_data_for_trusted_batch(
        &self,
        verifier: &CircuitVerifier<SC>,
        proof: &BatchStarkProof<SC>,
        statement: &[Val<SC>],
        runner: &mut CircuitRunner<'_, SC::Challenge>,
        op_ids: &[NonPrimitiveOpId],
    ) -> Result<(), VerificationError>;

    /// Constrain the preprocessing commitment allocated by `result` to `expected`, including
    /// enforcing equal presence and the complete commitment's exact root/limb cardinality.
    fn constrain_trusted_preprocessing(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        result: &Self::VerifierResult,
        expected: Option<&NativeCommitment<SC>>,
    ) -> Result<(), VerificationError>;
}

#[cfg(test)]
mod trusted_commitment_tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::CircuitBuilder;
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::MerkleCap;

    use super::ConstrainConstantCommitment;
    use crate::pcs::fri::MerkleCapTargets;
    use crate::traits::Recursive;

    #[test]
    fn complete_commitment_pins_every_cap_root_and_digest_limb() {
        type Targets = MerkleCapTargets<BabyBear, 2>;

        let expected = MerkleCap::<BabyBear, [BabyBear; 2]>::new(vec![
            [BabyBear::from_u32(1), BabyBear::from_u32(2)],
            [BabyBear::from_u32(3), BabyBear::from_u32(4)],
        ]);
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let targets = <Targets as Recursive<BabyBear>>::new(&mut builder, &expected);
        targets.constrain_constant(&mut builder, &expected).unwrap();
        let circuit = builder.build().unwrap();
        let honest = <Targets as Recursive<BabyBear>>::get_values(&expected);
        let mut runner = circuit.runner();
        runner.set_public_inputs(&honest).unwrap();
        runner.run().unwrap();

        for limb in 0..honest.len() {
            let mut wrong = honest.clone();
            wrong[limb] += BabyBear::ONE;
            let mut runner = circuit.runner();
            runner.set_public_inputs(&wrong).unwrap();
            assert!(runner.run().is_err(), "unbound cap limb {limb}");
        }
    }
}
