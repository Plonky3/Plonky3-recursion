//! Prepared-verifier native input contracts and borrowed input views.

mod aggregation;
pub(crate) mod input;
mod layer;
pub(crate) mod prover;
mod trusted;

#[cfg(test)]
#[path = "../../tests/common/mod.rs"]
pub(crate) mod test_common;

use alloc::vec::Vec;

pub use aggregation::{PreparedAggregation, PreparedAggregationCross};
pub use input::{NativeCommitment, PreparedInput, PreparedSource};
pub use layer::PreparedLayer;
use p3_circuit::{
    CircuitBuilder, CircuitRunner, NonPrimitiveOpId, StatementField, StatementSchema,
};
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier, StatementLayout};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};
pub use trusted::{
    TrustedPreparedAggregation, TrustedPreparedInput, TrustedPreparedLayer, TrustedPreparedSource,
};

use crate::recursion::{PcsRecursionBackend, RecursionInput};
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

/// Kind of child relation whose public statement is exported by a trusted recursive verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedChildStatementKind {
    Uni,
    Batch,
}

/// Trusted description of the exact child statement targets consumed by a verifier circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedChildStatementLayout {
    kind: TrustedChildStatementKind,
    schema: StatementSchema,
    public_values_len: usize,
    table_instance: Option<usize>,
}

impl TrustedChildStatementLayout {
    pub(crate) fn uni(
        public_values_len: usize,
        schema: StatementSchema,
    ) -> Result<Self, VerificationError> {
        if schema.base_len() != public_values_len
            || schema
                .fields()
                .iter()
                .any(|field| *field != StatementField::Base)
        {
            return Err(VerificationError::InvalidProofShape(
                "trusted uni statement schema must contain one Base field per AIR public value"
                    .into(),
            ));
        }
        Ok(Self {
            kind: TrustedChildStatementKind::Uni,
            schema,
            public_values_len,
            table_instance: None,
        })
    }

    pub(crate) fn batch(layout: &StatementLayout) -> Self {
        Self {
            kind: TrustedChildStatementKind::Batch,
            schema: layout.schema().clone(),
            public_values_len: layout.schema().base_len(),
            table_instance: layout.table_instance(),
        }
    }

    pub const fn kind(&self) -> TrustedChildStatementKind {
        self.kind
    }

    pub const fn schema(&self) -> &StatementSchema {
        &self.schema
    }

    pub const fn public_values_len(&self) -> usize {
        self.public_values_len
    }

    pub const fn table_instance(&self) -> Option<usize> {
        self.table_instance
    }
}

/// Opaque statement export whose targets have been checked against the verifier result that
/// actually consumes them.
pub struct VerifiedStatementTargets {
    schema: StatementSchema,
    base_targets: Vec<crate::Target>,
}

impl VerifiedStatementTargets {
    /// Construct a verified-target token for an explicitly trusted custom backend.
    ///
    /// # Safety
    ///
    /// `base_targets` must be the exact existing targets consumed as AIR public values by
    /// `result` in that backend's `verified_statement_targets` implementation. They must match
    /// `schema` in canonical flattened order and must not be new lookalike public inputs.
    pub unsafe fn new_unchecked(
        schema: StatementSchema,
        base_targets: Vec<crate::Target>,
    ) -> Result<Self, VerificationError> {
        schema.validate_values(&base_targets).map_err(|error| {
            VerificationError::InvalidProofShape(alloc::format!(
                "verified statement target length does not match schema: {error}"
            ))
        })?;
        Ok(Self {
            schema,
            base_targets,
        })
    }

    pub const fn schema(&self) -> &StatementSchema {
        &self.schema
    }

    pub(crate) fn install<BF, EF>(
        self,
        builder: &mut CircuitBuilder<EF>,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        // SAFETY: the only safe constructors are the checked built-in selector below; custom
        // backends can construct this opaque token only through an explicit unsafe promise.
        unsafe {
            builder.set_statement_base_targets::<BF>(self.schema, &self.base_targets)?;
        }
        Ok(())
    }
}

pub(crate) enum ConsumedStatementTargets<'a> {
    Uni(&'a [crate::Target]),
    Batch(&'a [Vec<crate::Target>]),
}

pub(crate) fn checked_statement_targets(
    consumed: ConsumedStatementTargets<'_>,
    source: &TrustedChildStatementLayout,
) -> Result<VerifiedStatementTargets, VerificationError> {
    let targets = match (consumed, source.kind) {
        (ConsumedStatementTargets::Uni(targets), TrustedChildStatementKind::Uni) => targets,
        (ConsumedStatementTargets::Batch(_), TrustedChildStatementKind::Uni)
        | (ConsumedStatementTargets::Uni(_), TrustedChildStatementKind::Batch) => {
            return Err(VerificationError::InvalidProofShape(
                "trusted statement source kind does not match verifier result branch".into(),
            ));
        }
        (ConsumedStatementTargets::Batch(_), TrustedChildStatementKind::Batch)
            if source.table_instance.is_none() =>
        {
            &[]
        }
        (ConsumedStatementTargets::Batch(all), TrustedChildStatementKind::Batch) => all
            .get(source.table_instance.expect("checked above"))
            .map(Vec::as_slice)
            .ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "trusted statement table instance is absent from verifier inputs".into(),
                )
            })?,
    };
    if targets.len() != source.public_values_len {
        return Err(VerificationError::InvalidProofShape(alloc::format!(
            "trusted statement verifier target length mismatch: expected {}, got {}",
            source.public_values_len,
            targets.len()
        )));
    }
    Ok(VerifiedStatementTargets {
        schema: source.schema.clone(),
        base_targets: targets.to_vec(),
    })
}

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

    /// Capture allocation-relevant input shape from retained batch-verifier authority while
    /// keeping only its audited Statement values runtime-dynamic.
    fn capture_trusted_batch_input_contract(
        &self,
        verifier: &CircuitVerifier<SC>,
        proof: &BatchStarkProof<SC>,
        expected_statement: &[Val<SC>],
    ) -> Result<Self::InputContract, VerificationError>;

    /// Validate a later trusted batch witness against the retained dynamic-statement contract.
    fn validate_trusted_batch_input(
        &self,
        verifier: &CircuitVerifier<SC>,
        contract: &Self::InputContract,
        proof: &BatchStarkProof<SC>,
        expected_statement: &[Val<SC>],
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

#[cfg(test)]
mod verified_statement_target_tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::{CircuitBuilder, StatementExport};
    use p3_field::extension::BinomialExtensionField;

    use super::{ConsumedStatementTargets, TrustedChildStatementLayout, checked_statement_targets};

    /// Returning host copies, allocating lookalike inputs, or relabelling the source schema would
    /// make the selected IDs or finalized schema differ here.
    #[test]
    fn checked_statement_targets_retain_consumed_ids_and_source_schema() {
        type Ext4 = BinomialExtensionField<BabyBear, 4>;

        let mut schema_builder = CircuitBuilder::<BabyBear>::new();
        let first = schema_builder.public_input();
        let second = schema_builder.public_input();
        let schema = schema_builder
            .set_statement_exports::<BabyBear>(&[
                StatementExport::Base(first),
                StatementExport::Base(second),
            ])
            .unwrap();
        let source = TrustedChildStatementLayout::uni(2, schema.clone()).unwrap();

        let mut wrapper = CircuitBuilder::<Ext4>::new();
        let consumed = vec![wrapper.public_input(), wrapper.public_input()];
        let verified =
            checked_statement_targets(ConsumedStatementTargets::Uni(&consumed), &source).unwrap();

        assert_eq!(verified.base_targets, consumed);
        verified.install::<BabyBear, Ext4>(&mut wrapper).unwrap();
        let circuit = wrapper.build().unwrap();
        assert_eq!(circuit.statement_schema(), Some(&schema));
    }
}
