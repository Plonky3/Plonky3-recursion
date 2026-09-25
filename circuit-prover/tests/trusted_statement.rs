use std::borrow::Cow;

#[cfg(debug_assertions)]
use p3_air::DebugConstraintBuilder;
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_batch_stark::StarkGenericConfig;
use p3_batch_stark::folder::{
    ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups,
};
use p3_circuit::ops::{NonPrimitivePreprocessedMap, NpoTypeId, generate_recompose_trace};
use p3_circuit::tables::Traces;
use p3_circuit::{
    Circuit, CircuitBuilder, CircuitError, PreprocessedColumns, StatementError, StatementExport,
    StatementSchema,
};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, BatchStarkProverError, BatchTableInstance, DynamicAirEntry,
    NonPrimitiveTableEntry, PreparedCircuitProver, RecomposeAirBuilder, RecomposePreprocessor,
    RecomposeProver, StatementAirBuilder, StatementPreprocessor, StatementProver, TablePacking,
    TableProver, recompose_air_builders,
};
use p3_circuit_prover::common::{
    BuiltNpoTable, CircuitTableAir, NpoAirBuilder, NpoPreprocessor, NpoRelation,
};
use p3_circuit_prover::{AirVariant, ConstraintProfile, config};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{Algebra, BasedVectorSpace, PrimeCharacteristicRing};
use p3_lookup::symbolic::InteractionSymbolicBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_test_utils::corpus::{CaseRng, CorpusSpec, derive_family_seed, for_each_case};
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};

type EF = BinomialExtensionField<BabyBear, 4>;
type SC = config::BabyBearConfig;
const D: usize = 4;
const STATIC_RECOMPOSE_VALUE: BabyBear = BabyBear::new(42);
const MAX_ASSURANCE_PROOF_CASES: u32 = 8;

fn assurance_proof_corpus_from_env() -> CorpusSpec {
    let start_seed = std::env::var("P3_ASSURANCE_START_SEED")
        .ok()
        .map_or(Ok(0), |raw| {
            raw.parse::<u64>()
                .map_err(|_| format!("P3_ASSURANCE_START_SEED must be a u64, got {raw:?}"))
        })
        .unwrap_or_else(|error| panic!("{error}"));
    let cases = std::env::var("P3_ASSURANCE_PROOF_CASES")
        .ok()
        .map_or(Ok(1), |raw| {
            raw.parse::<u32>().map_err(|_| {
                format!(
                    "P3_ASSURANCE_PROOF_CASES must be a u32 in 1..={MAX_ASSURANCE_PROOF_CASES}, got {raw:?}"
                )
            })
        })
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        (1..=MAX_ASSURANCE_PROOF_CASES).contains(&cases),
        "P3_ASSURANCE_PROOF_CASES must be in 1..={MAX_ASSURANCE_PROOF_CASES}, got {cases}"
    );
    CorpusSpec { start_seed, cases }
}

#[derive(Clone)]
struct OnePublicValueAir {
    inner: DynamicAirEntry<SC>,
}

impl OnePublicValueAir {
    const fn new(inner: DynamicAirEntry<SC>) -> Self {
        Self { inner }
    }
}

impl BaseAir<BabyBear> for OnePublicValueAir {
    fn width(&self) -> usize {
        BaseAir::<BabyBear>::width(&self.inner)
    }

    fn num_public_values(&self) -> usize {
        1
    }

    fn preprocessed_width(&self) -> usize {
        BaseAir::<BabyBear>::preprocessed_width(&self.inner)
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BabyBear>> {
        BaseAir::<BabyBear>::preprocessed_trace(&self.inner)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        BaseAir::<BabyBear>::main_next_row_columns(&self.inner)
    }

    fn num_periodic_columns(&self) -> usize {
        BaseAir::<BabyBear>::num_periodic_columns(&self.inner)
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<BabyBear>]> {
        BaseAir::<BabyBear>::periodic_columns(&self.inner)
    }
}

macro_rules! forward_air {
    ($(#[$cfg:meta])? $builder:ty) => {
        $(#[$cfg])?
        impl Air<$builder> for OnePublicValueAir {
            fn eval(&self, builder: &mut $builder) {
                <DynamicAirEntry<SC> as Air<$builder>>::eval(&self.inner, builder);
            }
        }
    };
}

forward_air!(InteractionSymbolicBuilder<BabyBear, <SC as StarkGenericConfig>::Challenge>);
#[cfg(debug_assertions)]
impl<'a> Air<DebugConstraintBuilder<'a, BabyBear, <SC as StarkGenericConfig>::Challenge>>
    for OnePublicValueAir
{
    fn eval(
        &self,
        builder: &mut DebugConstraintBuilder<'a, BabyBear, <SC as StarkGenericConfig>::Challenge>,
    ) {
        <DynamicAirEntry<SC> as Air<_>>::eval(&self.inner, builder);
    }
}
impl<'a> Air<ProverConstraintFolderWithLookups<'a, SC>> for OnePublicValueAir {
    fn eval(&self, builder: &mut ProverConstraintFolderWithLookups<'a, SC>) {
        <DynamicAirEntry<SC> as Air<_>>::eval(&self.inner, builder);
    }
}
impl<'a> Air<VerifierConstraintFolderWithLookups<'a, SC>> for OnePublicValueAir {
    fn eval(&self, builder: &mut VerifierConstraintFolderWithLookups<'a, SC>) {
        <DynamicAirEntry<SC> as Air<_>>::eval(&self.inner, builder);
    }
}

impl p3_circuit_prover::batch_stark_prover::BatchAir<SC> for OnePublicValueAir {}

fn one_public_value_air(air: DynamicAirEntry<SC>) -> DynamicAirEntry<SC> {
    DynamicAirEntry::new(Box::new(OnePublicValueAir::new(air)))
}

struct StaticPublicRecomposeAirBuilder {
    inner: RecomposeAirBuilder<D>,
}

impl StaticPublicRecomposeAirBuilder {
    fn new() -> Self {
        Self {
            inner: RecomposeAirBuilder::new(1, true),
        }
    }
}

impl NpoAirBuilder<SC, D> for StaticPublicRecomposeAirBuilder {
    fn lanes(&self) -> usize {
        1
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[BabyBear],
        min_height: usize,
        lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, D>, usize)> {
        let (air, degree) = <RecomposeAirBuilder<D> as NpoAirBuilder<SC, D>>::try_build(
            &self.inner,
            op_type,
            prep_base,
            min_height,
            lanes,
            constraint_profile,
        )?;
        let CircuitTableAir::Dynamic(air) = air else {
            unreachable!("recompose always builds a dynamic AIR")
        };
        Some((CircuitTableAir::Dynamic(one_public_value_air(air)), degree))
    }

    fn try_build_trusted(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[BabyBear],
        min_height: usize,
        lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<BuiltNpoTable<SC, D>> {
        let (air, degree) =
            self.try_build(op_type, prep_base, min_height, lanes, constraint_profile)?;
        Some(BuiltNpoTable::new(
            air,
            degree,
            NpoRelation::new(
                op_type.clone(),
                prep_base.len() / (2 + 2 * D),
                lanes,
                AirVariant::Baseline,
                vec![STATIC_RECOMPOSE_VALUE],
            ),
        ))
    }
}

struct StaticPublicRecomposeProver {
    inner: RecomposeProver<D>,
}

impl StaticPublicRecomposeProver {
    fn new() -> Self {
        Self {
            inner: RecomposeProver::new(1, true),
        }
    }

    fn with_static_public_value(
        &self,
        mut instance: BatchTableInstance<SC>,
    ) -> BatchTableInstance<SC> {
        instance.air = one_public_value_air(instance.air);
        instance.public_values = vec![STATIC_RECOMPOSE_VALUE];
        instance
    }
}

macro_rules! forward_static_public_instance {
    ($method:ident, $trace_field:ty) => {
        fn $method(
            &self,
            config: &SC,
            packing: &TablePacking,
            traces: &Traces<$trace_field>,
        ) -> Option<BatchTableInstance<SC>> {
            <RecomposeProver<D> as TableProver<SC>>::$method(&self.inner, config, packing, traces)
                .map(|instance| self.with_static_public_value(instance))
        }
    };
}

impl TableProver<SC> for StaticPublicRecomposeProver {
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::recompose_with_coeff_lookups()
    }

    fn lanes(&self) -> usize {
        1
    }

    forward_static_public_instance!(batch_instance_d1, BabyBear);
    forward_static_public_instance!(
        batch_instance_d2,
        BinomialExtensionField<BabyBear, 2>
    );
    forward_static_public_instance!(
        batch_instance_d4,
        BinomialExtensionField<BabyBear, 4>
    );
    forward_static_public_instance!(
        batch_instance_d6,
        BinomialExtensionField<BabyBear, 6>
    );
    forward_static_public_instance!(
        batch_instance_d8,
        BinomialExtensionField<BabyBear, 8>
    );

    fn batch_air_from_table_entry(
        &self,
        config: &SC,
        degree: usize,
        circuit_extension_degree: u32,
        table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        <RecomposeProver<D> as TableProver<SC>>::batch_air_from_table_entry(
            &self.inner,
            config,
            degree,
            circuit_extension_degree,
            table_entry,
        )
        .map(one_public_value_air)
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<BabyBear>,
        min_height: usize,
        lanes: usize,
        circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        <RecomposeProver<D> as TableProver<SC>>::air_with_committed_preprocessed(
            &self.inner,
            committed_prep,
            min_height,
            lanes,
            circuit_extension_degree,
        )
        .map(one_public_value_air)
    }
}

fn prepare_statement_circuit() -> (Circuit<EF>, StatementSchema, PreparedCircuitProver<SC>) {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);
    let base = builder.public_input();
    let extension = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[
            StatementExport::Base(base),
            StatementExport::Extension(extension),
        ])
        .unwrap();
    let circuit = builder.build().unwrap();

    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = vec![
        Box::new(RecomposePreprocessor::new(true)),
        Box::new(StatementPreprocessor::new(schema.clone())),
    ];
    let mut air_builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> = recompose_air_builders(1, true);
    air_builders.push(Box::new(StatementAirBuilder::<D>::new(schema.clone())));
    let mut prover = BatchStarkProver::new(config::baby_bear())
        .with_table_packing(TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4));
    prover.register_recompose_table::<D>(true);
    prover.register_table_prover(Box::new(StatementProver::<D>::new(schema.clone())));
    let prepared = prover
        .prepare_circuit::<EF, D>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    (circuit, schema, prepared)
}

fn prepare_statement_circuit_with_static_public_npo() -> (Circuit<EF>, PreparedCircuitProver<SC>) {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);
    let base = builder.public_input();
    let extension = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[
            StatementExport::Base(base),
            StatementExport::Extension(extension),
        ])
        .unwrap();
    let circuit = builder.build().unwrap();

    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = vec![
        Box::new(RecomposePreprocessor::new(true)),
        Box::new(StatementPreprocessor::new(schema.clone())),
    ];
    let air_builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> = vec![
        Box::new(RecomposeAirBuilder::<D>::new(1, false)),
        Box::new(StaticPublicRecomposeAirBuilder::new()),
        Box::new(StatementAirBuilder::<D>::new(schema.clone())),
    ];
    let mut prover = BatchStarkProver::new(config::baby_bear())
        .with_table_packing(TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4));
    prover.register_table_prover(Box::new(RecomposeProver::<D>::new(1, false)));
    prover.register_table_prover(Box::new(StaticPublicRecomposeProver::new()));
    prover.register_table_prover(Box::new(StatementProver::<D>::new(schema)));
    let prepared = prover
        .prepare_circuit::<EF, D>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    (circuit, prepared)
}

fn traces(circuit: &Circuit<EF>, base: u32, extension: [u32; D]) -> p3_circuit::tables::Traces<EF> {
    let extension = EF::from_basis_coefficients_slice(&extension.map(BabyBear::from_u32)).unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[EF::from(BabyBear::from_u32(base)), extension])
        .unwrap();
    runner.run().unwrap()
}

#[test]
fn one_trusted_preparation_proves_two_distinct_runtime_statements() {
    let (circuit, schema, prepared) = prepare_statement_circuit();

    let first = prepared
        .prove(&traces(&circuit, 7, [11, 12, 13, 14]))
        .unwrap();
    let second = prepared
        .prove(&traces(&circuit, 9, [21, 22, 23, 24]))
        .unwrap();
    let expected_first = [7, 11, 12, 13, 14].map(BabyBear::from_u32);
    let expected_second = [9, 21, 22, 23, 24].map(BabyBear::from_u32);

    assert_eq!(prepared.verifier().statement_layout().schema(), &schema);
    assert_eq!(
        prepared.verifier().statement_layout().table_instance(),
        Some(4),
        "the coefficient-aware recompose table precedes Statement"
    );
    assert_eq!(
        first.stark_common.preprocessed.as_ref().unwrap().commitment,
        second
            .stark_common
            .preprocessed
            .as_ref()
            .unwrap()
            .commitment
    );

    let verifier = prepared.verifier();
    assert_eq!(
        first
            .non_primitives
            .iter()
            .find(|entry| entry.op_type == NpoTypeId::statement())
            .unwrap()
            .public_values,
        expected_first
    );
    assert_eq!(
        second
            .non_primitives
            .iter()
            .find(|entry| entry.op_type == NpoTypeId::statement())
            .unwrap()
            .public_values,
        expected_second
    );
    drop(prepared);
    verifier.verify(&first, &expected_first).unwrap();
    verifier.verify(&second, &expected_second).unwrap();

    let first_table_values = verifier.table_public_values(&expected_first).unwrap();
    assert_eq!(first_table_values.len(), 5);
    assert_eq!(first_table_values[3], Vec::<BabyBear>::new());
    assert_eq!(first_table_values[4], expected_first);
}

fn check_trusted_verifier_rejects_seeded_statement_scalar_order_and_length(
    corpus: CorpusSpec,
    fixed_values: Option<(u32, [u32; D])>,
    fixed_scalar_mutation: Option<(usize, u32)>,
) {
    let (circuit, _schema, prepared) = prepare_statement_circuit();
    let verifier = prepared.verifier();

    for_each_case(corpus, |seed| {
        let mut rng = CaseRng::new(derive_family_seed(seed, 0x5354_4154_454d_454e));
        let (base, extension) = fixed_values.unwrap_or_else(|| {
            let base = 1 + (rng.next_u64() % 1000) as u32;
            (base, [base + 1, base + 2, base + 3, base + 4])
        });
        let honest =
            [base, extension[0], extension[1], extension[2], extension[3]].map(BabyBear::from_u32);
        let proof = prepared.prove(&traces(&circuit, base, extension)).unwrap();
        verifier.verify(&proof, &honest).unwrap_or_else(|error| {
            panic!(
                "family=trusted-statement field=BabyBear/D4 seed={seed} mutation=none expected-stage=native-accept error={error:?}"
            )
        });

        let (scalar_index, scalar_value) = fixed_scalar_mutation.map_or_else(
            || {
                let index = (rng.next_u64() as usize) % honest.len();
                (index, honest[index] + BabyBear::ONE)
            },
            |(index, value)| (index, BabyBear::from_u32(value)),
        );
        let mut wrong_scalar = honest;
        wrong_scalar[scalar_index] = scalar_value;
        if fixed_scalar_mutation.is_some() {
            assert_eq!(
                (scalar_index, wrong_scalar[2]),
                (2, BabyBear::from_u32(99)),
                "the named fixed regression must preserve the original index-2/value-99 mutation"
            );
        }
        let error = verifier.verify(&proof, &wrong_scalar).unwrap_err();
        assert!(
            matches!(
                &error,
                BatchStarkProverError::RelationMismatch(message)
                    if message == "attached Statement values differ from the caller's expected statement"
            ),
            "family=trusted-statement field=BabyBear/D4 seed={seed} mutation=caller-scalar expected-stage=relation-mismatch error={error:?}"
        );

        let mut wrong_order = honest;
        wrong_order.swap(1, 4);
        assert!(
            matches!(
                verifier.verify(&proof, &wrong_order),
                Err(BatchStarkProverError::RelationMismatch(_))
            ),
            "family=trusted-statement field=BabyBear/D4 seed={seed} mutation=caller-order expected-stage=relation-mismatch"
        );

        assert_eq!(
            verifier.table_public_values(&honest[..4]),
            Err(StatementError::ValueLengthMismatch {
                expected: 5,
                got: 4,
            }),
            "family=trusted-statement field=BabyBear/D4 seed={seed} mutation=caller-length expected-stage=statement-schema"
        );
        let error = verifier.verify(&proof, &honest[..4]).unwrap_err();
        assert!(
            matches!(
                &error,
                BatchStarkProverError::RelationMismatch(message)
                    if message == "statement value length mismatch: expected 5, got 4"
            ),
            "family=trusted-statement field=BabyBear/D4 seed={seed} mutation=caller-length expected-stage=relation-mismatch error={error:?}"
        );
    });
}

#[test]
fn trusted_verifier_rejects_wrong_statement_value_order_and_length() {
    check_trusted_verifier_rejects_seeded_statement_scalar_order_and_length(
        CorpusSpec {
            start_seed: 0,
            cases: 1,
        },
        Some((7, [11, 12, 13, 14])),
        Some((2, 99)),
    );
}

#[test]
fn assurance_trusted_verifier_rejects_seeded_statement_scalar_order_and_length() {
    check_trusted_verifier_rejects_seeded_statement_scalar_order_and_length(
        assurance_proof_corpus_from_env(),
        None,
        None,
    );
}

#[test]
fn caller_values_bind_cryptographically_when_attached_metadata_diagnostics_are_bypassed() {
    let (circuit, _schema, prepared) = prepare_statement_circuit();
    let proof = prepared
        .prove(&traces(&circuit, 7, [11, 12, 13, 14]))
        .unwrap();
    let verifier = prepared.verifier();
    let wrong = [7, 11, 99, 13, 14].map(BabyBear::from_u32);
    let airs = verifier.table_airs::<D>().unwrap();
    let table_public_values = verifier.table_public_values(&wrong).unwrap();

    let result = p3_batch_stark::verify_batch(
        verifier.config(),
        &airs,
        &proof.proof,
        &table_public_values,
        verifier.common_data(),
    );
    assert!(
        result.is_err(),
        "the retained AIR/key must reject wrong caller values without metadata diagnostics"
    );
}

#[test]
fn attached_statement_replacement_and_static_npo_values_are_not_adopted() {
    let (circuit, _schema, prepared) = prepare_statement_circuit();
    let mut proof = prepared
        .prove(&traces(&circuit, 7, [11, 12, 13, 14]))
        .unwrap();
    let verifier = prepared.verifier();
    let honest = [7, 11, 12, 13, 14].map(BabyBear::from_u32);

    let replacement = [9, 21, 22, 23, 24].map(BabyBear::from_u32);
    proof
        .non_primitives
        .iter_mut()
        .find(|entry| entry.op_type == NpoTypeId::statement())
        .unwrap()
        .public_values = replacement.to_vec();
    assert!(verifier.verify(&proof, &honest).is_err());
    assert!(verifier.verify(&proof, &replacement).is_err());

    proof
        .non_primitives
        .iter_mut()
        .find(|entry| entry.op_type == NpoTypeId::statement())
        .unwrap()
        .public_values = honest.to_vec();
    let static_recompose = proof
        .non_primitives
        .iter_mut()
        .find(|entry| entry.op_type == NpoTypeId::recompose_with_coeff_lookups())
        .unwrap();
    static_recompose.public_values.push(BabyBear::ONE);
    assert!(verifier.verify(&proof, &honest).is_err());
}

fn check_same_length_static_npo_value_substitution_is_rejected(
    corpus: CorpusSpec,
    fixed_values: Option<(u32, [u32; D])>,
) {
    let (circuit, prepared) = prepare_statement_circuit_with_static_public_npo();
    let verifier = prepared.verifier();

    for_each_case(corpus, |seed| {
        let mut rng = CaseRng::new(derive_family_seed(seed, 0x4e50_4f5f_5055_424c));
        let (base, extension) = fixed_values.unwrap_or_else(|| {
            let base = 1 + (rng.next_u64() % 1000) as u32;
            (base, [base + 1, base + 2, base + 3, base + 4])
        });
        let honest_statement =
            [base, extension[0], extension[1], extension[2], extension[3]].map(BabyBear::from_u32);
        let mut proof = prepared.prove(&traces(&circuit, base, extension)).unwrap();
        let static_recompose = proof
            .non_primitives
            .iter()
            .find(|entry| entry.op_type == NpoTypeId::recompose_with_coeff_lookups())
            .unwrap();

        assert_eq!(
            static_recompose.public_values,
            [STATIC_RECOMPOSE_VALUE],
            "family=trusted-npo field=BabyBear/D4 seed={seed} mutation=none expected-stage=setup"
        );
        verifier
            .verify(&proof, &honest_statement)
            .unwrap_or_else(|error| {
                panic!(
                    "family=trusted-npo field=BabyBear/D4 seed={seed} mutation=none expected-stage=native-accept error={error:?}"
                )
            });

        proof
            .non_primitives
            .iter_mut()
            .find(|entry| entry.op_type == NpoTypeId::recompose_with_coeff_lookups())
            .unwrap()
            .public_values[0] = BabyBear::new(43);
        let error = verifier.verify(&proof, &honest_statement).unwrap_err();
        assert!(
            matches!(
                &error,
                BatchStarkProverError::RelationMismatch(message)
                    if message == "submitted NPO metadata differs at index 0"
            ),
            "family=trusted-npo field=BabyBear/D4 seed={seed} mutation=static-public-value expected-stage=relation-mismatch error={error:?}"
        );
    });
}

#[test]
fn same_length_static_npo_value_substitution_is_rejected() {
    check_same_length_static_npo_value_substitution_is_rejected(
        CorpusSpec {
            start_seed: 0,
            cases: 1,
        },
        Some((7, [11, 12, 13, 14])),
    );
}

#[test]
fn assurance_same_length_static_npo_value_substitution_is_rejected() {
    check_same_length_static_npo_value_substitution_is_rejected(
        assurance_proof_corpus_from_env(),
        None,
    );
}

struct ForgedStatementAirBuilder {
    schema: StatementSchema,
}

impl NpoAirBuilder<SC, D> for ForgedStatementAirBuilder
where
    SymbolicExpressionExt<BabyBear, <SC as p3_uni_stark::StarkGenericConfig>::Challenge>: Algebra<SymbolicExpression<BabyBear>>
        + Algebra<<SC as p3_uni_stark::StarkGenericConfig>::Challenge>,
{
    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[BabyBear],
        min_height: usize,
        lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, D>, usize)> {
        <StatementAirBuilder<D> as NpoAirBuilder<SC, D>>::try_build(
            &StatementAirBuilder::new(self.schema.clone()),
            op_type,
            prep_base,
            min_height,
            lanes,
            constraint_profile,
        )
    }

    fn try_build_trusted(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[BabyBear],
        min_height: usize,
        lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<BuiltNpoTable<SC, D>> {
        <StatementAirBuilder<D> as NpoAirBuilder<SC, D>>::try_build_trusted(
            &StatementAirBuilder::new(self.schema.clone()),
            op_type,
            prep_base,
            min_height,
            lanes,
            constraint_profile,
        )
    }
}

#[test]
fn forged_same_name_builder_cannot_mint_dynamic_statement_policy() {
    let mut builder = CircuitBuilder::<EF>::new();
    let value = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[StatementExport::Base(value)])
        .unwrap();
    let circuit = builder.build().unwrap();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> =
        vec![Box::new(ForgedStatementAirBuilder {
            schema: schema.clone(),
        })];
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(StatementProver::<D>::new(schema)));

    let error = prover
        .prepare_circuit::<EF, D>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .err()
        .expect("delegating through a same-name custom builder must be rejected");
    assert!(matches!(
        error,
        BatchStarkProverError::RelationMismatch(message)
            if message.contains("only the built-in Statement AIR builder")
    ));
}

struct ForgedStatementProver(StatementProver<D>);

impl TableProver<SC> for ForgedStatementProver {
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::statement()
    }

    fn batch_instance_d1(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<BabyBear>,
    ) -> Option<BatchTableInstance<SC>> {
        self.0.batch_instance_d1(config, packing, traces)
    }

    fn batch_instance_d2(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<BabyBear, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.0.batch_instance_d2(config, packing, traces)
    }

    fn batch_instance_d4(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<BabyBear, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.0.batch_instance_d4(config, packing, traces)
    }

    fn batch_instance_d6(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<BabyBear, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.0.batch_instance_d6(config, packing, traces)
    }

    fn batch_instance_d8(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<BabyBear, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.0.batch_instance_d8(config, packing, traces)
    }

    fn batch_instance_d5(
        &self,
        config: &SC,
        packing: &TablePacking,
        traces: &Traces<QuinticTrinomialExtensionField<BabyBear>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.0.batch_instance_d5(config, packing, traces)
    }

    fn batch_air_from_table_entry(
        &self,
        config: &SC,
        degree: usize,
        circuit_extension_degree: u32,
        table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        self.0
            .batch_air_from_table_entry(config, degree, circuit_extension_degree, table_entry)
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<BabyBear>,
        min_height: usize,
        lanes: usize,
        circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        self.0.air_with_committed_preprocessed(
            committed_prep,
            min_height,
            lanes,
            circuit_extension_degree,
        )
    }
}

#[test]
fn forged_same_name_table_prover_cannot_consume_dynamic_statement_policy() {
    let mut builder = CircuitBuilder::<EF>::new();
    let value = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[StatementExport::Base(value)])
        .unwrap();
    let circuit = builder.build().unwrap();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> =
        vec![Box::new(StatementAirBuilder::<D>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(ForgedStatementProver(StatementProver::<D>::new(
        schema,
    ))));

    let error = prover
        .prepare_circuit::<EF, D>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .err()
        .expect("a same-name custom table prover must be rejected");
    assert!(matches!(
        error,
        BatchStarkProverError::RelationMismatch(message)
            if message.contains("only the built-in Statement table prover")
    ));
}

struct StatementMappingTamper;

impl NpoPreprocessor<BabyBear> for StatementMappingTamper {
    fn preprocess(
        &self,
        _circuit: &dyn core::any::Any,
        preprocessed: &mut dyn core::any::Any,
    ) -> Result<NonPrimitivePreprocessedMap<BabyBear>, CircuitError> {
        let preprocessed = preprocessed
            .downcast_mut::<PreprocessedColumns<EF, D>>()
            .unwrap();
        preprocessed
            .non_primitive
            .get_mut(&NpoTypeId::statement())
            .unwrap()[1] += EF::ONE;
        Ok(NonPrimitivePreprocessedMap::new())
    }
}

#[test]
fn unrelated_preprocessor_cannot_replace_the_circuit_minted_statement_mapping() {
    let mut builder = CircuitBuilder::<EF>::new();
    let value = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[StatementExport::Base(value)])
        .unwrap();
    let circuit = builder.build().unwrap();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = vec![
        Box::new(StatementMappingTamper),
        Box::new(StatementPreprocessor::new(schema.clone())),
    ];
    let air_builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> =
        vec![Box::new(StatementAirBuilder::<D>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(StatementProver::<D>::new(schema)));

    let error = prover
        .prepare_circuit::<EF, D>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .err()
        .expect("a custom preprocessor must not replace canonical Statement indices");
    assert!(matches!(
        error,
        BatchStarkProverError::RelationMismatch(message)
            if message.contains("changed the circuit-minted Statement mapping")
    ));
}

#[test]
fn empty_schema_has_no_statement_table_and_rejects_nonempty_expectation() {
    assert_eq!(StatementSchema::default().base_len(), 0);
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[])
        .expect("an explicitly empty schema is still defined once");
    let circuit = builder.build().unwrap();
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let proof = prepared.prove(&circuit.runner().run().unwrap()).unwrap();
    let verifier = prepared.verifier();

    assert_eq!(verifier.statement_layout().schema(), &schema);
    assert_eq!(verifier.statement_layout().table_instance(), None);
    verifier.verify(&proof, &[]).unwrap();
    assert!(verifier.verify(&proof, &[BabyBear::ONE]).is_err());
}

#[test]
fn native_verifier_retains_nonempty_ordered_aggregation_schema_boundary() {
    let mut left_builder = CircuitBuilder::<EF>::new();
    let left_value = left_builder.public_input();
    let left = left_builder
        .set_statement_exports::<BabyBear>(&[StatementExport::Base(left_value)])
        .unwrap();

    let mut right_builder = CircuitBuilder::<EF>::new();
    right_builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);
    let right_value = right_builder.public_input();
    let right = right_builder
        .set_statement_exports::<BabyBear>(&[StatementExport::Extension(right_value)])
        .unwrap();

    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);
    let base = builder.public_input();
    let extension = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[
            StatementExport::Base(base),
            StatementExport::Extension(extension),
        ])
        .unwrap();
    let layout = builder
        .set_aggregation_statement_layout(left, right)
        .expect("the parent schema is the exact ordered child concatenation");
    let circuit = builder.build().unwrap();

    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = vec![
        Box::new(RecomposePreprocessor::new(true)),
        Box::new(StatementPreprocessor::new(schema.clone())),
    ];
    let mut air_builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> = recompose_air_builders(1, true);
    air_builders.push(Box::new(StatementAirBuilder::<D>::new(schema.clone())));
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_recompose_table::<D>(true);
    prover.register_table_prover(Box::new(StatementProver::<D>::new(schema)));
    let prepared = prover
        .prepare_circuit::<EF, D>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();

    assert_eq!(
        prepared.verifier().aggregation_statement_layout(),
        Some(&layout)
    );
}
