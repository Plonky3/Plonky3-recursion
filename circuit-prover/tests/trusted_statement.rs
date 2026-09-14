use p3_baby_bear::BabyBear;
use p3_circuit::ops::{NonPrimitivePreprocessedMap, NpoTypeId, generate_recompose_trace};
use p3_circuit::tables::Traces;
use p3_circuit::{
    Circuit, CircuitBuilder, CircuitError, PreprocessedColumns, StatementExport, StatementSchema,
};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, BatchStarkProverError, BatchTableInstance, DynamicAirEntry,
    NonPrimitiveTableEntry, PreparedCircuitProver, RecomposePreprocessor, StatementAirBuilder,
    StatementPreprocessor, StatementProver, TablePacking, TableProver, recompose_air_builders,
};
use p3_circuit_prover::common::{BuiltNpoTable, CircuitTableAir, NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{ConstraintProfile, config};
use p3_field::extension::QuinticTrinomialExtensionField;
use p3_field::{Algebra, BasedVectorSpace, PrimeCharacteristicRing};
use p3_test_utils::baby_bear_params::BinomialExtensionField;
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};

type EF = BinomialExtensionField<BabyBear, 4>;
type SC = config::BabyBearConfig;
const D: usize = 4;

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

#[test]
fn trusted_verifier_rejects_wrong_statement_value_order_and_length() {
    let (circuit, _schema, prepared) = prepare_statement_circuit();
    let proof = prepared
        .prove(&traces(&circuit, 7, [11, 12, 13, 14]))
        .unwrap();
    let verifier = prepared.verifier();
    let honest = [7, 11, 12, 13, 14].map(BabyBear::from_u32);
    verifier.verify(&proof, &honest).unwrap();

    let mut wrong_scalar = honest;
    wrong_scalar[2] = BabyBear::from_u32(99);
    assert!(verifier.verify(&proof, &wrong_scalar).is_err());

    let mut wrong_order = honest;
    wrong_order.swap(1, 4);
    assert!(verifier.verify(&proof, &wrong_order).is_err());

    assert!(verifier.verify(&proof, &honest[..4]).is_err());
    assert!(verifier.table_public_values(&honest[..4]).is_err());
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
