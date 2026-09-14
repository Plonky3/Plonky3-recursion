#[cfg(not(debug_assertions))]
use p3_circuit::StatementSchema;
use p3_circuit::ops::{NpoTypeId, StatementTrace, generate_recompose_trace};
#[cfg(not(debug_assertions))]
use p3_circuit::tables::Traces;
use p3_circuit::{CircuitBuilder, StatementExport};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, CircuitProverData, RecomposePreprocessor, StatementAirBuilder,
    StatementPreprocessor, StatementProver, TablePacking, recompose_air_builders,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{ConstraintProfile, config};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_test_utils::baby_bear_params::{BabyBear, BinomialExtensionField};

type EF = BinomialExtensionField<BabyBear, 4>;
const D: usize = 4;

#[cfg(not(debug_assertions))]
fn base_statement_fixture(
    value: BabyBear,
    packing: TablePacking,
) -> (
    BatchStarkProver<config::BabyBearConfig>,
    CircuitProverData<config::BabyBearConfig>,
    Traces<EF>,
    StatementSchema,
) {
    let mut builder = CircuitBuilder::<EF>::new();
    let base = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[StatementExport::Base(base)])
        .unwrap();
    let circuit = builder.build().unwrap();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, D>>> =
        vec![Box::new(StatementAirBuilder::<D>::new(schema.clone()))];
    let (airs_degrees, primitive, non_primitive) =
        get_airs_and_degrees_with_prep::<config::BabyBearConfig, _, D>(
            &circuit,
            &packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[EF::from(value)]).unwrap();
    let traces = runner.run().unwrap();
    let cfg = config::baby_bear();
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let prover_data = p3_batch_stark::ProverData::from_airs_and_degrees(&cfg, &airs, &degrees);
    let prepared = CircuitProverData::new(prover_data, primitive, non_primitive);
    let mut prover = BatchStarkProver::new(cfg).with_table_packing(packing);
    prover.register_table_prover(Box::new(StatementProver::<D>::new(schema.clone())));
    (prover, prepared, traces, schema)
}

/// Dropping the Statement AIR registration, taking values from a host-side copy, flattening in
/// the wrong basis order, or exposing an incorrect public vector makes this end-to-end proof fail.
#[test]
fn statement_base_and_extension_prove_with_actual_public_values() {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);
    let base = builder.public_input();
    let extension = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[
            StatementExport::Base(base),
            StatementExport::Extension(extension),
            StatementExport::Base(base),
        ])
        .expect("define statement");
    let circuit = builder.build().expect("build circuit");

    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = vec![
        Box::new(RecomposePreprocessor::new(true)),
        Box::new(StatementPreprocessor::new(schema.clone())),
    ];
    let mut air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, D>>> =
        recompose_air_builders(1, true);
    air_builders.push(Box::new(StatementAirBuilder::<D>::new(schema.clone())));
    let packing = TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4);
    let (airs_degrees, primitive, non_primitive) =
        get_airs_and_degrees_with_prep::<config::BabyBearConfig, _, D>(
            &circuit,
            &packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("prepare all lookup-aware AIRs");

    let extension_value = EF::from_basis_coefficients_slice(&[
        BabyBear::from_u64(11),
        BabyBear::from_u64(12),
        BabyBear::from_u64(13),
        BabyBear::from_u64(14),
    ])
    .unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[EF::from(BabyBear::from_u64(7)), extension_value])
        .unwrap();
    let traces = runner.run().expect("statement reads actual witnesses");
    let statement = traces
        .non_primitive_trace::<StatementTrace<BabyBear>>(&NpoTypeId::statement())
        .expect("statement trace");
    assert_eq!(
        statement.values,
        [7, 11, 12, 13, 14, 7].map(BabyBear::from_u64)
    );

    let cfg = config::baby_bear();
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let prover_data = p3_batch_stark::ProverData::from_airs_and_degrees(&cfg, &airs, &degrees);
    let prepared = CircuitProverData::new(prover_data, primitive, non_primitive);
    let mut prover = BatchStarkProver::new(cfg).with_table_packing(packing);
    prover.register_recompose_table::<D>(true);
    prover.register_table_prover(Box::new(StatementProver::<D>::new(schema)));
    let proof = prover
        .prove_all_tables(&traces, &prepared)
        .expect("prove statement and its witness lookups");
    prover
        .verify_all_tables::<EF>(&proof)
        .expect("verify statement and its witness lookups");

    let statement_entry = proof
        .non_primitives
        .iter()
        .find(|entry| entry.op_type.as_str() == "statement")
        .expect("statement metadata");
    assert_eq!(statement_entry.public_values, statement.values);
    assert_eq!(statement_entry.rows, 1);
    assert_eq!(statement_entry.lanes, 1);
}

/// If the Statement lookup omits its high zero limbs, this forged Public creator tuple verifies.
#[test]
#[cfg(not(debug_assertions))]
fn statement_base_export_rejects_every_nonzero_high_limb_in_a_native_batch_proof() {
    for high_limb in 1..D {
        let (prover, prepared, mut traces, _) = base_statement_fixture(
            BabyBear::from_u64(7),
            TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4),
        );
        traces.public_trace.values[0] = EF::from_basis_coefficients_fn(|limb| {
            if limb == 0 || limb == high_limb {
                BabyBear::from_u64(7)
            } else {
                BabyBear::ZERO
            }
        });

        let proof = prover
            .prove_all_tables(&traces, &prepared)
            .expect("the algebraic prover constructs a forged proof candidate");
        assert!(
            prover.verify_all_tables::<EF>(&proof).is_err(),
            "high limb {high_limb} must be rejected by the full WitnessChecks tuple"
        );
    }
}

/// If Statement values come from a separate host vector, changing the actual sink row can pass.
/// Here the changed value becomes the table's public input, so rejection is specifically the CTL
/// mismatch against the unchanged source table.
#[test]
#[cfg(not(debug_assertions))]
fn statement_value_tampering_reaches_native_verifier_and_is_rejected_by_ctl() {
    let (prover, prepared, mut traces, _) = base_statement_fixture(
        BabyBear::from_u64(7),
        TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4),
    );
    let mut statement = traces
        .non_primitive_trace::<StatementTrace<BabyBear>>(&NpoTypeId::statement())
        .unwrap()
        .clone();
    statement.values[0] = BabyBear::from_u64(99);
    traces
        .non_primitive_traces
        .insert(NpoTypeId::statement(), Box::new(statement));

    let proof = prover
        .prove_all_tables(&traces, &prepared)
        .expect("the algebraic prover constructs a forged proof candidate");
    assert!(prover.verify_all_tables::<EF>(&proof).is_err());
}

/// The statement index is part of the committed preparation; changing the regenerated AIR while
/// retaining the original `ProverData` key must not yield a verifying proof.
#[test]
#[cfg(not(debug_assertions))]
fn statement_index_tampering_is_rejected_under_the_original_preparation() {
    let (prover, mut prepared, traces, _) = base_statement_fixture(
        BabyBear::from_u64(7),
        TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4),
    );
    prepared
        .non_primitive_columns
        .get_mut(&NpoTypeId::statement())
        .unwrap()[1] += BabyBear::from_u64(D as u64);

    let proof = prover
        .prove_all_tables(&traces, &prepared)
        .expect("the algebraic prover constructs a forged proof candidate");
    assert!(prover.verify_all_tables::<EF>(&proof).is_err());
}

/// Producer multiplicity is committed too. Decrementing the Public creator count while retaining
/// the original preparation commitment must be rejected rather than balanced by Statement.
#[test]
#[cfg(not(debug_assertions))]
fn statement_multiplicity_tampering_is_rejected_under_the_original_preparation() {
    let (prover, mut prepared, traces, _) = base_statement_fixture(
        BabyBear::from_u64(7),
        TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4),
    );
    prepared.primitive_columns[1][0] = BabyBear::ZERO;

    let proof = prover
        .prove_all_tables(&traces, &prepared)
        .expect("the algebraic prover constructs a forged proof candidate");
    assert!(prover.verify_all_tables::<EF>(&proof).is_err());
}

#[test]
fn statement_lane_override_is_rejected() {
    let packing = TablePacking::default().with_npo_lanes(NpoTypeId::statement(), 2);
    assert!(packing.validate().is_err());
}
