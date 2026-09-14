#[cfg(debug_assertions)]
use std::any::Any;
#[cfg(debug_assertions)]
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use p3_circuit::ops::{NpoTypeId, StatementTrace, generate_recompose_trace};
use p3_circuit::tables::Traces;
use p3_circuit::{CircuitBuilder, StatementExport, StatementField, StatementSchema};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, CircuitProverData, RecomposePreprocessor, StatementAirBuilder,
    StatementPreprocessor, StatementProver, TablePacking, recompose_air_builders,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{BatchStarkProverError, ConstraintProfile, config};
use p3_commit::ExtensionMmcs;
use p3_field::extension::QuinticTrinomialExtensionField;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_test_utils::baby_bear_params::{BabyBear, BinomialExtensionField};
use p3_test_utils::koala_bear_params::{
    Challenge, Challenger, DIGEST_ELEMS, Dft, MyCompress, MyHash,
};
use p3_test_utils::rejection_oracle::DebugRejectionKind;
#[cfg(debug_assertions)]
use p3_test_utils::rejection_oracle::classify_debug_diagnostic;
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Serialize;

type EF = BinomialExtensionField<BabyBear, 4>;
const D: usize = 4;

#[derive(Serialize)]
struct UncheckedStatementSchema {
    fields: Vec<StatementField>,
    base_len: usize,
}

#[test]
fn statement_schema_deserialization_recomputes_and_validates_width() {
    let malformed = UncheckedStatementSchema {
        fields: vec![StatementField::Extension { degree: 4 }],
        base_len: 1,
    };
    let encoded = postcard::to_allocvec(&malformed).unwrap();
    assert!(postcard::from_bytes::<StatementSchema>(&encoded).is_err());

    let overflowing = UncheckedStatementSchema {
        fields: vec![
            StatementField::Extension { degree: usize::MAX },
            StatementField::Base,
        ],
        base_len: usize::MAX,
    };
    let encoded = postcard::to_allocvec(&overflowing).unwrap();
    assert!(postcard::from_bytes::<StatementSchema>(&encoded).is_err());

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
    let encoded = postcard::to_allocvec(&schema).unwrap();
    assert_eq!(
        postcard::from_bytes::<StatementSchema>(&encoded).unwrap(),
        schema
    );
}

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

#[cfg(debug_assertions)]
fn classify_debug_panic(payload: &(dyn Any + Send)) -> Option<DebugRejectionKind> {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())?;
    classify_debug_diagnostic(message)
}

fn assert_rejected_as(
    context: &str,
    expected: DebugRejectionKind,
    check: impl FnOnce() -> Result<(), BatchStarkProverError>,
) {
    #[cfg(debug_assertions)]
    match catch_unwind(AssertUnwindSafe(check)) {
        Err(payload) => match classify_debug_panic(payload.as_ref()) {
            Some(kind) if kind == expected => {}
            Some(kind) => panic!("{context}: expected {expected:?} rejection, got {kind:?}"),
            None => resume_unwind(payload),
        },
        Ok(result) => panic!(
            "{context}: forged trace must hit a recognized debug algebraic rejection, got {result:?}"
        ),
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = expected;
        assert!(
            matches!(check(), Err(BatchStarkProverError::Verify(_))),
            "{context}: forged trace must prove and reach verifier algebraic rejection"
        );
    }
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

/// The strong coefficient-normalizer lookups reject the kernel substitution that a weighted-sum
/// extension relation alone would accept: `c0 += w`, `c1 -= 1` leaves `sum(c_i w^i)` unchanged.
#[test]
fn statement_extension_rejects_nonbase_coefficients_with_unchanged_weighted_sum() {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);
    let coefficients = builder.alloc_public_inputs(D, "statement extension coefficients");
    let extension = builder
        .recompose_base_coeffs_to_ext_with_coeff_lookups::<BabyBear>(&coefficients)
        .unwrap();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[StatementExport::Extension(extension)])
        .unwrap();
    let circuit = builder.build().unwrap();
    let packing = TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4);
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = vec![
        Box::new(RecomposePreprocessor::new(true)),
        Box::new(StatementPreprocessor::new(schema.clone())),
    ];
    let mut air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, D>>> =
        recompose_air_builders(1, true);
    air_builders.push(Box::new(StatementAirBuilder::<D>::new(schema.clone())));
    let (airs_degrees, primitive, non_primitive) =
        get_airs_and_degrees_with_prep::<config::BabyBearConfig, _, D>(
            &circuit,
            &packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();

    let honest_coefficients = [5, 7, 11, 13].map(BabyBear::from_u64);
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&honest_coefficients.map(EF::from))
        .unwrap();
    let traces = runner.run().unwrap();
    let cfg = config::baby_bear();
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let prover_data = p3_batch_stark::ProverData::from_airs_and_degrees(&cfg, &airs, &degrees);
    let prepared = CircuitProverData::new(prover_data, primitive, non_primitive);
    let mut prover = BatchStarkProver::new(cfg).with_table_packing(packing);
    prover.register_recompose_table::<D>(true);
    prover.register_table_prover(Box::new(StatementProver::<D>::new(schema)));

    let honest_proof = prover.prove_all_tables(&traces, &prepared).unwrap();
    prover.verify_all_tables::<EF>(&honest_proof).unwrap();

    let basis_one = EF::from_basis_coefficients_slice(&[
        BabyBear::ZERO,
        BabyBear::ONE,
        BabyBear::ZERO,
        BabyBear::ZERO,
    ])
    .unwrap();
    let basis = core::array::from_fn::<_, D, _>(|i| {
        EF::from_basis_coefficients_fn(|j| BabyBear::from_bool(i == j))
    });
    let weighted_sum = |values: &[EF; D]| {
        values
            .iter()
            .zip(basis)
            .fold(EF::ZERO, |sum, (&value, weight)| sum + value * weight)
    };
    let honest_ext_coefficients = honest_coefficients.map(EF::from);
    let mut forged_ext_coefficients = honest_ext_coefficients;
    forged_ext_coefficients[0] += basis_one;
    forged_ext_coefficients[1] -= EF::ONE;
    assert_eq!(
        weighted_sum(&forged_ext_coefficients),
        weighted_sum(&honest_ext_coefficients),
        "the forged coefficients must stay in the weak weighted-sum relation's kernel"
    );
    assert!(<EF as ExtensionField<BabyBear>>::as_base(&forged_ext_coefficients[0]).is_none());

    let mut forged_traces = traces;
    forged_traces.public_trace.values[..D].copy_from_slice(&forged_ext_coefficients);
    assert_rejected_as(
        "non-base extension coefficient substitution",
        DebugRejectionKind::Lookup,
        || {
            let proof = prover
                .prove_all_tables(&forged_traces, &prepared)
                .expect("the algebraic prover constructs a forged proof candidate");
            prover.verify_all_tables::<EF>(&proof)
        },
    );
}

macro_rules! statement_extension_field_case {
    ($name:ident, $bf:ty, $ef:ty, $config_ty:ty, $d:literal, $config:expr, $coefficients:expr) => {
        #[test]
        fn $name() {
            let coefficients: Vec<$bf> = $coefficients;
            let extension_value =
                <$ef>::from_basis_coefficients_slice(&coefficients).expect("valid coefficients");
            let mut builder = CircuitBuilder::<$ef>::new();
            builder.enable_recompose::<$bf>(generate_recompose_trace::<$bf, $ef>);
            let extension = builder.public_input();
            let schema = builder
                .set_statement_exports::<$bf>(&[StatementExport::Extension(extension)])
                .unwrap();
            let circuit = builder.build().unwrap();
            let packing = TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4);
            let preprocessors: Vec<Box<dyn NpoPreprocessor<$bf>>> = vec![
                Box::new(RecomposePreprocessor::new(true)),
                Box::new(StatementPreprocessor::new(schema.clone())),
            ];
            let mut air_builders: Vec<Box<dyn NpoAirBuilder<$config_ty, $d>>> =
                recompose_air_builders(1, true);
            air_builders.push(Box::new(StatementAirBuilder::<$d>::new(schema.clone())));
            let (airs_degrees, primitive, non_primitive) =
                get_airs_and_degrees_with_prep::<$config_ty, _, $d>(
                    &circuit,
                    &packing,
                    &preprocessors,
                    &air_builders,
                    ConstraintProfile::Standard,
                )
                .unwrap();
            let mut runner = circuit.runner();
            runner.set_public_inputs(&[extension_value]).unwrap();
            let traces = runner.run().unwrap();
            let statement = traces
                .non_primitive_trace::<StatementTrace<$bf>>(&NpoTypeId::statement())
                .unwrap();
            assert_eq!(statement.values, coefficients);

            let cfg = $config;
            let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
            let prover_data =
                p3_batch_stark::ProverData::from_airs_and_degrees(&cfg, &airs, &degrees);
            let prepared = CircuitProverData::new(prover_data, primitive, non_primitive);
            let mut prover = BatchStarkProver::new(cfg).with_table_packing(packing);
            prover.register_recompose_table::<$d>(true);
            prover.register_table_prover(Box::new(StatementProver::<$d>::new(schema)));
            let proof = prover.prove_all_tables(&traces, &prepared).unwrap();
            prover.verify_all_tables::<$ef>(&proof).unwrap();
        }
    };
}

statement_extension_field_case!(
    statement_extension_is_canonical_for_goldilocks_d2,
    Goldilocks,
    BinomialExtensionField<Goldilocks, 2>,
    config::GoldilocksConfig,
    2,
    config::goldilocks(),
    vec![Goldilocks::from_u64(31), Goldilocks::from_u64(37)]
);

statement_extension_field_case!(
    statement_extension_is_canonical_for_koalabear_d5,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    config::KoalaBearConfig,
    5,
    config::koala_bear(),
    vec![
        KoalaBear::from_u64(41),
        KoalaBear::from_u64(43),
        KoalaBear::from_u64(47),
        KoalaBear::from_u64(53),
        KoalaBear::from_u64(59),
    ]
);

/// Statement's fixed one-row shape remains sound when the PCS adds ZK hiding rows.
#[test]
fn statement_proves_and_verifies_with_hiding_fri() {
    const SALT_ELEMS: usize = 4;
    type HidingValMmcs = MerkleTreeHidingMmcs<
        <KoalaBear as p3_field::Field>::Packing,
        <KoalaBear as p3_field::Field>::Packing,
        MyHash,
        MyCompress,
        StdRng,
        2,
        DIGEST_ELEMS,
        SALT_ELEMS,
    >;
    type HidingChallengeMmcs = ExtensionMmcs<KoalaBear, Challenge, HidingValMmcs>;
    type HidingPcs = HidingFriPcs<KoalaBear, Dft, HidingValMmcs, HidingChallengeMmcs, StdRng>;
    type HidingConfig = StarkConfig<HidingPcs, Challenge, Challenger>;

    let permutation = default_koalabear_poseidon2_16();
    let value_mmcs = HidingValMmcs::new(
        MyHash::new(permutation.clone()),
        MyCompress::new(permutation.clone()),
        0,
        StdRng::seed_from_u64(11),
    );
    let fri_params = FriParameters::new_testing(HidingChallengeMmcs::new(value_mmcs.clone()), 0);
    let pcs = HidingPcs::new(
        Dft::default(),
        value_mmcs,
        fri_params,
        2,
        StdRng::seed_from_u64(7),
    );
    let cfg = HidingConfig::new(pcs, Challenger::new(permutation));

    let mut builder = CircuitBuilder::<KoalaBear>::new();
    let value = builder.public_input();
    let schema = builder
        .set_statement_exports::<KoalaBear>(&[StatementExport::Base(value)])
        .expect("define hiding statement");
    let circuit = builder.build().expect("build hiding statement circuit");
    let packing = TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 32);
    let preprocessors: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<HidingConfig, 1>>> =
        vec![Box::new(StatementAirBuilder::<1>::new(schema.clone()))];
    let (airs_degrees, primitive, non_primitive) =
        get_airs_and_degrees_with_prep::<HidingConfig, _, 1>(
            &circuit,
            &packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("prepare hiding statement AIR");

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[KoalaBear::from_u64(29)])
        .unwrap();
    let traces = runner.run().unwrap();
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    // `get_airs_and_degrees_with_prep` returns base trace degrees. HidingFriPcs commits one
    // additional randomized row bit, which is part of ProverData's extended degree metadata.
    let degrees: Vec<_> = degrees.into_iter().map(|degree| degree + 1).collect();
    let prover_data = p3_batch_stark::ProverData::from_airs_and_degrees(&cfg, &airs, &degrees);
    let prepared = CircuitProverData::new(prover_data, primitive, non_primitive);
    let mut prover = BatchStarkProver::new(cfg).with_table_packing(packing);
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema)));
    let proof = prover
        .prove_all_tables(&traces, &prepared)
        .expect("prove hiding statement");
    prover
        .verify_all_tables::<KoalaBear>(&proof)
        .expect("verify hiding statement");

    let statement_entry = proof
        .non_primitives
        .iter()
        .find(|entry| entry.op_type.as_str() == "statement")
        .unwrap();
    assert_eq!(statement_entry.public_values, [KoalaBear::from_u64(29)]);
    assert_eq!(statement_entry.rows, 1);
}

/// If the Statement lookup omits its high zero limbs, this forged Public creator tuple verifies.
#[test]
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

        assert_rejected_as(
            &format!("high limb {high_limb}"),
            DebugRejectionKind::Lookup,
            || {
                let proof = prover
                    .prove_all_tables(&traces, &prepared)
                    .expect("the algebraic prover constructs a forged proof candidate");
                prover.verify_all_tables::<EF>(&proof)
            },
        );
    }
}

/// If Statement values come from a separate host vector, changing the actual sink row can pass.
/// Here the changed value becomes the table's public input, so rejection is specifically the CTL
/// mismatch against the unchanged source table.
#[test]
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

    assert_rejected_as(
        "statement value tampering",
        DebugRejectionKind::Lookup,
        || {
            let proof = prover
                .prove_all_tables(&traces, &prepared)
                .expect("the algebraic prover constructs a forged proof candidate");
            prover.verify_all_tables::<EF>(&proof)
        },
    );
}

/// The ordered statement mapping is committed; swapping two sink values cannot merely swap the
/// proof-attached public vector and continue to match the original producer indices.
#[test]
fn statement_order_tampering_is_rejected_by_ctl() {
    let mut builder = CircuitBuilder::<EF>::new();
    let first = builder.public_input();
    let second = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[
            StatementExport::Base(first),
            StatementExport::Base(second),
        ])
        .unwrap();
    let circuit = builder.build().unwrap();
    let packing = TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4);
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
    runner
        .set_public_inputs(&[
            EF::from(BabyBear::from_u64(7)),
            EF::from(BabyBear::from_u64(9)),
        ])
        .unwrap();
    let mut traces = runner.run().unwrap();
    let mut statement = traces
        .non_primitive_trace::<StatementTrace<BabyBear>>(&NpoTypeId::statement())
        .unwrap()
        .clone();
    statement.values.swap(0, 1);
    traces
        .non_primitive_traces
        .insert(NpoTypeId::statement(), Box::new(statement));

    let cfg = config::baby_bear();
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let prover_data = p3_batch_stark::ProverData::from_airs_and_degrees(&cfg, &airs, &degrees);
    let prepared = CircuitProverData::new(prover_data, primitive, non_primitive);
    let mut prover = BatchStarkProver::new(cfg).with_table_packing(packing);
    prover.register_table_prover(Box::new(StatementProver::<D>::new(schema)));
    assert_rejected_as(
        "statement order tampering",
        DebugRejectionKind::Lookup,
        || {
            let proof = prover
                .prove_all_tables(&traces, &prepared)
                .expect("the algebraic prover constructs a forged proof candidate");
            prover.verify_all_tables::<EF>(&proof)
        },
    );
}

/// The statement index is part of the committed preparation; changing the regenerated AIR while
/// retaining the original `ProverData` key must not yield a verifying proof.
#[test]
fn statement_index_tampering_is_rejected_under_the_original_preparation() {
    let (prover, mut prepared, traces, _) = base_statement_fixture(
        BabyBear::from_u64(7),
        TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4),
    );
    prepared
        .non_primitive_columns
        .get_mut(&NpoTypeId::statement())
        .unwrap()[1] += BabyBear::from_u64(D as u64);

    assert_rejected_as(
        "statement index tampering",
        DebugRejectionKind::Lookup,
        || {
            let proof = prover
                .prove_all_tables(&traces, &prepared)
                .expect("the algebraic prover constructs a forged proof candidate");
            prover.verify_all_tables::<EF>(&proof)
        },
    );
}

/// The committed active selector cannot be changed to suppress the statement lookup.
#[test]
fn statement_active_tampering_is_rejected_under_the_original_preparation() {
    let (prover, mut prepared, traces, _) = base_statement_fixture(
        BabyBear::from_u64(7),
        TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4),
    );
    prepared
        .non_primitive_columns
        .get_mut(&NpoTypeId::statement())
        .unwrap()[0] = BabyBear::ZERO;

    assert_rejected_as(
        "statement active-selector tampering",
        DebugRejectionKind::Constraint,
        || {
            let proof = prover
                .prove_all_tables(&traces, &prepared)
                .expect("the algebraic prover constructs a forged proof candidate");
            prover.verify_all_tables::<EF>(&proof)
        },
    );
}

/// Producer multiplicity is committed too. Decrementing the Public creator count while retaining
/// the original preparation commitment must be rejected rather than balanced by Statement.
#[test]
fn statement_multiplicity_tampering_is_rejected_under_the_original_preparation() {
    let (prover, mut prepared, traces, _) = base_statement_fixture(
        BabyBear::from_u64(7),
        TablePacking::default().with_npo_min_height(NpoTypeId::statement(), 4),
    );
    prepared.primitive_columns[1][0] = BabyBear::ZERO;

    assert_rejected_as(
        "statement producer multiplicity tampering",
        DebugRejectionKind::Lookup,
        || {
            let proof = prover
                .prove_all_tables(&traces, &prepared)
                .expect("the algebraic prover constructs a forged proof candidate");
            prover.verify_all_tables::<EF>(&proof)
        },
    );
}

#[test]
fn statement_lane_override_is_rejected() {
    let packing = TablePacking::default().with_npo_lanes(NpoTypeId::statement(), 2);
    assert!(packing.validate().is_err());
}
