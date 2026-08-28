use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    NpoTypeId, Poseidon2Config, Poseidon2PermCall, generate_poseidon2_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders, recompose_air_builders};
use p3_circuit_prover::common::{CircuitTableAir, NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_test_utils::koala_bear_params::*;

/// End-to-end regression for per-table minimum-height overrides: builds a small Fibonacci
/// circuit (Const + Public + Alu ops, no non-primitive tables), sets a *different* minimum
/// height override on each of the three primitive tables, then round-trips the whole
/// prep-build -> prove -> verify pipeline.
///
/// This is the exact synchronization `get_airs_and_degrees_with_prep` (in `common.rs`) and
/// `BatchStarkProver::prove` (in `batch_stark_prover.rs`) must agree on: if either resolved a
/// table's height differently, `ProverData::from_airs_and_degrees` would panic (it asserts
/// `preprocessed.height() == 1 << degree` for every table with preprocessed data), or the
/// commitment built during proving would silently disagree with what was committed during
/// prep-build.
#[test]
fn per_table_min_height_overrides_round_trip_through_prove_and_verify() {
    let n: usize = 50;

    let mut builder = CircuitBuilder::new();

    let expected_result = builder.alloc_public_input("expected_result");

    let mut a = builder.alloc_const(F::ZERO, "F(0)");
    let mut b = builder.alloc_const(F::ONE, "F(1)");
    for _i in 2..=n {
        let next = builder.add(a, b);
        a = b;
        b = next;
    }
    builder.connect(b, expected_result);

    // Public has 1 row (expected_result) -> natural height 1.
    // Alu has n-1 = 49 rows with lanes=1 -> natural height 64.
    // Const's natural height also lands at 64 in this circuit (the builder emits more Const
    // entries than the 2 explicit `alloc_const` calls), so its override must exceed that to
    // exercise anything (confirmed empirically, not derived from the op count).
    //
    // The global floor is set to a realistic, non-trivial value (32, as a real recursion caller
    // would derive via `with_fri_params`) rather than left at the default of 1: with a floor of
    // 1, `unwrap_or(global)` is indistinguishable from `unwrap_or(1)`, so every override tested
    // trivially. Every override below is set strictly above both the table's natural height and
    // the floor, and each is a distinct value, so a swap between tables (e.g. Const accidentally
    // getting Public's override) would be caught.
    let table_packing = TablePacking::new(1, 1)
        .with_min_trace_height(32)
        .with_const_min_height(1024)
        .with_public_min_height(64)
        .with_alu_min_height(256);

    let config_proving = make_test_config();

    let circuit = builder.build().unwrap();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, _, 1>(
            &circuit,
            &table_packing,
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();

    for (air, degree) in &airs_degrees {
        let expected_height = match air {
            CircuitTableAir::Const(_) => 1024usize,
            CircuitTableAir::Public(_) => 64usize,
            CircuitTableAir::Alu(_) => 256usize,
            CircuitTableAir::Dynamic(_) => panic!("no non-primitive tables in this circuit"),
        };
        assert_eq!(
            1usize << degree,
            expected_height,
            "prep-build path did not honor the per-table minimum height override"
        );
    }

    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let expected_fib = compute_fibonacci_classical(n);
    runner.set_public_inputs(&[expected_fib]).unwrap();
    let traces = runner.run().unwrap();

    // Panics with a height-mismatch assertion if prep-build and prove ever disagree.
    let prover_data = ProverData::from_airs_and_degrees(&config_proving, &airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);
    let batch_stark_proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();

    prover.verify_all_tables::<F>(&batch_stark_proof).unwrap();
}

/// Same synchronization guarantee as
/// [`per_table_min_height_overrides_round_trip_through_prove_and_verify`], but for a
/// non-primitive (NPO) table: builds a small Poseidon2 permutation chain (mirroring
/// `circuit-prover/examples/poseidon2_perm_chain.rs`), sets an `npo_min_height` override on the
/// Poseidon2 table that is strictly above both its natural height and a realistic, non-trivial
/// global floor, and round-trips prep-build -> prove -> verify.
///
/// This exercises all three NPO call sites `batch_stark_prover.rs`'s `prove` resolves per-table
/// heights at (the committed-preprocessed override loop, the dynamic-instance trace padding
/// loop, and the debug-lookups committed-preprocessed rebuild -- enabled here via
/// `with_debug_lookups()`), plus `common.rs`'s non-primitive-table loop.
#[test]
fn npo_min_height_override_at_or_above_global_floor_round_trips() {
    let chain_length: usize = 3;
    let poseidon2_config = Poseidon2Config::KOALA_BEAR_D4_W16;
    let poseidon2_op_type = NpoTypeId::poseidon2_perm(poseidon2_config);

    let perm = default_koalabear_poseidon2_16();
    let mut builder = CircuitBuilder::<Challenge>::new();
    builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
        perm,
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let input_exprs: [ExprId; 4] = core::array::from_fn(|i| {
        builder.alloc_const(Challenge::from_u32((i + 1) as u32), "poseidon2_input")
    });

    for row in 0..chain_length {
        let is_first = row == 0;
        let is_last = row + 1 == chain_length;
        let mut inputs: Vec<Option<ExprId>> = vec![None; 4];
        if is_first {
            for limb in 0..4 {
                inputs[limb] = Some(input_exprs[limb]);
            }
        }
        builder
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: poseidon2_config,
                new_start: is_first,
                merkle_path: false,
                mmcs_bit: None,
                mmcs_bit2: None,
                inputs,
                out_ctl: vec![is_last, is_last],
                return_all_outputs: false,
                mmcs_index_sum: None,
                absorb_len: 0,
            })
            .unwrap();
    }

    let circuit = builder.build().unwrap();

    // Natural Poseidon2 rows = chain_length = 3 -> next_pow2 = 4. The floor (32) and the
    // override (128) are both set strictly above that, and the override is strictly above the
    // floor too, so a bug that silently fell back to either the natural height or the floor
    // (instead of genuinely honoring the override) would be caught.
    let table_packing = TablePacking::new(1, 1)
        .with_min_trace_height(32)
        .with_npo_min_height(poseidon2_op_type.clone(), 128);

    let stark_config = make_test_config();
    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::default()),
    ];
    let mut air_builders = poseidon2_air_builders::<_, 4>();
    air_builders.extend(recompose_air_builders(1, false));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, _, 4>(
            &circuit,
            &table_packing,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();

    assert!(
        non_primitive_columns.contains_key(&poseidon2_op_type),
        "expected a Poseidon2 non-primitive table to be present"
    );

    // This circuit only ever invokes the Poseidon2 permutation (no extension-to-base
    // decomposition is needed since nothing reads the outputs), so Recompose -- though
    // registered as a table prover/air builder, matching the working
    // `poseidon2_perm_chain.rs` example -- never actually gets an op and contributes no
    // Dynamic entry. Poseidon2 is therefore the only non-primitive table present.
    let dynamic_degrees: Vec<usize> = airs_degrees
        .iter()
        .filter_map(|(air, degree)| matches!(air, CircuitTableAir::Dynamic(_)).then_some(*degree))
        .collect();
    assert_eq!(
        dynamic_degrees.len(),
        1,
        "expected exactly 1 non-primitive table (Poseidon2)"
    );
    let poseidon2_degree = dynamic_degrees[0];
    assert_eq!(
        1usize << poseidon2_degree,
        128,
        "prep-build path did not honor the NPO per-table minimum height override"
    );

    let runner = circuit.runner();
    let traces = runner.run().unwrap();

    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    // Panics with a height-mismatch assertion if prep-build and prove ever disagree.
    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(stark_config)
        .with_table_packing(table_packing)
        .with_debug_lookups();
    prover.register_poseidon2_table::<4>(poseidon2_config);
    prover.register_recompose_table::<4>(false);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    prover.verify_all_tables::<Challenge>(&proof).unwrap();
}

fn compute_fibonacci_classical(n: usize) -> F {
    if n == 0 {
        return F::ZERO;
    }
    if n == 1 {
        return F::ONE;
    }

    let mut a = F::ZERO;
    let mut b = F::ONE;

    for _i in 2..=n {
        let next = a + b;
        a = b;
        b = next;
    }

    b
}
