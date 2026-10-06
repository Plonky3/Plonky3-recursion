//! A bound BinaryField128 arithmetic statement and its trusted next recursive layer.

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::{CircuitBuilder, CircuitError, StatementExport};
use p3_circuit_prover::ConstraintProfile;
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, StatementAirBuilder, StatementPreprocessor, StatementProver,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_recursion::{
    BatchOnly, ProveNextLayerParams, TrustedPreparedInput, TrustedPreparedLayer,
    TrustedPreparedSource,
};
use p3_test_utils::koala_bear_params::F;

use crate::common;

const A_RAW: u128 = 0x21bade026a6ae768f2ed66ffdcc99396;

fn limbs(raw: u128) -> [F; 8] {
    core::array::from_fn(|i| F::from_u16((raw >> (16 * i)) as u16))
}

fn statement(a: u128, b: u128) -> Vec<F> {
    let a_native = BinaryField128::from_repr(a);
    let b_native = BinaryField128::from_repr(b);
    limbs(a)
        .into_iter()
        .chain(limbs(b))
        .chain(limbs((a_native + b_native).to_repr()))
        .chain(limbs((a_native * b_native).to_repr()))
        .chain(limbs(a_native.square().to_repr()))
        .collect()
}

fn witness(a: u128, b: u128) -> Vec<F> {
    limbs(a).into_iter().chain(limbs(b)).collect()
}

#[test]
fn dense_inverse_relation_proves_and_recurses_with_bound_limbs() {
    let (config, backend) = common::koala_bear_d4_recursion_config_and_backend();
    let mut builder = CircuitBuilder::<F>::new();
    let a_inputs = builder.alloc_private_input_array::<8>("tower a limbs");
    let b_inputs = builder.alloc_private_input_array::<8>("tower b limbs");
    let a = builder.binary128_from_limbs::<F>(a_inputs).unwrap();
    let b = builder.binary128_from_limbs::<F>(b_inputs).unwrap();
    let sum = builder.binary128_add(&a, &b);
    let product = builder.binary128_mul(&a, &b);
    let square = builder.binary128_square(&a);
    builder.assert_binary128_inverse(&a, &b);
    let sum_limbs = builder.binary128_to_limbs::<F>(&sum).unwrap();
    let product_limbs = builder.binary128_to_limbs::<F>(&product).unwrap();
    let square_limbs = builder.binary128_to_limbs::<F>(&square).unwrap();

    // Statement order: a[0..8], b[0..8], sum[0..8], product[0..8], square[0..8].
    let exports: Vec<_> = a_inputs
        .into_iter()
        .chain(b_inputs)
        .chain(sum_limbs)
        .chain(product_limbs)
        .chain(square_limbs)
        .map(StatementExport::Base)
        .collect();
    let schema = builder.set_statement_exports::<F>(&exports).unwrap();
    assert_eq!(schema.base_len(), 40);
    let circuit = builder.build().unwrap();

    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<common::KoalaBearD4RecursionConfig, 1>>> =
        vec![Box::new(StatementAirBuilder::<1>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config.clone());
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema)));
    let prepared = prover
        .prepare_circuit::<F, 1>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();

    let a_native = BinaryField128::from_repr(A_RAW);
    let b_raw = a_native.try_inverse().unwrap().to_repr();
    let expected = statement(A_RAW, b_raw);
    assert_eq!(expected[24], F::ONE);
    assert!(expected[25..32].iter().all(|value| *value == F::ZERO));
    let mut runner = circuit.runner();
    runner.set_private_inputs(&witness(A_RAW, b_raw)).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    let child_verifier = prepared.verifier();
    child_verifier.verify(&proof, &expected).unwrap();

    let mut changed = expected.clone();
    changed[32] += F::ONE; // A wrong square limb with the same valid 40-limb schema.
    assert!(child_verifier.verify(&proof, &changed).is_err());

    let owner = TrustedPreparedLayer::<_, _, BatchOnly, _, 4>::new(
        TrustedPreparedSource::BatchStark {
            verifier: child_verifier,
            proof: &proof,
            statement: &expected,
        },
        config,
        backend,
        ProveNextLayerParams::default(),
    )
    .unwrap();
    let parent = owner
        .prove(TrustedPreparedInput::BatchStark {
            proof: &proof,
            statement: &expected,
        })
        .unwrap();
    owner.verifier().verify(&parent.0, &expected).unwrap();
    assert!(owner.verifier().verify(&parent.0, &changed).is_err());

    for (context, bad_a, bad_b) in [
        ("wrong inverse", A_RAW, b_raw ^ 1),
        ("zero has no inverse", 0, 0),
    ] {
        let mut runner = circuit.runner();
        runner.set_private_inputs(&witness(bad_a, bad_b)).unwrap();
        assert!(
            matches!(runner.run(), Err(CircuitError::WitnessConflict { .. })),
            "{context}: multiplication-to-one must reject the witness"
        );
    }
}
