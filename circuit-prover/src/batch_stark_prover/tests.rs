use p3_baby_bear::BabyBear;
use p3_circuit::builder::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;

use super::*;
use crate::batch_stark_prover::{BABY_BEAR_MODULUS, KOALA_BEAR_MODULUS};
use crate::common::get_airs_and_degrees_with_prep;
use crate::config::{self, BabyBearConfig, GoldilocksConfig, KoalaBearConfig};

#[test]
fn test_babybear_batch_stark_base_field() {
    let mut builder = CircuitBuilder::<BabyBear>::new();

    // x + 5*2 - 3 + (-1) == expected
    let x = builder.add_public_input();
    let expected = builder.add_public_input();
    let c5 = builder.add_const(BabyBear::from_u64(5));
    let c2 = builder.add_const(BabyBear::from_u64(2));
    let c3 = builder.add_const(BabyBear::from_u64(3));
    let neg_one = builder.add_const(BabyBear::NEG_ONE);

    let mul_result = builder.mul(c5, c2); // 10
    let add_result = builder.add(x, mul_result); // x + 10
    let sub_result = builder.sub(add_result, c3); // x + 7
    let final_result = builder.add(sub_result, neg_one); // x + 6

    let diff = builder.sub(final_result, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let cfg = config::baby_bear().build();
    let (airs_degrees, preprocessed_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            TablePacking::default(),
            None,
        )
        .unwrap();
    let (mut airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &log_degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let mut runner = circuit.runner();

    let x_val = BabyBear::from_u64(7);
    let expected_val = BabyBear::from_u64(13); // 7 + 10 - 3 - 1 = 13
    runner.set_public_inputs(&[x_val, expected_val]).unwrap();
    let traces = runner.run().unwrap();

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 1);
    assert!(proof.w_binomial.is_none());

    assert!(
        prover
            .verify_all_tables(&proof, circuit_prover_data.common_data())
            .is_ok()
    );
}

#[test]
fn test_table_lookups() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let cfg = config::baby_bear().build();

    // x + 5*2 - 3 + (-1) == expected
    let x = builder.add_public_input();
    let expected = builder.add_public_input();
    let c5 = builder.add_const(BabyBear::from_u64(5));
    let c2 = builder.add_const(BabyBear::from_u64(2));
    let c3 = builder.add_const(BabyBear::from_u64(3));
    let neg_one = builder.add_const(BabyBear::NEG_ONE);

    let mul_result = builder.mul(c5, c2); // 10
    let add_result = builder.add(x, mul_result); // x + 10
    let sub_result = builder.sub(add_result, c3); // x + 7
    let final_result = builder.add(sub_result, neg_one); // x + 6

    let diff = builder.sub(final_result, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let default_packing = TablePacking::default();
    let (airs_degrees, preprocessed_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(&circuit, default_packing, None)
            .unwrap();
    let (mut airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    // Witness multiplicities: index 0 gets c_idx lookups from ALU ops without c; values from preprocessed.
    let mut expected_multiplicities = vec![BabyBear::from_u64(2); 11];
    expected_multiplicities[0] = BabyBear::from_u64(5);
    expected_multiplicities[7] = BabyBear::from_u64(0);
    // Pad multiplicities.
    let total_witness_length = (expected_multiplicities
        .len()
        .div_ceil(default_packing.witness_lanes()))
    .next_power_of_two()
        * default_packing.witness_lanes();
    expected_multiplicities.resize(total_witness_length, BabyBear::ZERO);

    // Get expected preprocessed trace for `WitnessAir`.
    let expected_preprocessed_trace = RowMajorMatrix::new(
        expected_multiplicities
            .iter()
            .enumerate()
            .flat_map(|(i, m)| vec![*m, BabyBear::from_usize(i)])
            .collect::<Vec<_>>(),
        2 * TablePacking::default().witness_lanes(),
    );
    assert_eq!(
        airs[0]
            .preprocessed_trace()
            .expect("Witness table should have preprocessed trace"),
        expected_preprocessed_trace,
        "witness_multiplicities {:?} expected {:?}",
        airs[0].preprocessed_trace(),
        expected_preprocessed_trace,
    );

    let mut runner = circuit.runner();

    let x_val = BabyBear::from_u64(7);
    let expected_val = BabyBear::from_u64(13); // 7 + 10 - 3 - 1 = 13
    runner.set_public_inputs(&[x_val, expected_val]).unwrap();
    let traces = runner.run().unwrap();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &log_degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 1);
    assert!(proof.w_binomial.is_none());

    assert!(
        prover
            .verify_all_tables(&proof, circuit_prover_data.common_data())
            .is_ok()
    );

    // Check that the generated lookups are correct and consistent across tables.
    for air in airs.iter_mut() {
        let lookups =
            Air::<SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>>::get_lookups(
                air,
            );

        match air {
            CircuitTableAir::Witness(_) => {
                assert_eq!(
                    lookups.len(),
                    default_packing.witness_lanes(),
                    "Witness table should have {} lookups, found {}",
                    default_packing.witness_lanes(),
                    lookups.len()
                );
            }
            CircuitTableAir::Const(_) => {
                assert_eq!(lookups.len(), 1, "Const table should have one lookup");
            }
            CircuitTableAir::Public(_) => {
                assert_eq!(lookups.len(), 1, "Public table should have one lookup");
            }
            CircuitTableAir::Alu(_) => {
                // ALU table sends 4 lookups per lane: one for each operand (a, b, c, out)
                let expected_num_lookups = default_packing.alu_lanes() * 4;
                assert_eq!(
                    lookups.len(),
                    expected_num_lookups,
                    "ALU table should have {} lookups, found {}",
                    expected_num_lookups,
                    lookups.len()
                );
            }
            CircuitTableAir::Dynamic(_dynamic_air) => {
                assert!(
                    lookups.is_empty(),
                    "There is no dynamic table in this test, so no lookups expected"
                );
            }
        }
    }
}

#[test]
fn test_extension_field_batch_stark() {
    const D: usize = 4;
    type Ext4 = BinomialExtensionField<BabyBear, D>;
    let cfg = config::baby_bear().build();

    let mut builder = CircuitBuilder::<Ext4>::new();
    let x = builder.add_public_input();
    let y = builder.add_public_input();
    let z = builder.add_public_input();
    let expected = builder.add_public_input();
    let xy = builder.mul(x, y);
    let res = builder.add(xy, z);
    let diff = builder.sub(res, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let (airs_degrees, preprocessed_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, D>(
            &circuit,
            TablePacking::default(),
            None,
        )
        .unwrap();
    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let mut runner = circuit.runner();
    let xv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(2),
        BabyBear::from_u64(3),
        BabyBear::from_u64(5),
        BabyBear::from_u64(7),
    ])
    .unwrap();
    let yv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(11),
        BabyBear::from_u64(13),
        BabyBear::from_u64(17),
        BabyBear::from_u64(19),
    ])
    .unwrap();
    let zv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(23),
        BabyBear::from_u64(29),
        BabyBear::from_u64(31),
        BabyBear::from_u64(37),
    ])
    .unwrap();
    let expected_v = xv * yv + zv;
    runner.set_public_inputs(&[xv, yv, zv, expected_v]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 4);
    // Ensure W was captured
    let expected_w = <Ext4 as ExtractBinomialW<BabyBear>>::extract_w().unwrap();
    assert_eq!(proof.w_binomial, Some(expected_w));
    prover
        .verify_all_tables(&proof, circuit_prover_data.common_data())
        .unwrap();
}

#[test]
fn test_extension_field_table_lookups() {
    const D: usize = 4;
    type Ext4 = BinomialExtensionField<BabyBear, D>;
    let cfg = config::baby_bear().build();

    let mut builder = CircuitBuilder::<Ext4>::new();
    let x = builder.add_public_input();
    let y = builder.add_public_input();
    let z = builder.add_public_input();
    let expected = builder.add_public_input();
    let xy = builder.mul(x, y);
    let res = builder.add(xy, z);
    let diff = builder.sub(res, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let default_packing = TablePacking::default();
    let (airs_degrees, preprocessed_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, D>(&circuit, default_packing, None)
            .unwrap();
    let (mut airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    // Check that the multiplicities of `WitnessAir` are computed correctly.
    // With MulAdd fusion, mul+add pairs are fused, reducing the number of ALU ops.
    let mut expected_multiplicities = vec![BabyBear::from_u64(2); 7];
    expected_multiplicities[0] = BabyBear::from_u64(3); // reduced due to MulAdd fusion
    expected_multiplicities[5] = BabyBear::from_u64(0); // changed due to fusion
    // Pad multiplicities.
    let total_witness_length = (expected_multiplicities
        .len()
        .div_ceil(default_packing.witness_lanes()))
    .next_power_of_two()
        * default_packing.witness_lanes();
    expected_multiplicities.resize(total_witness_length, BabyBear::ZERO);

    // Get expected preprocessed trace for `WitnessAir`.
    let expected_preprocessed_trace = RowMajorMatrix::new(
        expected_multiplicities
            .iter()
            .enumerate()
            .flat_map(|(i, m)| vec![*m, BabyBear::from_usize(i)])
            .collect::<Vec<_>>(),
        2 * TablePacking::default().witness_lanes(),
    );

    assert_eq!(
        airs[0]
            .preprocessed_trace()
            .expect("Witness table should have preprocessed trace"),
        expected_preprocessed_trace,
        "witness_multiplicities {:?} expected {:?}",
        airs[0].preprocessed_trace(),
        expected_preprocessed_trace,
    );

    let mut runner = circuit.runner();

    let xv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(2),
        BabyBear::from_u64(3),
        BabyBear::from_u64(5),
        BabyBear::from_u64(7),
    ])
    .unwrap();
    let yv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(11),
        BabyBear::from_u64(13),
        BabyBear::from_u64(17),
        BabyBear::from_u64(19),
    ])
    .unwrap();
    let zv = Ext4::from_basis_coefficients_slice(&[
        BabyBear::from_u64(23),
        BabyBear::from_u64(29),
        BabyBear::from_u64(31),
        BabyBear::from_u64(37),
    ])
    .unwrap();
    let expected_v = xv * yv + zv;
    runner.set_public_inputs(&[xv, yv, zv, expected_v]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &log_degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 4);
    // Ensure W was captured
    let expected_w = <Ext4 as ExtractBinomialW<BabyBear>>::extract_w().unwrap();
    assert_eq!(proof.w_binomial, Some(expected_w));

    assert!(
        prover
            .verify_all_tables(&proof, circuit_prover_data.common_data())
            .is_ok()
    );

    // Check that the generated lookups are correct and consistent across tables.
    for air in airs.iter_mut() {
        let lookups =
            Air::<SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>>::get_lookups(
                air,
            );

        match air {
            CircuitTableAir::Witness(_) => {
                assert_eq!(
                    lookups.len(),
                    default_packing.witness_lanes(),
                    "Witness table should have {} lookups, found {}",
                    default_packing.witness_lanes(),
                    lookups.len()
                );
            }
            CircuitTableAir::Const(_) => {
                assert_eq!(lookups.len(), 1, "Const table should have one lookup");
            }
            CircuitTableAir::Public(_) => {
                assert_eq!(lookups.len(), 1, "Public table should have one lookup");
            }
            CircuitTableAir::Alu(_) => {
                // ALU table sends 4 lookups per lane: one for each operand (a, b, c, out)
                let expected_num_lookups = default_packing.alu_lanes() * 4;
                assert_eq!(
                    lookups.len(),
                    expected_num_lookups,
                    "ALU table should have {} lookups, found {}",
                    expected_num_lookups,
                    lookups.len()
                );
            }
            CircuitTableAir::Dynamic(_dynamic_air) => {
                assert!(
                    lookups.is_empty(),
                    "There is no dynamic table in this test, so no lookups expected"
                );
            }
        }
    }
}

#[test]
fn test_koalabear_batch_stark_base_field() {
    let mut builder = CircuitBuilder::<KoalaBear>::new();
    let cfg = config::koala_bear().build();

    // a * b + 100 - (-1) == expected
    let a = builder.add_public_input();
    let b = builder.add_public_input();
    let expected = builder.add_public_input();
    let c = builder.add_const(KoalaBear::from_u64(100));
    let d = builder.add_const(KoalaBear::NEG_ONE);

    let ab = builder.mul(a, b);
    let add = builder.add(ab, c);
    let final_res = builder.sub(add, d);
    let diff = builder.sub(final_res, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let (airs_degrees, preprocessed_columns) = get_airs_and_degrees_with_prep::<
        KoalaBearConfig,
        _,
        1,
    >(&circuit, TablePacking::default(), None)
    .unwrap();
    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let a_val = KoalaBear::from_u64(42);
    let b_val = KoalaBear::from_u64(13);
    let expected_val = KoalaBear::from_u64(647); // 42*13 + 100 - (-1)
    runner
        .set_public_inputs(&[a_val, b_val, expected_val])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 1);
    assert!(proof.w_binomial.is_none());
    prover
        .verify_all_tables(&proof, circuit_prover_data.common_data())
        .unwrap();
}

#[test]
fn test_koalabear_batch_stark_extension_field_d8() {
    const D: usize = 8;
    type KBExtField = BinomialExtensionField<KoalaBear, D>;
    let mut builder = CircuitBuilder::<KBExtField>::new();
    let cfg = config::koala_bear().build();

    // x * y * z == expected
    let x = builder.add_public_input();
    let y = builder.add_public_input();
    let expected = builder.add_public_input();
    let z = builder.add_const(
        KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(1),
            KoalaBear::NEG_ONE,
            KoalaBear::from_u64(2),
            KoalaBear::from_u64(3),
            KoalaBear::from_u64(4),
            KoalaBear::from_u64(5),
            KoalaBear::from_u64(6),
            KoalaBear::from_u64(7),
        ])
        .unwrap(),
    );

    let xy = builder.mul(x, y);
    let xyz = builder.mul(xy, z);
    let diff = builder.sub(xyz, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let (airs_degrees, preprocessed_columns) = get_airs_and_degrees_with_prep::<
        KoalaBearConfig,
        _,
        D,
    >(&circuit, TablePacking::default(), None)
    .unwrap();
    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let x_val = KBExtField::from_basis_coefficients_slice(&[
        KoalaBear::from_u64(4),
        KoalaBear::from_u64(6),
        KoalaBear::from_u64(8),
        KoalaBear::from_u64(10),
        KoalaBear::from_u64(12),
        KoalaBear::from_u64(14),
        KoalaBear::from_u64(16),
        KoalaBear::from_u64(18),
    ])
    .unwrap();
    let y_val = KBExtField::from_basis_coefficients_slice(&[
        KoalaBear::from_u64(12),
        KoalaBear::from_u64(14),
        KoalaBear::from_u64(16),
        KoalaBear::from_u64(18),
        KoalaBear::from_u64(20),
        KoalaBear::from_u64(22),
        KoalaBear::from_u64(24),
        KoalaBear::from_u64(26),
    ])
    .unwrap();
    let z_val = KBExtField::from_basis_coefficients_slice(&[
        KoalaBear::from_u64(1),
        KoalaBear::NEG_ONE,
        KoalaBear::from_u64(2),
        KoalaBear::from_u64(3),
        KoalaBear::from_u64(4),
        KoalaBear::from_u64(5),
        KoalaBear::from_u64(6),
        KoalaBear::from_u64(7),
    ])
    .unwrap();

    let expected_val = x_val * y_val * z_val;
    runner
        .set_public_inputs(&[x_val, y_val, expected_val])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 8);
    let expected_w = <KBExtField as ExtractBinomialW<KoalaBear>>::extract_w().unwrap();
    assert_eq!(proof.w_binomial, Some(expected_w));
    prover
        .verify_all_tables(&proof, circuit_prover_data.common_data())
        .unwrap();
}

#[test]
fn test_goldilocks_batch_stark_extension_field_d2() {
    const D: usize = 2;
    type Ext2 = BinomialExtensionField<Goldilocks, D>;
    let mut builder = CircuitBuilder::<Ext2>::new();
    let cfg = config::goldilocks().build();

    // x * y + z == expected
    let x = builder.add_public_input();
    let y = builder.add_public_input();
    let z = builder.add_public_input();
    let expected = builder.add_public_input();

    let xy = builder.mul(x, y);
    let res = builder.add(xy, z);
    let diff = builder.sub(res, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let (airs_degrees, preprocessed_columns) = get_airs_and_degrees_with_prep::<
        GoldilocksConfig,
        _,
        D,
    >(&circuit, TablePacking::default(), None)
    .unwrap();
    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let x_val =
        Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(3), Goldilocks::NEG_ONE])
            .unwrap();
    let y_val =
        Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(7), Goldilocks::from_u64(11)])
            .unwrap();
    let z_val =
        Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(13), Goldilocks::from_u64(17)])
            .unwrap();
    let expected_val = x_val * y_val + z_val;

    runner
        .set_public_inputs(&[x_val, y_val, z_val, expected_val])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    assert_eq!(proof.ext_degree, 2);
    let expected_w = <Ext2 as ExtractBinomialW<Goldilocks>>::extract_w().unwrap();
    assert_eq!(proof.w_binomial, Some(expected_w));
    prover
        .verify_all_tables(&proof, circuit_prover_data.common_data())
        .unwrap();
}

#[test]
fn test_koalabear_modulus_constant() {
    // Verify KOALA_BEAR_MODULUS matches the actual KoalaBear field modulus.
    // The modulus p satisfies: from_u64(p) == 0 in the field.
    assert_eq!(
        KoalaBear::from_u64(KOALA_BEAR_MODULUS),
        KoalaBear::ZERO,
        "KOALA_BEAR_MODULUS (0x{:x}) does not match KoalaBear's actual modulus",
        KOALA_BEAR_MODULUS
    );

    // Verify the exact hex value (2130706433 = 0x7f000001).
    assert_eq!(KOALA_BEAR_MODULUS, 0x7f000001);
    assert_eq!(KOALA_BEAR_MODULUS, 2130706433);

    // Verify arithmetic at the modulus boundary with hardcoded expected values.
    // (p - 1) + 2 = 1 in the field
    let p_minus_1 = KoalaBear::from_u64(KOALA_BEAR_MODULUS - 1);
    assert_eq!(p_minus_1, KoalaBear::NEG_ONE);
    assert_eq!(p_minus_1 + KoalaBear::TWO, KoalaBear::ONE);

    // (p - 1) * (p - 1) = 1 in the field (since (-1) * (-1) = 1)
    assert_eq!(p_minus_1 * p_minus_1, KoalaBear::ONE);

    // Verify from_u64(p + 1) == 1
    assert_eq!(KoalaBear::from_u64(KOALA_BEAR_MODULUS + 1), KoalaBear::ONE);
}

#[test]
fn test_babybear_modulus_constant() {
    // Verify BABY_BEAR_MODULUS matches the actual BabyBear field modulus.
    assert_eq!(
        BabyBear::from_u64(BABY_BEAR_MODULUS),
        BabyBear::ZERO,
        "BABY_BEAR_MODULUS (0x{:x}) does not match BabyBear's actual modulus",
        BABY_BEAR_MODULUS
    );

    // Verify the exact hex value (2013265921 = 0x78000001).
    assert_eq!(BABY_BEAR_MODULUS, 0x78000001);
    assert_eq!(BABY_BEAR_MODULUS, 2013265921);

    // Verify arithmetic at the modulus boundary.
    let p_minus_1 = BabyBear::from_u64(BABY_BEAR_MODULUS - 1);
    assert_eq!(p_minus_1, BabyBear::NEG_ONE);
    assert_eq!(p_minus_1 + BabyBear::TWO, BabyBear::ONE);
    assert_eq!(BabyBear::from_u64(BABY_BEAR_MODULUS + 1), BabyBear::ONE);
}

#[test]
fn test_mul_only_circuit_padding() {
    // Circuit with only mul operations; ALU table still needs correct padding/lanes handling.
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let cfg = config::baby_bear().build();

    let x = builder.add_public_input();
    let y = builder.add_public_input();

    // Only multiplication, no addition
    builder.mul(x, y);

    let circuit = builder.build().unwrap();
    let (airs_degrees, preprocessed_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            TablePacking::default(),
            None,
        )
        .unwrap();
    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let x_val = BabyBear::from_u64(7);
    let y_val = BabyBear::from_u64(11);
    runner.set_public_inputs(&[x_val, y_val]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let common = circuit_prover_data.common_data();

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    prover.verify_all_tables(&proof, common).unwrap();
}

#[test]
fn test_add_only_circuit_padding() {
    // Circuit with only add operations; ALU table still needs correct padding/lanes handling.
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let cfg = config::baby_bear().build();

    let x = builder.add_public_input();
    let y = builder.add_public_input();
    let expected = builder.add_public_input();

    // Only addition, no multiplication
    let sum = builder.add(x, y);
    let diff = builder.sub(sum, expected);
    builder.assert_zero(diff);

    let circuit = builder.build().unwrap();
    let (airs_degrees, preprocessed_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            TablePacking::default(),
            None,
        )
        .unwrap();
    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let x_val = BabyBear::from_u64(42);
    let y_val = BabyBear::from_u64(13);
    let expected_val = x_val + y_val;
    runner
        .set_public_inputs(&[x_val, y_val, expected_val])
        .unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let common = circuit_prover_data.common_data();

    let prover = BatchStarkProver::new(cfg);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    prover.verify_all_tables(&proof, common).unwrap();
}
