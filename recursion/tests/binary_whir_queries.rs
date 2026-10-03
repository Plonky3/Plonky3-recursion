//! Fixed stratified query schedules match the released WHIR transcript driver.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_challenger::FieldChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::ByteHash;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::BinaryWhirQueryPlan;
use p3_recursion::transcript::domain_separator_seed;
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_test_utils::binary_field_params::{blake3, keccak};
use p3_whir::transcript::{SumcheckShape, WhirShape, WhirVerifierTranscript};
use p3_whir::{FoldingFactor, SecurityAssumption};

// An isolated final query site: delegate brackets contain no arithmetic. The
// released driver itself owns seed encoding and every stratified index draw.
fn shape(bits: usize, draws: usize) -> WhirShape {
    WhirShape {
        num_variables: 1,
        commitment_ood_samples: 0,
        num_opening_claims: 0,
        commitment_row_width: 2,
        initial_sumcheck: SumcheckShape {
            rounds: 1,
            pow_bits: 0,
        },
        rounds: vec![],
        final_poly_len: 1,
        final_pow_bits: 0,
        final_query_draws: draws,
        final_index_bits: bits,
        final_query_summand_depths: (0..bits).rev().filter(|&d| (draws >> d) & 1 != 0).collect(),
        stratified_queries: true,
        final_sumcheck: SumcheckShape {
            rounds: 0,
            pow_bits: 0,
        },
        security_level: 8,
        pow_budget: 0,
        starting_log_inv_rate: 1,
        soundness_type: SecurityAssumption::JohnsonBound,
        folding_factor: FoldingFactor::Constant(1),
        domain_id: b"p3-whir-domain:cantor-tower-128-v1".to_vec(),
    }
}

macro_rules! check {
    ($params:ident, $hash:expr, $bits:expr, $draws:expr) => {{
        type E = BinaryField128;
        let shape = shape($bits, $draws);
        let plan = BinaryWhirQueryPlan::new($bits, $draws).unwrap();
        let mut native =
            $params::LevelChallenger::<E>::from_hasher(vec![9; 3], $params::byte_hash());
        use p3_challenger::CanSampleUniformBits;
        assert_eq!(native.sample_uniform_bits::<false>(0).unwrap(), 0);
        let mut driver = WhirVerifierTranscript::<_, E, E>::new(&mut native, shape.clone());
        driver.delegate_initial_fold(|_| ());
        driver.final_poly(&[E::ZERO]).unwrap();
        driver.query_pow(0, E::ZERO).unwrap();
        let indices = driver.query_indices(0);
        driver.delegate_final_fold(|_| ());
        driver.finish();
        let expected = native.sample_algebra_element::<E>().to_repr();
        assert_eq!(indices.len(), plan.num_queries());
        if $bits == 32 {
            assert!(
                indices
                    .iter()
                    .any(|&index| index as u64 >= BabyBear::ORDER_U64)
            );
        }
        if $draws == 21 {
            assert!(
                indices
                    .iter()
                    .enumerate()
                    .any(|(i, index)| indices[..i].contains(index))
            );
        }
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let initial = (0..3)
            .map(|_| b.define_const(BabyBear::from_u8(9)))
            .collect::<Vec<_>>();
        let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        ch.sample_bits::<BabyBear, BabyBear>(&mut b, 0).unwrap();
        let seed = domain_separator_seed(&shape.domain_separator::<E, E>())
            .into_iter()
            .flat_map(|v| v.to_repr().to_le_bytes())
            .map(|v| b.define_const(BabyBear::from_u8(v)))
            .collect::<Vec<_>>();
        ch.observe_bytes::<BabyBear, BabyBear>(&mut b, &seed)
            .unwrap();
        let zero = b.binary128_constant(0).unwrap();
        ch.observe::<BabyBear, BabyBear>(&mut b, &zero).unwrap();
        let targets = plan.sample::<BabyBear, BabyBear>(&mut b, &mut ch).unwrap();
        let mut values = vec![];
        for (bits, index) in targets.iter().zip(&indices) {
            for (i, &bit) in bits.iter().enumerate() {
                let expected = b.alloc_private_input("native WHIR index bit");
                values.push(BabyBear::from_bool((index >> i) & 1 != 0));
                let diff = b.sub(bit, expected);
                b.assert_zero(diff);
            }
        }
        let actual = ch.sample::<BabyBear, BabyBear>(&mut b).unwrap();
        let limbs = b.alloc_private_input_array::<8>("native continued WHIR challenge");
        values.extend((0..8).map(|i| BabyBear::from_u16((expected >> (16 * i)) as u16)));
        let expected = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
        for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
            let diff = b.sub(a, e);
            b.assert_zero(diff);
        }
        let circuit = b.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_private_inputs(&values).unwrap();
        runner.run().unwrap();
        values[0] += BabyBear::ONE;
        let mut runner = circuit.runner();
        runner.set_private_inputs(&values).unwrap();
        assert!(runner.run().is_err());
        circuit
    }};
}

#[test]
fn stratified_summands_preserve_native_draw_order_and_continuation() {
    check!(keccak, ByteHash::Keccak256, 5, 13);
    check!(blake3, ByteHash::Blake3, 5, 21);
    check!(keccak, ByteHash::Keccak256, 32, 3);
}

#[test]
fn exhaustive_sites_consume_no_query_draws_including_zero_bit_domain() {
    check!(keccak, ByteHash::Keccak256, 3, 0);
    check!(blake3, ByteHash::Blake3, 0, 0);
}

#[test]
fn query_plans_reject_invalid_or_unbounded_geometry() {
    assert!(BinaryWhirQueryPlan::new(4, 16).is_err());
    assert!(BinaryWhirQueryPlan::new(usize::BITS as usize, 1).is_err());
    let limits = VerifierLimits {
        max_queries_per_round: 7,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryWhirQueryPlan::with_limits(3, 0, &limits),
        Err(VerificationError::ResourceLimitExceeded { .. })
    ));
    let limits = VerifierLimits {
        max_total_scalar_elements: 8,
        ..VerifierLimits::default()
    };
    assert!(BinaryWhirQueryPlan::with_limits(5, 3, &limits).is_err());
}
