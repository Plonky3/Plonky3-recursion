//! Complete native binary AIR proofs bound to prime-circuit public statements.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProverData};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder, StatementExport};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::verifier::{BinaryMultiStarkVerifier, VerificationError, VerifierLimits};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_test_utils::binary_field_params::{blake3, keccak};

#[derive(Clone, Copy)]
struct RecurrenceAir;
impl<F> BaseAir<F> for RecurrenceAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
}
impl<AB: AirBuilder> Air<AB> for RecurrenceAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let current = main.current_slice();
        let next = main.next_slice();
        let public = b.public_values();
        let (a, c, output) = (public[0], public[1], public[2]);
        b.when_first_row().assert_eq(current[0], a);
        b.when_first_row().assert_eq(current[1], c);
        b.when_transition().assert_eq(next[0], current[1]);
        b.when_transition()
            .assert_eq(next[1], current[0] * current[1] + current[0]);
        b.when_last_row().assert_eq(current[1], output);
    }
}

fn public_field(
    b: &mut CircuitBuilder<BabyBear>,
    exports: &mut Vec<StatementExport>,
) -> BinaryTower128Target {
    let limbs = core::array::from_fn(|_| b.public_input());
    exports.extend(limbs.map(StatementExport::Base));
    b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}
fn private_field(b: &mut CircuitBuilder<BabyBear>) -> BinaryTower128Target {
    let limbs = b.alloc_private_input_array::<8>("binary MultiStark continuation");
    b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}
fn limbs(value: BinaryField128) -> impl Iterator<Item = BabyBear> {
    (0..8).map(move |i| BabyBear::from_u16((value.to_repr() >> (16 * i)) as u16))
}
fn run(circuit: &Circuit<BabyBear>, private: &[BabyBear], public: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(private).unwrap();
    runner.set_public_inputs(public).unwrap();
    runner.run().is_ok()
}

macro_rules! check {
    ($params:ident, $hash:expr, $heights:expr, $pow:expr, $fold:expr, $cap:expr) => {{
        type F = BinaryField128;
        type M = $params::LevelMmcs<F>;
        type Ch = $params::LevelChallenger<F>;
        struct Config {
            pcs: BinaryPcs<F, F, M, M>,
        }
        impl MultiStarkConfig for Config {
            type Val = F;
            type Challenge = F;
            type Challenger = Ch;
            type Pcs = BinaryPcs<F, F, M, M>;
            fn pcs(&self) -> &Self::Pcs {
                &self.pcs
            }
            fn min_num_variables(&self) -> usize {
                1
            }
            fn build_witness(&self, tables: Vec<Table<F>>) -> Witness<F> {
                SuffixProver::<F, F>::new_witness(tables, 0)
            }
            fn committed_table<'a>(
                &self,
                data: &'a BinaryPcsProverData<F, F, M>,
                index: usize,
            ) -> &'a Table<F> {
                data.table(index)
            }
        }
        let heights: Vec<usize> = $heights;
        let cells: usize = heights.iter().map(|&h| 2usize << h).sum();
        let n = p3_util::log2_ceil_usize(cells);
        let config = BinaryPcsConfig::try_new::<F, F>(
            n,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 40,
            },
        )
        .unwrap()
        .try_with_folding($fold)
        .unwrap();
        let mmcs = M::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap,
        );
        let native = Config {
            pcs: BinaryPcs::new(config, mmcs.clone(), mmcs.clone()).unwrap(),
        };
        let airs: Vec<_> = heights.iter().map(|_| RecurrenceAir).collect();
        let refs: Vec<_> = airs.iter().collect();
        let verifier = BinaryMultiStarkVerifier::<F>::new(
            &refs,
            &heights,
            config,
            $hash,
            $cap,
            $pow,
            heights.iter().max().unwrap() + 4,
            if n > 2 { 256 } else { 64 },
        )
        .unwrap();
        let shape = verifier.input_shape();
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let (pk, vk) = setup(&native, &refs, &mut make()).unwrap();
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let mut exports = Vec::new();
        let public_targets: Vec<_> = airs
            .iter()
            .map(|_| (0..3).map(|_| public_field(&mut b, &mut exports)).collect())
            .collect();
        let targets = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut b)
            .unwrap();
        let initial: Vec<_> = [7, 19, 13]
            .into_iter()
            .map(|v| b.define_const(BabyBear::from_u8(v)))
            .collect();
        let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        let token = verifier
            .verify::<BabyBear, BabyBear>(&mut b, ch, &public_targets, &targets)
            .unwrap();
        let observation: Vec<_> = (0..16)
            .map(|i| b.define_const(BabyBear::from_u8(if i == 0 { 9 } else { 0 })))
            .collect();
        let mut ch = token
            .resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation)
            .unwrap();
        let next = ch.sample::<BabyBear, BabyBear>(&mut b).unwrap();
        let expected = private_field(&mut b);
        for (&a, &e) in next.bits().iter().zip(expected.bits()) {
            let diff = b.sub(a, e);
            b.assert_zero(diff);
        }
        b.set_statement_exports::<BabyBear>(&exports).unwrap();
        let circuit = b.build().unwrap();
        let mut final_values = (vec![], vec![]);
        for seed in [2u128, 19] {
            let mut tables = Vec::new();
            let mut public = Vec::new();
            for (i, &height) in heights.iter().enumerate() {
                let a = F::from_repr(
                    0x0123_4567_89ab_cdef_fedc_ba98_7654_3210 ^ (seed + 37 * i as u128),
                );
                let c = F::from_repr(
                    0xfedc_ba98_7654_3210_0123_4567_89ab_cdef ^ (seed + 71 * i as u128),
                );
                let (mut x, mut y) = (a, c);
                let mut values = Vec::new();
                for _ in 0..1usize << height {
                    values.extend([x, y]);
                    (x, y) = (y, x * y + x);
                }
                public.push(vec![a, c, *values.last().unwrap()]);
                tables.push(Table::new(RowMajorMatrix::new(values, 2).transpose()));
            }
            let instances = airs
                .iter()
                .zip(tables)
                .zip(&public)
                .map(|((air, table), values)| ProverInstance::new(air, table, &pk, values))
                .collect();
            let proof = prove(&native, ProverInstances::new(instances), $pow, &mut make()).unwrap();
            let instances = airs
                .iter()
                .zip(&heights)
                .zip(&public)
                .map(|((air, &height), values)| VerifierInstance::new(air, &vk, height, values))
                .collect();
            let mut expected_ch = make();
            verify(
                &native,
                VerifierInstances::new(instances),
                &proof,
                $pow,
                &mut expected_ch,
            )
            .unwrap();
            let mut imported_ch = make();
            let imported = verifier
                .import_native(&mmcs, &mmcs, &public, &proof, &mut imported_ch)
                .unwrap();
            expected_ch.observe(F::from_repr(9));
            imported_ch.observe(F::from_repr(9));
            let next = expected_ch.sample_algebra_element::<F>();
            assert_eq!(next, imported_ch.sample_algebra_element::<F>());
            let mut private = imported.private_values::<BabyBear>(&shape).unwrap();
            let commitment_limbs = (1usize << $cap) * 16;
            private.extend(limbs(next));
            let public_limbs: Vec<_> = public.iter().flatten().copied().flat_map(limbs).collect();
            let mut runner = circuit.runner();
            runner.set_private_inputs(&private).unwrap();
            runner.set_public_inputs(&public_limbs).unwrap();
            runner
                .run()
                .expect("complete native MultiStark circuit must verify");
            let mut wrong = private.clone();
            wrong[0] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public_limbs));
            let mut wrong = private.clone();
            wrong[commitment_limbs] = BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public_limbs));
            let mut wrong = private.clone();
            wrong[commitment_limbs + 8] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public_limbs));
            let mut wrong = public_limbs.clone();
            wrong[16] += BabyBear::ONE;
            assert!(!run(&circuit, &private, &wrong));
            let mut wrong = private.clone();
            let last = wrong.len() - 8;
            wrong[last] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public_limbs));

            let duplicate = || p3_multi_stark::MultiStarkProof::<Config> {
                commitment: proof.commitment.clone(),
                lookup: None,
                indexed: None,
                bus: None,
                sumcheck: proof.sumcheck.clone(),
                opening: proof.opening.clone(),
                preprocessed_opening: None,
            };
            let unchanged = |bad: p3_multi_stark::MultiStarkProof<Config>| {
                let mut ch = make();
                let mut expected = ch.clone();
                assert!(
                    verifier
                        .import_native(&mmcs, &mmcs, &public, &bad, &mut ch)
                        .is_err()
                );
                assert_eq!(
                    ch.sample_algebra_element::<F>(),
                    expected.sample_algebra_element::<F>()
                );
            };
            let mut bad = duplicate();
            bad.sumcheck.round_polys.pop();
            unchanged(bad);
            let mut bad = duplicate();
            bad.sumcheck.pow_witnesses.push(F::ZERO);
            unchanged(bad);
            let mut bad = duplicate();
            bad.opening.evals.pop();
            unchanged(bad);
            let mut bad = duplicate();
            bad.preprocessed_opening = Some(bad.opening.clone());
            unchanged(bad);
            let mut bad = duplicate();
            bad.opening.base_multi_proof.sibling_hashes.push([0; 32]);
            unchanged(bad);
            final_values = (private, public_limbs);
        }
        (circuit, final_values.0, final_values.1)
    }};
}

#[test]
fn nonlinear_native_binary_air_proofs_match_both_hash_transcripts() {
    check!(keccak, ByteHash::Keccak256, vec![1], 0, 1, 0);
    check!(blake3, ByteHash::Blake3, vec![1], 0, 2, 1);
}

#[test]
fn mixed_trace_heights_and_positive_sumcheck_grinding_match_native() {
    check!(keccak, ByteHash::Keccak256, vec![2, 1], 3, 2, 0);
}

#[test]
fn a_complete_native_binary_air_proof_verifies_in_a_prime_field_proof() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
        StatementAirBuilder, StatementPreprocessor, StatementProver,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, private, public) = check!(keccak, ByteHash::Keccak256, vec![1], 0, 2, 0);
    let mut prover = BatchStarkProver::new(config::baby_bear());
    let schema = circuit.statement_schema().unwrap().clone();
    prover.register_table_prover(Box::new(KeccakF1600Prover::<1>));
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema.clone())));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &[
                Box::new(KeccakF1600Preprocessor),
                Box::new(StatementPreprocessor::new(schema.clone())),
            ],
            &[
                Box::new(KeccakF1600AirBuilder::<1>),
                Box::new(StatementAirBuilder::<1>::new(schema)),
            ],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&private).unwrap();
    runner.set_public_inputs(&public).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &public).unwrap();
    let mut wrong = public;
    wrong[16] += BabyBear::ONE;
    assert!(prepared.verifier().verify(&proof, &wrong).is_err());
}

#[test]
fn trusted_multi_stark_geometry_and_combined_resources_are_bounded() {
    let config = BinaryPcsConfig::try_new::<BinaryField128, BinaryField128>(
        2,
        BinaryPcsParams {
            log_inv_rate: 2,
            pow_bits: 0,
            security_level: 40,
        },
    )
    .unwrap();
    assert!(
        BinaryMultiStarkVerifier::<BinaryField128>::new(
            &[&RecurrenceAir],
            &[0],
            config,
            ByteHash::Keccak256,
            0,
            0,
            1,
            64
        )
        .is_err()
    );
    assert!(
        BinaryMultiStarkVerifier::<BinaryField128>::new(
            &[&RecurrenceAir],
            &[],
            config,
            ByteHash::Keccak256,
            0,
            0,
            5,
            64
        )
        .is_err()
    );
    assert!(
        BinaryMultiStarkVerifier::<BinaryField128>::new(
            &[&RecurrenceAir],
            &[2],
            config,
            ByteHash::Keccak256,
            0,
            0,
            6,
            64
        )
        .is_err()
    );
    let limits = VerifierLimits {
        max_total_scalar_elements: 24,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryMultiStarkVerifier::<BinaryField128>::with_limits(
            &[&RecurrenceAir],
            &[1],
            config,
            ByteHash::Keccak256,
            0,
            0,
            5,
            64,
            &limits
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
    let height = usize::BITS as usize;
    let limits = VerifierLimits {
        max_rounds: 256,
        max_log_domain_or_degree: height,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryMultiStarkVerifier::<BinaryField128>::with_limits(
            &[&RecurrenceAir],
            &[height],
            config,
            ByteHash::Keccak256,
            0,
            0,
            height + 4,
            64,
            &limits
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "binary MultiStark trace log height",
            actual,
            limit,
        }) if actual == height && limit == height - 1
    ));
}
