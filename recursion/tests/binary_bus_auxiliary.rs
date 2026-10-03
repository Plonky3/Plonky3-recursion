//! Bus payloads consume authenticated preprocessing and the original public values.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProverData};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::{
    BinaryMultiStarkPreprocessing, BinaryMultiStarkVerifier, VerifierLimits,
};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_test_utils::binary_field_params::{blake3, keccak};

struct AuxiliaryBusAir<F> {
    direction: BusDirection,
    fixed: Vec<F>,
}
impl<F: RecursiveBinaryTowerField> BaseAir<F> for AuxiliaryBusAir<F> {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        2
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(RowMajorMatrix::new(self.fixed.clone(), 1))
    }
}
impl<F: RecursiveBinaryTowerField, AB: AirBuilder<F = F> + BusInteractionBuilder> Air<AB>
    for AuxiliaryBusAir<F>
{
    fn eval(&self, b: &mut AB) {
        let main = b.main().current_slice()[0];
        let fixed = b.preprocessed().current_slice()[0];
        let first = b.public_values()[0];
        let salt: AB::Expr = b.public_values()[1].into();
        b.when_first_row().assert_eq(main, first);
        // Neither fixed nor salt occurs in an ordinary assertion. Their
        // contribution must be evaluated through the bus expression roots.
        b.push_bus_interaction(
            BusName::new("auxiliary"),
            self.direction,
            [main * main + fixed * salt.clone(), fixed.into(), salt],
            BusActivation::Always,
        );
    }
}

fn field<F: RecursiveBinaryTowerField>(raw: u128) -> F {
    F::from_le_byte_iter(raw.to_le_bytes().into_iter().take(F::RAW_BITS / 8))
}
fn limbs<F: RecursiveBinaryTowerField>(value: F) -> impl Iterator<Item = BabyBear> {
    let raw = value.raw_coordinates();
    (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16))
}
fn run(circuit: &Circuit<BabyBear>, private: &[BabyBear], public: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(private).unwrap();
    runner.set_public_inputs(public).unwrap();
    runner.run().is_ok()
}

macro_rules! check {
    ($base:ty, $extension:ty, $params:ident, $hash:expr) => {{
        type F = $base;
        type E = $extension;
        type M = $params::LevelMmcs<F>;
        type ME = $params::LevelMmcs<E>;
        type Ch = $params::LevelChallenger<F>;
        type Pcs = BinaryPcs<F, E, M, ME>;
        struct Config {
            main: Pcs,
            preprocessing: Pcs,
        }
        impl MultiStarkConfig for Config {
            type Val = F;
            type Challenge = E;
            type Challenger = Ch;
            type Pcs = Pcs;
            fn pcs(&self) -> &Pcs {
                &self.main
            }
            fn preprocessed_pcs(&self) -> &Pcs {
                &self.preprocessing
            }
            fn min_num_variables(&self) -> usize {
                1
            }
            fn build_witness(&self, tables: Vec<Table<F>>) -> Witness<F> {
                SuffixProver::<F, E>::new_witness(tables, 0)
            }
            fn committed_table<'a>(
                &self,
                data: &'a BinaryPcsProverData<F, E, M>,
                index: usize,
            ) -> &'a Table<F> {
                data.table(index)
            }
        }
        let cfg = BinaryPcsConfig::try_new::<F, E>(
            2,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 40,
            },
        )
        .unwrap()
        .try_with_folding(2)
        .unwrap();
        let base = |cap| {
            M::new(
                $params::FieldHash::new($params::byte_hash()),
                $params::Compress::new($params::byte_hash()),
                cap,
            )
        };
        let round = |cap| {
            ME::new(
                $params::FieldHash::new($params::byte_hash()),
                $params::Compress::new($params::byte_hash()),
                cap,
            )
        };
        let (main_base, main_round, pre_base, pre_round) = (base(0), round(0), base(1), round(1));
        let native = Config {
            main: Pcs::new(cfg, main_base.clone(), main_round.clone()).unwrap(),
            preprocessing: Pcs::new(cfg, pre_base.clone(), pre_round.clone()).unwrap(),
        };
        let airs = [BusDirection::Push, BusDirection::Pull].map(|direction| AuxiliaryBusAir::<F> {
            direction,
            fixed: vec![field(0xab15_2983_47cd_6917), field(0x715d_39af_b597_2381)],
        });
        let refs = airs.iter().collect::<Vec<_>>();
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let (pk, vk) = setup(&native, &refs, &mut make()).unwrap();
        let tables = airs
            .iter()
            .map(|air| Table::new(air.preprocessed_trace().unwrap().transpose()))
            .collect();
        let (cap, _) = native
            .preprocessing
            .commit(native.build_witness(tables), &mut make())
            .unwrap();
        let verifier = BinaryMultiStarkVerifier::<F, E>::with_preprocessing(
            &refs,
            &[1, 1],
            cfg,
            $hash,
            0,
            0,
            5,
            128,
            BinaryMultiStarkPreprocessing {
                config: cfg,
                hash: $hash,
                cap_height: 1,
                max_query_draws: 128,
                commitment: cap,
            },
            &VerifierLimits::default(),
        )
        .unwrap();
        let shape = verifier.input_shape();
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let public_targets: Vec<_> = (0..2)
            .map(|_| {
                (0..2)
                    .map(|_| {
                        let values = core::array::from_fn(|_| b.public_input());
                        b.binary128_from_limbs::<BabyBear>(values).unwrap()
                    })
                    .collect()
            })
            .collect();
        let targets = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut b)
            .unwrap();
        let proof_private_len = b.private_input_count();
        let pre = targets.preprocessed_opening.as_ref().unwrap();
        let pre_fields = 2 * pre.sumcheck.len()
            + pre
                .evals
                .iter()
                .map(|batch| batch.current().len() + batch.next().len())
                .sum::<usize>()
            + pre
                .rounds
                .iter()
                .map(|round| round.rows.len())
                .sum::<usize>()
            + pre.base_rows.len()
            + pre.final_codeword.len()
            + 1;
        let pre_digests = pre
            .rounds
            .iter()
            .map(|round| round.cap.len() + round.paths.iter().map(Vec::len).sum::<usize>())
            .sum::<usize>()
            + pre.base_paths.iter().map(Vec::len).sum::<usize>();
        let pre_values = 8 * pre_fields
            + 16 * pre_digests
            + pre.query_indices.iter().map(Vec::len).sum::<usize>();
        let pre_claim_offset = proof_private_len - pre_values + 16 * pre.sumcheck.len();
        let initial: Vec<_> = [7, 19, 13]
            .map(|byte| b.define_const(BabyBear::from_u8(byte)))
            .to_vec();
        let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        let done = verifier
            .verify::<BabyBear, BabyBear>(&mut b, ch, &public_targets, &targets)
            .unwrap();
        let observation: Vec<_> = (0..F::RAW_BITS / 8)
            .map(|i| b.define_const(BabyBear::from_u8(if i == 0 { 9 } else { 0 })))
            .collect();
        let mut ch = done
            .resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation)
            .unwrap();
        let bytes = ch
            .sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8)
            .unwrap();
        let mut bits = [ExprId::ZERO; 128];
        for (i, byte) in bytes.into_iter().enumerate() {
            bits[8 * i..8 * i + 8]
                .copy_from_slice(&b.decompose_to_bits::<BabyBear>(byte, 8).unwrap());
        }
        let actual = b.binary128_from_bits(bits).unwrap();
        let expected_limbs = b.alloc_private_input_array::<8>("auxiliary bus continuation");
        let expected = b.binary128_from_limbs::<BabyBear>(expected_limbs).unwrap();
        for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
            let difference = b.sub(a, e);
            b.assert_zero(difference);
        }
        let circuit = b.build().unwrap();
        for seed in [3u128, 29] {
            let values = vec![field::<F>(seed), field::<F>(seed + 7)];
            let public = vec![vec![values[0], field::<F>(0xdeaf_9237_7139_5721u128 * seed)]; 2];
            let instances = airs
                .iter()
                .zip(&public)
                .map(|(air, public)| {
                    ProverInstance::new(
                        air,
                        Table::new(RowMajorMatrix::new(values.clone(), 1).transpose()),
                        &pk,
                        public,
                    )
                })
                .collect();
            let proof = prove(&native, ProverInstances::new(instances), 0, &mut make()).unwrap();
            let mut expected_ch = make();
            let instances = airs
                .iter()
                .zip(&public)
                .map(|(air, public)| VerifierInstance::new(air, &vk, 1, public))
                .collect();
            verify(
                &native,
                VerifierInstances::new(instances),
                &proof,
                0,
                &mut expected_ch,
            )
            .unwrap();
            let mut imported_ch = make();
            let input = verifier
                .import_native_with_preprocessing(
                    &main_base,
                    &main_round,
                    Some((&pre_base, &pre_round)),
                    &public,
                    &proof,
                    &mut imported_ch,
                )
                .unwrap();
            expected_ch.observe(field::<F>(9));
            imported_ch.observe(field::<F>(9));
            let next = expected_ch.sample_algebra_element::<E>();
            assert_eq!(next, imported_ch.sample_algebra_element::<E>());
            let mut private = input.private_values::<BabyBear>(&shape).unwrap();
            assert_eq!(private.len(), proof_private_len);
            private.extend(limbs(next));
            let public: Vec<_> = public.iter().flatten().copied().flat_map(limbs).collect();
            assert!(run(&circuit, &private, &public));
            // Public salt is read only by the bus, while the first value is
            // also read by the ordinary first-row constraint.
            for offset in [0, 8, 16, 24] {
                let mut wrong = public.clone();
                wrong[offset] += BabyBear::ONE;
                assert!(!run(&circuit, &private, &wrong));
            }
            let mut wrong = private.clone();
            wrong[16] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public));
            let mut wrong = private.clone();
            wrong[pre_claim_offset] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public));
            let mut wrong = private.clone();
            let index = wrong.len() - 8;
            wrong[index] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public));
        }
    }};
}

#[test]
fn narrow_binary_bus_payloads_authenticate_fixed_columns_and_public_values() {
    check!(BinaryField8, BinaryField64, blake3, ByteHash::Blake3);
}
#[test]
fn wide_binary_bus_payloads_authenticate_fixed_columns_and_public_values() {
    check!(BinaryField128, BinaryField128, keccak, ByteHash::Keccak256);
}
