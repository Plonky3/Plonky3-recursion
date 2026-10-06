//! Full native binary bus constraints inside prime-field circuits.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProverData};
use p3_bus::{BusActivation, BusBoundary, BusDirection, BusInteractionBuilder, BusName};
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
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::BinaryMultiStarkVerifier;
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_test_utils::binary_field_params::{blake3, keccak};

#[derive(Clone, Copy)]
enum Activation {
    Boolean,
    Always,
    First,
    Last,
}

#[derive(Clone, Copy)]
struct BusAir {
    direction: BusDirection,
    activation: Activation,
}
impl<F> BaseAir<F> for BusAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        2
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}
impl<AB: AirBuilder + BusInteractionBuilder> Air<AB> for BusAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let current = main.current_slice();
        let (x, selected) = (current[0], current[1]);
        let (first, last) = (b.public_values()[0], b.public_values()[1]);
        b.when_first_row().assert_eq(x, first);
        b.when_last_row().assert_eq(x, last);
        let activation = match self.activation {
            Activation::Boolean => BusActivation::Boolean(selected.into()),
            Activation::Always => BusActivation::Always,
            Activation::First => BusActivation::Boundary(BusBoundary::First),
            Activation::Last => BusActivation::Boundary(BusBoundary::Last),
        };
        // Lexicographic domain order differs from declaration order, and the
        // two domains have different payload widths. The selector's repeated
        // Boolean assertions must remain in the ordinary AIR fold.
        b.push_bus_interaction(
            BusName::new("zeta"),
            self.direction,
            [x * x],
            activation.clone(),
        );
        b.push_bus_interaction(
            BusName::new("alpha"),
            self.direction,
            [x * x, x.into()],
            activation,
        );
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
    ($params:ident, $hash:expr, $heights:expr, $pow:expr, $fold:expr, $cap:expr) => {
        check!(
            BinaryField128,
            BinaryField128,
            $params,
            $hash,
            $heights,
            $pow,
            $fold,
            $cap
        )
    };
    ($base:ty, $extension:ty, $params:ident, $hash:expr, $heights:expr, $pow:expr, $fold:expr, $cap:expr) => {
        check!(
            $base,
            $extension,
            $params,
            $hash,
            $heights,
            $pow,
            $fold,
            $cap,
            Activation::Boolean
        )
    };
    ($base:ty, $extension:ty, $params:ident, $hash:expr, $heights:expr, $pow:expr, $fold:expr, $cap:expr, $activation:expr) => {{
        type F = $base;
        type E = $extension;
        type M = $params::LevelMmcs<F>;
        type ME = $params::LevelMmcs<E>;
        type Ch = $params::LevelChallenger<F>;
        struct Config {
            pcs: BinaryPcs<F, E, M, ME>,
        }
        impl MultiStarkConfig for Config {
            type Val = F;
            type Challenge = E;
            type Challenger = Ch;
            type Pcs = BinaryPcs<F, E, M, ME>;
            fn pcs(&self) -> &Self::Pcs {
                &self.pcs
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
        let heights: Vec<usize> = $heights;
        let cells: usize = heights.iter().map(|&h| 2usize << h).sum();
        let n = p3_util::log2_ceil_usize(cells);
        let config = BinaryPcsConfig::try_new::<F, E>(
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
        let round_mmcs = ME::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap,
        );
        let native = Config {
            pcs: BinaryPcs::new(config, mmcs.clone(), round_mmcs.clone()).unwrap(),
        };
        let airs: Vec<_> = heights
            .iter()
            .enumerate()
            .map(|(i, _)| BusAir {
                direction: if i == 0 {
                    BusDirection::Push
                } else {
                    BusDirection::Pull
                },
                activation: $activation,
            })
            .collect();
        let refs: Vec<_> = airs.iter().collect();
        let verifier = BinaryMultiStarkVerifier::<F, E>::new(
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
            .map(|_| (0..2).map(|_| public_field(&mut b, &mut exports)).collect())
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
        let observation: Vec<_> = (0..F::RAW_BITS / 8)
            .map(|i| b.define_const(BabyBear::from_u8(if i == 0 { 9 } else { 0 })))
            .collect();
        let mut ch = token
            .resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation)
            .unwrap();
        let next_bytes = ch
            .sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8)
            .unwrap();
        let mut next_bits = [p3_circuit::ExprId::ZERO; 128];
        for (i, byte) in next_bytes.into_iter().enumerate() {
            let bits = b.decompose_to_bits::<BabyBear>(byte, 8).unwrap();
            next_bits[8 * i..8 * i + 8].copy_from_slice(&bits);
        }
        let next = b.binary128_from_bits(next_bits).unwrap();
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
            let active_count = 1usize << heights.iter().min().unwrap();
            for (i, &height) in heights.iter().enumerate() {
                let mut values = Vec::new();
                for row in 0..1usize << height {
                    let reverse = matches!($activation, Activation::Boolean | Activation::Always);
                    let slot = if i == 1 && row < active_count && reverse {
                        active_count - 1 - row
                    } else {
                        row
                    };
                    let x = F::from_le_byte_iter(
                        0x783920571fd326a958c94327af63de81u128
                            .wrapping_mul(seed + slot as u128)
                            .to_le_bytes()
                            .into_iter()
                            .take(F::RAW_BITS / 8),
                    );
                    values.extend([x, F::from_bool(heights.len() > 1 && row < active_count)]);
                }
                public.push(vec![values[0], values[values.len() - 2]]);
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
                .import_native(&mmcs, &round_mmcs, &public, &proof, &mut imported_ch)
                .unwrap();
            let observation =
                F::from_le_byte_iter((0..F::RAW_BITS / 8).map(|i| if i == 0 { 9 } else { 0 }));
            expected_ch.observe(observation);
            imported_ch.observe(observation);
            let next = expected_ch.sample_algebra_element::<E>();
            assert_eq!(next, imported_ch.sample_algebra_element::<E>());
            let mut private = imported.private_values::<BabyBear>(&shape).unwrap();
            let other_airs: Vec<_> = airs
                .iter()
                .map(|air| BusAir {
                    direction: if air.direction == BusDirection::Push {
                        BusDirection::Pull
                    } else {
                        BusDirection::Push
                    },
                    activation: air.activation,
                })
                .collect();
            let other_refs: Vec<_> = other_airs.iter().collect();
            let other = BinaryMultiStarkVerifier::<F, E>::new(
                &other_refs,
                &heights,
                config,
                $hash,
                $cap,
                $pow,
                heights.iter().max().unwrap() + 4,
                if n > 2 { 256 } else { 64 },
            )
            .unwrap();
            assert!(
                imported
                    .private_values::<BabyBear>(&other.input_shape())
                    .is_err()
            );
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
            wrong[commitment_limbs] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public_limbs));
            let mut wrong = private.clone();
            wrong[commitment_limbs + 8] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public_limbs));
            let mut wrong = public_limbs.clone();
            let public_limb = wrong.len() - 8;
            wrong[public_limb] += BabyBear::ONE;
            assert!(!run(&circuit, &private, &wrong));
            if F::RAW_BITS < 128 {
                let mut wrong = public_limbs.clone();
                wrong[F::RAW_BITS / 16] +=
                    BabyBear::from_u16(if F::RAW_BITS == 8 { 256 } else { 1 });
                assert!(!run(&circuit, &private, &wrong));
            }
            let mut wrong = private.clone();
            let last = wrong.len() - 8;
            wrong[last] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public_limbs));

            let duplicate = || p3_multi_stark::MultiStarkProof::<Config> {
                commitment: proof.commitment.clone(),
                lookup: None,
                indexed: None,
                bus: proof.bus.clone(),
                sumcheck: proof.sumcheck.clone(),
                opening: proof.opening.clone(),
                preprocessed_opening: None,
            };
            let unchanged = |bad: p3_multi_stark::MultiStarkProof<Config>| {
                let mut ch = make();
                let mut expected = ch.clone();
                assert!(
                    verifier
                        .import_native(&mmcs, &round_mmcs, &public, &bad, &mut ch)
                        .is_err()
                );
                assert_eq!(
                    ch.sample_algebra_element::<E>(),
                    expected.sample_algebra_element::<E>()
                );
            };
            let mut bad = duplicate();
            bad.bus = None;
            unchanged(bad);
            let mut bad = duplicate();
            bad.bus.as_mut().unwrap().product.layers.pop();
            unchanged(bad);
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
fn native_nonlinear_bus_proofs_match_both_binary_transcripts() {
    check!(keccak, ByteHash::Keccak256, vec![1, 1], 0, 2, 0);
    check!(
        BinaryField8,
        BinaryField64,
        blake3,
        ByteHash::Blake3,
        vec![1, 1],
        0,
        2,
        0
    );
}

#[test]
fn bus_blocks_with_unequal_heights_bind_the_shared_air_point() {
    check!(keccak, ByteHash::Keccak256, vec![2, 1], 0, 2, 0);
}

#[test]
fn disabled_one_sided_bus_declarations_balance_the_identity_tree() {
    check!(
        BinaryField8,
        BinaryField64,
        blake3,
        ByteHash::Blake3,
        vec![1],
        0,
        2,
        0
    );
}

#[test]
fn unconditional_and_boundary_bus_declarations_match_native_reductions() {
    for activation in [Activation::Always, Activation::First, Activation::Last] {
        check!(
            BinaryField8,
            BinaryField64,
            blake3,
            ByteHash::Blake3,
            vec![1, 1],
            0,
            2,
            0,
            activation
        );
    }
    check!(
        BinaryField128,
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        vec![1, 1],
        0,
        2,
        0,
        Activation::First
    );
}

fn prove_bound_statement(circuit: &Circuit<BabyBear>, private: &[BabyBear], public: Vec<BabyBear>) {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
        StatementAirBuilder, StatementPreprocessor, StatementProver,
    };
    let mut prover = BatchStarkProver::new(crate::proof_config());
    let schema = circuit.statement_schema().unwrap().clone();
    prover.register_table_prover(Box::new(KeccakF1600Prover::<1>));
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema.clone())));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            circuit,
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
    runner.set_private_inputs(private).unwrap();
    runner.set_public_inputs(&public).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &public).unwrap();
    let mut wrong = public;
    wrong[16] += BabyBear::ONE;
    assert!(prepared.verifier().verify(&proof, &wrong).is_err());
}

#[test]
fn a_complete_binary_bus_proof_verifies_in_a_prime_field_proof() {
    let (circuit, private, public) = check!(
        BinaryField8,
        BinaryField64,
        keccak,
        ByteHash::Keccak256,
        vec![1, 1],
        0,
        2,
        0
    );
    prove_bound_statement(&circuit, &private, public);
}
