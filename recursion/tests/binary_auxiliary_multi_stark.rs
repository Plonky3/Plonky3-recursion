//! Binary MultiStark preprocessing is fixed by trusted verifier construction.

use std::borrow::Cow;

use p3_air::boundary::{BoundaryEnd, BoundaryPublic};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProverData};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{Circuit, CircuitBuilder, ExprId, StatementExport};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleCap;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::{
    BinaryMultiStarkPreprocessing, BinaryMultiStarkVerifier, VerificationError, VerifierLimits,
};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_test_utils::binary_field_params::{blake3, keccak};

struct PreprocessedAir;
impl<F> BaseAir<F> for PreprocessedAir {
    fn width(&self) -> usize {
        1
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
}
impl<AB: AirBuilder> Air<AB> for PreprocessedAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main().current_slice()[0];
        let preprocessing = b.preprocessed().current_slice()[0];
        b.assert_eq(main, preprocessing);
    }
}

fn config(n: usize) -> BinaryPcsConfig {
    BinaryPcsConfig::try_new::<BinaryField128, BinaryField128>(
        n,
        BinaryPcsParams {
            log_inv_rate: 2,
            pow_bits: 0,
            security_level: 40,
        },
    )
    .unwrap()
}

#[test]
fn a_preprocessing_cap_is_required_and_retained_in_the_trusted_shape() {
    let cfg = config(2);
    assert!(
        BinaryMultiStarkVerifier::<BinaryField128>::new(
            &[&PreprocessedAir],
            &[2],
            cfg,
            ByteHash::Keccak256,
            0,
            0,
            6,
            64,
        )
        .is_err()
    );
    let prepare = |root| {
        BinaryMultiStarkVerifier::<BinaryField128>::with_preprocessing(
            &[&PreprocessedAir],
            &[2],
            cfg,
            ByteHash::Keccak256,
            0,
            0,
            6,
            64,
            BinaryMultiStarkPreprocessing {
                config: cfg,
                hash: ByteHash::Keccak256,
                cap_height: 0,
                max_query_draws: 64,
                commitment: MerkleCap::new(vec![root]),
            },
            &VerifierLimits::default(),
        )
        .unwrap()
    };
    let verifier = prepare([0; 32]);
    let changed = prepare([1; 32]);
    assert_ne!(verifier.input_shape(), changed.input_shape());
    let mut b = CircuitBuilder::<BabyBear>::new();
    let targets = verifier
        .input_shape()
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    assert!(targets.preprocessed_opening.is_some());
}

#[test]
fn preprocessing_cap_geometry_and_combined_costs_are_checked() {
    let cfg = config(2);
    let prepare = |cap_height, roots, limits: &VerifierLimits| {
        BinaryMultiStarkVerifier::<BinaryField128>::with_preprocessing(
            &[&PreprocessedAir],
            &[2],
            cfg,
            ByteHash::Keccak256,
            0,
            0,
            6,
            64,
            BinaryMultiStarkPreprocessing {
                config: cfg,
                hash: ByteHash::Keccak256,
                cap_height,
                max_query_draws: 64,
                commitment: MerkleCap::new(roots),
            },
            limits,
        )
    };
    assert!(prepare(0, vec![[0; 32]; 2], &VerifierLimits::default()).is_err());
    assert!(
        prepare(
            usize::BITS as usize,
            vec![[0; 32]],
            &VerifierLimits::default()
        )
        .is_err()
    );
    let limits = VerifierLimits {
        max_cap_roots: 3,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        prepare(0, vec![[0; 32]], &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "cap roots",
            ..
        })
    ));
}

struct AuxiliaryAir<F> {
    height: usize,
    preprocessed: bool,
    periods: Vec<Vec<F>>,
}

fn field<F: RecursiveBinaryTowerField>(raw: u128) -> F {
    F::from_le_byte_iter(raw.to_le_bytes().into_iter().take(F::RAW_BITS / 8))
}

impl<F: RecursiveBinaryTowerField> AuxiliaryAir<F> {
    fn new(height: usize, preprocessed: bool) -> Self {
        Self {
            height,
            preprocessed,
            periods: vec![
                vec![field(19)],
                vec![field(37), field(71)],
                (0..if height == 1 { 2 } else { 4 })
                    .map(|i| field(11 + 6 * i))
                    .collect(),
            ],
        }
    }
    fn preprocessing(&self) -> Vec<F> {
        let (mut a, mut c) = (
            field::<F>(0x8539_437b_215d_1351),
            field::<F>(0x3917_b573_d157_9933),
        );
        let mut values = Vec::new();
        for row in 0..1usize << self.height {
            values.extend([a, field(31 + row as u128), c]);
            (a, c) = (c + self.periods[1][row % 2], a);
        }
        values
    }
    fn main_values(&self) -> Vec<F> {
        let preprocessing = self.preprocessing();
        (0..1usize << self.height)
            .flat_map(|row| {
                let periodic = self.periods[0][0] * self.periods[1][row % 2]
                    + self.periods[2][row % self.periods[2].len()];
                if self.preprocessed {
                    let a = preprocessing[row * 3];
                    [a + periodic, a]
                } else {
                    [periodic, periodic]
                }
            })
            .collect()
    }
}

impl<F: RecursiveBinaryTowerField> BaseAir<F> for AuxiliaryAir<F> {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        2
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        if self.preprocessed { vec![1] } else { vec![] }
    }
    fn preprocessed_width(&self) -> usize {
        if self.preprocessed { 3 } else { 0 }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        if self.preprocessed {
            vec![2, 0]
        } else {
            vec![]
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.preprocessed
            .then(|| RowMajorMatrix::new(self.preprocessing(), 3))
    }
    fn num_periodic_columns(&self) -> usize {
        3
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Borrowed(&self.periods)
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        const PINS: [BoundaryPublic; 2] = [
            BoundaryPublic::new(1, BoundaryEnd::First, 0),
            BoundaryPublic::new(0, BoundaryEnd::Last, 1),
        ];
        &PINS
    }
}

impl<F: RecursiveBinaryTowerField, AB: AirBuilder<F = F>> Air<AB> for AuxiliaryAir<F> {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let (current0, current1) = (main.current_slice()[0], main.current_slice()[1]);
        let next1 = self.preprocessed.then(|| main.next_slice()[1]);
        let periods = b.periodic_values();
        let product: AB::Expr = periods[0].into() * periods[1].into();
        let last_period: AB::Expr = periods[2].into();
        let next_period: AB::Expr = periods[1].into();
        if self.preprocessed {
            let preprocessed = b.preprocessed();
            let current = preprocessed.current_slice();
            let next = preprocessed.next_slice();
            let (a, c, next_a, next_c) = (current[0], current[2], next[0], next[2]);
            let successor = c.into() + next_period;
            b.assert_eq(current0, a.into() + product + last_period);
            b.assert_eq(current1, a);
            b.when_transition()
                .assert_eq(next1.unwrap(), successor.clone());
            b.when_transition().assert_eq(next_a, successor);
            b.when_transition().assert_eq(next_c, a);
        } else {
            b.assert_eq(current0, product + last_period);
            b.assert_eq(current1, current0);
        }
    }
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
    ($f:ty, $e:ty, $params:ident, $hash:expr, $instances:expr) => {{
        type F = $f;
        type E = $e;
        type M = $params::LevelMmcs<F>;
        type ME = $params::LevelMmcs<E>;
        type Ch = $params::LevelChallenger<F>;
        type Pcs = BinaryPcs<F, E, M, ME>;
        struct Config { main: Pcs, preprocessing: Pcs }
        impl MultiStarkConfig for Config {
            type Val = F;
            type Challenge = E;
            type Challenger = Ch;
            type Pcs = Pcs;
            fn pcs(&self) -> &Pcs { &self.main }
            fn preprocessed_pcs(&self) -> &Pcs { &self.preprocessing }
            fn min_num_variables(&self) -> usize { 1 }
            fn build_witness(&self, tables: Vec<Table<F>>) -> Witness<F> {
                SuffixProver::<F, E>::new_witness(tables, 0)
            }
            fn committed_table<'a>(&self, data: &'a BinaryPcsProverData<F, E, M>, index: usize) -> &'a Table<F> {
                data.table(index)
            }
        }
        let airs: Vec<AuxiliaryAir<F>> = $instances.into_iter()
            .map(|(height, preprocessed)| AuxiliaryAir::new(height, preprocessed)).collect();
        let refs: Vec<_> = airs.iter().collect();
        let heights: Vec<_> = airs.iter().map(|air| air.height).collect();
        let make_config = |cells| BinaryPcsConfig::try_new::<F, E>(p3_util::log2_ceil_usize(cells),
            BinaryPcsParams { log_inv_rate: 2, pow_bits: 0, security_level: 40 })
            .unwrap().try_with_folding(2).unwrap();
        let main_config = make_config(airs.iter().map(|air| 2usize << air.height).sum());
        let preprocessed_config = make_config(airs.iter().filter(|air| air.preprocessed)
            .map(|air| 3usize << air.height).sum());
        let base = |cap| M::new($params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()), cap);
        let round = |cap| ME::new($params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()), cap);
        let (main_base, main_round, pre_base, pre_round) = (base(0), round(0), base(1), round(1));
        let native = Config {
            main: Pcs::new(main_config, main_base.clone(), main_round.clone()).unwrap(),
            preprocessing: Pcs::new(preprocessed_config, pre_base.clone(), pre_round.clone()).unwrap(),
        };
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let (pk, vk) = setup(&native, &refs, &mut make()).unwrap();
        let tables = airs.iter().filter(|air| air.preprocessed)
            .map(|air| Table::new(air.preprocessed_trace().unwrap().transpose())).collect();
        let (pre_cap, _) = native.preprocessing.commit(native.build_witness(tables), &mut make()).unwrap();
        let verifier_for = |cap| BinaryMultiStarkVerifier::<F, E>::with_preprocessing(
            &refs, &heights, main_config, $hash, 0, 0, heights.iter().max().unwrap() + 4,
            if main_config.num_variables() > 2 { 256 } else { 64 },
            BinaryMultiStarkPreprocessing {
                config: preprocessed_config, hash: $hash, cap_height: 1,
                max_query_draws: if preprocessed_config.num_variables() > 3 { 256 } else { 128 }, commitment: cap,
            }, &VerifierLimits::default(),
        ).unwrap();
        let verifier = verifier_for(pre_cap.clone());
        let build = |verifier: &BinaryMultiStarkVerifier<F, E>| {
            let mut b = CircuitBuilder::<BabyBear>::new();
            match $hash {
                ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
                ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
            }
            let mut exports = Vec::new();
            let public_targets: Vec<_> = airs.iter().map(|_| (0..2).map(|_| {
                let limbs = core::array::from_fn(|_| b.public_input());
                exports.extend(limbs.map(StatementExport::Base));
                b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
            }).collect()).collect();
            let targets = verifier.input_shape().allocate_targets::<BabyBear, BabyBear>(&mut b).unwrap();
            let initial: Vec<_> = [7, 19, 13].into_iter().map(|v| b.define_const(BabyBear::from_u8(v))).collect();
            let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(&mut b, $hash, &initial).unwrap();
            let continuation = verifier.verify::<BabyBear, BabyBear>(&mut b, ch, &public_targets, &targets).unwrap();
            let observation: Vec<_> = (0..F::RAW_BITS / 8).map(|i| b.define_const(BabyBear::from_u8(if i == 0 { 9 } else { 0 }))).collect();
            let mut ch = continuation.resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation).unwrap();
            let bytes = ch.sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8).unwrap();
            let mut bits = [ExprId::ZERO; 128];
            for (i, byte) in bytes.into_iter().enumerate() {
                bits[8 * i..8 * i + 8].copy_from_slice(&b.decompose_to_bits::<BabyBear>(byte, 8).unwrap());
            }
            let actual = b.binary128_from_bits(bits).unwrap();
            let expected_limbs = b.alloc_private_input_array::<8>("preprocessing transcript continuation");
            let expected = b.binary128_from_limbs::<BabyBear>(expected_limbs).unwrap();
            for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
                let difference = b.sub(a, e);
                b.assert_zero(difference);
            }
            b.set_statement_exports::<BabyBear>(&exports).unwrap();
            b.build().unwrap()
        };
        let circuit = build(&verifier);
        let mut public = Vec::new();
        let tables: Vec<_> = airs.iter().map(|air| {
            let values = air.main_values();
            public.push(vec![values[1], values[values.len() - 2]]);
            Table::new(RowMajorMatrix::new(values, 2).transpose())
        }).collect();
        let instances = airs.iter().zip(tables).zip(&public)
            .map(|((air, table), public)| ProverInstance::new(air, table, &pk, public)).collect();
        let proof = prove(&native, ProverInstances::new(instances), 0, &mut make()).unwrap();
        let native_verify = |proof: &p3_multi_stark::MultiStarkProof<Config>, ch: &mut Ch| {
            let instances = airs.iter().zip(&public).map(|(air, public)| VerifierInstance::new(air, &vk, air.height, public)).collect();
            verify(&native, VerifierInstances::new(instances), proof, 0, ch)
        };
        let mut expected_ch = make();
        native_verify(&proof, &mut expected_ch).unwrap();
        let shape = verifier.input_shape();
        let import = |proof: &p3_multi_stark::MultiStarkProof<Config>, ch: &mut Ch| {
            verifier.import_native_with_preprocessing(&main_base, &main_round, Some((&pre_base, &pre_round)), &public, proof, ch)
        };
        let mut imported_ch = make();
        let imported = import(&proof, &mut imported_ch).unwrap();
        expected_ch.observe(field::<F>(9));
        imported_ch.observe(field::<F>(9));
        let continuation = expected_ch.sample_algebra_element::<E>();
        assert_eq!(continuation, imported_ch.sample_algebra_element::<E>());
        let mut private = imported.private_values::<BabyBear>(&shape).unwrap();
        private.extend(limbs(continuation));
        let public_limbs: Vec<_> = public.iter().flatten().copied().flat_map(limbs).collect();
        let mut runner = circuit.runner();
        runner.set_private_inputs(&private).unwrap();
        runner.set_public_inputs(&public_limbs).unwrap();
        runner.run().expect("full preprocessing and periodic proof must verify");
        let mut wrong = public_limbs.clone();
        wrong[8] += BabyBear::ONE;
        assert!(!run(&circuit, &private, &wrong));
        let mut wrong_cap = pre_cap.roots().to_vec();
        wrong_cap[0][0] ^= 1;
        let changed = verifier_for(MerkleCap::new(wrong_cap));
        assert_ne!(shape, changed.input_shape());
        assert!(imported.private_values::<BabyBear>(&changed.input_shape()).is_err());
        assert!(!run(&build(&changed), &private, &public_limbs));
        let copy = || p3_multi_stark::MultiStarkProof::<Config> {
            commitment: proof.commitment.clone(), lookup: None, indexed: None, bus: None,
            sumcheck: proof.sumcheck.clone(), opening: proof.opening.clone(),
            preprocessed_opening: proof.preprocessed_opening.clone(),
        };
        for late in [false, true] {
            let mut bad = copy();
            if late {
                bad.preprocessed_opening.as_mut().unwrap().base_multi_proof.sibling_hashes.push([0; 32]);
            } else { bad.preprocessed_opening = None; }
            let mut actual = make();
            let mut expected = actual.clone();
            assert!(import(&bad, &mut actual).is_err());
            assert_eq!(actual.sample_algebra_element::<E>(), expected.sample_algebra_element::<E>());
        }
        let mut bad = copy();
        let opening = bad.preprocessed_opening.as_mut().unwrap();
        let mut current = opening.evals[0].current().to_vec();
        current[0] += E::ONE;
        opening.evals[0] = p3_sumcheck::OpeningBatch::new(current, opening.evals[0].next().to_vec());
        assert!(native_verify(&bad, &mut make()).is_err());
        let mut bad_ch = make();
        if let Ok(bad) = import(&bad, &mut bad_ch) {
            let mut bad_private = bad.private_values::<BabyBear>(&shape).unwrap();
            bad_ch.observe(field::<F>(9));
            bad_private.extend(limbs(bad_ch.sample_algebra_element::<E>()));
            assert!(!run(&circuit, &bad_private, &public_limbs));
        }
        (circuit, private, public_limbs)
    }};
}

#[test]
fn native_preprocessed_and_periodic_proofs_match_both_hashes_and_tower_widths() {
    check!(
        BinaryField128,
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        vec![(1, true)]
    );
    check!(
        BinaryField8,
        BinaryField64,
        blake3,
        ByteHash::Blake3,
        vec![(1, true)]
    );
}

#[test]
fn filtered_preprocessing_slots_follow_mixed_height_air_order() {
    check!(
        BinaryField128,
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        vec![(2, true), (1, false), (2, true)]
    );
}

#[test]
fn a_complete_preprocessed_binary_air_proof_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
        StatementAirBuilder, StatementPreprocessor, StatementProver,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, private, public) = check!(
        BinaryField8,
        BinaryField64,
        keccak,
        ByteHash::Keccak256,
        vec![(1, true)]
    );
    let schema = circuit.statement_schema().unwrap().clone();
    let mut prover = BatchStarkProver::new(config::baby_bear());
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
    wrong[8] += BabyBear::ONE;
    assert!(prepared.verifier().verify(&proof, &wrong).is_err());
}
