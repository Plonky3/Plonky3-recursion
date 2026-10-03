//! Complete binary AIR statements through released additive WHIR layouts.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{CircuitBuilder, StatementExport};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::verifier::{
    BinaryPolyWhirMultiStarkPreprocessing, BinaryPolyWhirMultiStarkVerifier, VerifierLimits,
};
use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver, Table, Witness};
use p3_sumcheck::strategy::VariableOrder;
use p3_test_utils::binary_field_params::{blake3, keccak};
use p3_whir::pcs::WhirProverData;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

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
        let cur = main.current_slice();
        let next = main.next_slice();
        let public = b.public_values();
        let (first, second, last) = (public[0], public[1], public[2]);
        b.when_first_row().assert_eq(cur[0], first);
        b.when_first_row().assert_eq(cur[1], second);
        b.when_transition().assert_eq(next[0], cur[1]);
        b.when_transition()
            .assert_eq(next[1], cur[0] * cur[1] + cur[0]);
        b.when_last_row().assert_eq(cur[1], last);
    }
}
macro_rules! check {
    ($params:ident, $layout:ident, $hash:expr, $heights:expr, $variables:expr) => {{
        type F = Poly64;
        type E = Poly192;
        type Ch = $params::LevelChallenger<F>;
        type M = $params::LevelMmcs<F>;
        type L = $layout<F, E>;
        type P = WhirProver<E, F, BinaryWhirDomain<F>, M, Ch, L>;
        struct Config {
            pcs: P,
        }
        impl MultiStarkConfig for Config {
            type Val = F;
            type Challenge = E;
            type Challenger = Ch;
            type Pcs = P;
            fn pcs(&self) -> &P {
                &self.pcs
            }
            fn min_num_variables(&self) -> usize {
                self.pcs.round_folding_factor(0)
            }
            fn build_witness(&self, tables: Vec<Table<F>>) -> Witness<F> {
                L::new_witness(tables, self.pcs.round_folding_factor(0))
            }
            fn committed_table<'a>(
                &self,
                data: &'a WhirProverData<F, E, M, L>,
                index: usize,
            ) -> &'a Table<F> {
                data.table(index)
            }
        }
        let heights = $heights;
        let domain = BinaryWhirDomain::<F>::default();
        let config = WhirConfig::<E, F, Ch>::new_with_domain(
            $variables,
            ProtocolParameters {
                security_level: 8,
                pow_bits: 0,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(2),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            &domain,
        )
        .unwrap();
        let mmcs = M::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let native = Config {
            pcs: P::new(config.clone(), domain, mmcs.clone()),
        };
        let air = RecurrenceAir;
        let refs = vec![&air; heights.len()];
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let (pk, vk) = setup(&native, &refs, &mut make()).unwrap();
        let recursive = BinaryPolyWhirMultiStarkVerifier::new(
            &refs,
            &heights,
            &config,
            L::variable_order(),
            $hash,
            0,
            0,
            8,
        )
        .unwrap();
        let shape = recursive.input_shape();
        let mut builder = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
        }
        let mut exports = vec![];
        let public_targets = heights
            .iter()
            .map(|_| {
                (0..3)
                    .map(|_| {
                        let limbs = core::array::from_fn(|_| builder.public_input());
                        exports.extend(limbs.map(StatementExport::Base));
                        builder.binary_poly64_from_limbs::<BabyBear>(limbs).unwrap()
                    })
                    .collect()
            })
            .collect::<Vec<_>>();
        let targets = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut builder)
            .unwrap();
        let initial = [7, 19, 13].map(|v| builder.define_const(BabyBear::from_u8(v)));
        let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut builder,
            $hash,
            &initial,
        )
        .unwrap();
        let mut ch = recursive
            .verify::<BabyBear, BabyBear>(&mut builder, ch, &public_targets, &targets)
            .unwrap();
        for _ in 0..2 {
            let actual = ch
                .sample_poly192::<BabyBear, BabyBear>(&mut builder)
                .unwrap();
            let expected_limbs =
                builder.alloc_private_input_array::<12>("native Poly192 continuation");
            let expected = builder
                .binary_poly192_from_limbs::<BabyBear>(expected_limbs)
                .unwrap();
            for (a, e) in actual.coefficients().iter().zip(expected.coefficients()) {
                for (&a, &e) in a.bits().iter().zip(e.bits()) {
                    let difference = builder.sub(a, e);
                    builder.assert_zero(difference);
                }
            }
        }
        let observation = Poly64::new(0x91ab_cdef_0123_4567);
        let observed = builder
            .binary_poly64_constant(observation.to_bits())
            .unwrap();
        ch.observe_poly64::<BabyBear, BabyBear>(&mut builder, &observed)
            .unwrap();
        let actual = ch
            .sample_poly192::<BabyBear, BabyBear>(&mut builder)
            .unwrap();
        let limbs =
            builder.alloc_private_input_array::<12>("continuation after Poly64 observation");
        let expected = builder
            .binary_poly192_from_limbs::<BabyBear>(limbs)
            .unwrap();
        for (a, e) in actual.coefficients().iter().zip(expected.coefficients()) {
            for (&a, &e) in a.bits().iter().zip(e.bits()) {
                let difference = builder.sub(a, e);
                builder.assert_zero(difference);
            }
        }
        builder.set_statement_exports::<BabyBear>(&exports).unwrap();
        let circuit = builder.build().unwrap();
        for seed in [0x2134_5678_91ab_cdefu64, 0xbcde_f012_3456_789a] {
            let mut publics = vec![];
            let mut tables = vec![];
            for (i, &height) in heights.iter().enumerate() {
                let a = F::new(seed.wrapping_add(0x2173_85a9_4fcbu64 * i as u64));
                let c = a + F::ONE;
                let (mut x, mut y) = (a, c);
                let mut values = vec![];
                for _ in 0..1usize << height {
                    values.extend([x, y]);
                    (x, y) = (y, x * y + x);
                }
                publics.push(vec![a, c, *values.last().unwrap()]);
                tables.push(Table::new(RowMajorMatrix::new(values, 2).transpose()));
            }
            let public = publics;
            let instances = tables
                .into_iter()
                .zip(&public)
                .map(|(table, public)| ProverInstance::new(&air, table, &pk, public))
                .collect();
            let proof = prove(&native, ProverInstances::new(instances), 0, &mut make()).unwrap();
            let mut native_ch = make();
            verify(
                &native,
                VerifierInstances::new(
                    heights
                        .iter()
                        .zip(&public)
                        .map(|(&h, p)| VerifierInstance::new(&air, &vk, h, p))
                        .collect(),
                ),
                &proof,
                0,
                &mut native_ch,
            )
            .unwrap();
            let mut imported_ch = make();
            let imported = recursive
                .import_native(&config, &mmcs, &public, &proof, &mut imported_ch)
                .unwrap();
            let pack = |raw: u64| (0..4).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
            let mut private = imported.private_values::<BabyBear>(&shape).unwrap();
            for _ in 0..2 {
                let next = native_ch.sample_algebra_element::<E>();
                assert_eq!(next, imported_ch.sample_algebra_element::<E>());
                private.extend(
                    next.coefficients()
                        .into_iter()
                        .flat_map(|c| pack(c.to_bits())),
                );
            }
            native_ch.observe(observation);
            imported_ch.observe(observation);
            let next = native_ch.sample_algebra_element::<E>();
            assert_eq!(next, imported_ch.sample_algebra_element::<E>());
            private.extend(
                next.coefficients()
                    .into_iter()
                    .flat_map(|c| pack(c.to_bits())),
            );
            let public_limbs: Vec<_> = public
                .iter()
                .flatten()
                .flat_map(|v| pack(v.to_bits()))
                .collect();
            let mut runner = circuit.runner();
            runner.set_private_inputs(&private).unwrap();
            runner.set_public_inputs(&public_limbs).unwrap();
            runner.run().unwrap();
            let mut wrong = public_limbs.clone();
            wrong[0] += BabyBear::ONE;
            let mut runner = circuit.runner();
            runner.set_private_inputs(&private).unwrap();
            runner.set_public_inputs(&wrong).unwrap();
            assert!(runner.run().is_err());
            for at in [0, 16 + 12 + 8, private.len() - 4] {
                let mut wrong = private.clone();
                wrong[at] += BabyBear::ONE;
                let mut runner = circuit.runner();
                if runner.set_private_inputs(&wrong).is_ok() {
                    runner.set_public_inputs(&public_limbs).unwrap();
                    assert!(runner.run().is_err());
                }
            }
        }
    }};
}
#[test]
fn polynomial_suffix_and_prefix_close_air_and_full_width_continuations() {
    check!(keccak, SuffixProver, ByteHash::Keccak256, vec![3], 4);
    check!(blake3, PrefixProver, ByteHash::Blake3, vec![3], 4);
}

#[test]
fn mixed_heights_preserve_air_order_beta_weights_and_layout_placements() {
    check!(blake3, SuffixProver, ByteHash::Blake3, vec![3, 2], 5);
    check!(blake3, PrefixProver, ByteHash::Blake3, vec![2, 3], 5);
}

#[test]
fn constructors_reject_geometry_outside_the_native_witness_contract() {
    let domain = BinaryWhirDomain::<Poly64>::default();
    let make = |fold| {
        WhirConfig::<Poly192, Poly64, PpCh>::new_with_domain(
            4,
            ProtocolParameters {
                security_level: 8,
                pow_bits: 0,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(fold),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            &domain,
        )
        .unwrap()
    };
    let main = make(2);
    assert!(
        BinaryPolyWhirMultiStarkVerifier::new(
            &[&RecurrenceAir],
            &[1],
            &main,
            VariableOrder::Suffix,
            ByteHash::Blake3,
            0,
            0,
            8
        )
        .is_err()
    );
    for (pp, order) in [
        (make(3), VariableOrder::Suffix),
        (make(2), VariableOrder::Prefix),
    ] {
        assert!(
            BinaryPolyWhirMultiStarkVerifier::with_preprocessing(
                &[&CopyPreprocessingAir],
                &[3],
                &main,
                VariableOrder::Suffix,
                ByteHash::Blake3,
                0,
                0,
                8,
                BinaryPolyWhirMultiStarkPreprocessing {
                    config: pp,
                    order,
                    hash: ByteHash::Blake3,
                    cap_height: 0,
                    commitment: p3_merkle_tree::MerkleCap::new(vec![[0; 32]])
                },
                &VerifierLimits::default()
            )
            .is_err()
        );
    }
}

struct CopyPreprocessingAir;
impl BaseAir<Poly64> for CopyPreprocessingAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        2
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![1]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![1]
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Poly64>> {
        Some(RowMajorMatrix::new(
            (0..8)
                .flat_map(|i| {
                    let x = Poly64::new(0x1234_abcd_7654_ef90u64 ^ (i * 0x2317_9badu64));
                    [x, x + Poly64::ONE]
                })
                .collect(),
            2,
        ))
    }
}
impl<AB: AirBuilder<F = Poly64>> Air<AB> for CopyPreprocessingAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let pp = b.preprocessed();
        let current = main.current_slice();
        let prepared = [
            pp.current_slice()[0],
            pp.current_slice()[1],
            pp.next_slice()[1],
        ];
        b.assert_eq(current[0], prepared[0]);
        b.assert_eq(current[1], prepared[1]);
        b.when_transition()
            .assert_eq(main.next_slice()[1], prepared[2]);
        let public = b.public_values()[0];
        b.when_first_row().assert_eq(current[0], public);
    }
}

type PpCh = blake3::LevelChallenger<Poly64>;
type PpTree = blake3::LevelMmcs<Poly64>;
type PpLayout = SuffixProver<Poly64, Poly192>;
type PpPcs = WhirProver<Poly192, Poly64, BinaryWhirDomain<Poly64>, PpTree, PpCh, PpLayout>;
struct PpConfig {
    main: PpPcs,
    pp: PpPcs,
}
impl MultiStarkConfig for PpConfig {
    type Val = Poly64;
    type Challenge = Poly192;
    type Challenger = PpCh;
    type Pcs = PpPcs;
    fn pcs(&self) -> &PpPcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &PpPcs {
        &self.pp
    }
    fn min_num_variables(&self) -> usize {
        self.main.round_folding_factor(0)
    }
    fn build_witness(&self, tables: Vec<Table<Poly64>>) -> Witness<Poly64> {
        PpLayout::new_witness(tables, self.main.round_folding_factor(0))
    }
    fn committed_table<'a>(
        &self,
        data: &'a WhirProverData<Poly64, Poly192, PpTree, PpLayout>,
        index: usize,
    ) -> &'a Table<Poly64> {
        data.table(index)
    }
}

#[test]
fn independent_preprocessing_caps_rates_and_sparse_successors_close_the_relation() {
    let domain = BinaryWhirDomain::<Poly64>::default();
    let parameters = |rate| {
        WhirConfig::<Poly192, Poly64, PpCh>::new_with_domain(
            4,
            ProtocolParameters {
                security_level: 8,
                pow_bits: 0,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(2),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: rate,
            },
            &domain,
        )
        .unwrap()
    };
    let main_cfg = parameters(1);
    let pp_cfg = parameters(2);
    let tree = |height| {
        PpTree::new(
            blake3::FieldHash::new(blake3::byte_hash()),
            blake3::Compress::new(blake3::byte_hash()),
            height,
        )
    };
    let main_tree = tree(0);
    let pp_tree = tree(1);
    let native = PpConfig {
        main: PpPcs::new(main_cfg.clone(), domain.clone(), main_tree.clone()),
        pp: PpPcs::new(pp_cfg.clone(), domain, pp_tree.clone()),
    };
    let make = || PpCh::from_hasher(vec![7, 19, 13], blake3::byte_hash());
    let air = CopyPreprocessingAir;
    let (pk, vk) = setup(&native, &[&air], &mut make()).unwrap();
    let rows = air.preprocessed_trace().unwrap();
    let public = vec![vec![rows.values[0]]];
    let table = Table::new(rows.transpose());
    let (pp_cap, _) = native
        .pp
        .commit(PpLayout::new_witness(vec![table.clone()], 2), &mut make())
        .unwrap();
    let build = |limits: &VerifierLimits| {
        BinaryPolyWhirMultiStarkVerifier::with_preprocessing(
            &[&air],
            &[3],
            &main_cfg,
            PpLayout::variable_order(),
            ByteHash::Blake3,
            0,
            0,
            8,
            BinaryPolyWhirMultiStarkPreprocessing {
                config: pp_cfg.clone(),
                order: PpLayout::variable_order(),
                hash: ByteHash::Blake3,
                cap_height: 1,
                commitment: pp_cap.clone(),
            },
            limits,
        )
    };
    let recursive = build(&VerifierLimits::default()).unwrap();
    let below = VerifierLimits {
        max_compressed_frontier_hashes: recursive.input_resource_usage().compressed_frontier_hashes
            - 1,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        build(&below),
        Err(
            p3_recursion::verifier::VerificationError::ResourceLimitExceeded {
                component: "compressed frontier hashes",
                ..
            }
        )
    ));
    assert_eq!(recursive.input_resource_usage().instances, 1);
    let mut proof = prove(
        &native,
        ProverInstances::new(vec![ProverInstance::new(&air, table, &pk, &public[0])]),
        0,
        &mut make(),
    )
    .unwrap();
    let saved_openings = proof
        .preprocessed_opening
        .as_ref()
        .unwrap()
        .whir
        .final_openings
        .clone();
    use p3_whir::pcs::proof::QueryOpenings;
    for late in [false, true] {
        let openings = &mut proof
            .preprocessed_opening
            .as_mut()
            .unwrap()
            .whir
            .final_openings;
        if late {
            let hashes = match openings {
                QueryOpenings::Base(o) => &mut o.proof.sibling_hashes,
                QueryOpenings::Extension(o) => &mut o.proof.sibling_hashes,
            };
            hashes
                .pop()
                .expect("fixture has a nonempty preprocessing frontier");
        } else {
            match openings {
                QueryOpenings::Base(o) => {
                    o.rows.pop();
                }
                QueryOpenings::Extension(o) => {
                    o.rows.pop();
                }
            }
        }
        let mut unchanged = make();
        let result = recursive.import_native_with_preprocessing::<PpConfig, _, _, _>(
            &main_cfg,
            &main_tree,
            Some((&pp_cfg, &pp_tree)),
            &public,
            &proof,
            &mut unchanged,
        );
        if late {
            assert!(matches!(result,
                Err(p3_recursion::verifier::VerificationError::InvalidProofShape(message))
                if message == "binary WHIR native path restoration failed"));
        } else {
            assert!(result.is_err());
        }
        assert_eq!(
            unchanged.sample_algebra_element::<Poly192>(),
            make().sample_algebra_element::<Poly192>()
        );
        proof
            .preprocessed_opening
            .as_mut()
            .unwrap()
            .whir
            .final_openings = saved_openings.clone();
    }
    let mut expected = make();
    verify(
        &native,
        VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 3, &public[0])]),
        &proof,
        0,
        &mut expected,
    )
    .unwrap();
    let mut imported_ch = make();
    let input = recursive
        .import_native_with_preprocessing::<PpConfig, _, _, _>(
            &main_cfg,
            &main_tree,
            Some((&pp_cfg, &pp_tree)),
            &public,
            &proof,
            &mut imported_ch,
        )
        .unwrap();
    let next = expected.sample_algebra_element::<Poly192>();
    assert_eq!(next, imported_ch.sample_algebra_element::<Poly192>());
    let shape = recursive.input_shape();
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_blake3_compress::<BabyBear>();
    let public_limbs = core::array::from_fn(|_| b.public_input());
    let public_target = b
        .binary_poly64_from_limbs::<BabyBear>(public_limbs)
        .unwrap();
    let targets = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let initial = [7, 19, 13].map(|v| b.define_const(BabyBear::from_u8(v)));
    let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
        &mut b,
        ByteHash::Blake3,
        &initial,
    )
    .unwrap();
    let mut ch = recursive
        .verify::<BabyBear, BabyBear>(&mut b, ch, &[vec![public_target]], &targets)
        .unwrap();
    let actual = ch.sample_poly192::<BabyBear, BabyBear>(&mut b).unwrap();
    let limbs = b.alloc_private_input_array::<12>("preprocessed Poly continuation");
    let compared = b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap();
    for (a, e) in actual.coefficients().iter().zip(compared.coefficients()) {
        for (&a, &e) in a.bits().iter().zip(e.bits()) {
            let diff = b.sub(a, e);
            b.assert_zero(diff);
        }
    }
    let circuit = b.build().unwrap();
    let pack = |raw: u64| (0..4).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
    let mut private = input.private_values::<BabyBear>(&shape).unwrap();
    private.extend(
        next.coefficients()
            .into_iter()
            .flat_map(|c| pack(c.to_bits())),
    );
    let public_limbs = pack(public[0][0].to_bits()).collect::<Vec<_>>();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&private).unwrap();
    runner.set_public_inputs(&public_limbs).unwrap();
    runner.run().unwrap();
}
