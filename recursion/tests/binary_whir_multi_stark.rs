//! Complete binary AIR statements through released additive WHIR layouts.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{CircuitBuilder, StatementExport};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::IndexedLookupBuilder;
use p3_lookup::indexed::TraceWindow;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::{
    BinaryWhirMultiStarkPreprocessing, BinaryWhirMultiStarkVerifier,
    NativeBinaryWhirMultiStarkInput, VerificationError, VerifierLimits,
};
use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver, Table, Witness};
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
    ($field:ty, $params:ident, $layout:ident, $hash:expr) => {{
        type F = $field;
        type E = BinaryField128;
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
        let domain = BinaryWhirDomain::<F>::default();
        let config = WhirConfig::<E, F, Ch>::new_with_domain(
            4,
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
        let refs = [&air];
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let (pk, vk) = setup(&native, &refs, &mut make()).unwrap();
        let recursive = BinaryWhirMultiStarkVerifier::<F>::new(
            &refs,
            &[3],
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
        let public_targets = vec![
            (0..3)
                .map(|_| {
                    let limbs = core::array::from_fn(|_| builder.public_input());
                    exports.extend(limbs.map(StatementExport::Base));
                    builder.binary128_from_limbs::<BabyBear>(limbs).unwrap()
                })
                .collect(),
        ];
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
        let actual = ch.sample::<BabyBear, BabyBear>(&mut builder).unwrap();
        let expected_limbs = builder.alloc_private_input_array::<8>("native WHIR continuation");
        let expected = builder
            .binary128_from_limbs::<BabyBear>(expected_limbs)
            .unwrap();
        for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
            let difference = builder.sub(a, e);
            builder.assert_zero(difference);
        }
        builder.set_statement_exports::<BabyBear>(&exports).unwrap();
        let circuit = builder.build().unwrap();
        for seed in [2u128, 19] {
            let a = F::from_le_byte_iter(seed.to_le_bytes().into_iter().take(F::RAW_BITS / 8));
            let c = a + F::ONE;
            let (mut x, mut y) = (a, c);
            let mut values = vec![];
            for _ in 0..8 {
                values.extend([x, y]);
                (x, y) = (y, x * y + x);
            }
            let public = vec![vec![a, c, *values.last().unwrap()]];
            let table = Table::new(RowMajorMatrix::new(values, 2).transpose());
            let proof = prove(
                &native,
                ProverInstances::new(vec![ProverInstance::new(&air, table, &pk, &public[0])]),
                0,
                &mut make(),
            )
            .unwrap();
            let mut native_ch = make();
            verify(
                &native,
                VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 3, &public[0])]),
                &proof,
                0,
                &mut native_ch,
            )
            .unwrap();
            let mut imported_ch = make();
            let imported = recursive
                .import_native(&config, &mmcs, &public, &proof, &mut imported_ch)
                .unwrap();
            let next = native_ch.sample_algebra_element::<E>();
            assert_eq!(next, imported_ch.sample_algebra_element::<E>());
            let pack =
                |raw: u128| (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
            let mut private = imported.private_values::<BabyBear>(&shape).unwrap();
            private.extend(pack(next.to_repr()));
            let public_limbs: Vec<_> = public
                .iter()
                .flatten()
                .flat_map(|v| pack(v.to_repr() as u128))
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
        }
    }};
}
#[test]
fn tower32_suffix_and_tower128_prefix_close_air_and_exact_continuations() {
    check!(BinaryField32, keccak, SuffixProver, ByteHash::Keccak256);
    check!(BinaryField128, blake3, PrefixProver, ByteHash::Blake3);
}

type E = BinaryField128;
type GateTree = keccak::LevelMmcs<E>;
type GateCh = keccak::LevelChallenger<E>;
type GateLayout = SuffixProver<E, E>;
type GatePcs = WhirProver<E, E, BinaryWhirDomain<E>, GateTree, GateCh, GateLayout>;
struct GateAir {
    interactions: bool,
}
impl BaseAir<E> for GateAir {
    fn width(&self) -> usize {
        5
    }
    fn num_public_values(&self) -> usize {
        3
    }
    fn preprocessed_width(&self) -> usize {
        3
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![0]
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<E>> {
        Some(RowMajorMatrix::new(
            (0..32)
                .flat_map(|i| {
                    let a = E::from_bool(i & 1 != 0);
                    let b = E::from_bool(i & 2 != 0);
                    [a, b, a + b]
                })
                .collect(),
            3,
        ))
    }
}
impl<AB: AirBuilder<F = E> + BusInteractionBuilder + IndexedLookupBuilder> Air<AB> for GateAir {
    fn eval(&self, b: &mut AB) {
        let [a, c, carry, sum, out] = b.main().current_slice().try_into().unwrap();
        let pp = b.preprocessed().current_slice().to_vec();
        let next = b.preprocessed().next_slice()[0];
        b.assert_eq(sum, a + c + carry);
        b.assert_eq(out, a * c + carry * a + carry * c);
        b.assert_eq(a, pp[0]);
        b.assert_eq(c, pp[1]);
        b.assert_eq(a + c, pp[2]);
        b.when_transition().assert_eq(carry, next);
        let public = b.public_values().to_vec();
        for (value, expected) in [a, c, carry].into_iter().zip(public) {
            b.when_first_row().assert_eq(value, expected);
        }
        if self.interactions {
            b.push_bus_interaction(
                BusName::new("bits"),
                BusDirection::Push,
                [a, c],
                BusActivation::Always,
            );
            b.push_bus_interaction(
                BusName::new("bits"),
                BusDirection::Pull,
                [c, a],
                BusActivation::Always,
            );
            b.push_indexed_table("parity", TraceWindow::Preprocessed, [0]);
            b.push_indexed_read("parity", 0, [0]);
        }
    }
}

struct GateConfig {
    main: GatePcs,
    pp: GatePcs,
}
impl MultiStarkConfig for GateConfig {
    type Val = E;
    type Challenge = E;
    type Challenger = GateCh;
    type Pcs = GatePcs;
    fn pcs(&self) -> &GatePcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &GatePcs {
        &self.pp
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn min_num_variables(&self) -> usize {
        self.main.round_folding_factor(0)
    }
    fn build_witness(&self, tables: Vec<Table<E>>) -> Witness<E> {
        GateLayout::new_witness(tables, self.main.round_folding_factor(0))
    }
    fn committed_table<'a>(
        &self,
        data: &'a WhirProverData<E, E, GateTree, GateLayout>,
        index: usize,
    ) -> &'a Table<E> {
        data.table(index)
    }
}
fn check_preprocessed(
    interactions: bool,
) -> (
    BinaryWhirMultiStarkVerifier<E>,
    NativeBinaryWhirMultiStarkInput<E>,
    Vec<Vec<E>>,
) {
    let domain = BinaryWhirDomain::<E>::default();
    let make_config = |n, rate| {
        WhirConfig::<E, E, GateCh>::new_with_domain(
            n,
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
    let main_cfg = make_config(8, 3);
    let pp_cfg = make_config(7, 2);
    let tree = |cap| {
        GateTree::new(
            keccak::FieldHash::new(keccak::byte_hash()),
            keccak::Compress::new(keccak::byte_hash()),
            cap,
        )
    };
    let main_tree = tree(0);
    let pp_tree = tree(1);
    let native = GateConfig {
        main: GatePcs::new(main_cfg.clone(), domain.clone(), main_tree.clone()),
        pp: GatePcs::new(pp_cfg.clone(), domain, pp_tree.clone()),
    };
    let make = || GateCh::from_hasher(vec![7, 19, 13], keccak::byte_hash());
    let air = GateAir { interactions };
    let (pk, vk) = setup(&native, &[&air], &mut make()).unwrap();
    let pp_table = Table::new(air.preprocessed_trace().unwrap().transpose());
    let (pp_cap, _) = native
        .pp
        .commit(
            GateLayout::new_witness(vec![pp_table], pp_cfg.round_folding_factor(0)),
            &mut make(),
        )
        .unwrap();
    let build = |limits: &VerifierLimits| {
        BinaryWhirMultiStarkVerifier::<E>::with_preprocessing(
            &[&air],
            &[5],
            &main_cfg,
            GateLayout::variable_order(),
            ByteHash::Keccak256,
            0,
            0,
            8,
            BinaryWhirMultiStarkPreprocessing {
                config: pp_cfg.clone(),
                order: GateLayout::variable_order(),
                hash: ByteHash::Keccak256,
                cap_height: 1,
                commitment: pp_cap.clone(),
            },
            limits,
        )
    };
    let recursive = build(&VerifierLimits::default()).unwrap();
    if !interactions {
        assert_eq!(recursive.input_resource_usage().instances, 1);
    }
    let public = vec![vec![E::ZERO, E::ZERO, E::ONE]];
    let rows = (0..32)
        .flat_map(|i| {
            let a = E::from_bool(i & 1 != 0);
            let c = E::from_bool(i & 2 != 0);
            let carry = E::ONE + a;
            [a, c, carry, a + c + carry, a * c + carry * a + carry * c]
        })
        .collect();
    let table = Table::new(RowMajorMatrix::new(rows, 5).transpose());
    let mut proof = prove(
        &native,
        ProverInstances::new(vec![ProverInstance::new(&air, table, &pk, &public[0])]),
        0,
        &mut make(),
    )
    .unwrap();
    assert_eq!(proof.bus.is_some(), interactions);
    assert_eq!(proof.indexed.is_some(), interactions);
    let mut expected_ch = make();
    verify(
        &native,
        VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 5, &public[0])]),
        &proof,
        0,
        &mut expected_ch,
    )
    .unwrap();
    let mut imported_ch = make();
    let input = recursive
        .import_native_with_preprocessing::<GateConfig, _, _, _>(
            &main_cfg,
            &main_tree,
            Some((&pp_cfg, &pp_tree)),
            &public,
            &proof,
            &mut imported_ch,
        )
        .unwrap();
    expected_ch.observe(E::from_repr(29));
    imported_ch.observe(E::from_repr(29));
    let expected = expected_ch.sample_algebra_element::<E>();
    assert_eq!(expected, imported_ch.sample_algebra_element::<E>());
    let shape = recursive.input_shape();
    if interactions {
        let mut native = CircuitBuilder::<E>::new();
        let public = native.public_input();
        let private = native.alloc_private_input("retained");
        native.connect(public, private);
        assert!(shape.allocate_native_targets(&mut native).is_err());
        let unchanged = native.build().unwrap();
        assert_eq!(unchanged.public_flat_len, 1);
        assert_eq!(unchanged.private_flat_len, 1);
    }
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_keccak_f1600::<BabyBear>();
    let public_targets = vec![
        (0..3)
            .map(|_| {
                let limbs = core::array::from_fn(|_| b.public_input());
                b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
            })
            .collect(),
    ];
    let targets = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let initial = [7, 19, 13].map(|v| b.define_const(BabyBear::from_u8(v)));
    let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
        &mut b,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    let mut ch = recursive
        .verify::<BabyBear, BabyBear>(&mut b, ch, &public_targets, &targets)
        .unwrap();
    let observation = 29u128
        .to_le_bytes()
        .map(|v| b.define_const(BabyBear::from_u8(v)));
    ch.observe_bytes::<BabyBear, BabyBear>(&mut b, &observation)
        .unwrap();
    let actual = ch.sample::<BabyBear, BabyBear>(&mut b).unwrap();
    let expected_limbs = b.alloc_private_input_array::<8>("native WHIR preprocessing continuation");
    let expected_target = b.binary128_from_limbs::<BabyBear>(expected_limbs).unwrap();
    for (&a, &e) in actual.bits().iter().zip(expected_target.bits()) {
        let d = b.sub(a, e);
        b.assert_zero(d);
    }
    let circuit = b.build().unwrap();
    let pack = |raw: u128| (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
    let mut private = input.private_values::<BabyBear>(&shape).unwrap();
    private.extend(pack(expected.to_repr()));
    let public_limbs: Vec<_> = public
        .iter()
        .flatten()
        .flat_map(|v| pack(v.to_repr()))
        .collect();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&private).unwrap();
    runner.set_public_inputs(&public_limbs).unwrap();
    runner.run().unwrap();
    let mut wrong = private.clone();
    wrong[0] += BabyBear::ONE;
    let mut runner = circuit.runner();
    runner.set_private_inputs(&wrong).unwrap();
    runner.set_public_inputs(&public_limbs).unwrap();
    assert!(runner.run().is_err());
    // Drop one required PP frontier digest. Visible shape inspection accepts
    // its smaller frontier; restoration fails after main transcript replay.
    use p3_whir::pcs::proof::QueryOpenings;
    let pp = proof.preprocessed_opening.as_mut().unwrap();
    let opening = if let Some(first) = pp.whir.rounds.first_mut() {
        &mut first.openings
    } else {
        &mut pp.whir.final_openings
    };
    let frontier = match opening {
        QueryOpenings::Base(o) => &mut o.proof.sibling_hashes,
        QueryOpenings::Extension(o) => &mut o.proof.sibling_hashes,
    };
    assert!(!frontier.is_empty());
    frontier.pop();
    let mut unchanged = make();
    let mut before = unchanged.clone();
    assert!(
        matches!(recursive.import_native_with_preprocessing::<GateConfig, _, _, _>(&main_cfg, &main_tree, Some((&pp_cfg, &pp_tree)), &public, &proof, &mut unchanged), Err(VerificationError::InvalidProofShape(message)) if message == "binary WHIR native path restoration failed")
    );
    assert_eq!(
        unchanged.sample_algebra_element::<E>(),
        before.sample_algebra_element::<E>()
    );
    (recursive, input, public)
}
#[test]
fn whir_multi_stark_retains_independent_preprocessing_and_late_failure_rollback() {
    check_preprocessed(false);
}
#[test]
fn whir_multi_stark_closes_product_bus_and_indexed_reads() {
    check_preprocessed(true);
}

#[test]
fn prepared_whir_multi_stark_proves_its_bound_statement() {
    use p3_field::PrimeField64;
    use p3_recursion::ProveNextLayerParams;
    use p3_recursion::artifact::{
        ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
        PortableVerifier,
    };
    use p3_recursion::builtin_config::{FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary};
    use p3_recursion::prepared::PreparedBinaryWhirMultiStarkLayer;
    let (recursive, input, public) = check_preprocessed(false);
    let limits = ArtifactLimits::default();
    let output_config = baby_bear_d4_poseidon2_binary(
        &FriConfigV1::new(
            SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
            1,
            0,
            2,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        &limits.verifier,
    )
    .unwrap();
    let layer = PreparedBinaryWhirMultiStarkLayer::<E, _, 4>::new(
        recursive,
        ByteHash::Keccak256,
        &[7, 19, 13],
        output_config,
        ProveNextLayerParams::default(),
    )
    .unwrap();
    assert_eq!(layer.statement_layout().public_value_counts(), &[3]);
    assert_eq!(layer.statement_layout().schema().base_len(), 24);
    let output = layer.prove(&input, &public).unwrap();
    layer
        .verifier()
        .verify(
            &output.0,
            &layer.statement_layout().pack::<BabyBear>(&public).unwrap(),
        )
        .unwrap();
    let expected = layer.statement_layout().pack::<BabyBear>(&public).unwrap();
    let mut wrong = expected.clone();
    wrong[16] += BabyBear::ONE;
    assert!(layer.verifier().verify(&output.0, &wrong).is_err());
    let statement = expected
        .iter()
        .flat_map(|v| (v.as_canonical_u64() as u32).to_le_bytes())
        .collect::<Vec<_>>();
    let verifier = layer.verifier();
    let proof = verifier.encode_proof_artifact(&output.0, limits).unwrap();
    let identity = verifier.encode_verifier_artifact(limits).unwrap();
    drop(output);
    drop(layer);
    drop(verifier);
    let portable = PortableVerifier::decode(
        &identity,
        ExpectedVerifierArtifact::from_trusted_bytes(&identity),
        limits,
    )
    .unwrap();
    portable
        .verify_encoded(&proof, CanonicalStatement::new(&statement, 24))
        .unwrap();
}
