//! Complete AIR and interaction checks through grouped Boolean trace openings.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField64, TowerLevel};
use p3_binary_pcs::{
    BinaryPcsConfig, BinaryPcsParams, BooleanTraceData, BooleanTracePcs, GroupedCodewordMmcs,
};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::ByteHash;
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
use p3_recursion::pcs::binary::{BinaryCodewordGrouping, RecursiveBinaryTowerField};
use p3_recursion::verifier::{
    BinaryGroupedBooleanTraceMultiStarkPreprocessing, BinaryGroupedBooleanTraceMultiStarkVerifier,
    NativeBinaryGroupedBooleanTraceMultiStarkInput, VerificationError, VerifierLimits,
};
use p3_sumcheck::layout::Table;
use p3_test_utils::binary_field_params::keccak;

type E = BinaryField64;
type Tree = keccak::LevelMmcs<E>;
type M = GroupedCodewordMmcs<Tree>;
type Pcs = BooleanTracePcs<E, M, M>;
type Ch = keccak::LevelChallenger<E>;

struct Config {
    main: Pcs,
    pp: Pcs,
}
impl MultiStarkConfig for Config {
    type Val = E;
    type Challenge = E;
    type Challenger = Ch;
    type Pcs = Pcs;
    fn pcs(&self) -> &Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Pcs {
        &self.pp
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn min_num_variables(&self) -> usize {
        1
    }
    fn build_witness(&self, tables: Vec<Table<E>>) -> Vec<Table<E>> {
        tables
    }
    fn committed_table<'a>(&self, data: &'a BooleanTraceData<E, M>, i: usize) -> &'a Table<E> {
        data.table(i)
    }
}

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

fn limbs(value: E) -> impl Iterator<Item = BabyBear> {
    let raw = value.raw_coordinates();
    (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16))
}

fn check(
    interactions: bool,
) -> (
    BinaryGroupedBooleanTraceMultiStarkVerifier<E>,
    NativeBinaryGroupedBooleanTraceMultiStarkInput<E>,
    Vec<Vec<E>>,
) {
    let params = BinaryPcsParams {
        log_inv_rate: 5,
        pow_bits: 0,
        security_level: 8,
    };
    let main_cfg = BinaryPcsConfig::try_new::<E, E>(2, params).unwrap();
    let pp_cfg = BinaryPcsConfig::try_new::<E, E>(1, params).unwrap();
    let tree = |cap| {
        Tree::new(
            keccak::FieldHash::new(keccak::byte_hash()),
            keccak::Compress::new(keccak::byte_hash()),
            cap,
        )
    };
    let main_tree = tree(0);
    let pp_tree = tree(1);
    let mmcs = GroupedCodewordMmcs::for_folding(main_tree.clone(), &main_cfg);
    let pp_mmcs = GroupedCodewordMmcs::for_folding(pp_tree.clone(), &pp_cfg);
    let native = Config {
        main: Pcs::new(main_cfg, mmcs.clone(), mmcs, 8).unwrap(),
        pp: Pcs::new(pp_cfg, pp_mmcs.clone(), pp_mmcs, 7).unwrap(),
    };
    let make = || Ch::from_hasher(vec![7, 19, 13], keccak::byte_hash());
    let air = GateAir { interactions };
    let (pk, vk) = setup(&native, &[&air], &mut make()).unwrap();
    let pp_table = Table::new(air.preprocessed_trace().unwrap().transpose());
    let (pp_cap, _) = native.pp.commit(vec![pp_table], &mut make()).unwrap();
    let build = |limits: &VerifierLimits| {
        BinaryGroupedBooleanTraceMultiStarkVerifier::<E>::with_preprocessing(
            &[&air],
            &[5],
            main_cfg,
            ByteHash::Keccak256,
            0,
            0,
            8,
            64,
            BinaryCodewordGrouping::Folding,
            BinaryCodewordGrouping::Folding,
            BinaryGroupedBooleanTraceMultiStarkPreprocessing {
                config: pp_cfg,
                hash: ByteHash::Keccak256,
                cap_height: 1,
                max_query_draws: 64,
                base_grouping: BinaryCodewordGrouping::Folding,
                round_grouping: BinaryCodewordGrouping::Folding,
                commitment: pp_cap.clone(),
            },
            limits,
        )
    };
    let recursive = build(&VerifierLimits::default()).unwrap();
    if !interactions {
        // Main: logical table + one ring claim + packed PCS. PP: logical
        // table + three ring claims + packed PCS. Only logical tables overlap
        // the AIR relation's already charged instance.
        assert_eq!(recursive.input_resource_usage().instances, 7);
        let limits = VerifierLimits {
            max_instances: 6,
            ..VerifierLimits::default()
        };
        use p3_recursion::pcs::binary::BinaryGroupedBooleanTraceVerifier;
        use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
        for (config, width, next, cap) in [(main_cfg, 5, vec![], 0), (pp_cfg, 3, vec![0], 1)] {
            BinaryGroupedBooleanTraceVerifier::<E>::with_limits(
                config,
                OpeningProtocol::new(vec![TableSpec::new(
                    TableShape::new(5, width),
                    vec![OpeningBatch::new((0..width).collect(), next)],
                )]),
                ByteHash::Keccak256,
                cap,
                64,
                BinaryCodewordGrouping::Folding,
                BinaryCodewordGrouping::Folding,
                &limits,
            )
            .unwrap();
        }
        assert!(matches!(
            build(&limits),
            Err(VerificationError::ResourceLimitExceeded {
                component: "instances",
                ..
            })
        ));
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
    let mut expected_ch = make();
    verify(
        &native,
        VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 5, &public[0])]),
        &proof,
        0,
        &mut expected_ch,
    )
    .unwrap();
    assert_eq!(proof.bus.is_some(), interactions);
    assert_eq!(proof.indexed.is_some(), interactions);
    #[derive(serde::Deserialize)]
    struct GroupedView {
        inner: p3_merkle_tree::PrunedMerklePaths<u8, 32>,
        missing_symbols: Vec<E>,
    }
    let frontier = |p: &p3_binary_pcs::BooleanTraceProof<E, M, M>| {
        let p = &p.opening.opening;
        core::iter::once(&p.base_multi_proof)
            .chain(p.rounds.iter().map(|r| &r.multi_proof))
            .map(|proof| {
                let view: GroupedView =
                    postcard::from_bytes(&postcard::to_allocvec(proof).unwrap()).unwrap();
                assert!(view.missing_symbols.is_empty());
                view.inner.sibling_hashes.len()
            })
            .sum::<usize>()
    };
    let main_frontier = frontier(&proof.opening);
    let pp_frontier = frontier(proof.preprocessed_opening.as_ref().unwrap());
    assert!(
        main_frontier > 0 && pp_frontier > 0,
        "main frontier {main_frontier}, PP frontier {pp_frontier}; main {:?}, PP {:?}",
        p3_binary_pcs::transcript::BinaryPcsShape::new(&main_cfg),
        p3_binary_pcs::transcript::BinaryPcsShape::new(&pp_cfg)
    );
    let bounded = build(&VerifierLimits {
        max_compressed_frontier_hashes: main_frontier + pp_frontier - 1,
        ..VerifierLimits::default()
    })
    .unwrap();
    let mut unchanged = make();
    let mut before = unchanged.clone();
    assert!(matches!(
        bounded.import_native_with_preprocessing::<Config, _, _, _, _, _>(
            &main_tree,
            &main_tree,
            Some((&pp_tree, &pp_tree)),
            &public,
            &proof,
            &mut unchanged,
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "compressed frontier hashes",
            ..
        })
    ));
    assert_eq!(
        unchanged.sample_algebra_element::<E>(),
        before.sample_algebra_element::<E>()
    );
    let mut imported_ch = make();
    let input = recursive
        .import_native_with_preprocessing::<Config, _, _, _, _, _>(
            &main_tree,
            &main_tree,
            Some((&pp_tree, &pp_tree)),
            &public,
            &proof,
            &mut imported_ch,
        )
        .unwrap();
    expected_ch.observe(E::from_repr(29));
    imported_ch.observe(E::from_repr(29));
    let expected = expected_ch.sample_algebra_element::<E>();
    assert_eq!(imported_ch.sample_algebra_element::<E>(), expected);

    let shape = recursive.input_shape();
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_keccak_f1600::<BabyBear>();
    let public_targets = vec![
        (0..3)
            .map(|_| {
                let inputs = core::array::from_fn(|_| b.public_input());
                b.binary128_from_limbs::<BabyBear>(inputs).unwrap()
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
    let token = recursive
        .verify::<BabyBear, BabyBear>(&mut b, ch, &public_targets, &targets)
        .unwrap();
    let observation = 29u64
        .to_le_bytes()
        .map(|v| b.define_const(BabyBear::from_u8(v)));
    let mut ch = token
        .resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation)
        .unwrap();
    let bytes = ch.sample_bytes::<BabyBear, BabyBear>(&mut b, 8).unwrap();
    let expected_inputs = b.alloc_private_input_array::<8>("continued trace challenge");
    let expected_target = b.binary128_from_limbs::<BabyBear>(expected_inputs).unwrap();
    for (byte, bits) in bytes
        .into_iter()
        .zip(expected_target.bits()[..64].as_chunks::<8>().0.iter())
    {
        let actual = b.decompose_to_bits::<BabyBear>(byte, 8).unwrap();
        for (actual, &expected) in actual.into_iter().zip(bits) {
            let difference = b.sub(actual, expected);
            b.assert_zero(difference);
        }
    }
    let circuit = b.build().unwrap();
    let mut private = input.private_values::<BabyBear>(&shape).unwrap();
    private.extend(limbs(expected));
    let public_limbs = public
        .iter()
        .flatten()
        .copied()
        .flat_map(limbs)
        .collect::<Vec<_>>();
    let run = |private: &[BabyBear], public: &[BabyBear]| {
        let mut runner = circuit.runner();
        runner.set_private_inputs(private).unwrap();
        runner.set_public_inputs(public).unwrap();
        runner.run().is_ok()
    };
    assert!(run(&private, &public_limbs));
    let mut wrong = private.clone();
    wrong[0] += BabyBear::ONE;
    assert!(!run(&wrong, &public_limbs));
    let mut wrong = public_limbs;
    wrong[0] += BabyBear::ONE;
    assert!(!run(&private, &wrong));
    let pp = proof.preprocessed_opening.take();
    let mut unchanged = make();
    let mut before = unchanged.clone();
    assert!(
        recursive
            .import_native_with_preprocessing::<Config, _, _, _, _, _>(
                &main_tree,
                &main_tree,
                Some((&pp_tree, &pp_tree)),
                &public,
                &proof,
                &mut unchanged,
            )
            .is_err()
    );
    assert_eq!(
        unchanged.sample_algebra_element::<E>(),
        before.sample_algebra_element::<E>()
    );
    proof.preprocessed_opening = pp;
    (recursive, input, public)
}

#[test]
fn grouped_boolean_trace_multi_stark_binds_air_and_independent_preprocessing() {
    check(false);
}

#[test]
fn grouped_boolean_trace_multi_stark_closes_bus_and_indexed_reductions() {
    check(true);
}

#[test]
#[ignore = "proves a grouped BF128 trace verifier above hosted runner memory; run explicitly"]
fn prepared_grouped_boolean_trace_multi_stark_proves_its_bound_statement() {
    use p3_field::PrimeField64;
    use p3_recursion::ProveNextLayerParams;
    use p3_recursion::artifact::{
        ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
        PortableVerifier,
    };
    use p3_recursion::builtin_config::{FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary};
    use p3_recursion::prepared::PreparedBinaryGroupedBooleanTraceMultiStarkLayer;
    let (recursive, input, public) = check(false);
    // This complete relation has more primitive scalar rows than the default
    // portable-artifact budget. Keep the larger fixture budget explicit.
    let limits = ArtifactLimits {
        verifier: VerifierLimits {
            max_total_scalar_elements: 1 << 25,
            ..VerifierLimits::default()
        },
        ..ArtifactLimits::default()
    };
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
    let layer = PreparedBinaryGroupedBooleanTraceMultiStarkLayer::<E, _, 4>::new(
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
