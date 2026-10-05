//! Complete AIR and interaction checks through Boolean WHIR trace openings.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirData, BooleanWhirPcs, BooleanWhirProof};
use p3_binary_pcs::{
    BooleanTraceCommitment, BooleanTraceCommitmentData, BooleanTraceCommitmentProof,
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
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::{
    BinaryBooleanWhirTraceMultiStarkPreprocessing, BinaryBooleanWhirTraceMultiStarkVerifier,
    NativeBinaryBooleanWhirTraceMultiStarkInput, VerificationError, VerifierLimits,
};
use p3_sumcheck::layout::{SuffixProver, Table};
use p3_test_utils::binary_field_params::keccak;
use p3_whir::pcs::proof::QueryOpenings;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

type E = BinaryField128;
type Tree = keccak::LevelMmcs<E>;
type M = Tree;
type Inner = BooleanWhirPcs<E, BinaryWhirDomain<E>, M, Ch>;
type Pcs = BooleanTraceCommitment<E, Inner>;
type TraceProof = BooleanTraceCommitmentProof<E, BooleanWhirProof<E, M>>;
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
    fn committed_table<'a>(
        &self,
        data: &'a BooleanTraceCommitmentData<E, BooleanWhirData<E, M>>,
        i: usize,
    ) -> &'a Table<E> {
        data.table(i)
    }
}

struct GateAir {
    interactions: bool,
    height: usize,
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
            (0..1usize << self.height)
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
    height: usize,
) -> (
    BinaryBooleanWhirTraceMultiStarkVerifier,
    NativeBinaryBooleanWhirTraceMultiStarkInput,
    Vec<Vec<E>>,
) {
    let config = |n, first| {
        WhirConfig::<E, E, Ch>::new_with_domain(
            n,
            ProtocolParameters {
                starting_log_inv_rate: 3,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(first),
                soundness_type: SecurityAssumption::JohnsonBound,
                security_level: 8,
                pow_bits: 0,
            },
            &BinaryWhirDomain::<E>::default(),
        )
        .unwrap()
    };
    let main_cfg = config(height - 4, 2);
    let pp_cfg = config(height - 5, 1);
    let tree = |cap| {
        Tree::new(
            keccak::FieldHash::new(keccak::byte_hash()),
            keccak::Compress::new(keccak::byte_hash()),
            cap,
        )
    };
    let main_tree = tree(0);
    let pp_tree = tree(1);
    let pcs = |cfg: &WhirConfig<E, E, Ch>, mmcs: M| {
        Pcs::from_commitment(
            BooleanWhirPcs::new(
                WhirProver::<E, E, _, _, Ch, SuffixProver<E, E>>::new(
                    cfg.clone(),
                    BinaryWhirDomain::<E>::default(),
                    mmcs,
                ),
                cfg.num_variables() + 7,
            )
            .unwrap(),
        )
    };
    let native = Config {
        main: pcs(&main_cfg, main_tree.clone()),
        pp: pcs(&pp_cfg, pp_tree.clone()),
    };
    let make = || Ch::from_hasher(vec![7, 19, 13], keccak::byte_hash());
    let air = GateAir {
        interactions,
        height,
    };
    let (pk, vk) = setup(&native, &[&air], &mut make()).unwrap();
    let pp_table = Table::new(air.preprocessed_trace().unwrap().transpose());
    let (pp_cap, _) = native.pp.commit(vec![pp_table], &mut make()).unwrap();
    let base_limits = VerifierLimits {
        max_rounds: 128,
        max_metadata_entries: 1 << 18,
        ..VerifierLimits::default()
    };
    let build = |limits: &VerifierLimits| {
        BinaryBooleanWhirTraceMultiStarkVerifier::with_preprocessing(
            &[&air],
            &[height],
            &main_cfg,
            ByteHash::Keccak256,
            0,
            0,
            8,
            BinaryBooleanWhirTraceMultiStarkPreprocessing {
                config: pp_cfg.clone(),
                hash: ByteHash::Keccak256,
                cap_height: 1,
                commitment: pp_cap.clone(),
            },
            limits,
        )
    };
    let recursive = build(&base_limits).unwrap();
    if !interactions {
        // Main: logical table + one ring claim + packed PCS. PP: logical
        // table + three ring claims + packed PCS. Only logical tables overlap
        // the AIR relation's already charged instance.
        assert_eq!(recursive.input_resource_usage().instances, 7);
        let limits = VerifierLimits {
            max_instances: 6,
            ..base_limits
        };
        use p3_recursion::pcs::binary::BinaryBooleanWhirTraceVerifier;
        use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
        for (config, width, next, cap) in [(&main_cfg, 5, vec![], 0), (&pp_cfg, 3, vec![0], 1)] {
            BinaryBooleanWhirTraceVerifier::with_limits(
                config,
                OpeningProtocol::new(vec![TableSpec::new(
                    TableShape::new(height, width),
                    vec![OpeningBatch::new((0..width).collect(), next)],
                )]),
                ByteHash::Keccak256,
                cap,
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
    let rows = (0..1usize << height)
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
        VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, height, &public[0])]),
        &proof,
        0,
        &mut expected_ch,
    )
    .unwrap();
    assert_eq!(proof.bus.is_some(), interactions);
    assert_eq!(proof.indexed.is_some(), interactions);
    let frontier = |p: &TraceProof| {
        let p = &p.opening.opening.whir;
        let count = |q: &QueryOpenings<E, E, p3_merkle_tree::PrunedMerklePaths<u8, 32>>| match q {
            QueryOpenings::Base(o) => o.proof.sibling_hashes.len(),
            QueryOpenings::Extension(o) => o.proof.sibling_hashes.len(),
        };
        count(&p.final_openings) + p.rounds.iter().map(|r| count(&r.openings)).sum::<usize>()
    };
    let main_frontier = frontier(&proof.opening);
    let pp_frontier = frontier(proof.preprocessed_opening.as_ref().unwrap());
    assert!(main_frontier > 0 && pp_frontier > 0);
    // Construction prices the conservative per-query path bound for both
    // commitments. A budget below their aggregate fails before replay.
    assert!(matches!(
        build(&VerifierLimits {
            max_compressed_frontier_hashes: recursive
                .input_resource_usage()
                .compressed_frontier_hashes
                - 1,
            ..base_limits
        }),
        Err(VerificationError::ResourceLimitExceeded {
            component: "compressed frontier hashes",
            ..
        })
    ));
    let mut imported_ch = make();
    let input = recursive
        .import_native_with_preprocessing::<Config, _, _, _>(
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
    let mut ch = recursive
        .verify::<BabyBear, BabyBear>(&mut b, ch, &public_targets, &targets)
        .unwrap();
    let observation = 29u128
        .to_le_bytes()
        .map(|v| b.define_const(BabyBear::from_u8(v)));
    ch.observe_bytes::<BabyBear, BabyBear>(&mut b, &observation)
        .unwrap();
    let actual = ch.sample::<BabyBear, BabyBear>(&mut b).unwrap();
    let expected_inputs = b.alloc_private_input_array::<8>("continued trace challenge");
    let expected_target = b.binary128_from_limbs::<BabyBear>(expected_inputs).unwrap();
    for (&actual, &expected) in actual.bits().iter().zip(expected_target.bits()) {
        let difference = b.sub(actual, expected);
        b.assert_zero(difference);
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
            .import_native_with_preprocessing::<Config, _, _, _>(
                &main_cfg,
                &main_tree,
                Some((&pp_cfg, &pp_tree)),
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
    let rounds = core::mem::take(
        &mut proof
            .preprocessed_opening
            .as_mut()
            .unwrap()
            .opening
            .reduction
            .sumcheck
            .polynomial_evaluations,
    );
    assert!(!rounds.is_empty());
    let mut unchanged = make();
    let mut before = unchanged.clone();
    assert!(
        matches!(recursive.import_native_with_preprocessing::<Config, _, _, _>(
        &main_cfg, &main_tree, Some((&pp_cfg, &pp_tree)), &public, &proof, &mut unchanged,
    ), Err(VerificationError::InvalidProofShape(message))
        if message == "binary ring-switch native round count mismatch")
    );
    assert_eq!(
        unchanged.sample_algebra_element::<E>(),
        before.sample_algebra_element::<E>()
    );
    proof
        .preprocessed_opening
        .as_mut()
        .unwrap()
        .opening
        .reduction
        .sumcheck
        .polynomial_evaluations = rounds;
    let whir = &mut proof
        .preprocessed_opening
        .as_mut()
        .unwrap()
        .opening
        .opening
        .whir;
    let openings = if let Some(round) = whir.rounds.first_mut() {
        &mut round.openings
    } else {
        &mut whir.final_openings
    };
    let frontier = match openings {
        QueryOpenings::Base(o) => &mut o.proof.sibling_hashes,
        QueryOpenings::Extension(o) => &mut o.proof.sibling_hashes,
    };
    assert!(frontier.pop().is_some());
    let mut unchanged = make();
    let mut before = unchanged.clone();
    assert!(
        matches!(recursive.import_native_with_preprocessing::<Config,_,_,_>(
        &main_cfg, &main_tree, Some((&pp_cfg, &pp_tree)), &public, &proof, &mut unchanged),
        Err(VerificationError::InvalidProofShape(message)) if message == "binary WHIR native path restoration failed")
    );
    assert_eq!(
        unchanged.sample_algebra_element::<E>(),
        before.sample_algebra_element::<E>()
    );
    (recursive, input, public)
}

#[test]
fn boolean_whir_trace_multi_stark_binds_air_and_independent_preprocessing() {
    check(false, 6);
}

#[test]
fn boolean_whir_trace_multi_stark_closes_bus_and_indexed_reductions() {
    check(true, 6);
}

#[test]
fn prepared_boolean_whir_trace_multi_stark_proves_its_bound_statement() {
    use p3_field::PrimeField64;
    use p3_recursion::ProveNextLayerParams;
    use p3_recursion::artifact::{
        ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
        PortableVerifier,
    };
    use p3_recursion::builtin_config::{FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary};
    use p3_recursion::prepared::PreparedBinaryBooleanWhirTraceMultiStarkLayer;
    let (recursive, input, public) = check(false, 6);
    // This complete relation has more primitive scalar rows than the default
    // portable-artifact budget. Keep the larger fixture budget explicit.
    let limits = ArtifactLimits {
        verifier: VerifierLimits {
            max_total_scalar_elements: 1 << 26,
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
    let layer = PreparedBinaryBooleanWhirTraceMultiStarkLayer::<_, 4>::new(
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

#[test]
fn boolean_whir_trace_multi_stark_retains_successor_tensors_and_final_sumchecks() {
    check(true, 8);
}
