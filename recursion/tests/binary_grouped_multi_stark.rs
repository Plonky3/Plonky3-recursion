//! Complete native binary AIR proofs bound to prime-circuit public statements.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, TowerLevel};
use p3_binary_pcs::{
    BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProverData, GroupedCodewordMmcs,
};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder, StatementExport};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::IndexedLookupBuilder;
use p3_lookup::indexed::TraceWindow;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::PrunedMerklePaths;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{BinaryCodewordGrouping, RecursiveBinaryTowerField};
use p3_recursion::verifier::{
    BinaryGroupedMultiStarkPreprocessing, BinaryGroupedMultiStarkVerifier, VerificationError,
    VerifierLimits,
};
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
    ($base:ty, $extension:ty, $params:ident, $hash:expr, $heights:expr, $pow:expr, $fold:expr, $cap:expr) => {{
        type F = $base;
        type E = $extension;
        type Tree = $params::LevelMmcs<F>;
        type RoundTree = $params::LevelMmcs<E>;
        type M = GroupedCodewordMmcs<Tree>;
        type ME = GroupedCodewordMmcs<RoundTree>;
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
        let mmcs = Tree::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap,
        );
        let round_mmcs = RoundTree::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap,
        );
        let native = Config {
            pcs: BinaryPcs::new(
                config,
                GroupedCodewordMmcs::new(mmcs.clone(), 8),
                GroupedCodewordMmcs::for_folding(round_mmcs.clone(), &config),
            )
            .unwrap(),
        };
        let airs: Vec<_> = heights.iter().map(|_| RecurrenceAir).collect();
        let refs: Vec<_> = airs.iter().collect();
        let verifier = BinaryGroupedMultiStarkVerifier::<F, E>::new(
            &refs,
            &heights,
            config,
            $hash,
            $cap,
            $pow,
            heights.iter().max().unwrap() + 4,
            if n > 2 { 256 } else { 64 },
            BinaryCodewordGrouping::Codeword(8),
            BinaryCodewordGrouping::Folding,
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
        let grouped_inputs: usize = targets
            .opening
            .oracles
            .iter()
            .map(|o| {
                o.leaves.iter().map(|r| r.len() * 8).sum::<usize>()
                    + o.paths.iter().map(|p| p.len() * 16).sum::<usize>()
            })
            .sum();
        let grouped_start = b.private_input_count() - grouped_inputs;
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
            for (i, &height) in heights.iter().enumerate() {
                let a = F::from_le_byte_iter(
                    (0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128 ^ (seed + 37 * i as u128))
                        .to_le_bytes()
                        .into_iter()
                        .take(F::RAW_BITS / 8),
                );
                let c = F::from_le_byte_iter(
                    (0xfedc_ba98_7654_3210_0123_4567_89ab_cdefu128 ^ (seed + 71 * i as u128))
                        .to_le_bytes()
                        .into_iter()
                        .take(F::RAW_BITS / 8),
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
                .import_native(&mmcs, &round_mmcs, &public, &proof, &mut imported_ch)
                .unwrap();
            let observation =
                F::from_le_byte_iter((0..F::RAW_BITS / 8).map(|i| if i == 0 { 9 } else { 0 }));
            expected_ch.observe(observation);
            imported_ch.observe(observation);
            let next = expected_ch.sample_algebra_element::<E>();
            assert_eq!(next, imported_ch.sample_algebra_element::<E>());
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
            let mut wrong_group = private.clone();
            // An authenticated lane outside the selected logical symbol cannot change.
            wrong_group[grouped_start + 8 * (targets.opening.oracles[0].leaves[0].len() - 1)] +=
                BabyBear::ONE;
            assert!(!run(&circuit, &wrong_group, &public_limbs));
            let mut wrong = public_limbs.clone();
            wrong[16] += BabyBear::ONE;
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
                        .import_native(&mmcs, &round_mmcs, &public, &bad, &mut ch)
                        .is_err()
                );
                assert_eq!(
                    ch.sample_algebra_element::<E>(),
                    expected.sample_algebra_element::<E>()
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

            final_values = (private, public_limbs);
        }
        (circuit, final_values.0, final_values.1)
    }};
}

#[test]
fn grouped_multi_stark_matches_both_hashes_and_mixed_heights() {
    check!(
        BinaryField8,
        BinaryField64,
        keccak,
        ByteHash::Keccak256,
        vec![1],
        0,
        1,
        0
    );
    check!(
        BinaryField8,
        BinaryField64,
        blake3,
        ByteHash::Blake3,
        vec![1, 3],
        0,
        2,
        1
    );
}

#[test]
fn grouped_multi_stark_proves_an_independently_bound_statement() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver, StatementAirBuilder, StatementPreprocessor, StatementProver,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, private, public) = check!(
        BinaryField8,
        BinaryField64,
        blake3,
        ByteHash::Blake3,
        vec![1],
        0,
        1,
        0
    );
    let schema = circuit.statement_schema().unwrap().clone();
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(Blake3CompressProver::<1>));
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema.clone())));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &[
                Box::new(Blake3CompressPreprocessor),
                Box::new(StatementPreprocessor::new(schema.clone())),
            ],
            &[
                Box::new(Blake3CompressAirBuilder::<1>),
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

struct CoupledAir {
    provider: bool,
}
impl BaseAir<BinaryField8> for CoupledAir {
    fn width(&self) -> usize {
        3
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        usize::from(self.provider)
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BinaryField8>> {
        self.provider
            .then(|| RowMajorMatrix::new((7u8..15).map(BinaryField8::from_repr).collect(), 1))
    }
}
impl<AB: AirBuilder<F = BinaryField8> + IndexedLookupBuilder + BusInteractionBuilder> Air<AB>
    for CoupledAir
{
    fn eval(&self, b: &mut AB) {
        b.assert_eq(b.main().current_slice()[2], b.public_values()[0]);
        let (payload, direction) = if self.provider {
            b.push_indexed_table("payload", TraceWindow::Preprocessed, [0]);
            (b.preprocessed().current_slice()[0], BusDirection::Pull)
        } else {
            b.push_indexed_read("payload", 0, [1]);
            (b.main().current_slice()[1], BusDirection::Push)
        };
        b.push_bus_interaction(
            BusName::new("payload"),
            direction,
            [payload],
            BusActivation::Always,
        );
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct GroupedWire<F> {
    inner: PrunedMerklePaths<u8, 32>,
    missing_symbols: Vec<F>,
}
fn grouped_frontier_count<F: serde::de::DeserializeOwned>(proof: &impl serde::Serialize) -> usize {
    let wire: GroupedWire<F> =
        postcard::from_bytes(&postcard::to_allocvec(proof).unwrap()).unwrap();
    wire.inner.sibling_hashes.len()
}

#[test]
fn grouped_bus_and_indexed_proofs_authenticate_an_independent_preprocessed_cap() {
    type F = BinaryField8;
    type E = BinaryField64;
    type Tree = blake3::LevelMmcs<F>;
    type RoundTree = blake3::LevelMmcs<E>;
    type M = GroupedCodewordMmcs<Tree>;
    type ME = GroupedCodewordMmcs<RoundTree>;
    type Pcs = BinaryPcs<F, E, M, ME>;
    type Ch = blake3::LevelChallenger<F>;
    struct Config {
        main: Pcs,
        preprocessed: Pcs,
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
            &self.preprocessed
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
            i: usize,
        ) -> &'a Table<F> {
            data.table(i)
        }
    }
    let cfg = |n| {
        BinaryPcsConfig::try_new::<F, E>(
            n,
            BinaryPcsParams {
                log_inv_rate: if n == 3 { 4 } else { 2 },
                pow_bits: 0,
                security_level: 24,
            },
        )
        .unwrap()
        .try_with_folding(2)
        .unwrap()
    };
    let (main_config, pp_config) = (cfg(6), cfg(3));
    let base = |cap| {
        Tree::new(
            blake3::FieldHash::new(blake3::byte_hash()),
            blake3::Compress::new(blake3::byte_hash()),
            cap,
        )
    };
    let round = |cap| {
        RoundTree::new(
            blake3::FieldHash::new(blake3::byte_hash()),
            blake3::Compress::new(blake3::byte_hash()),
            cap,
        )
    };
    let (main_base, main_round, pp_base, pp_round) = (base(0), round(0), base(1), round(1));
    let native = Config {
        main: Pcs::new(
            main_config,
            M::with_group_size(main_base.clone(), &main_config, 8),
            ME::for_folding(main_round.clone(), &main_config),
        )
        .unwrap(),
        preprocessed: Pcs::new(
            pp_config,
            M::with_group_size(pp_base.clone(), &pp_config, 2),
            ME::with_group_size(pp_round.clone(), &pp_config, 8),
        )
        .unwrap(),
    };
    let airs = [
        CoupledAir { provider: false },
        CoupledAir { provider: true },
    ];
    let refs = airs.iter().collect::<Vec<_>>();
    let make = || Ch::from_hasher(vec![7, 19, 13], blake3::byte_hash());
    let (pk, vk) = setup(&native, &refs, &mut make()).unwrap();
    let pp_table = Table::new(airs[1].preprocessed_trace().unwrap().transpose());
    let (pp_cap, _) = native
        .preprocessed
        .commit(native.build_witness(vec![pp_table]), &mut make())
        .unwrap();
    let pp = BinaryGroupedMultiStarkPreprocessing {
        config: pp_config,
        hash: ByteHash::Blake3,
        cap_height: 1,
        max_query_draws: 512,
        base_grouping: BinaryCodewordGrouping::Message(2),
        round_grouping: BinaryCodewordGrouping::Message(8),
        commitment: pp_cap,
    };
    let build = |pp, limits: &VerifierLimits| {
        BinaryGroupedMultiStarkVerifier::<F, E>::with_preprocessing(
            &refs,
            &[3, 3],
            main_config,
            ByteHash::Blake3,
            0,
            0,
            8,
            512,
            BinaryCodewordGrouping::Message(8),
            BinaryCodewordGrouping::Folding,
            pp,
            limits,
        )
    };
    let verifier = build(pp.clone(), &VerifierLimits::default()).unwrap();
    let shape = verifier.input_shape();
    let public = vec![vec![F::from_repr(0x53)], vec![F::from_repr(0x97)]];
    let traces = [
        (0u8..8)
            .flat_map(|i| [F::from_repr(i), F::from_repr(i + 7), public[0][0]])
            .collect(),
        (0u8..8)
            .flat_map(|i| [F::from_repr(i), F::from_repr(27), public[1][0]])
            .collect(),
    ];
    let instances = airs
        .iter()
        .zip(traces)
        .zip(&public)
        .map(|((air, trace), values)| {
            ProverInstance::new(
                air,
                Table::new(RowMajorMatrix::new(trace, 3).transpose()),
                &pk,
                values,
            )
        })
        .collect();
    let proof = prove(&native, ProverInstances::new(instances), 0, &mut make()).unwrap();
    assert!(proof.bus.is_some() && proof.indexed.is_some() && proof.preprocessed_opening.is_some());
    let instances = airs
        .iter()
        .zip(&public)
        .map(|(air, values)| VerifierInstance::new(air, &vk, 3, values))
        .collect();
    let mut expected = make();
    verify(
        &native,
        VerifierInstances::new(instances),
        &proof,
        0,
        &mut expected,
    )
    .unwrap();
    let mut actual = make();
    let input = verifier
        .import_native_with_preprocessing(
            &main_base,
            &main_round,
            Some((&pp_base, &pp_round)),
            &public,
            &proof,
            &mut actual,
        )
        .unwrap();
    expected.observe(F::from_repr(9));
    actual.observe(F::from_repr(9));
    assert_eq!(
        actual.sample_algebra_element::<E>(),
        expected.sample_algebra_element::<E>()
    );
    let main_frontiers = grouped_frontier_count::<F>(&proof.opening.base_multi_proof)
        + proof
            .opening
            .rounds
            .iter()
            .map(|r| grouped_frontier_count::<E>(&r.multi_proof))
            .sum::<usize>();
    let pp_proof = proof.preprocessed_opening.as_ref().unwrap();
    let pp_frontiers = grouped_frontier_count::<F>(&pp_proof.base_multi_proof)
        + pp_proof
            .rounds
            .iter()
            .map(|r| grouped_frontier_count::<E>(&r.multi_proof))
            .sum::<usize>();
    assert!(main_frontiers > 0 && pp_frontiers > 0);
    let frontier_limit = main_frontiers + pp_frontiers - 1;
    assert!(main_frontiers <= frontier_limit && pp_frontiers <= frontier_limit);
    let limits = VerifierLimits {
        max_compressed_frontier_hashes: frontier_limit,
        ..VerifierLimits::default()
    };
    let bounded = build(pp.clone(), &limits).unwrap();
    let mut retry = make();
    let mut entry = retry.clone();
    assert!(matches!(
        bounded.import_native_with_preprocessing(
            &main_base,
            &main_round,
            Some((&pp_base, &pp_round)),
            &public,
            &proof,
            &mut retry
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "compressed frontier hashes",
            ..
        })
    ));
    assert_eq!(
        retry.sample_algebra_element::<E>(),
        entry.sample_algebra_element::<E>()
    );
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_blake3_compress::<BabyBear>();
    let mut exports = Vec::new();
    let targets_public: Vec<_> = public
        .iter()
        .map(|values| {
            values
                .iter()
                .map(|_| public_field(&mut b, &mut exports))
                .collect()
        })
        .collect();
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
    verifier
        .verify::<BabyBear, BabyBear>(&mut b, ch, &targets_public, &targets)
        .unwrap();
    b.set_statement_exports::<BabyBear>(&exports).unwrap();
    let circuit = b.build().unwrap();
    let private = input.private_values::<BabyBear>(&shape).unwrap();
    let public_limbs: Vec<_> = public.iter().flatten().copied().flat_map(limbs).collect();
    assert!(run(&circuit, &private, &public_limbs));
    for offset in [0, 16, private.len() - 1] {
        let mut wrong = private.clone();
        wrong[offset] += BabyBear::ONE;
        assert!(!run(&circuit, &wrong, &public_limbs));
    }
    let mut wrong_statement = public_limbs.clone();
    wrong_statement[0] += BabyBear::ONE;
    assert!(!run(&circuit, &private, &wrong_statement));
    let mut foreign_pp = pp.clone();
    foreign_pp.commitment = p3_merkle_tree::MerkleCap::new(vec![[0; 32]; 2]);
    assert!(
        input
            .private_values::<BabyBear>(
                &build(foreign_pp, &VerifierLimits::default())
                    .unwrap()
                    .input_shape()
            )
            .is_err()
    );
    let usage = verifier.input_resource_usage();
    let limits = VerifierLimits {
        max_total_scalar_elements: usage.scalar_elements - 1,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        build(pp, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
}
