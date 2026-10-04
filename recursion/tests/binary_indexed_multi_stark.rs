//! Indexed binary AIR reductions authenticated at every scheduled PCS point.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProverData};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder, StatementExport};
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
    BinaryAirConstraintPlan, BinaryMultiStarkPreprocessing, BinaryMultiStarkVerifier,
    VerificationError, VerifierLimits,
};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_test_utils::binary_field_params::{blake3, keccak};

#[derive(Clone)]
struct IndexedAir {
    width: usize,
    read: Option<(&'static str, usize, Vec<usize>)>,
    provide: Option<(&'static str, Vec<usize>)>,
    preprocessed: bool,
    bus: Option<BusDirection>,
}

impl<F: RecursiveBinaryTowerField> BaseAir<F> for IndexedAir {
    fn width(&self) -> usize {
        self.width
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn preprocessed_width(&self) -> usize {
        if self.preprocessed { 2 } else { 0 }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.preprocessed
            .then(|| RowMajorMatrix::new([0, 7, 3, 11].into_iter().map(field::<F>).collect(), 2))
    }
}

impl<AB: AirBuilder + IndexedLookupBuilder + BusInteractionBuilder> Air<AB> for IndexedAir
where
    AB::F: RecursiveBinaryTowerField,
{
    fn eval(&self, b: &mut AB) {
        let first = b.main().current_slice()[0];
        let public = b.public_values()[0];
        b.when_first_row().assert_eq(first, public);
        if let Some((name, position, payload)) = &self.read {
            b.push_indexed_read(name, *position, payload.iter().copied());
        }
        if let Some((name, columns)) = &self.provide {
            b.push_indexed_table(
                name,
                if self.preprocessed {
                    TraceWindow::Preprocessed
                } else {
                    TraceWindow::Main
                },
                columns.iter().copied(),
            );
        }
        if let Some(direction) = self.bus {
            let column = self.read.as_ref().map_or(0, |(_, _, payload)| payload[0]);
            let payload = b.main().current_slice()[column];
            b.push_bus_interaction(
                BusName::new("indexed-payload"),
                direction,
                [payload],
                BusActivation::Always,
            );
        }
    }
}

fn airs() -> Vec<IndexedAir> {
    // Name order differs from AIR order. Provider "a" reverses its columns,
    // and the two readers of "z" have unequal heights.
    vec![
        IndexedAir {
            width: 2,
            read: Some(("z", 0, vec![1])),
            provide: None,
            preprocessed: false,
            bus: None,
        },
        IndexedAir {
            width: 2,
            read: None,
            provide: Some(("a", vec![1, 0])),
            preprocessed: false,
            bus: None,
        },
        IndexedAir {
            width: 3,
            read: Some(("a", 0, vec![1, 2])),
            provide: None,
            preprocessed: false,
            bus: None,
        },
        IndexedAir {
            width: 1,
            read: None,
            provide: Some(("z", vec![0])),
            preprocessed: false,
            bus: None,
        },
        IndexedAir {
            width: 2,
            read: Some(("z", 0, vec![1])),
            provide: None,
            preprocessed: false,
            bus: None,
        },
    ]
}

fn field<F: RecursiveBinaryTowerField>(raw: u128) -> F {
    F::from_le_byte_iter(raw.to_le_bytes().into_iter().take(F::RAW_BITS / 8))
}
fn limbs<F: RecursiveBinaryTowerField>(value: F) -> impl Iterator<Item = BabyBear> {
    let raw = value.raw_coordinates();
    (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16))
}
fn private_field(b: &mut CircuitBuilder<BabyBear>) -> BinaryTower128Target {
    let limbs = b.alloc_private_input_array::<8>("indexed continuation");
    b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}
fn run(circuit: &Circuit<BabyBear>, private: &[BabyBear], public: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(private).unwrap();
    runner.set_public_inputs(public).unwrap();
    runner.run().is_ok()
}

macro_rules! check {
    ($base:ty, $extension:ty, $params:ident, $hash:expr) => {
        check!($base, $extension, $params, $hash, false)
    };
    ($base:ty, $extension:ty, $params:ident, $hash:expr, $small:expr) => {{
        check!($base, $extension, $params, $hash, $small, false)
    }};
    ($base:ty, $extension:ty, $params:ident, $hash:expr, $small:expr, $preprocessed:expr) => {{
        check!($base, $extension, $params, $hash, $small, $preprocessed, false)
    }};
    ($base:ty, $extension:ty, $params:ident, $hash:expr, $small:expr, $preprocessed:expr, $bus:expr) => {{
        type F = $base;
        type E = $extension;
        type M = $params::LevelMmcs<F>;
        type ME = $params::LevelMmcs<E>;
        type Ch = $params::LevelChallenger<F>;
        struct Config {
            pcs: BinaryPcs<F, E, M, ME>,
            preprocessing: BinaryPcs<F, E, M, ME>,
        }
        impl MultiStarkConfig for Config {
            type Val = F;
            type Challenge = E;
            type Challenger = Ch;
            type Pcs = BinaryPcs<F, E, M, ME>;
            fn pcs(&self) -> &Self::Pcs {
                &self.pcs
            }
            fn preprocessed_pcs(&self) -> &Self::Pcs { &self.preprocessing }
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
        let heights = if $small {
            vec![1, 1]
        } else {
            vec![2, 1, 1, 2, 1]
        };
        let mut airs = if $small {
            vec![
                IndexedAir {
                    width: 2,
                    read: Some(("a", 0, vec![1])),
                    provide: None,
                    preprocessed: false,
                    bus: None,
                },
                IndexedAir {
                    width: 1,
                    read: None,
                    provide: Some(("a", vec![0])),
                    preprocessed: false,
                    bus: None,
                },
            ]
        } else {
            airs()
        };
        airs[1].preprocessed = $preprocessed;
        if $bus {
            assert!($small && !$preprocessed);
            airs[0].bus = Some(BusDirection::Push);
            airs[1].bus = Some(BusDirection::Pull);
        }
        let cells: usize = airs
            .iter()
            .zip(&heights)
            .map(|(air, &height)| air.width << height)
            .sum();
        let max_query_draws = if $small { 128 } else { 256 };
        let cfg = BinaryPcsConfig::try_new::<F, E>(
            p3_util::log2_ceil_usize(cells),
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 40,
            },
        )
        .unwrap()
        .try_with_folding(2)
        .unwrap();
        let mmcs = M::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let round_mmcs = ME::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let native = Config {
            pcs: BinaryPcs::new(cfg, mmcs.clone(), round_mmcs.clone()).unwrap(),
            preprocessing: BinaryPcs::new(BinaryPcsConfig::try_new::<F,E>(2, BinaryPcsParams { log_inv_rate: 2, pow_bits: 0, security_level: 40 }).unwrap().try_with_folding(2).unwrap(),
                M::new($params::FieldHash::new($params::byte_hash()), $params::Compress::new($params::byte_hash()), 1),
                ME::new($params::FieldHash::new($params::byte_hash()), $params::Compress::new($params::byte_hash()), 1)).unwrap(),
        };
        let refs: Vec<_> = airs.iter().collect();
        assert!(BinaryAirConstraintPlan::<F, E>::from_air(&airs[0], 2).is_err());
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let (pk, vk) = setup(&native, &refs, &mut make()).unwrap();
        let pre_cfg = BinaryPcsConfig::try_new::<F,E>(2, BinaryPcsParams { log_inv_rate: 2, pow_bits: 0, security_level: 40 }).unwrap().try_with_folding(2).unwrap();
        let pre_base = M::new($params::FieldHash::new($params::byte_hash()), $params::Compress::new($params::byte_hash()), 1);
        let pre_round = ME::new($params::FieldHash::new($params::byte_hash()), $params::Compress::new($params::byte_hash()), 1);
        let pre_cap = if $preprocessed {
            let tables: Vec<Table<F>> = airs.iter().filter(|air| air.preprocessed).map(|air| Table::new(air.preprocessed_trace().unwrap().transpose())).collect();
            Some(native.preprocessing.commit(native.build_witness(tables), &mut make()).unwrap().0)
        } else { None };
        let recursive = |refs: &[&IndexedAir]| {
            if let Some(cap) = &pre_cap {
                BinaryMultiStarkVerifier::<F,E>::with_preprocessing(refs, &heights, cfg, $hash, 0, 0, 8, max_query_draws,
                    BinaryMultiStarkPreprocessing { config: pre_cfg, hash: $hash, cap_height: 1, max_query_draws: 128, commitment: cap.clone() }, &VerifierLimits::default())
            } else { BinaryMultiStarkVerifier::<F,E>::new(refs, &heights, cfg, $hash, 0, 0, 8, max_query_draws) }
        };
        let verifier = recursive(&refs).unwrap();
        let shape = verifier.input_shape();
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let mut exports = Vec::new();
        let public_targets: Vec<_> = airs
            .iter()
            .map(|_| {
                let limbs = core::array::from_fn(|_| b.public_input());
                exports.extend(limbs.map(StatementExport::Base));
                vec![b.binary128_from_limbs::<BabyBear>(limbs).unwrap()]
            })
            .collect();
        let targets = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut b)
            .unwrap();
        let mut malformed = targets.clone();
        malformed.indexed.as_mut().unwrap().reader_claims.pop();
        let mut untouched = CircuitBuilder::<BabyBear>::new();
        assert!(matches!(verifier.verify::<BabyBear, BabyBear>(&mut untouched,
            BinaryTower128Challenger::new($hash), &public_targets, &malformed),
            Err(VerificationError::InvalidProofShape(message)) if message.contains("indexed reader claims")));
        assert_eq!(untouched.build().unwrap().ops.len(), CircuitBuilder::<BabyBear>::new().build().unwrap().ops.len());
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
        let obs: Vec<_> = (0..F::RAW_BITS / 8)
            .map(|i| b.define_const(BabyBear::from_u8(if i == 0 { 9 } else { 0 })))
            .collect();
        let mut ch = token
            .resume_with_observation::<BabyBear, BabyBear>(&mut b, &obs)
            .unwrap();
        let bytes = ch
            .sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8)
            .unwrap();
        let mut bits = [p3_circuit::ExprId::ZERO; 128];
        for (i, byte) in bytes.into_iter().enumerate() {
            bits[8 * i..8 * i + 8]
                .copy_from_slice(&b.decompose_to_bits::<BabyBear>(byte, 8).unwrap());
        }
        let next = b.binary128_from_bits(bits).unwrap();
        let expected = private_field(&mut b);
        for (&a, &e) in next.bits().iter().zip(expected.bits()) {
            let diff = b.sub(a, e);
            b.assert_zero(diff);
        }
        b.set_statement_exports::<BabyBear>(&exports).unwrap();
        let circuit = b.build().unwrap();
        let mut final_values = (vec![], vec![]);
        for seed in [0u128, 37] {
            let z = [0, 5, 10, 19].map(|v| v ^ seed);
            let a_seed = if $preprocessed { 0 } else { seed };
            let a = [[a_seed, 7 ^ a_seed], [3 ^ a_seed, 11 ^ a_seed]];
            let rows: Vec<Vec<u128>> = if $small {
                vec![vec![0, 7 ^ seed, 1, 11 ^ seed], vec![7 ^ seed, 11 ^ seed]]
            } else {
                vec![
                    [0usize, 1, 3, 2]
                        .into_iter()
                        .flat_map(|p| [p as u128, z[p]])
                        .collect(),
                    a.into_iter().flatten().map(|value| value ^ if $preprocessed { seed } else { 0 }).collect(),
                    [0usize, 1]
                        .into_iter()
                        .flat_map(|p| [p as u128, a[p][1], a[p][0]])
                        .collect(),
                    z.to_vec(),
                    [0usize, 3]
                        .into_iter()
                        .flat_map(|p| [p as u128, z[p]])
                        .collect(),
                ]
            };
            let public: Vec<_> = rows.iter().map(|row| vec![field::<F>(row[0])]).collect();
            let tables: Vec<_> = rows
                .iter()
                .zip(&airs)
                .map(|(row, air)| {
                    Table::new(
                        RowMajorMatrix::new(
                            row.iter().copied().map(field::<F>).collect(),
                            air.width,
                        )
                        .transpose(),
                    )
                })
                .collect();
            let instances = airs
                .iter()
                .zip(tables)
                .zip(&public)
                .map(|((air, table), values)| ProverInstance::new(air, table, &pk, values))
                .collect();
            let proof = prove(&native, ProverInstances::new(instances), 0, &mut make()).unwrap();
            assert_eq!(proof.opening.evals.len(), (if $small { 4 } else { 10 }) - usize::from($preprocessed));
            if $preprocessed { assert_eq!(proof.preprocessed_opening.as_ref().unwrap().evals.len(), 2); }
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
                0,
                &mut expected_ch,
            )
            .unwrap();
            let mut imported_ch = make();
            let input = verifier
                .import_native_with_preprocessing(&mmcs, &round_mmcs, $preprocessed.then_some((&pre_base, &pre_round)), &public, &proof, &mut imported_ch)
                .unwrap();
            let mut other_airs = airs.clone();
            if $small {
                other_airs[0].read.as_mut().unwrap().0 = "b";
                other_airs[1].provide.as_mut().unwrap().0 = "b";
            } else {
                other_airs[2].read.as_mut().unwrap().2.reverse();
            }
            let other_refs: Vec<_> = other_airs.iter().collect();
            let other = recursive(&other_refs).unwrap();
            assert!(
                input
                    .private_values::<BabyBear>(&other.input_shape())
                    .is_err()
            );
            expected_ch.observe(field::<F>(9));
            imported_ch.observe(field::<F>(9));
            let next = expected_ch.sample_algebra_element::<E>();
            assert_eq!(next, imported_ch.sample_algebra_element::<E>());
            let mut private = input.private_values::<BabyBear>(&shape).unwrap();
            private.extend(limbs(next));
            let public_limbs: Vec<_> = public.iter().flatten().copied().flat_map(limbs).collect();
            let mut runner = circuit.runner();
            runner.set_private_inputs(&private).unwrap();
            runner.set_public_inputs(&public_limbs).unwrap();
            runner
                .run()
                .expect("indexed MultiStark constraints must verify");
            let mut wrong = public_limbs.clone();
            wrong[8] += BabyBear::ONE;
            assert!(!run(&circuit, &private, &wrong));
            let mut wrong = private.clone();
            wrong[16] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public_limbs));
            let mut wrong = private.clone();
            let last = wrong.len() - 8;
            wrong[last] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong, &public_limbs));

            let indexed = targets.indexed.as_ref().unwrap();
            let fields = |polys: &[Vec<BinaryTower128Target>], pow: &[BinaryTower128Target]| {
                1 + polys.iter().map(Vec::len).sum::<usize>() + pow.len()
            };
            let bus_fields = targets.bus.as_ref().map_or(0, |bus| {
                bus.roots.len() + bus.layers.iter().map(|layer| {
                    layer.round_polys.iter().map(Vec::len).sum::<usize>()
                        + layer.children.iter().map(Vec::len).sum::<usize>()
                }).sum::<usize>()
            });
            let reader_start = 16 + 8 * bus_fields
                + 8 * fields(
                    &targets.sumcheck.round_polys,
                    &targets.sumcheck.pow_witnesses,
                );
            let push_start =
                reader_start + 8 * indexed.reader_claims.iter().map(Vec::len).sum::<usize>();
            let fraction_start = push_start
                + 8 * indexed
                    .reduction
                    .pushforwards
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>();
            let positions_start = fraction_start
                + 8 * (1 + indexed
                    .reduction
                    .fraction_gkr
                    .layers
                    .iter()
                    .map(|layer| 3 * layer.round_polys.len() + 4)
                    .sum::<usize>());
            let product_start = positions_start + 8 * indexed.reduction.position_claims.len();
            let columns_start = product_start
                + 8 * fields(
                    &indexed.reduction.product.round_polys,
                    &indexed.reduction.product.pow_witnesses,
                );
            for offset in [
                reader_start,
                push_start,
                fraction_start,
                positions_start,
                product_start,
                columns_start,
            ] {
                let mut wrong = private.clone();
                wrong[offset] += BabyBear::ONE;
                assert!(
                    !run(&circuit, &wrong, &public_limbs),
                    "tampered indexed field at {offset}"
                );
            }
            if E::RAW_BITS == 64 {
                let mut wrong = private.clone();
                wrong[reader_start + 4] += BabyBear::ONE;
                assert!(!run(&circuit, &wrong, &public_limbs));
            }
            let duplicate = || p3_multi_stark::MultiStarkProof::<Config> {
                commitment: proof.commitment.clone(),
                lookup: None,
                indexed: proof.indexed.clone(),
                bus: proof.bus.clone(),
                sumcheck: proof.sumcheck.clone(),
                opening: proof.opening.clone(),
                preprocessed_opening: proof.preprocessed_opening.clone(),
            };
            let unchanged = |bad| {
                let mut ch = make();
                let mut expected = ch.clone();
                assert!(
                    verifier
                        .import_native_with_preprocessing(&mmcs, &round_mmcs, $preprocessed.then_some((&pre_base, &pre_round)), &public, &bad, &mut ch)
                        .is_err()
                );
                assert_eq!(
                    ch.sample_algebra_element::<E>(),
                    expected.sample_algebra_element::<E>()
                );
            };
            let mut bad = duplicate();
            bad.indexed = None;
            unchanged(bad);
            let mut bad = duplicate();
            bad.indexed.as_mut().unwrap().reader_claims.pop();
            unchanged(bad);
            let mut bad = duplicate();
            bad.indexed.as_mut().unwrap().reader_claims[0].pop();
            unchanged(bad);
            let mut bad = duplicate();
            bad.indexed
                .as_mut()
                .unwrap()
                .reduction
                .fraction_gkr
                .layers
                .pop();
            unchanged(bad);
            let mut bad = duplicate();
            bad.indexed.as_mut().unwrap().reduction.column_claims[0].pop();
            unchanged(bad);
            let mut bad = duplicate();
            bad.indexed
                .as_mut()
                .unwrap()
                .reduction
                .position_claims
                .pop();
            unchanged(bad);
            let mut bad = duplicate();
            bad.indexed.as_mut().unwrap().reader_claims[0][0] += E::ONE;
            unchanged(bad);
            let mut bad = duplicate();
            bad.opening.evals.pop();
            unchanged(bad);
            let mut bad = duplicate();
            bad.opening.base_multi_proof.sibling_hashes.push([0; 32]);
            unchanged(bad);
            if $preprocessed {
                let mut bad = duplicate(); bad.preprocessed_opening = None; unchanged(bad);
                let mut bad = duplicate(); bad.preprocessed_opening.as_mut().unwrap().evals.pop(); unchanged(bad);
                let mut bad = duplicate(); bad.preprocessed_opening.as_mut().unwrap().base_multi_proof.sibling_hashes.push([0; 32]); unchanged(bad);
                let mut wrong = private.clone();
                // Preprocessing is packed after the main opening and before
                // the eight final continuation limbs.
                let pre = targets.preprocessed_opening.as_ref().unwrap();
                let pre_len = 16 * pre.sumcheck.len()
                    + 8 * pre.evals.iter().map(|batch| batch.current().len() + batch.next().len()).sum::<usize>()
                    + pre.rounds.iter().map(|round| 16 * round.cap.len() + 8 * round.rows.len() + 16 * round.paths.iter().map(Vec::len).sum::<usize>()).sum::<usize>()
                    + 8 * pre.base_rows.len() + 16 * pre.base_paths.iter().map(Vec::len).sum::<usize>()
                    + 8 * pre.final_codeword.len() + 8 + pre.query_indices.iter().map(Vec::len).sum::<usize>();
                let pre_start = private.len() - 8 - pre_len;
                let columns_batch = pre_start + 16 * pre.sumcheck.len() + 16;
                wrong[columns_batch] += BabyBear::ONE;
                assert!(!run(&circuit, &wrong, &public_limbs));
            }
            final_values = (private, public_limbs);
        }
        (circuit, final_values.0, final_values.1)
    }};
}

#[test]
fn indexed_tables_and_reader_payloads_match_the_native_batch_schedule() {
    check!(BinaryField8, BinaryField64, blake3, ByteHash::Blake3);
}

#[test]
fn indexed_tower128_proofs_match_the_keccak_transcript() {
    check!(BinaryField128, BinaryField128, keccak, ByteHash::Keccak256);
}

#[test]
fn indexed_preprocessed_providers_use_the_trusted_cap_and_their_own_pcs_geometry() {
    check!(
        BinaryField8,
        BinaryField64,
        blake3,
        ByteHash::Blake3,
        false,
        true
    );
    check!(
        BinaryField128,
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        false,
        true
    );
}

#[test]
fn indexed_authority_and_combined_resource_limits_are_checked() {
    let cfg = BinaryPcsConfig::try_new::<BinaryField8, BinaryField64>(
        5,
        BinaryPcsParams {
            log_inv_rate: 2,
            pow_bits: 0,
            security_level: 40,
        },
    )
    .unwrap()
    .try_with_folding(2)
    .unwrap();
    let prepare = |airs: &[IndexedAir], heights: &[usize], limits: &VerifierLimits| {
        let refs: Vec<_> = airs.iter().collect();
        BinaryMultiStarkVerifier::<BinaryField8, BinaryField64>::with_limits(
            &refs,
            heights,
            cfg,
            ByteHash::Blake3,
            0,
            0,
            8,
            256,
            limits,
        )
    };
    let airs = airs();
    let heights = [2, 1, 1, 2, 1];
    let defaults = VerifierLimits::default();
    let verifier = prepare(&airs, &heights, &defaults).unwrap();
    let usage = verifier.input_resource_usage();
    assert_eq!(usage.instances, airs.len());
    assert!(
        prepare(
            &airs,
            &heights,
            &VerifierLimits {
                max_instances: airs.len(),
                ..defaults.clone()
            }
        )
        .is_ok()
    );
    assert!(
        prepare(
            &airs,
            &heights,
            &VerifierLimits {
                max_instances: airs.len() - 1,
                ..defaults.clone()
            }
        )
        .is_err()
    );
    let mut bad = airs.clone();
    bad[1].provide = None;
    assert!(prepare(&bad, &heights, &defaults).is_err());
    let mut bad = airs.clone();
    bad[1].provide.as_mut().unwrap().0 = "z";
    assert!(prepare(&bad, &heights, &defaults).is_err());
    let mut bad = airs.clone();
    bad[2].read.as_mut().unwrap().2 = vec![1];
    assert!(prepare(&bad, &heights, &defaults).is_err());
    let mut bad = airs.clone();
    bad[2].read.as_mut().unwrap().2 = vec![1, 1];
    assert!(prepare(&bad, &heights, &defaults).is_err());
    let mut bad = airs.clone();
    bad[2].read = None;
    assert!(prepare(&bad, &heights, &defaults).is_err());
    let mut bad_heights = heights;
    bad_heights[3] = 8;
    assert!(prepare(&airs, &bad_heights, &defaults).is_err());
    for limits in [
        VerifierLimits {
            max_rounds: usage.rounds - 1,
            ..defaults.clone()
        },
        VerifierLimits {
            max_queries_per_round: 255,
            ..defaults.clone()
        },
        VerifierLimits {
            max_total_scalar_elements: usage.scalar_elements - 1,
            ..defaults.clone()
        },
        VerifierLimits {
            max_metadata_entries: usage.metadata_entries - 1,
            ..defaults.clone()
        },
        VerifierLimits {
            max_metadata_string_bytes: usage.metadata_string_bytes - 1,
            ..defaults.clone()
        },
    ] {
        assert!(matches!(
            prepare(&airs, &heights, &limits),
            Err(VerificationError::ResourceLimitExceeded { .. })
        ));
    }
    let exact = VerifierLimits {
        max_metadata_entries: usage.metadata_entries,
        ..defaults
    };
    assert!(prepare(&airs, &heights, &exact).is_ok());
}

#[test]
fn bus_and_indexed_reductions_share_the_native_transcript_and_air_point() {
    check!(
        BinaryField8,
        BinaryField64,
        blake3,
        ByteHash::Blake3,
        true,
        false,
        true
    );
    check!(
        BinaryField128,
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        true,
        false,
        true
    );
}

#[test]
fn a_complete_indexed_binary_air_proof_verifies_in_a_prime_field_proof() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver, StatementAirBuilder, StatementPreprocessor, StatementProver,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, private, public) =
        check!(BinaryField8, BinaryField64, blake3, ByteHash::Blake3, true);
    let mut prover = BatchStarkProver::new(config::baby_bear());
    let schema = circuit.statement_schema().unwrap().clone();
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
    wrong[8] += BabyBear::ONE;
    assert!(prepared.verifier().verify(&proof, &wrong).is_err());
}
