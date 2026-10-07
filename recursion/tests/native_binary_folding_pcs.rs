//! Full BaseFold openings verified in the exact native Tower128 carrier.

use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::transcript::BinaryPcsShape;
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, NativeTower128Target, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{BinaryPcsVerifier, RecursiveBinaryTowerField};
use p3_sumcheck::layout::{Layout, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::keccak;

type F = BinaryField128;
type H = NativeBinaryEncoding;

fn scalar(b: &mut CircuitBuilder<F>) -> NativeTower128Target {
    let expression = b.public_input();
    b.native_tower128_from_expr(expression)
}
fn run(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}
fn protocol(rows: usize, width: usize) -> OpeningProtocol {
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(rows, width),
        vec![OpeningBatch::new(
            (0..width).rev().collect(),
            (0..width).collect(),
        )],
    )])
}

/// Private-input offsets of one authenticated oracle: `size` rows per query,
/// then each row's `depth` sibling digests of sixteen words.
struct Oracle {
    rows: usize,
    paths: usize,
    size: usize,
    depth: usize,
}

/// Private-input offsets of each witness class, in `allocate_native_targets` order.
struct Offsets {
    evals: usize,
    rounds: Vec<Oracle>,
    base: Oracle,
    final_codeword: usize,
    pow: usize,
    queries: usize,
}
fn offsets(config: &BinaryPcsConfig, protocol: &OpeningProtocol, cap_height: usize) -> Offsets {
    let shape = BinaryPcsShape::new(config);
    let n = config.num_variables();
    let k = config.log_folding_factor();
    let log_domain = n + config.log_inv_rate();
    let claims: usize = protocol
        .iter_openings()
        .map(|(_, b)| b.current().len() + b.next().len())
        .sum();
    let mut cursor = 2 * n;
    let evals = cursor;
    cursor += claims;
    let oracle = |cursor: &mut usize, arity: usize, depth: usize| {
        let size = 1usize << arity;
        let rows = *cursor;
        *cursor += shape.num_pairs * size;
        let paths = *cursor;
        *cursor += shape.num_pairs * size * depth * 16;
        Oracle {
            rows,
            paths,
            size,
            depth,
        }
    };
    let mut rounds = Vec::new();
    let mut start = k;
    while start < n {
        let arity = k.min(n - start);
        cursor += 16 << cap_height;
        rounds.push(oracle(&mut cursor, arity, log_domain - start - cap_height));
        start += k;
    }
    let base = oracle(&mut cursor, k, log_domain - cap_height);
    let final_codeword = cursor;
    cursor += shape.final_codeword_len;
    let pow = cursor;
    cursor += 1;
    Offsets {
        evals,
        rounds,
        base,
        final_codeword,
        pow,
        queries: cursor,
    }
}

macro_rules! check {
    ($base:ty, $n:expr, $k:expr, $cap_height:expr, $pow:expr, $after:expr) => {{
        type Ch = keccak::LevelChallenger<$base>;
        let config = BinaryPcsConfig::try_new_with_folding::<$base, F>(
            $n,
            BinaryPcsParams {
                log_inv_rate: 1,
                pow_bits: $pow,
                security_level: 8,
            },
            $k,
        )
        .unwrap();
        let protocol = protocol($n, 1);
        let base_mmcs = keccak::LevelMmcs::<$base>::new(
            keccak::FieldHash::new(keccak::byte_hash()),
            keccak::Compress::new(keccak::byte_hash()),
            $cap_height,
        );
        let round_mmcs = keccak::LevelMmcs::<F>::new(
            keccak::FieldHash::new(keccak::byte_hash()),
            keccak::Compress::new(keccak::byte_hash()),
            $cap_height,
        );
        let pcs = BinaryPcs::<$base, F, _, _>::new(config, base_mmcs.clone(), round_mmcs.clone())
            .unwrap();
        let mask = u128::MAX >> (128 - <$base as RecursiveBinaryTowerField>::RAW_BITS);
        // One polynomial per matrix row: a single column of 2^n hypercube evaluations.
        let table = Table::new(RowMajorMatrix::new(
            (0..1usize << $n)
                .map(|i| {
                    <$base>::from_raw_coordinates(
                        0x21bade026a6ae768f2ed66ffdcc99396u128.wrapping_mul(i as u128 + 5) & mask,
                    )
                    .unwrap()
                })
                .collect(),
            1 << $n,
        ));
        let make = || Ch::from_hasher(vec![129, 9, 251], keccak::byte_hash());
        let points = vec![Point::new(
            (0..$n)
                .map(|j| {
                    F::from_repr(
                        0x492f307c9bfa3e514379dc5a1b279591u128.wrapping_mul(j as u128 + 71),
                    )
                })
                .collect(),
        )];
        let mut prover = make();
        let (cap, data) = pcs
            .commit(
                SuffixProver::<$base, F>::new_witness(vec![table], 0),
                &mut prover,
            )
            .unwrap();
        let native = pcs
            .try_open_at(data, &protocol, &points, &mut prover)
            .unwrap();
        let mut native_ch = make();
        pcs.observe_commitment(&cap, &mut native_ch);
        pcs.verify_at(&cap, &native, &protocol, &points, &mut native_ch)
            .unwrap();
        let recursive = BinaryPcsVerifier::<$base, F>::new(
            config,
            protocol.clone(),
            ByteHash::Keccak256,
            $cap_height,
            64,
        )
        .unwrap();
        let shape = recursive.input_shape();
        let mut entry = make();
        pcs.observe_commitment(&cap, &mut entry);
        let imported = recursive
            .import_native(&base_mmcs, &round_mmcs, &cap, &points, &native, entry)
            .unwrap();

        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let cap_targets: Vec<_> = (0..1usize << $cap_height)
            .map(|_| {
                b.alloc_public_input_array::<16>("expected BaseFold commitment")
                    .to_vec()
            })
            .collect();
        let point_targets: Vec<Vec<_>> = points
            .iter()
            .map(|p| p.iter().map(|_| scalar(&mut b)).collect())
            .collect();
        let proof = shape.allocate_native_targets(&mut b).unwrap();
        for eval in &proof.evals {
            for value in eval.current().iter().chain(eval.next()) {
                let expected = scalar(&mut b);
                let difference = b.sub(value.as_expr(), expected.as_expr());
                b.assert_zero(difference);
            }
        }
        let initial = [129, 9, 251].map(|byte| b.define_const(H::encode_u16(byte).unwrap()));
        let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
            &mut b,
            ByteHash::Keccak256,
            &initial,
        )
        .unwrap();
        recursive
            .observe_commitment_with_host::<H, F>(&mut b, &mut ch, &cap_targets)
            .unwrap();
        let continuation = recursive
            .verify_at_native(&mut b, ch, &cap_targets, &point_targets, &proof)
            .unwrap();
        if $after {
            let second = shape.allocate_native_targets(&mut b).unwrap();
            assert!(
                recursive
                    .verify_at_native_after_queries(
                        &mut b,
                        continuation,
                        &cap_targets,
                        &point_targets,
                        &second,
                    )
                    .is_ok()
            );
            // Construction only; the MultiStark verifier tests cover the full
            // preprocessing path.
            return;
        }
        let circuit = b.build().unwrap();
        let private = imported.private_native_values(&shape).unwrap();
        let mut public: Vec<_> = cap
            .roots()
            .iter()
            .flat_map(|root| {
                bytes_to_limbs(root)
                    .into_iter()
                    .map(|w| H::encode_u16(w).unwrap())
            })
            .collect();
        public.extend(points.iter().flat_map(|p| p.iter().copied()));
        let public_evals = public.len();
        public.extend(
            native
                .evals
                .iter()
                .flat_map(|e| e.current().iter().chain(e.next()).copied()),
        );
        assert!(
            run(&circuit, &public, &private),
            "honest opening must verify"
        );

        let o = offsets(&config, &protocol, $cap_height);
        let pcs_shape = BinaryPcsShape::new(&config);
        let bits = pcs_shape.pair_bits;
        assert_eq!(o.queries + pcs_shape.num_pairs * bits, private.len());
        assert!(
            private[o.queries..]
                .iter()
                .all(|&bit| bit == F::ZERO || bit == F::ONE),
            "query index bits are Boolean"
        );
        let tamper = |index: usize, delta: F| {
            let mut wrong = private.clone();
            wrong[index] += delta;
            run(&circuit, &public, &wrong)
        };
        assert!(!tamper(0, F::ONE), "sumcheck message");
        // The statement binding moves with the witness, so only the opening
        // relation can reject the changed evaluation claim.
        let mut claimed = public.clone();
        claimed[public_evals] += F::ONE;
        let mut opened = private.clone();
        opened[o.evals] += F::ONE;
        assert!(!run(&circuit, &claimed, &opened), "opened evaluation");
        let round = o
            .rounds
            .first()
            .expect("every config commits a round oracle");
        assert!(!tamper(round.rows, F::ONE), "round oracle row");
        assert!(!tamper(o.base.rows, F::ONE), "base row");
        assert!(!tamper(o.base.paths, F::ONE), "Merkle sibling word");
        assert!(pcs_shape.final_codeword_len > 1);
        assert!(
            !tamper(o.final_codeword + 1, F::ONE),
            "non-uniform final codeword"
        );
        if $pow == 0 {
            assert!(!tamper(o.pow, F::ONE), "nonzero PoW witness");
        }
        assert!(!tamper(o.queries, F::ONE), "query index bit");
        assert!(pcs_shape.num_pairs > 1);
        // The second query slot receives the first query's index, rows and
        // paths, so every authentication and fold check of that slot holds
        // and only the query index relation can reject.
        let mut duplicate = private.clone();
        duplicate.copy_within(o.queries..o.queries + bits, o.queries + bits);
        for oracle in o.rounds.iter().chain([&o.base]) {
            let paths = oracle.size * oracle.depth * 16;
            duplicate.copy_within(
                oracle.rows..oracle.rows + oracle.size,
                oracle.rows + oracle.size,
            );
            duplicate.copy_within(oracle.paths..oracle.paths + paths, oracle.paths + paths);
        }
        assert!(
            !run(&circuit, &public, &duplicate),
            "duplicated query index"
        );
        let index = |slot: usize| {
            (0..bits).fold(0usize, |acc, bit| {
                acc | usize::from(private[o.queries + slot * bits + bit] == F::ONE) << bit
            })
        };
        assert!(
            index(0) < index(1),
            "honest query slots are strictly sorted"
        );
        // Swapping two whole query slots keeps every per-slot authentication,
        // fold and membership check intact, so only strict ordering can reject.
        let swap = |values: &mut [F], start: usize, len: usize| {
            let (left, right) = values[start..start + 2 * len].split_at_mut(len);
            left.swap_with_slice(right);
        };
        let mut swapped = private.clone();
        swap(&mut swapped, o.queries, bits);
        for oracle in o.rounds.iter().chain([&o.base]) {
            swap(&mut swapped, oracle.rows, oracle.size);
            swap(&mut swapped, oracle.paths, oracle.size * oracle.depth * 16);
        }
        assert!(!run(&circuit, &public, &swapped), "unsorted query indices");
        if <$base as RecursiveBinaryTowerField>::RAW_BITS < 128 {
            let high = F::from_repr(1u128 << <$base as RecursiveBinaryTowerField>::RAW_BITS);
            assert!(!tamper(o.base.rows, high), "base row above its alphabet");
            if $pow > 0 {
                // The witness is observed only through its alphabet's bytes and
                // used nowhere else, so only the width constraint can reject.
                assert!(!tamper(o.pow, high), "PoW witness above its alphabet");
            }
        }
        let mut wrong = public.clone();
        wrong[0] += F::ONE;
        assert!(!run(&circuit, &wrong, &private), "commitment word");
        let other = BinaryPcsVerifier::<$base, F>::new(
            config,
            protocol,
            ByteHash::Keccak256,
            $cap_height,
            65,
        )
        .unwrap();
        assert!(
            imported
                .private_native_values(&other.input_shape())
                .is_err()
        );
    }};
}

#[test]
fn native_basefold_single_variable_folds_bind_every_class() {
    check!(F, 5, 1, 0, 0, false);
}
#[test]
fn native_basefold_batched_folds_with_cap_and_grinding() {
    check!(F, 6, 2, 1, 1, false);
}
#[test]
fn native_basefold_fold_arity_four() {
    check!(F, 8, 4, 0, 0, false);
}
#[test]
fn tower32_basefold_rows_stay_narrow() {
    check!(BinaryField32, 6, 2, 0, 0, false);
}
#[test]
fn tower32_basefold_grinding_witness_stays_narrow() {
    check!(BinaryField32, 6, 2, 0, 1, false);
}
#[test]
fn native_basefold_preprocessing_continuation_is_constructible() {
    check!(F, 5, 1, 0, 0, true);
}
