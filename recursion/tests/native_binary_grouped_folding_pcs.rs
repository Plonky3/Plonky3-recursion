//! Grouped (`for_folding`) BaseFold openings verified in the exact native
//! Tower128 carrier, each fold coset hashed as one Merkle leaf.

use p3_binary_field::{BinaryField8, BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::transcript::BinaryPcsShape;
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, GroupedCodewordMmcs};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, NativeTower128Target, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError, NpoTypeId};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryCodewordGrouping, BinaryGroupedPcsVerifier, RecursiveBinaryTowerField,
};
use p3_recursion::verifier::VerificationError;
use p3_sumcheck::layout::{Layout, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::keccak;

type F = BinaryField128;
type H = NativeBinaryEncoding;
use BinaryCodewordGrouping::{Codeword, Folding, Message};

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
fn native_builder() -> CircuitBuilder<F> {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    b
}
const fn params(log_inv_rate: usize) -> BinaryPcsParams {
    BinaryPcsParams {
        log_inv_rate,
        pow_bits: 0,
        security_level: 8,
    }
}

/// Private-input offsets of one oracle: `size` coset rows per query, then
/// one path of `path_words` words per query, the siblings above the grouped
/// coset leaf. A round oracle's cap precedes its rows.
struct Oracle {
    cap: Option<usize>,
    rows: usize,
    paths: usize,
    size: usize,
    path_words: usize,
}

/// Private-input offsets of each witness class, in `allocate_native_targets` order.
struct Offsets {
    rounds: Vec<Oracle>,
    base: Oracle,
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
    let mut cursor = 2 * n + claims;
    let oracle = |cursor: &mut usize, start: usize, arity: usize, cap: Option<usize>| {
        let size = 1usize << arity;
        // The grouped tree has one leaf per coset: 2^(log_domain - start - arity) leaves.
        let path_words = 16 * (log_domain - start - arity - cap_height);
        let rows = *cursor;
        *cursor += shape.num_pairs * size;
        let paths = *cursor;
        *cursor += shape.num_pairs * path_words;
        Oracle {
            cap,
            rows,
            paths,
            size,
            path_words,
        }
    };
    let mut rounds = Vec::new();
    let mut start = k;
    while start < n {
        let arity = k.min(n - start);
        let cap = cursor;
        cursor += 16 << cap_height;
        rounds.push(oracle(&mut cursor, start, arity, Some(cap)));
        start += k;
    }
    let base = oracle(&mut cursor, 0, k, None);
    cursor += shape.final_codeword_len + 1;
    Offsets {
        rounds,
        base,
        queries: cursor,
    }
}

macro_rules! check {
    ($base:ty, $n:expr, $k:expr, $log_inv_rate:expr, $cap_height:expr) => {{
        type Ch = keccak::LevelChallenger<$base>;
        let config =
            BinaryPcsConfig::try_new_with_folding::<$base, F>($n, params($log_inv_rate), $k)
                .unwrap();
        let protocol = protocol($n, 1);
        let base_tree = keccak::LevelMmcs::<$base>::new(
            keccak::FieldHash::new(keccak::byte_hash()),
            keccak::Compress::new(keccak::byte_hash()),
            $cap_height,
        );
        let round_tree = keccak::LevelMmcs::<F>::new(
            keccak::FieldHash::new(keccak::byte_hash()),
            keccak::Compress::new(keccak::byte_hash()),
            $cap_height,
        );
        let pcs = BinaryPcs::<$base, F, _, _>::new(
            config,
            GroupedCodewordMmcs::for_folding(base_tree.clone(), &config),
            GroupedCodewordMmcs::for_folding(round_tree.clone(), &config),
        )
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
        let recursive = BinaryGroupedPcsVerifier::<$base, F>::new(
            config,
            protocol.clone(),
            ByteHash::Keccak256,
            $cap_height,
            64,
            Folding,
            Folding,
        )
        .unwrap();
        let shape = recursive.input_shape();
        let mut entry = make();
        pcs.observe_commitment(&cap, &mut entry);
        let imported = recursive
            .import_native(&base_tree, &round_tree, &cap, &points, &native, &mut entry)
            .unwrap();

        let mut b = native_builder();
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
        let allocated = b.private_input_count();
        recursive
            .check_native_targets(&cap_targets, &point_targets, &proof)
            .unwrap();
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
        recursive
            .verify_at_native(&mut b, ch, &cap_targets, &point_targets, &proof)
            .unwrap();
        assert_eq!(b.private_input_count(), allocated);
        let circuit = b.build().unwrap();
        let private = imported.private_native_values(&shape).unwrap();
        assert_eq!(private.len(), allocated, "packing matches allocation");
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
        public.extend(
            native
                .evals
                .iter()
                .flat_map(|e| e.current().iter().chain(e.next()).copied()),
        );
        assert!(
            run(&circuit, &public, &private),
            "honest grouped opening must verify"
        );

        let o = offsets(&config, &protocol, $cap_height);
        let pcs_shape = BinaryPcsShape::new(&config);
        assert_eq!(
            o.queries + pcs_shape.num_pairs * pcs_shape.pair_bits,
            private.len(),
            "the layout model matches the packed private values"
        );
        let tamper = |index: usize, delta: F| {
            let mut wrong = private.clone();
            wrong[index] += delta;
            run(&circuit, &public, &wrong)
        };
        let round = o
            .rounds
            .last()
            .expect("every config commits a round oracle");
        assert!(
            !tamper(round.rows + round.size - 1, F::ONE),
            "round row at the coset's last offset"
        );
        assert!(o.base.size > 5);
        assert!(!tamper(o.base.rows + 5, F::ONE), "base row at offset 5");
        assert_ne!(private[o.base.rows + 1], private[o.base.rows + 2]);
        let mut swapped = private.clone();
        swapped.swap(o.base.rows + 1, o.base.rows + 2);
        assert!(
            !run(&circuit, &public, &swapped),
            "two distinct symbols swapped within one coset"
        );
        assert!(o.base.path_words > 0);
        assert!(
            !tamper(o.base.paths + o.base.path_words - 1, F::ONE),
            "base upper sibling word"
        );
        for round in o.rounds.iter().filter(|r| r.path_words > 0) {
            assert!(!tamper(round.paths, F::ONE), "round upper sibling word");
        }
        let round_cap = round.cap.expect("round oracles carry a cap");
        assert!(!tamper(round_cap, F::ONE), "round cap root word");
        let mut wrong = public.clone();
        wrong[0] += F::ONE;
        assert!(!run(&circuit, &wrong, &private), "commitment cap root word");
        let other = BinaryGroupedPcsVerifier::<$base, F>::new(
            config,
            protocol,
            ByteHash::Keccak256,
            $cap_height,
            65,
            Folding,
            Folding,
        )
        .unwrap();
        assert!(
            imported
                .private_native_values(&other.input_shape())
                .is_err()
        );
        o
    }};
}

#[test]
fn grouped_tower128_cosets_hash_as_single_leaves() {
    let o = check!(F, 8, 4, 1, 0);
    assert!(o.rounds.iter().all(|r| r.path_words > 0));
}
#[test]
fn grouped_tower32_base_cosets_hash_as_single_leaves() {
    check!(BinaryField32, 8, 4, 1, 0);
}
#[test]
fn grouped_tower8_base_cosets_pack_bytes_across_symbols() {
    // A Tower8 codeword fits at most 2^8 symbols.
    check!(BinaryField8, 6, 4, 1, 0);
}
#[test]
fn grouped_short_last_batch_hashes_its_narrower_coset() {
    // Arity-4 folds over six variables leave a final arity-2 batch.
    let o = check!(F, 6, 4, 1, 0);
    assert_eq!(o.rounds.last().unwrap().size, 4);
}
#[test]
fn grouped_cap_at_log_inv_rate_leaves_an_empty_round_path() {
    // The last grouped tree has 2^log_inv_rate leaves, all of them cap roots:
    // its path is empty and the query bits only select a cap root.
    let o = check!(F, 8, 4, 1, 1);
    assert_eq!(o.rounds.last().unwrap().path_words, 0);
}

#[test]
fn grouped_native_support_checks_every_site_size_and_the_cap() {
    // Arity-4 folds over six variables leave a final arity-2 batch.
    let config = BinaryPcsConfig::try_new_with_folding::<F, F>(6, params(1), 4).unwrap();
    let make = |hash, cap_height, base, rounds| {
        BinaryGroupedPcsVerifier::<F, F>::new(
            config,
            protocol(6, 1),
            hash,
            cap_height,
            64,
            base,
            rounds,
        )
    };
    let shape_error =
        |error: &VerificationError| matches!(error, VerificationError::InvalidProofShape(_));
    // The last grouped tree has 2^log_inv_rate leaves, so a larger cap is
    // rejected before any native tree could be built.
    let error = make(ByteHash::Keccak256, 2, Folding, Folding).unwrap_err();
    assert!(shape_error(&error), "{error}");

    let twin = make(ByteHash::Keccak256, 0, Folding, Folding).unwrap();
    // Inputs shaped by the one-leaf-per-coset twin.
    let twin_inputs = |b: &mut CircuitBuilder<F>| {
        let cap = vec![b.alloc_public_input_array::<16>("cap").to_vec()];
        let points = vec![(0..6).map(|_| scalar(b)).collect::<Vec<_>>()];
        let targets = twin.input_shape().allocate_native_targets(b).unwrap();
        let ch = BinaryTower128Challenger::new(ByteHash::Keccak256);
        (cap, points, targets, ch)
    };
    let reject = |verifier: &BinaryGroupedPcsVerifier<F, F>,
                  expected: &dyn Fn(&VerificationError) -> bool| {
        let mut b = native_builder();
        let error = verifier
            .input_shape()
            .allocate_native_targets(&mut b)
            .unwrap_err();
        assert!(expected(&error), "{error}");
        assert_eq!(b.private_input_count(), 0);
        let (cap, points, targets, ch) = twin_inputs(&mut b);
        let usage = b.construction_usage().unwrap();
        let error = verifier
            .verify_at_native(&mut b, ch, &cap, &points, &targets)
            .unwrap_err();
        assert!(expected(&error), "{error}");
        assert_eq!(b.construction_usage().unwrap(), usage);
    };
    // Codeword(16) is the full coset at the base but twice the short final
    // coset; Message(8) is half the base coset.
    for (base, rounds) in [(Folding, Codeword(16)), (Message(8), Folding)] {
        let verifier = make(ByteHash::Keccak256, 0, base, rounds).unwrap();
        reject(&verifier, &shape_error);
        let mut b = native_builder();
        let (cap, points, targets, _) = twin_inputs(&mut b);
        let error = verifier
            .check_native_targets(&cap, &points, &targets)
            .unwrap_err();
        assert!(shape_error(&error), "{error}");
    }
    // The native host evaluates Blake3, so its targets allocate, while its
    // openings need the native Blake3 compression the builder does not allow.
    let blake3 = make(ByteHash::Blake3, 0, Folding, Folding).unwrap();
    let mut b = native_builder();
    let (cap, points, _, ch) = twin_inputs(&mut b);
    let targets = blake3
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap();
    let error = blake3
        .verify_at_native(&mut b, ch, &cap, &points, &targets)
        .unwrap_err();
    assert!(
        matches!(
            &error,
            VerificationError::CircuitBuilder(CircuitBuilderError::OpNotAllowed { op })
                if *op == NpoTypeId::native_blake3_compress()
        ),
        "{error}"
    );
    // The effective size decides, not the policy: these are exactly the cosets.
    let equivalent = make(ByteHash::Keccak256, 0, Codeword(16), Message(16)).unwrap();
    let mut b = native_builder();
    let (cap, points, targets, ch) = twin_inputs(&mut b);
    equivalent
        .check_native_targets(&cap, &points, &targets)
        .unwrap();
    let continuation = equivalent
        .verify_at_native(&mut b, ch, &cap, &points, &targets)
        .unwrap();
    let second = equivalent
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap();
    // Construction only, as for the ungrouped preprocessing continuation.
    equivalent
        .verify_at_native_after_queries(&mut b, continuation, &cap, &points, &second)
        .unwrap();
}

#[test]
fn grouped_native_packing_rejects_imports_of_wider_groups() {
    type Ch = keccak::LevelChallenger<F>;
    // The final arity-2 coset sits inside a 16-symbol Codeword(16) leaf.
    let config = BinaryPcsConfig::try_new_with_folding::<F, F>(6, params(1), 4).unwrap();
    let protocol = protocol(6, 1);
    let tree = keccak::LevelMmcs::<F>::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        0,
    );
    let pcs = BinaryPcs::<F, F, _, _>::new(
        config,
        GroupedCodewordMmcs::new(tree.clone(), 16),
        GroupedCodewordMmcs::new(tree.clone(), 16),
    )
    .unwrap();
    let table = Table::new(RowMajorMatrix::new(
        (0..64u128)
            .map(|i| F::from_repr(0x9e3779b97f4a7c15f39cc0605cedc834u128.wrapping_mul(i + 1)))
            .collect(),
        64,
    ));
    let make = || Ch::from_hasher(vec![3, 1, 4], keccak::byte_hash());
    let points = vec![Point::new(
        (0..6).map(|j| F::from_repr(0x1234 + j as u128)).collect(),
    )];
    let mut prover = make();
    let (cap, data) = pcs
        .commit(
            SuffixProver::<F, F>::new_witness(vec![table], 0),
            &mut prover,
        )
        .unwrap();
    let native = pcs
        .try_open_at(data, &protocol, &points, &mut prover)
        .unwrap();
    let verifier = BinaryGroupedPcsVerifier::<F, F>::new(
        config,
        protocol,
        ByteHash::Keccak256,
        0,
        64,
        Codeword(16),
        Codeword(16),
    )
    .unwrap();
    let mut entry = make();
    pcs.observe_commitment(&cap, &mut entry);
    let imported = verifier
        .import_native(&tree, &tree, &cap, &points, &native, &mut entry)
        .unwrap();
    let error = imported
        .private_native_values(&verifier.input_shape())
        .unwrap_err();
    assert!(
        matches!(error, VerificationError::InvalidProofShape(_)),
        "{error}"
    );
}
