//! Full additive WHIR openings verified in the exact native Tower128 carrier.

use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NativeTower128Target, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{BinaryWhirVerifier, MerkleArity};
use p3_recursion::verifier::VerifierLimits;
use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_symmetric::CompressionFunctionFromHasher;
use p3_test_utils::binary_field_params::{blake3, keccak};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

use crate::native_bus_circuit::{
    reject_flipped_grinding_bits, reject_wide_grinding_word, tower_accepts,
};

type F = BinaryField128;
type H = NativeBinaryEncoding;
fn scalar(b: &mut CircuitBuilder<F>) -> NativeTower128Target {
    let expression = b.public_input();
    b.native_tower128_from_expr(expression)
}
fn bind(b: &mut CircuitBuilder<F>, actual: &NativeTower128Target) {
    let expected = scalar(b);
    let difference = b.sub(actual.as_expr(), expected.as_expr());
    b.assert_zero(difference);
}
fn run(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}
fn protocol(rows: usize, width: usize, next: bool) -> OpeningProtocol {
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(rows, width),
        vec![OpeningBatch::new(
            (0..width).collect(),
            if next { vec![width - 1] } else { vec![] },
        )],
    )])
}

macro_rules! check {
    ($base:ty, $layout:ident, $protocol:expr, $cap_height:expr, $pow:expr) => {
        check!($base, $layout, $protocol, $cap_height, $pow, 2)
    };
    ($base:ty, $layout:ident, $protocol:expr, $cap_height:expr, $pow:expr, $folding:expr) => {
        check!($base, $layout, $protocol, $cap_height, $pow, $folding, 8)
    };
    (
        $base:ty,
        $layout:ident,
        $protocol:expr,
        $cap_height:expr,
        $pow:expr,
        $folding:expr,
        $security:expr
    ) => {
        check!($base, $layout, $protocol, $cap_height, $pow, $folding, $security, Two, 2)
    };
    (
        $base:ty,
        $layout:ident,
        $protocol:expr,
        $cap_height:expr,
        $pow:expr,
        $folding:expr,
        $security:expr,
        $arity:ident,
        $digests:literal
    ) => {
        check!(
            $base, $layout, $protocol, $cap_height, $pow, $folding, $security, $arity, $digests,
            keccak, Keccak256
        )
    };
    (
        $base:ty,
        $layout:ident,
        $protocol:expr,
        $cap_height:expr,
        $pow:expr,
        $folding:expr,
        $security:expr,
        $arity:ident,
        $digests:literal,
        $hash:ident,
        $byte_hash:ident
    ) => {{
        type Ch = $hash::LevelChallenger<$base>;
        type L = $layout<$base, F>;
        let protocol = $protocol;
        let n = p3_sumcheck::layout::plan_stacked_layout(&protocol.table_shapes()).0;
        let domain = BinaryWhirDomain::<$base>::default();
        let config = WhirConfig::<F, $base, Ch>::new_with_domain(
            n,
            ProtocolParameters {
                security_level: $security,
                pow_bits: $pow,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant($folding),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            &domain,
        )
        .unwrap();
        let arity = MerkleArity::$arity;
        let mmcs = MerkleTreeMmcs::<
            $base,
            u8,
            $hash::FieldHash,
            CompressionFunctionFromHasher<$hash::ByteHash, $digests, 32>,
            $digests,
            32,
        >::new(
            $hash::FieldHash::new($hash::byte_hash()),
            CompressionFunctionFromHasher::new($hash::byte_hash()),
            $cap_height,
        );
        let pcs = WhirProver::<F, $base, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
        let recursive = BinaryWhirVerifier::<$base>::with_limits(
            &config,
            protocol.clone(),
            L::variable_order(),
            ByteHash::$byte_hash,
            arity,
            $cap_height,
            &VerifierLimits::default(),
        )
        .unwrap();
        let shape = recursive.input_shape();
        let make = || Ch::from_hasher(vec![129, 9, 251], $hash::byte_hash());
        let dense = |i: usize| {
            F::from_repr(0x492f307c9bfa3e514379dc5a1b279591u128.wrapping_mul(i as u128 + 13))
        };
        let tables = protocol
            .table_shapes()
            .iter()
            .enumerate()
            .map(|(table, shape)| {
                Table::new(RowMajorMatrix::new(
                    (0..shape.width() * (1 << shape.num_variables()))
                        .map(|i| {
                            let raw = dense(i + 17 * table).to_repr();
                            let bits = <$base as p3_recursion::pcs::binary::RecursiveBinaryTowerField>::RAW_BITS;
                            <$base as p3_circuit::ops::binary_native::BinaryCoordinateField>::from_raw_coordinates(raw & (u128::MAX >> (128 - bits))).unwrap()
                        })
                        .collect(),
                    1 << shape.num_variables(),
                ))
            })
            .collect();
        let witness = L::new_witness(tables, config.round_folding_factor(0));
        let points: Vec<_> = protocol
            .iter_openings()
            .enumerate()
            .map(|(opening, (table, _))| {
                Point::new(
                    (0..protocol.table_shapes()[table].num_variables())
                        .map(|j| dense(j + 23 * opening + 71))
                        .collect(),
                )
            })
            .collect();
        let mut prover = make();
        let (commitment, data) = pcs.commit(witness, &mut prover).unwrap();
        let native = pcs.open_at(data, &protocol, &points, &mut prover).unwrap();
        let mut native_ch = make();
        pcs.observe_commitment(&commitment, &mut native_ch);
        pcs.verify_at(&commitment, &native, &protocol, &points, &mut native_ch)
            .unwrap();
        let mut entry = make();
        pcs.observe_commitment(&commitment, &mut entry);
        let imported = recursive
            .import_native(&config, &mmcs, &commitment, &points, &native, &mut entry)
            .unwrap();
        let next = native_ch.sample_algebra_element::<F>();
        assert_eq!(next, entry.sample_algebra_element::<F>());
        // A verifier of the other arity refuses the tree, when its cap fits.
        let other_arity = match arity {
            MerkleArity::Two => MerkleArity::Four,
            MerkleArity::Four => MerkleArity::Two,
        };
        if let Ok(foreign) = BinaryWhirVerifier::<$base>::with_limits(
            &config,
            protocol.clone(),
            L::variable_order(),
            ByteHash::$byte_hash,
            other_arity,
            $cap_height,
            &VerifierLimits::default(),
        ) {
            let mut unchanged = make();
            pcs.observe_commitment(&commitment, &mut unchanged);
            assert!(
                foreign
                    .import_native(&config, &mmcs, &commitment, &points, &native, &mut unchanged)
                    .is_err()
            );
        }
        // Restoration happens after transcript replay; failures must roll back.
        for oversized in [false, true] {
            let mut malformed = native.clone();
            let frontier = match &mut malformed.whir.final_openings {
                p3_whir::pcs::proof::QueryOpenings::Base(opening) => &mut opening.proof.sibling_hashes,
                p3_whir::pcs::proof::QueryOpenings::Extension(opening) => &mut opening.proof.sibling_hashes,
            };
            if !oversized && frontier.is_empty() { continue; }
            if oversized { frontier.resize(4096, [0; 32]); } else { frontier.clear(); }
            let mut unchanged = make(); pcs.observe_commitment(&commitment, &mut unchanged);
            let mut before = unchanged.clone();
            assert!(recursive.import_native(&config, &mmcs, &commitment, &points, &malformed, &mut unchanged).is_err());
            assert_eq!(unchanged.sample_algebra_element::<F>(), before.sample_algebra_element::<F>());
        }
        let mut b = CircuitBuilder::<F>::new();
        match ByteHash::$byte_hash {
            ByteHash::Keccak256 => b.enable_native_keccak_f1600().unwrap(),
            ByteHash::Blake3 => b.enable_native_blake3_compress().unwrap(),
        }
        let cap: Vec<_> = (0..arity.cap_roots($cap_height).unwrap())
            .map(|_| {
                b.alloc_public_input_array::<16>("expected WHIR commitment")
                    .to_vec()
            })
            .collect();
        let point_targets: Vec<Vec<_>> = points
            .iter()
            .map(|point| point.iter().map(|_| scalar(&mut b)).collect())
            .collect();
        let proof = shape.allocate_native_targets(&mut b).unwrap();
        let initial = [129, 9, 251].map(|byte| b.define_const(H::encode_u16(byte).unwrap()));
        let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
            &mut b,
            ByteHash::$byte_hash,
            &initial,
        )
        .unwrap();
        recursive
            .observe_commitment_with_host::<H, F>(&mut b, &mut ch, &cap)
            .unwrap();
        let (evals, mut ch) = recursive
            .verify_at_native(&mut b, ch, &cap, &point_targets, &proof)
            .unwrap();
        for eval in &evals {
            for value in eval.current().iter().chain(eval.next()) {
                bind(&mut b, value);
            }
        }
        let bits = ch.sample_with_host::<H, F>(&mut b).unwrap();
        let actual = b.native_tower128_from_bits(*bits.bits()).unwrap();
        bind(&mut b, &actual);
        let circuit = b.build().unwrap();
        let private = imported.private_native_values(&shape).unwrap();
        let mut public: Vec<_> = commitment
            .roots()
            .iter()
            .flat_map(|root| {
                bytes_to_limbs(root)
                    .into_iter()
                    .map(|word| H::encode_u16(word).unwrap())
            })
            .collect();
        public.extend(points.iter().flat_map(|point| point.iter().copied()));
        public.extend(
            native
                .evals
                .iter()
                .flat_map(|eval| eval.current().iter().chain(eval.next()).copied()),
        );
        public.push(next);
        assert!(run(&circuit, &public, &private));
        for index in [
            0,
            arity.cap_roots($cap_height).unwrap() * 16,
            public.len() - 2,
            public.len() - 1,
        ] {
            let mut wrong = public.clone();
            wrong[index] += F::ONE;
            assert!(!run(&circuit, &wrong, &private));
        }
        for index in [0, protocol.checked_num_claims().unwrap(), private.len() - 1] {
            let mut wrong = private.clone();
            wrong[index] += F::ONE;
            assert!(!run(&circuit, &public, &wrong));
        }
        // A zero-bit site pins its grinding witness to zero; any other site
        // observes it before the next draw, which the closing sample binds.
        let sumchecks = std::iter::once(&proof.initial_sumcheck)
            .chain(proof.rounds.iter().map(|round| &round.sumcheck))
            .chain([&proof.final_sumcheck]);
        let pow_witnesses = proof
            .rounds
            .iter()
            .map(|round| &round.pow_witness)
            .chain([&proof.final_pow_witness])
            .chain(sumchecks.flat_map(|sumcheck| &sumcheck.pow_witnesses));
        let mut pow_rows = Vec::new();
        for witness in pow_witnesses {
            let row = circuit.expr_to_widx[&witness.as_expr()];
            let index = circuit
                .private_input_rows
                .iter()
                .position(|&private_row| private_row == row)
                .unwrap();
            let mut wrong = private.clone();
            wrong[index] += F::ONE;
            assert!(!run(&circuit, &public, &wrong));
            pow_rows.push(row);
        }
        // Every site binds the first and last sibling of its paths to the cap.
        // A four-digest tree of odd height under a zero cap pads its top group
        // with two default digests, the last siblings of each of its paths.
        let private_index = |limb: &p3_circuit::ExprId| {
            let row = circuit.expr_to_widx[limb];
            circuit
                .private_input_rows
                .iter()
                .position(|&private_row| private_row == row)
                .unwrap()
        };
        let whir_shape = p3_whir::transcript::WhirShape::new(&config, protocol.num_openings());
        assert_eq!(whir_shape.rounds.len(), proof.rounds.len());
        let site_bits = whir_shape
            .rounds
            .iter()
            .map(|round| round.index_bits)
            .chain([whir_shape.final_index_bits]);
        let site_paths = proof
            .rounds
            .iter()
            .map(|round| &round.paths)
            .chain([&proof.final_paths]);
        let mut padded_sites = 0;
        for (bits, paths) in site_bits.zip(site_paths) {
            let path = &paths[0];
            if arity == MerkleArity::Four && bits % 2 == 1 && $cap_height == 0 {
                let default = path.last().unwrap();
                assert!(default.iter().all(|limb| private[private_index(limb)] == F::ZERO));
                padded_sites += 1;
            }
            for digest in [path.first(), path.last()].into_iter().flatten() {
                let mut wrong = private.clone();
                wrong[private_index(&digest[0])] += F::ONE;
                assert!(!run(&circuit, &public, &wrong));
            }
        }
        let other = BinaryWhirVerifier::<$base>::with_limits(
            &config,
            protocol,
            if L::variable_order() == p3_sumcheck::strategy::VariableOrder::Prefix {
                p3_sumcheck::strategy::VariableOrder::Suffix
            } else {
                p3_sumcheck::strategy::VariableOrder::Prefix
            },
            ByteHash::$byte_hash,
            arity,
            $cap_height,
            &VerifierLimits::default(),
        )
        .unwrap();
        assert!(
            imported
                .private_native_values(&other.input_shape())
                .is_err()
        );
        (circuit, config, padded_sites, (public, private, pow_rows))
    }};
}

#[test]
fn native_initial_and_closing_folds_bind_prefix_openings() {
    check!(F, PrefixProver, protocol(3, 1, false), 0, 0);
}
#[test]
fn native_intermediate_rounds_and_grinding_bind_suffix_successors() {
    check!(F, SuffixProver, protocol(9, 1, true), 0, 2);
}
#[test]
fn native_mixed_height_and_column_batches_bind_every_prescribed_reading() {
    let protocol = OpeningProtocol::new(vec![
        TableSpec::new(
            TableShape::new(4, 2),
            vec![
                OpeningBatch::new(vec![1], vec![0, 1]),
                OpeningBatch::new(vec![1, 0], vec![]),
            ],
        ),
        TableSpec::new(
            TableShape::new(6, 1),
            vec![OpeningBatch::new(vec![0], vec![])],
        ),
        TableSpec::new(TableShape::new(3, 1), vec![]),
    ]);
    check!(F, SuffixProver, protocol, 0, 0);
}
#[test]
fn native_zero_closing_rounds_and_leaf_caps_preserve_transcript() {
    check!(F, SuffixProver, protocol(2, 1, true), 1, 0);
}

#[test]
fn tower32_whir_keeps_base_rows_narrow_and_challenges_wide() {
    check!(BinaryField32, SuffixProver, protocol(2, 2, true), 0, 1);
}

/// Folding four variables opens sixteen-value rows: a Tower128 row is a
/// 256-byte leaf hashed over two Keccak blocks, a Tower32 base row a
/// 64-byte leaf. Hashing rows as sixteen-bit words, these verifiers take
/// 44,288 and 37,433 witnesses, against 182,912 and 77,561 when every value
/// is split into checked bytes; the bounds sit about 25% above the former.
#[test]
fn native_sixteen_value_rows_authenticate_as_word_leaves() {
    let (tower128, _, _, _) = check!(F, SuffixProver, protocol(9, 1, true), 0, 0, 4);
    assert!(tower128.witness_count <= 55_000);
    let (tower32, _, _, _) = check!(BinaryField32, PrefixProver, protocol(9, 1, false), 0, 0, 4);
    assert!(tower32.witness_count <= 47_000);
}

/// Four-digest nodes open each query along half as many levels, three siblings
/// a level. Folding two variables at a time from a ten-bit domain leaves trees
/// of even and odd heights, whose top level pads two children with default
/// digests; a one-level cap holds four roots.
#[test]
fn native_arity_four_trees_bind_every_query_at_even_and_odd_heights() {
    let (_, _, padded_sites, _) =
        check!(F, SuffixProver, protocol(9, 1, true), 0, 2, 2, 8, Four, 4);
    assert!(padded_sites > 0);
    check!(F, PrefixProver, protocol(9, 1, false), 1, 0, 2, 8, Four, 4);
    check!(
        BinaryField32,
        SuffixProver,
        protocol(9, 2, true),
        1,
        1,
        4,
        8,
        Four,
        4
    );
}

/// Grinding twelve of sixteen security bits puts more than eight bits on
/// some site, which draws them from two sampled bytes; the cases above stay
/// within the first byte.
#[test]
fn native_grinding_beyond_one_sampled_byte_binds_every_witness() {
    let (_, config, _, _) = check!(F, SuffixProver, protocol(9, 1, true), 0, 12, 2, 16);
    assert!(config.max_pow_bits() > 8);
}

/// A site that grinds observes its witness as the unchecked sixteen-bit words
/// of its base width, which the refill of the draw after it range-checks as
/// Keccak lanes. The runner refuses a flipped witness bit under Tower128 and
/// Tower32. Moving coordinate 32 of the witness into its second word keeps the
/// absorbed bytes; under Tower128 the forged witness stays in the base field
/// but differs from the one the bytes encode, and under Tower32 it leaves the
/// base field. Only the lane range check refuses either.
#[test]
fn native_grinding_witness_words_refuse_a_flipped_bit_and_a_wide_word() {
    let (circuit, _, _, (public, private, pow_rows)) =
        check!(F, PrefixProver, protocol(3, 1, false), 0, 2);
    reject_flipped_grinding_bits(&circuit, &public, &private, &pow_rows, 128);
    reject_wide_grinding_word(
        &circuit,
        &public,
        &private,
        &pow_rows,
        128,
        (1, 32),
        tower_accepts,
    );
    let (circuit, _, _, (public, private, pow_rows)) =
        check!(BinaryField32, PrefixProver, protocol(3, 1, false), 0, 2);
    reject_flipped_grinding_bits(&circuit, &public, &private, &pow_rows, 32);
    reject_wide_grinding_word(
        &circuit,
        &public,
        &private,
        &pow_rows,
        32,
        (1, 32),
        tower_accepts,
    );
}

/// Under BLAKE3 the refill absorbs each word of a Tower32 grinding witness as
/// a block word of a native compression. The runner refuses a flipped witness
/// bit, and moving coordinate 32 of the witness into its second word, which
/// keeps the absorbed bytes and leaves the base field, is refused only by the
/// compression's range check of that block word.
#[test]
fn native_blake3_grinding_witness_words_refuse_a_flipped_bit_and_a_wide_word() {
    let (circuit, _, _, (public, private, pow_rows)) = check!(
        BinaryField32,
        PrefixProver,
        protocol(3, 1, false),
        0,
        2,
        2,
        8,
        Two,
        2,
        blake3,
        Blake3
    );
    reject_flipped_grinding_bits(&circuit, &public, &private, &pow_rows, 32);
    reject_wide_grinding_word(
        &circuit,
        &public,
        &private,
        &pow_rows,
        32,
        (1, 32),
        tower_accepts,
    );
}

type Ch = keccak::LevelChallenger<F>;

/// Grinds honestly except at one site, where it writes a witness short of its
/// zero bits and still absorbs it, so the transcript continues from it as from
/// an honest one. Its witness checks absorb without judging the witness.
#[derive(Clone)]
struct ShortGrind {
    inner: Ch,
    short: Option<usize>,
    sites: usize,
}
impl<T> CanObserve<T> for ShortGrind
where
    Ch: CanObserve<T>,
{
    fn observe(&mut self, value: T) {
        self.inner.observe(value);
    }
}
impl<T> CanSample<T> for ShortGrind
where
    Ch: CanSample<T>,
{
    fn sample(&mut self) -> T {
        self.inner.sample()
    }
}
impl CanSampleBits<usize> for ShortGrind {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}
impl CanSampleUniformBits<F> for ShortGrind {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        self.inner.sample_uniform_bits::<RESAMPLE>(bits)
    }
}
impl FieldChallenger<F> for ShortGrind {}
impl GrindingChallenger for ShortGrind {
    type Witness = F;
    fn grind(&mut self, bits: usize) -> F {
        let site = self.sites;
        self.sites += 1;
        if self.short != Some(site) {
            return self.inner.grind(bits);
        }
        let witness = (0..)
            .map(F::from_repr)
            .find(|&witness| !self.inner.clone().check_witness(bits, witness))
            .unwrap();
        assert!(!self.inner.check_witness(bits, witness));
        witness
    }
    fn check_witness(&mut self, bits: usize, witness: F) -> bool {
        let _ = self.inner.check_witness(bits, witness);
        true
    }
}

/// A witness short of its zero bits, followed by an honest continuation of
/// the transcript, leaves every later draw, fold and opening consistent: the
/// native verifier accepts it once witness checks are waived. Only the
/// circuit's check that the bits drawn after the witness are zero refuses it.
#[test]
fn native_grinding_check_alone_refuses_a_witness_short_of_its_bits() {
    type L = SuffixProver<F, F>;
    let protocol = protocol(9, 1, true);
    let n = p3_sumcheck::layout::plan_stacked_layout(&protocol.table_shapes()).0;
    let domain = BinaryWhirDomain::<F>::default();
    let config = WhirConfig::<F, F, ShortGrind>::new_with_domain(
        n,
        ProtocolParameters {
            security_level: 8,
            pow_bits: 2,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(2),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        &domain,
    )
    .unwrap();
    let mmcs = keccak::mmcs();
    let pcs = WhirProver::<F, F, _, _, ShortGrind, L>::new(config.clone(), domain, mmcs.clone());
    let recursive = BinaryWhirVerifier::<F>::new(
        &config,
        protocol.clone(),
        L::variable_order(),
        ByteHash::Keccak256,
        0,
    )
    .unwrap();
    let shape = recursive.input_shape();
    let make = |short| ShortGrind {
        inner: Ch::from_hasher(vec![129, 9, 251], keccak::byte_hash()),
        short,
        sites: 0,
    };
    let dense = |i: usize| {
        F::from_repr(0x492f307c9bfa3e514379dc5a1b279591u128.wrapping_mul(i as u128 + 13))
    };
    let table = Table::new(RowMajorMatrix::new(
        (0..1 << 9).map(dense).collect(),
        1 << 9,
    ));
    let points = vec![Point::new((0..9).map(|j| dense(j + 71)).collect())];

    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap = vec![
        b.alloc_public_input_array::<16>("expected WHIR commitment")
            .to_vec(),
    ];
    let point_targets: Vec<Vec<_>> = vec![(0..9).map(|_| scalar(&mut b)).collect()];
    let targets = shape.allocate_native_targets(&mut b).unwrap();
    let initial = [129, 9, 251].map(|byte| b.define_const(H::encode_u16(byte).unwrap()));
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
        &mut b,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    recursive
        .observe_commitment_with_host::<H, F>(&mut b, &mut ch, &cap)
        .unwrap();
    let (evals, mut ch) = recursive
        .verify_at_native(&mut b, ch, &cap, &point_targets, &targets)
        .unwrap();
    for value in evals
        .iter()
        .flat_map(|eval| eval.current().iter().chain(eval.next()))
    {
        bind(&mut b, value);
    }
    let bits = ch.sample_with_host::<H, F>(&mut b).unwrap();
    let actual = b.native_tower128_from_bits(*bits.bits()).unwrap();
    bind(&mut b, &actual);
    let circuit = b.build().unwrap();

    // Proves with the witness at `short` short of its bits, verifies natively
    // with witness checks waived, and runs the circuit on the result.
    let accepts = |short| {
        let witness = L::new_witness(vec![table.clone()], config.round_folding_factor(0));
        let mut prover = make(short);
        let (commitment, data) = pcs.commit(witness, &mut prover).unwrap();
        let proof = pcs.open_at(data, &protocol, &points, &mut prover).unwrap();
        let mut native = make(None);
        pcs.observe_commitment(&commitment, &mut native);
        pcs.verify_at(&commitment, &proof, &protocol, &points, &mut native)
            .unwrap();
        let mut entry = make(None);
        pcs.observe_commitment(&commitment, &mut entry);
        let imported = recursive
            .import_native(&config, &mmcs, &commitment, &points, &proof, &mut entry)
            .unwrap();
        let mut public: Vec<_> = bytes_to_limbs(&commitment.roots()[0])
            .into_iter()
            .map(|word| H::encode_u16(word).unwrap())
            .collect();
        public.extend(points[0].iter().copied());
        public.extend(
            proof
                .evals
                .iter()
                .flat_map(|eval| eval.current().iter().chain(eval.next()).copied()),
        );
        public.push(native.sample_algebra_element::<F>());
        let private = imported.private_native_values(&shape).unwrap();
        (run(&circuit, &public, &private), prover.sites)
    };
    // Every site that grinds a nonzero number of bits is shorted in turn.
    let (honest, sites) = accepts(None);
    assert!(honest);
    assert!(sites > 1);
    for site in 0..sites {
        assert!(!accepts(Some(site)).0);
    }
}
