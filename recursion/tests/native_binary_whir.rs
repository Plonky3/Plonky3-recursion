//! Full additive WHIR openings verified in the exact native Tower128 carrier.

use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_challenger::FieldChallenger;
use p3_circuit::{
    Circuit, CircuitBuilder,
    ops::{
        ByteHash, NativeTower128Target,
        binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding},
        bytes_to_limbs,
    },
};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::{BinaryTower128Challenger, pcs::binary::BinaryWhirVerifier};
use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::keccak;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

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
    ($base:ty, $layout:ident, $protocol:expr, $cap_height:expr, $pow:expr) => {{
        type Ch = keccak::LevelChallenger<$base>;
        type L = $layout<$base, F>;
        let protocol = $protocol;
        let n = p3_sumcheck::layout::plan_stacked_layout(&protocol.table_shapes()).0;
        let domain = BinaryWhirDomain::<$base>::default();
        let config = WhirConfig::<F, $base, Ch>::new_with_domain(
            n,
            ProtocolParameters {
                security_level: 8,
                pow_bits: $pow,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(2),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            &domain,
        )
        .unwrap();
        let mmcs = keccak::LevelMmcs::<$base>::new(
            keccak::FieldHash::new(keccak::byte_hash()),
            keccak::Compress::new(keccak::byte_hash()),
            $cap_height,
        );
        let pcs = WhirProver::<F, $base, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
        let recursive = BinaryWhirVerifier::<$base>::new(
            &config,
            protocol.clone(),
            L::variable_order(),
            ByteHash::Keccak256,
            $cap_height,
        )
        .unwrap();
        let shape = recursive.input_shape();
        let make = || Ch::from_hasher(vec![129, 9, 251], keccak::byte_hash());
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
        b.enable_native_keccak_f1600().unwrap();
        let cap: Vec<_> = (0..1usize << $cap_height)
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
            ByteHash::Keccak256,
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
            (1usize << $cap_height) * 16,
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
        let other = BinaryWhirVerifier::<$base>::new(
            &config,
            protocol,
            if L::variable_order() == p3_sumcheck::strategy::VariableOrder::Prefix {
                p3_sumcheck::strategy::VariableOrder::Suffix
            } else {
                p3_sumcheck::strategy::VariableOrder::Prefix
            },
            ByteHash::Keccak256,
            $cap_height,
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
