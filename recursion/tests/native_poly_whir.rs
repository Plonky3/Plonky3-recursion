//! Additive Poly64/Poly192 WHIR verified entirely in native Poly64 cells.

use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_challenger::FieldChallenger;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NativePoly192Target, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::BinaryPolyWhirVerifier;
use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::keccak;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

type F = Poly64;
type E = Poly192;
type H = NativeBinaryEncoding;
fn scalar(b: &mut CircuitBuilder<F>) -> NativePoly192Target {
    let coefficients = core::array::from_fn(|_| b.public_input());
    b.native_poly192_from_coefficients(coefficients)
}
fn bind(b: &mut CircuitBuilder<F>, actual: &NativePoly192Target) {
    let expected = scalar(b);
    for (&actual, &expected) in actual.coefficients().iter().zip(expected.coefficients()) {
        let difference = b.sub(actual, expected);
        b.assert_zero(difference);
    }
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
    ($layout:ident, $protocol:expr, $cap_height:expr, $pow:expr) => {{
        type Ch = keccak::LevelChallenger<F>;
        type L = $layout<F, E>;
        let protocol = $protocol;
        let n = p3_sumcheck::layout::plan_stacked_layout(&protocol.table_shapes()).0;
        let domain = BinaryWhirDomain::<F>::default();
        let config = WhirConfig::<E, F, Ch>::new_with_domain(
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
        let mmcs = keccak::LevelMmcs::<F>::new(
            keccak::FieldHash::new(keccak::byte_hash()),
            keccak::Compress::new(keccak::byte_hash()),
            $cap_height,
        );
        let pcs = WhirProver::<E, F, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
        let recursive = BinaryPolyWhirVerifier::new(
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
            E::new(core::array::from_fn(|k| {
                F::new(0x492f307c9bfa3e51u64.wrapping_mul(i as u64 + 13 + 71 * k as u64))
            }))
        };
        let tables = protocol
            .table_shapes()
            .iter()
            .enumerate()
            .map(|(table, shape)| {
                Table::new(RowMajorMatrix::new(
                    (0..shape.width() * (1 << shape.num_variables()))
                        .map(|i| {
                            F::new(
                                0x8123456789abcdefu64
                                    .wrapping_mul(i as u64 + 17 * table as u64 + 13),
                            )
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
        let next = native_ch.sample_algebra_element::<E>();
        assert_eq!(next, entry.sample_algebra_element::<E>());
        // Restoration happens after transcript replay; failures must roll back.
        for oversized in [false, true] {
            let mut malformed = native.clone();
            let frontier = match &mut malformed.whir.final_openings {
                p3_whir::pcs::proof::QueryOpenings::Base(opening) => {
                    &mut opening.proof.sibling_hashes
                }
                p3_whir::pcs::proof::QueryOpenings::Extension(opening) => {
                    &mut opening.proof.sibling_hashes
                }
            };
            if !oversized && frontier.is_empty() {
                continue;
            }
            if oversized {
                frontier.resize(4096, [0; 32]);
            } else {
                frontier.clear();
            }
            let mut unchanged = make();
            pcs.observe_commitment(&commitment, &mut unchanged);
            let mut before = unchanged.clone();
            assert!(
                recursive
                    .import_native(
                        &config,
                        &mmcs,
                        &commitment,
                        &points,
                        &malformed,
                        &mut unchanged
                    )
                    .is_err()
            );
            assert_eq!(
                unchanged.sample_algebra_element::<E>(),
                before.sample_algebra_element::<E>()
            );
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
        let bits = ch.sample_poly192_with_host::<H, F>(&mut b).unwrap();
        let actual = b
            .native_poly192_from_bits(core::array::from_fn(|i| {
                bits.coefficients()[i / 64].bits()[i % 64]
            }))
            .unwrap();
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
        public.extend(
            points
                .iter()
                .flat_map(|point| point.iter().copied())
                .flat_map(|value| value.coefficients()),
        );
        public.extend(
            native
                .evals
                .iter()
                .flat_map(|eval| eval.current().iter().chain(eval.next()).copied())
                .flat_map(|value| value.coefficients()),
        );
        public.extend(next.coefficients());
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
        let other = BinaryPolyWhirVerifier::new(
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
fn native_poly_whir_initial_and_closing_folds_bind_prefix_openings() {
    check!(PrefixProver, protocol(3, 1, false), 0, 0);
}
#[test]
fn native_poly_whir_intermediate_rounds_and_pow_bind_suffix_successors() {
    check!(SuffixProver, protocol(9, 1, true), 0, 2);
}
#[test]
fn native_poly_whir_caps_and_mixed_widths_bind_every_opening() {
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
    check!(PrefixProver, protocol, 1, 0);
}
