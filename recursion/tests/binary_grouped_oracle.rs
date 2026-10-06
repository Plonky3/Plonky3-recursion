//! Grouped leaves bind the requested symbol's low-bit lane and full byte row.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128, TowerLevel};
use p3_binary_pcs::GroupedCodewordMmcs;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::pcs::binary::{BinaryGroupedOraclePlan, RecursiveBinaryTowerField};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn pack(raw: u128) -> impl Iterator<Item = BabyBear> {
    (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16))
}

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

macro_rules! check {
    ($field:ty, $params:ident, $hash:expr, $group:expr, $cap:expr) => {{
        type F = $field;
        let group = $group;
        let cap_height = $cap;
        let tree = $params::LevelMmcs::<F>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            cap_height,
        );
        let grouped = GroupedCodewordMmcs::new(tree.clone(), group);
        let plan = BinaryGroupedOraclePlan::<F>::new(6, group, $hash, cap_height).unwrap();
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let index = (0..6)
            .map(|_| b.alloc_private_input("grouped symbol index bit"))
            .collect::<Vec<_>>();
        let limbs = b.alloc_private_input_array::<8>("grouped requested symbol");
        let symbol = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
        let leaf = (0..group)
            .map(|_| {
                let limbs = b.alloc_private_input_array::<8>("grouped leaf symbol");
                b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
            })
            .collect::<Vec<_>>();
        let path = (0..6 - group.ilog2() as usize - cap_height)
            .map(|_| b.alloc_private_input_array::<16>("grouped path").to_vec())
            .collect::<Vec<_>>();
        let cap = (0..1usize << cap_height)
            .map(|_| b.alloc_private_input_array::<16>("grouped cap").to_vec())
            .collect::<Vec<_>>();
        assert_eq!(
            plan.input_resource_usage().scalar_elements,
            b.private_input_count()
        );
        plan.verify_symbol::<BabyBear, BabyBear>(&mut b, &index, &symbol, &leaf, &path, &cap)
            .unwrap();
        let circuit = b.build().unwrap();
        let mut last = vec![];
        for seed in [7, 53] {
            let symbols = (0..64)
                .map(|i| {
                    let raw = 0x72fba395146de8014bfea3751926840du128 ^ ((i + seed) as u128);
                    F::from_le_byte_iter(raw.to_le_bytes().into_iter())
                })
                .collect::<Vec<_>>();
            let (commitment, data) = grouped.commit_matrix(RowMajorMatrix::new(symbols.clone(), 1));
            let (ordinary_cap, ordinary_data) =
                tree.commit_matrix(RowMajorMatrix::new(symbols.clone(), group));
            assert_eq!(commitment.roots(), ordinary_cap.roots());
            for at in [0usize, 3, 19, 63] {
                let native = grouped.open_batch(at, &data);
                grouped
                    .verify_batch(
                        &commitment,
                        &[p3_matrix::Dimensions {
                            width: 1,
                            height: 64,
                        }],
                        at,
                        (&native).into(),
                    )
                    .unwrap();
                let native_leaf = tree.open_batch(at / group, &ordinary_data);
                let mut values = (0..6)
                    .map(|i| BabyBear::from_bool(at >> i & 1 != 0))
                    .collect::<Vec<_>>();
                values.extend(pack(symbols[at].raw_coordinates()));
                values.extend(
                    native_leaf.opened_values[0]
                        .iter()
                        .flat_map(|v| pack(v.raw_coordinates())),
                );
                values.extend(
                    native_leaf.opening_proof.iter().flat_map(|digest| {
                        bytes_to_limbs(digest).into_iter().map(BabyBear::from_u16)
                    }),
                );
                let cap_start = values.len();
                values.extend(
                    commitment.roots().iter().flat_map(|digest| {
                        bytes_to_limbs(digest).into_iter().map(BabyBear::from_u16)
                    }),
                );
                assert!(run(&circuit, &values));
                let selected_root = at >> (6 - cap_height);
                for offset in [
                    0,
                    6,
                    14,
                    14 + 8 * (group - 1),
                    cap_start + 16 * selected_root,
                ] {
                    let mut wrong = values.clone();
                    wrong[offset] += BabyBear::ONE;
                    assert!(
                        !run(&circuit, &wrong),
                        "group={group}, index={at}, input={offset}"
                    );
                }
                let mut wrong = values.clone();
                wrong[0] = BabyBear::from_u8(2);
                assert!(!run(&circuit, &wrong));
                last = values;
            }
        }
        (circuit, last)
    }};
}

#[test]
fn grouped_symbol_lanes_match_native_across_widths_hashes_and_caps() {
    for group in [1usize, 2, 4, 16] {
        check!(BinaryField8, keccak, ByteHash::Keccak256, group, 1);
        check!(BinaryField64, blake3, ByteHash::Blake3, group, 1);
    }
    check!(BinaryField128, keccak, ByteHash::Keccak256, 64usize, 0);
}

#[test]
fn grouped_symbol_authentication_proves_in_a_prime_field() {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    let (circuit, values) = check!(BinaryField64, blake3, ByteHash::Blake3, 4usize, 1);
    let mut prover = BatchStarkProver::new(crate::proof_config());
    prover.register_table_prover(Box::new(Blake3CompressProver::<1>));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &[Box::new(Blake3CompressPreprocessor)],
            &[Box::new(Blake3CompressAirBuilder::<1>)],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}

#[test]
fn grouped_oracle_geometry_and_scalar_limits_reject_before_allocation() {
    let make = |bits, group, cap, limits: &VerifierLimits| {
        BinaryGroupedOraclePlan::<BinaryField128>::with_limits(
            bits,
            group,
            ByteHash::Blake3,
            cap,
            limits,
        )
    };
    let defaults = VerifierLimits::default();
    for (bits, group, cap) in [
        (6, 0, 0),
        (6, 3, 0),
        (6, 128, 0),
        (6, 16, 3),
        (usize::BITS as usize, 1, 0),
    ] {
        assert!(make(bits, group, cap, &defaults).is_err());
    }
    let limits = VerifierLimits {
        max_matrix_width: 3,
        ..defaults
    };
    assert!(matches!(
        make(6, 4, 0, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "binary grouped leaf width",
            ..
        })
    ));
    let plan = make(6, 4, 0, &defaults).unwrap();
    let limits = VerifierLimits {
        max_total_scalar_elements: plan.input_resource_usage().scalar_elements - 1,
        ..defaults
    };
    assert!(matches!(
        make(6, 4, 0, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
}
