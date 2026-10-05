//! Reusable binary verifier owners preserve their original public statement.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField16, BinaryField32, BinaryField64, BinaryField128};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProverData};
use p3_circuit::ops::ByteHash;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{ProverInstance, ProverInstances, prove, setup};
use p3_recursion::ProveNextLayerParams;
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::prepared::{BinaryStatementLayout, PreparedBinaryMultiStarkLayer};
use p3_recursion::verifier::{BinaryMultiStarkVerifier, VerificationError, VerifierLimits};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_test_utils::binary_field_params::{blake3, keccak};

struct ConstantAir;
impl<F> BaseAir<F> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}
impl<AB: AirBuilder> Air<AB> for ConstantAir {
    fn eval(&self, b: &mut AB) {
        let value = b.main().current_slice()[0];
        let public = b.public_values()[0];
        b.assert_eq(value, public);
    }
}

macro_rules! check {
    ($params:ident, $hash:expr) => {{
        type F = BinaryField8;
        type E = BinaryField64;
        type M = $params::LevelMmcs<F>;
        type ME = $params::LevelMmcs<E>;
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
        let cfg = BinaryPcsConfig::try_new::<F, E>(
            1,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 40,
            },
        )
        .unwrap();
        let mmcs = M::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let round = ME::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let native = Config {
            pcs: BinaryPcs::new(cfg, mmcs.clone(), round.clone()).unwrap(),
        };
        let plan =
            BinaryMultiStarkVerifier::<F, E>::new(&[&ConstantAir], &[1], cfg, $hash, 0, 0, 4, 64)
                .unwrap();
        assert!(matches!(
            PreparedBinaryMultiStarkLayer::<F, E, _, 2>::new(
                plan.clone(),
                $hash,
                &[7, 19, 13],
                p3_circuit_prover::config::baby_bear(),
                ProveNextLayerParams::default()
            ),
            Err(VerificationError::InvalidProofShape(_))
        ));
        let limits = VerifierLimits {
            max_metadata_entries: plan.input_resource_usage().metadata_entries,
            ..VerifierLimits::default()
        };
        assert!(matches!(
            PreparedBinaryMultiStarkLayer::<F, E, _, 4>::with_limits(
                plan.clone(),
                $hash,
                &[7, 19, 13],
                p3_circuit_prover::config::baby_bear(),
                ProveNextLayerParams::default(),
                &limits
            ),
            Err(VerificationError::ResourceLimitExceeded { .. })
        ));
        let layer = PreparedBinaryMultiStarkLayer::<F, E, _, 4>::new(
            plan,
            $hash,
            &[7, 19, 13],
            p3_circuit_prover::config::baby_bear(),
            ProveNextLayerParams::default(),
        )
        .unwrap();
        assert_eq!(layer.statement_layout().public_value_counts(), &[1]);
        assert_eq!(layer.statement_layout().schema().base_len(), 8);
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let (pk, _) = setup(&native, &[&ConstantAir], &mut make()).unwrap();
        for raw in [3u8, 157] {
            let value = F::from_le_bytes([raw]);
            let public = vec![vec![value]];
            let table = Table::new(RowMajorMatrix::new(vec![value; 2], 1).transpose());
            let proof = prove(
                &native,
                ProverInstances::new(vec![ProverInstance::new(
                    &ConstantAir,
                    table,
                    &pk,
                    &public[0],
                )]),
                0,
                &mut make(),
            )
            .unwrap();
            let input = layer
                .binary_verifier()
                .import_native(&mmcs, &round, &public, &proof, &mut make())
                .unwrap();
            let output = layer.prove(&input, &public).unwrap();
            let expected = layer.statement_layout().pack::<BabyBear>(&public).unwrap();
            assert_eq!(
                expected,
                [
                    BabyBear::from_u8(raw),
                    BabyBear::ZERO,
                    BabyBear::ZERO,
                    BabyBear::ZERO,
                    BabyBear::ZERO,
                    BabyBear::ZERO,
                    BabyBear::ZERO,
                    BabyBear::ZERO
                ]
            );
            layer.verifier().verify(&output.0, &expected).unwrap();
            let mut wrong = expected.clone();
            wrong[0] += BabyBear::ONE;
            assert!(layer.verifier().verify(&output.0, &wrong).is_err());
            let mut wrong = public.clone();
            wrong[0][0] += F::ONE;
            assert!(layer.prove(&input, &wrong).is_err());
            assert!(layer.prove(&input, &[]).is_err());
            let other = BinaryMultiStarkVerifier::<F, E>::new(
                &[&ConstantAir],
                &[1],
                cfg,
                $hash,
                0,
                0,
                5,
                64,
            )
            .unwrap();
            assert!(
                input
                    .private_values::<BabyBear>(&other.input_shape())
                    .is_err()
            );
            let foreign = other
                .import_native(&mmcs, &round, &public, &proof, &mut make())
                .unwrap();
            assert!(layer.prove(&foreign, &public).is_err());
        }
    }};
}

#[test]
fn prepared_binary_layers_reuse_trusted_keccak_and_blake3_circuits() {
    check!(keccak, ByteHash::Keccak256);
    check!(blake3, ByteHash::Blake3);
}

fn check_statement<F: RecursiveBinaryTowerField>() {
    let layout =
        BinaryStatementLayout::<F>::with_limits(&[2, 0, 1], &VerifierLimits::default()).unwrap();
    let field =
        |raw: u128| F::from_le_byte_iter(raw.to_le_bytes().into_iter().take(F::RAW_BITS / 8));
    let values = [
        field(0x0123_4567_89ab_cdef_1357_2468_aabb_ccddu128),
        field(u128::MAX),
        field(0x8765_4321_dead_beef_1122_3344_5566_7788u128),
    ];
    let public = vec![vec![values[0], values[1]], vec![], vec![values[2]]];
    let packed = layout.pack::<BabyBear>(&public).unwrap();
    assert_eq!(packed.len(), 24);
    assert_eq!(layout.field_bits(), F::RAW_BITS);
    assert!(
        layout
            .schema()
            .fields()
            .iter()
            .all(|field| *field == p3_circuit::StatementField::Base)
    );
    for (value, limbs) in values.iter().zip(packed.as_chunks::<8>().0.iter()) {
        let raw = value.raw_coordinates();
        let expected: Vec<_> = (0..8)
            .map(|i| BabyBear::from_u16((raw >> (16 * i)) as u16))
            .collect();
        assert_eq!(limbs.as_slice(), expected);
    }
    let mut wrong = public.clone();
    wrong[1].push(values[0]);
    assert!(layout.pack::<BabyBear>(&wrong).is_err());
    assert!(layout.pack::<BabyBear>(&public[..2]).is_err());
}

#[test]
fn every_released_binary_statement_width_has_an_injective_host_encoding() {
    check_statement::<BinaryField8>();
    check_statement::<BinaryField16>();
    check_statement::<BinaryField32>();
    check_statement::<BinaryField64>();
    check_statement::<BinaryField128>();
}

#[test]
fn statement_geometry_and_total_public_allocations_are_bounded() {
    let defaults = VerifierLimits::default();
    for limits in [
        VerifierLimits {
            max_instances: 2,
            ..defaults
        },
        VerifierLimits {
            max_total_scalar_elements: 23,
            ..defaults
        },
        VerifierLimits {
            max_metadata_entries: 26,
            ..defaults
        },
        VerifierLimits {
            max_matrix_width: 24,
            ..defaults
        },
    ] {
        assert!(matches!(
            BinaryStatementLayout::<BinaryField128>::with_limits(&[2, 0, 1], &limits),
            Err(VerificationError::ResourceLimitExceeded { .. })
        ));
    }
    let exact = VerifierLimits {
        max_instances: 3,
        max_total_scalar_elements: 24,
        max_metadata_entries: 27,
        max_matrix_width: 25,
        ..defaults
    };
    assert!(BinaryStatementLayout::<BinaryField128>::with_limits(&[2, 0, 1], &exact).is_ok());
    let wide = VerifierLimits {
        max_total_scalar_elements: usize::MAX,
        max_metadata_entries: usize::MAX,
        ..defaults
    };
    for counts in [vec![usize::MAX, 1], vec![usize::MAX / 8 + 1]] {
        assert!(matches!(
            BinaryStatementLayout::<BinaryField128>::with_limits(&counts, &wide),
            Err(VerificationError::ResourceArithmeticOverflow { .. })
        ));
    }
    let empty = BinaryStatementLayout::<BinaryField8>::with_limits(&[0, 0], &defaults).unwrap();
    assert!(
        empty
            .pack::<BabyBear>(&[vec![], vec![]])
            .unwrap()
            .is_empty()
    );
}
