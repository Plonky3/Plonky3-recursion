//! Reusable binary verifier owners preserve their original public statement.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64};
use p3_binary_pcs::{
    BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProverData, GroupedCodewordMmcs,
};
use p3_circuit::ops::ByteHash;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{ProverInstance, ProverInstances, prove, setup};
use p3_recursion::ProveNextLayerParams;
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableVerifier,
};
use p3_recursion::builtin_config::{FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary};
use p3_recursion::pcs::binary::BinaryCodewordGrouping;
use p3_recursion::prepared::PreparedBinaryGroupedMultiStarkLayer;
use p3_recursion::verifier::{BinaryGroupedMultiStarkVerifier, VerificationError, VerifierLimits};
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
        let cfg = BinaryPcsConfig::try_new::<F, E>(
            1,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 40,
            },
        )
        .unwrap();
        let mmcs = Tree::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let round = RoundTree::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let native = Config {
            pcs: BinaryPcs::new(
                cfg,
                M::new(mmcs.clone(), 8),
                ME::for_folding(round.clone(), &cfg),
            )
            .unwrap(),
        };
        let artifact_limits = ArtifactLimits::default();
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
            &artifact_limits.verifier,
        )
        .unwrap();
        let plan = BinaryGroupedMultiStarkVerifier::<F, E>::new(
            &[&ConstantAir],
            &[1],
            cfg,
            $hash,
            0,
            0,
            4,
            64,
            BinaryCodewordGrouping::Codeword(8),
            BinaryCodewordGrouping::Folding,
        )
        .unwrap();
        assert!(matches!(
            PreparedBinaryGroupedMultiStarkLayer::<F, E, _, 2>::new(
                plan.clone(),
                $hash,
                &[7, 19, 13],
                output_config.clone(),
                ProveNextLayerParams::default()
            ),
            Err(VerificationError::InvalidProofShape(_))
        ));
        let limits = VerifierLimits {
            max_metadata_entries: plan.input_resource_usage().metadata_entries,
            ..VerifierLimits::default()
        };
        assert!(matches!(
            PreparedBinaryGroupedMultiStarkLayer::<F, E, _, 4>::with_limits(
                plan.clone(),
                $hash,
                &[7, 19, 13],
                output_config.clone(),
                ProveNextLayerParams::default(),
                &limits
            ),
            Err(VerificationError::ResourceLimitExceeded { .. })
        ));
        let layer = PreparedBinaryGroupedMultiStarkLayer::<F, E, _, 4>::new(
            plan,
            $hash,
            &[7, 19, 13],
            output_config,
            ProveNextLayerParams::default(),
        )
        .unwrap();
        assert_eq!(layer.statement_layout().public_value_counts(), &[1]);
        assert_eq!(layer.statement_layout().schema().base_len(), 8);
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let (pk, _) = setup(&native, &[&ConstantAir], &mut make()).unwrap();
        let mut encoded_outputs = Vec::new();
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
            encoded_outputs.push((
                layer
                    .verifier()
                    .encode_proof_artifact(&output.0, artifact_limits)
                    .unwrap(),
                expected.clone(),
            ));
            let mut wrong = expected.clone();
            wrong[0] += BabyBear::ONE;
            assert!(layer.verifier().verify(&output.0, &wrong).is_err());
            let mut wrong = public.clone();
            wrong[0][0] += F::ONE;
            assert!(layer.prove(&input, &wrong).is_err());
            assert!(layer.prove(&input, &[]).is_err());
            let other = BinaryGroupedMultiStarkVerifier::<F, E>::new(
                &[&ConstantAir],
                &[1],
                cfg,
                $hash,
                0,
                0,
                5,
                64,
                BinaryCodewordGrouping::Codeword(8),
                BinaryCodewordGrouping::Folding,
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
        let verifier_bytes = layer
            .verifier()
            .encode_verifier_artifact(artifact_limits)
            .unwrap();
        drop(layer);
        drop(pk);
        let portable = PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            artifact_limits,
        )
        .unwrap();
        for (proof, statement) in &encoded_outputs {
            let canonical: Vec<_> = statement
                .iter()
                .flat_map(|v| (v.as_canonical_u64() as u32).to_le_bytes())
                .collect();
            portable
                .verify_encoded(proof, CanonicalStatement::new(&canonical, 8))
                .unwrap();
        }
        let wrong: Vec<_> = encoded_outputs[1]
            .1
            .iter()
            .flat_map(|v| (v.as_canonical_u64() as u32).to_le_bytes())
            .collect();
        assert!(
            portable
                .verify_encoded(&encoded_outputs[0].0, CanonicalStatement::new(&wrong, 8),)
                .is_err()
        );
    }};
}

#[test]
fn prepared_grouped_binary_layers_reuse_trusted_keccak_and_blake3_circuits() {
    check!(keccak, ByteHash::Keccak256);
    check!(blake3, ByteHash::Blake3);
}
