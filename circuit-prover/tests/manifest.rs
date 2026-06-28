use p3_baby_bear::BabyBear;
use p3_batch_stark::ProverData;
use p3_circuit::builder::CircuitBuilder;
use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::ConstraintProfile;
use p3_circuit_prover::air::AluExtMulKind;
use p3_circuit_prover::air::AluExtMulKind::Base;
use p3_circuit_prover::batch_stark_prover::{
    AirVariant, BatchStarkProver, CircuitProverData, ProofMetadataError, TablePacking,
};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::config::{self, BabyBearConfig};
use p3_circuit_prover::manifest::{ExpectedNpoEntry, VerifierManifest};
use p3_field::PrimeCharacteristicRing;

fn baby_bear_base_proof() -> p3_circuit_prover::batch_stark_prover::BatchStarkProof<BabyBearConfig>
{
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let x = builder.public_input();
    let y = builder.public_input();
    let z = builder.add(x, y);
    let c = builder.define_const(BabyBear::from_u64(3));
    let diff = builder.sub(z, c);
    builder.assert_zero(diff);
    let circuit = builder.build().unwrap();

    let cfg = config::baby_bear();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &TablePacking::default(),
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&cfg, &airs, &log_degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u64(1), BabyBear::from_u64(2)])
        .unwrap();
    let traces = runner.run().unwrap();
    BatchStarkProver::new(cfg)
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap()
}

#[test]
fn manifest_matches_base_field_proof() {
    let proof = baby_bear_base_proof();
    let manifest = VerifierManifest::<BabyBear> {
        ext_degree: 1,
        reduction: Base,
        alu_variant: AirVariant::Optimized,
        expected_npo: vec![],
    };
    assert_eq!(manifest.matches(&proof), Ok(()));
}

#[test]
fn manifest_rejects_ext_degree_mismatch() {
    let proof = baby_bear_base_proof();
    let manifest = VerifierManifest {
        ext_degree: 4,
        reduction: AluExtMulKind::Binomial {
            w: BabyBear::from_u64(11),
        },
        alu_variant: AirVariant::Baseline,
        expected_npo: vec![],
    };
    assert!(matches!(
        manifest.matches(&proof),
        Err(ProofMetadataError::ExtDegreeMismatch {
            expected: 4,
            got: 1
        })
    ));
}

#[test]
fn manifest_rejects_binomial_w_mismatch() {
    let proof = baby_bear_base_proof();
    // Proof is D=1 (Base), but manifest declares D=1 Binomial (wrong reduction kind).
    let manifest = VerifierManifest {
        ext_degree: 1,
        reduction: AluExtMulKind::Binomial {
            w: BabyBear::from_u64(11),
        },
        alu_variant: AirVariant::Baseline,
        expected_npo: vec![],
    };
    assert!(matches!(
        manifest.matches(&proof),
        Err(ProofMetadataError::BinomialWMismatch)
    ));
}

#[test]
fn manifest_rejects_alu_variant_mismatch() {
    let proof = baby_bear_base_proof();
    let manifest = VerifierManifest::<BabyBear> {
        ext_degree: 1,
        reduction: Base,
        alu_variant: AirVariant::Baseline,
        expected_npo: vec![],
    };
    assert!(matches!(
        manifest.matches(&proof),
        Err(ProofMetadataError::AluVariantMismatch {
            expected: AirVariant::Baseline,
            got: AirVariant::Optimized,
        })
    ));
}

#[test]
fn manifest_rejects_npo_count_mismatch() {
    let proof = baby_bear_base_proof();
    let manifest = VerifierManifest::<BabyBear> {
        ext_degree: 1,
        reduction: Base,
        alu_variant: AirVariant::Optimized,
        expected_npo: vec![ExpectedNpoEntry {
            op_type: NpoTypeId::new("dummy/op"),
            air_variant: AirVariant::Baseline,
            public_values_len: 0,
        }],
    };
    assert!(matches!(
        manifest.matches(&proof),
        Err(ProofMetadataError::NpoCountMismatch {
            expected: 1,
            got: 0
        })
    ));
}
