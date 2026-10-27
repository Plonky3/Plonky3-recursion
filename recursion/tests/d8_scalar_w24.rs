//! Scalar W24 transcript geometry for experimental D8 recursion.

use p3_challenger::{CanObserve, CanSample, DuplexChallenger};
use p3_circuit::ops::{Poseidon2Config, Poseidon2PermCall};
use p3_circuit::{CircuitBuilder, CircuitRunner};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_24};
use p3_recursion::FriRecursionConfig;
use p3_recursion::builtin_config::{
    FriConfigV1, SuiteIdV1, experimental_koala_bear_d8_poseidon2_w24_random_codeword,
};
use p3_recursion::challenger::CircuitChallenger;
use p3_recursion::traits::RecursiveChallenger;
use p3_recursion::verifier::VerifierLimits;
use p3_symmetric::Permutation;

type E = BinomialExtensionField<KoalaBear, 8>;

fn phase(label: &'static str) {
    eprintln!("D8_TEST_PHASE {label}");
}

fn descriptor() -> FriConfigV1 {
    FriConfigV1::new(
        SuiteIdV1::ExperimentalKoalaBearD8Poseidon2W24RandomCodewordFri,
        1,
        0,
        1,
        2,
        0,
        0,
        0,
        0,
        8,
        0,
    )
}

fn transcript(interleave: bool) {
    let config = experimental_koala_bear_d8_poseidon2_w24_random_codeword(
        &descriptor(),
        &VerifierLimits::default(),
        rand::rngs::StdRng::seed_from_u64(9),
    )
    .unwrap();
    let mut builder = CircuitBuilder::<E>::new();
    config
        .prepare_circuit_for_verification(&mut builder)
        .unwrap();
    let mut recursive =
        CircuitChallenger::<24, 12, Poseidon2Config>::new(Poseidon2Config::KOALA_BEAR_D1_W24);
    let mut native =
        DuplexChallenger::<KoalaBear, _, 24, 12>::new(default_koalabear_poseidon2_24());
    let mut outputs = Vec::new();
    for round in 0..4 {
        // Exercise partial/full absorption, a capacity-crossing extension
        // challenge and repeated squeezes after arbitrary ordinary hashes.
        for index in 0..(round * 7 + 1) {
            let scalar = KoalaBear::from_u32((round * 100 + index + 1) as u32);
            let target = builder.alloc_const(E::from(scalar), "transcript scalar");
            <CircuitChallenger<24, 12, Poseidon2Config> as RecursiveChallenger<KoalaBear, E>>::observe(
                &mut recursive,
                &mut builder,
                target,
            );
            native.observe(scalar);
        }
        for _ in 0..3 {
            let actual = <CircuitChallenger<24, 12, Poseidon2Config> as RecursiveChallenger<
                KoalaBear,
                E,
            >>::sample_ext(&mut recursive, &mut builder);
            let expected: E = native.sample();
            let public = builder.public_input();
            builder.connect(actual, public);
            outputs.push(expected);
            if interleave {
                let scalar = builder.alloc_const(E::ONE, "ordinary compression scalar");
                builder
                    .add_poseidon2_perm(&Poseidon2PermCall {
                        config: Poseidon2Config::KOALA_BEAR_D1_W24,
                        new_start: true,
                        merkle_path: false,
                        mmcs_bit: None,
                        mmcs_bit2: None,
                        inputs: vec![Some(scalar); 24],
                        out_ctl: vec![true; 12],
                        return_all_outputs: false,
                        absorb_len: 0,
                    })
                    .unwrap();
            }
        }
    }
    let circuit = builder.build().unwrap();
    let mut runner = CircuitRunner::new(&circuit);
    runner.set_public_inputs(&outputs).unwrap();
    runner.run().unwrap();
}

use rand::SeedableRng;

#[test]
fn scalar_w24_d8_transcript_matches_native() {
    phase("transcript.native_equivalence.begin");
    transcript(false);
    phase("transcript.native_equivalence.complete");
}

#[test]
fn scalar_w24_challenger_is_not_changed_by_mmcs_table_interleaving() {
    phase("transcript.interleaving.begin");
    transcript(true);
    phase("transcript.interleaving.complete");
}

#[test]
fn scalar_w24_d8_binary_compression_matches_native_for_both_directions() {
    phase("binary_compression.begin");
    let config = experimental_koala_bear_d8_poseidon2_w24_random_codeword(
        &descriptor(),
        &VerifierLimits::default(),
        rand::rngs::StdRng::seed_from_u64(11),
    )
    .unwrap();
    let mut builder = CircuitBuilder::<E>::new();
    config
        .prepare_circuit_for_verification(&mut builder)
        .unwrap();
    let mut public_values = Vec::new();
    for direction in [false, true] {
        let scalars: [KoalaBear; 24] = core::array::from_fn(|i| KoalaBear::from_usize(i + 1));
        let inputs = scalars
            .iter()
            .map(|&scalar| Some(builder.alloc_const(E::from(scalar), "binary compression scalar")))
            .collect();
        let bit = builder.alloc_const(E::from_bool(direction), "binary compression direction");
        let (_, outputs) = builder
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: Poseidon2Config::KOALA_BEAR_D1_W24,
                new_start: true,
                merkle_path: true,
                mmcs_bit: Some(bit),
                mmcs_bit2: None,
                inputs,
                out_ctl: vec![true; 12],
                return_all_outputs: false,
                absorb_len: 0,
            })
            .unwrap();
        assert_eq!(outputs.len(), 24);
        assert!(outputs[..12].iter().all(Option::is_some));
        assert!(outputs[12..].iter().all(Option::is_none));
        let mut ordered = scalars;
        if direction {
            ordered.rotate_left(12);
        }
        let expected = default_koalabear_poseidon2_24().permute(ordered);
        for (actual, expected) in outputs
            .into_iter()
            .take(12)
            .zip(expected.into_iter().take(12))
        {
            let public = builder.public_input();
            builder.connect(actual.unwrap(), public);
            public_values.push(E::from(expected));
        }
    }
    let circuit = builder.build().unwrap();
    let mut runner = CircuitRunner::new(&circuit);
    runner.set_public_inputs(&public_values).unwrap();
    runner.run().unwrap();
    phase("binary_compression.complete");
}

#[test]
fn experimental_suite_keeps_native_d8_and_digest12() {
    phase("suite_geometry.begin");
    let spec = descriptor().suite().spec();
    assert_eq!(
        (
            spec.extension_degree,
            spec.challenger_width,
            spec.challenger_rate,
            spec.mmcs_width,
            spec.mmcs_rate,
            spec.digest_elements,
            spec.merkle_arity
        ),
        (8, 24, 12, 24, 12, 12, 2)
    );
    assert_eq!(SuiteIdV1::from_u16(0xF824).unwrap(), descriptor().suite());
    assert!(descriptor().validate(&VerifierLimits::default()).is_ok());
    let too_few_masks = FriConfigV1::new(descriptor().suite(), 1, 0, 1, 2, 0, 0, 0, 0, 7, 0);
    assert!(too_few_masks.validate(&VerifierLimits::default()).is_err());
    phase("suite_geometry.complete");
}

#[test]
fn d8_statement_preprocessor_preserves_base_and_extension_exports() {
    use p3_circuit::StatementExport;
    use p3_circuit::ops::NpoTypeId;
    use p3_circuit_prover::StatementPreprocessor;
    use p3_circuit_prover::common::NpoPreprocessor;

    phase("statement_preprocessor.begin");
    let mut builder = CircuitBuilder::<E>::new();
    builder.enable_recompose::<KoalaBear>(
        p3_circuit::ops::recompose::generate_recompose_trace::<KoalaBear, E>,
    );
    let base = builder.public_input();
    let extension = builder.public_input();
    let schema = builder
        .set_statement_exports::<KoalaBear>(&[
            StatementExport::Base(base),
            StatementExport::Extension(extension),
        ])
        .unwrap();
    assert_eq!(schema.base_len(), 9);
    let circuit = builder.build().unwrap();
    let mut preprocessed = circuit.generate_preprocessed_columns::<8>().unwrap();
    let expected = preprocessed.non_primitive[&NpoTypeId::statement()]
        .iter()
        .map(|value| value.as_base().unwrap())
        .collect::<Vec<_>>();
    let columns = <StatementPreprocessor as NpoPreprocessor<KoalaBear>>::preprocess(
        &StatementPreprocessor::new(schema),
        &circuit,
        &mut preprocessed,
    )
    .unwrap();
    assert_eq!(columns.len(), 1);
    assert_eq!(columns[&NpoTypeId::statement()], expected);
    assert_eq!(expected.len(), 10);
    assert_eq!(expected[0], KoalaBear::ONE);
    phase("statement_preprocessor.complete");
}

/// A real hiding D8 proof exercises positive opening-batch work through a
/// reusable recursive circuit. Mutations retain the exact accepted shape.
#[test]
fn d8_positive_batch_work_prepared_proof_rejects_nonce_and_opening_claim_mutations() {
    phase("prepared_batch_work.begin");
    use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
    use p3_circuit_prover::TablePacking;
    use p3_recursion::builtin_config::ExperimentalKoalaBearD8Poseidon2W24RandomCodewordConfig;
    use p3_recursion::{
        BatchOnly, FriRecursionBackend, FriRecursionBackendForExt, PcsRecursionBackend,
        PreparedInput, PreparedLayer, PreparedPcsRecursionBackend, PreparedSource,
        ProveNextLayerParams, RecursionInput,
    };
    use p3_uni_stark::{prove, verify};

    type Config = ExperimentalKoalaBearD8Poseidon2W24RandomCodewordConfig<rand::rngs::StdRng>;
    type Backend = FriRecursionBackendForExt<8, 24, 12, Poseidon2Config>;
    let descriptor =
        FriConfigV1::new(descriptor().suite(), 2, 0, 1, 2, 0, 0, 0, 0, 8, 0).with_batch_pow_bits(4);
    let config = experimental_koala_bear_d8_poseidon2_w24_random_codeword(
        &descriptor,
        &VerifierLimits::default(),
        rand::rngs::StdRng::seed_from_u64(41),
    )
    .unwrap();
    let backend: Backend =
        FriRecursionBackend::<24, 12, _>::new(Poseidon2Config::KOALA_BEAR_D1_W24)
            .for_extension_degree::<8>();
    let n = 64;
    let (mut a, mut b) = (KoalaBear::ZERO, KoalaBear::ONE);
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    let public = vec![KoalaBear::ZERO, KoalaBear::ONE, b];
    let air = FibonacciAir {};
    phase("prepared_batch_work.native_prove");
    let mut proof = prove(
        &config,
        &air,
        generate_trace_rows::<KoalaBear>(0, 1, n),
        &public,
    )
    .unwrap();
    phase("prepared_batch_work.native_verify");
    verify(&config, &air, &proof, &public).unwrap();
    phase("prepared_batch_work.prepare");
    let prepared = PreparedLayer::<Config, FibonacciAir, Backend, 8>::new(
        PreparedSource::UniStark {
            air: &air,
            proof: &proof,
            public_inputs: &public,
            preprocessed_commit: None,
        },
        config.clone(),
        backend,
        ProveNextLayerParams {
            table_packing: TablePacking::new(4, 4).with_min_trace_height(128),
            ..Default::default()
        },
    )
    .unwrap();
    phase("prepared_batch_work.recursive_prove");
    let output = prepared
        .prove(PreparedInput::UniStark {
            proof: &proof,
            public_inputs: &public,
            preprocessed_commit: None,
        })
        .unwrap();
    phase("prepared_batch_work.recursive_verify");
    let verifier = prepared.verifier();
    verifier.verify(&output.0, &[]).unwrap();
    // Exercise generic batch-input capture and replay, not only the trusted
    // verifier path. These dispatchers must preserve the proof's D8 geometry.
    phase("prepared_batch_work.generic_batch_capture");
    let backend: Backend =
        FriRecursionBackend::<24, 12, _>::new(Poseidon2Config::KOALA_BEAR_D1_W24)
            .for_extension_degree::<8>();
    let table_public_inputs = verifier.table_public_values(&[]).unwrap();
    let batch_input: RecursionInput<'_, Config, BatchOnly> = RecursionInput::BatchStark {
        proof: &output.0,
        common_data: verifier.common_data(),
        table_public_inputs: table_public_inputs.clone(),
    };
    let contract =
        <Backend as PreparedPcsRecursionBackend<Config, BatchOnly, 8>>::capture_input_contract(
            &backend,
            &config,
            &batch_input,
        )
        .unwrap();
    <Backend as PreparedPcsRecursionBackend<Config, BatchOnly, 8>>::validate_prepared_input(
        &backend,
        &config,
        &contract,
        &PreparedInput::BatchStark {
            proof: &output.0,
            common_data: verifier.common_data(),
            table_public_inputs: &table_public_inputs,
        },
    )
    .unwrap();
    let mut invalid_public = table_public_inputs.clone();
    invalid_public[0].push(KoalaBear::ONE);
    let invalid_input: RecursionInput<'_, Config, BatchOnly> = RecursionInput::BatchStark {
        proof: &output.0,
        common_data: verifier.common_data(),
        table_public_inputs: invalid_public,
    };
    assert!(
        <Backend as PreparedPcsRecursionBackend<Config, BatchOnly, 8>>::capture_input_contract(
            &backend,
            &config,
            &invalid_input,
        )
        .is_err(),
        "generic D8 capture binds reconstructed table public values"
    );
    phase("prepared_batch_work.generic_batch_replay");
    let tables =
        <Backend as PcsRecursionBackend<Config, BatchOnly, 8>>::non_primitive_provers(&backend, 8);
    p3_recursion::backend::replay_recursion_input_transcript(&config, &batch_input, &tables)
        .unwrap();
    let original_nonce = proof.opening_proof.1.batch_pow_witness;
    // A nonce is not unique: choose an actually rejected same-shape candidate.
    phase("prepared_batch_work.invalid_nonce");
    let mut rejected_nonce = false;
    for _ in 0..256 {
        proof.opening_proof.1.batch_pow_witness += KoalaBear::ONE;
        if verify(&config, &air, &proof, &public).is_err() {
            rejected_nonce = true;
            break;
        }
    }
    assert!(rejected_nonce, "bounded invalid nonce search");
    assert!(verify(&config, &air, &proof, &public).is_err());
    assert!(
        prepared
            .prove(PreparedInput::UniStark {
                proof: &proof,
                public_inputs: &public,
                preprocessed_commit: None,
            })
            .is_err()
    );
    proof.opening_proof.1.batch_pow_witness = original_nonce;
    phase("prepared_batch_work.invalid_opening_coefficients");
    let original_claim = proof.opened_values.trace_local[0];
    for coefficient in 0..8 {
        let mut delta = [KoalaBear::ZERO; 8];
        delta[coefficient] = KoalaBear::ONE;
        proof.opened_values.trace_local[0] =
            original_claim + E::from_basis_coefficients_slice(&delta).unwrap();
        assert!(
            verify(&config, &air, &proof, &public).is_err(),
            "opening coefficient {coefficient}"
        );
        assert!(
            prepared
                .prove(PreparedInput::UniStark {
                    proof: &proof,
                    public_inputs: &public,
                    preprocessed_commit: None,
                })
                .is_err(),
            "prepared opening coefficient {coefficient}"
        );
    }
    phase("prepared_batch_work.complete");
}

/// The host permutation intentionally reads constant coefficients. Full
/// witness-bus lookups must reject the other seven coefficients in a proof,
/// including when the host runner accepts the unchanged scalar digest.
#[test]
fn scalar_w24_prepared_proof_rejects_nonconstant_d8_input_coefficients() {
    phase("scalar_witness_bus.begin");
    use p3_circuit::StatementExport;
    use p3_circuit_prover::{
        BatchStarkProver, ConstraintProfile, StatementAirBuilder, StatementPreprocessor,
        StatementProver, TablePacking,
    };
    use p3_recursion::artifact::{
        ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
        PortableVerifier,
    };
    use p3_recursion::builtin_config::ExperimentalKoalaBearD8Poseidon2W24RandomCodewordConfig;
    use p3_recursion::{
        BatchOnly, FriRecursionBackend, FriRecursionBackendForExt, PcsRecursionBackend,
    };

    type Config = ExperimentalKoalaBearD8Poseidon2W24RandomCodewordConfig<rand::rngs::StdRng>;
    type Backend = FriRecursionBackendForExt<8, 24, 12, Poseidon2Config>;
    let config = experimental_koala_bear_d8_poseidon2_w24_random_codeword(
        &descriptor(),
        &VerifierLimits::default(),
        rand::rngs::StdRng::seed_from_u64(71),
    )
    .unwrap();
    let backend: Backend =
        FriRecursionBackend::<24, 12, _>::new(Poseidon2Config::KOALA_BEAR_D1_W24)
            .for_extension_degree::<8>();
    let mut builder = CircuitBuilder::<E>::new();
    config
        .prepare_circuit_for_verification(&mut builder)
        .unwrap();
    let inputs = builder.alloc_public_inputs(24, "scalar W24 input");
    let scalars: [KoalaBear; 24] = core::array::from_fn(|i| KoalaBear::from_usize(i + 1));
    let expected = default_koalabear_poseidon2_24().permute(scalars);
    let (_, outputs) = builder
        .add_poseidon2_perm(&Poseidon2PermCall {
            config: Poseidon2Config::KOALA_BEAR_D1_W24,
            new_start: true,
            merkle_path: false,
            mmcs_bit: None,
            mmcs_bit2: None,
            inputs: inputs.iter().copied().map(Some).collect(),
            out_ctl: vec![true; 12],
            return_all_outputs: false,
            absorb_len: 0,
        })
        .unwrap();
    let exported_outputs = outputs
        .into_iter()
        .take(12)
        .map(Option::unwrap)
        .collect::<Vec<_>>();
    for (&output, scalar) in exported_outputs.iter().zip(expected.into_iter().take(12)) {
        let constant = builder.define_const(E::from(scalar));
        builder.connect(output, constant);
    }
    let schema = builder
        .set_statement_exports::<KoalaBear>(
            &exported_outputs
                .into_iter()
                .map(StatementExport::Base)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let circuit = builder.build().unwrap();
    let mut preprocessors =
        <Backend as PcsRecursionBackend<Config, BatchOnly, 8>>::non_primitive_preprocessors(
            &backend,
        );
    let mut air_builders =
        <Backend as PcsRecursionBackend<Config, BatchOnly, 8>>::non_primitive_air_builders(
            &backend,
        );
    preprocessors.push(Box::new(StatementPreprocessor::new(schema.clone())));
    air_builders.push(Box::new(StatementAirBuilder::<8>::new(schema.clone())));
    let mut prover = BatchStarkProver::new(config)
        .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(128));
    for table in
        <Backend as PcsRecursionBackend<Config, BatchOnly, 8>>::non_primitive_provers(&backend, 8)
    {
        prover.register_table_prover(table);
    }
    prover.register_table_prover(Box::new(StatementProver::<8>::new(schema)));
    phase("scalar_witness_bus.prepare");
    let prepared = prover
        .prepare_circuit::<E, 8>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let public: Vec<_> = scalars.into_iter().map(E::from).collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    phase("scalar_witness_bus.valid_runner");
    let traces = runner.run().unwrap();
    phase("scalar_witness_bus.valid_prove");
    let (proof, _) = prepared.prove_with_legacy_data(&traces).unwrap();
    phase("scalar_witness_bus.valid_verify");
    let verifier = prepared.verifier();
    let expected_statement = &expected[..12];
    verifier.verify(&proof, expected_statement).unwrap();
    for index in [0, 11] {
        let mut invalid_statement = expected_statement.to_vec();
        invalid_statement[index] += KoalaBear::ONE;
        assert!(verifier.verify(&proof, &invalid_statement).is_err());
    }
    phase("scalar_witness_bus.portable_roundtrip");
    let limits = ArtifactLimits::default();
    let verifier_bytes = verifier.encode_verifier_artifact(limits).unwrap();
    let proof_bytes = verifier.encode_proof_artifact(&proof, limits).unwrap();
    let imported = PortableVerifier::decode(
        &verifier_bytes,
        ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
        limits,
    )
    .unwrap();
    let statement_bytes = expected_statement
        .iter()
        .flat_map(|value| (value.as_canonical_u64() as u32).to_le_bytes())
        .collect::<Vec<_>>();
    imported
        .verify_encoded(&proof_bytes, CanonicalStatement::new(&statement_bytes, 12))
        .unwrap();
    let mut invalid_statement_bytes = statement_bytes.clone();
    invalid_statement_bytes[..4].copy_from_slice(
        &((expected_statement[0] + KoalaBear::ONE).as_canonical_u64() as u32).to_le_bytes(),
    );
    assert!(
        imported
            .verify_encoded(
                &proof_bytes,
                CanonicalStatement::new(&invalid_statement_bytes, 12),
            )
            .is_err()
    );
    phase("scalar_witness_bus.invalid_coefficients");
    for coefficient in 1..8 {
        let mut invalid = public.clone();
        let mut delta = [KoalaBear::ZERO; 8];
        delta[coefficient] = KoalaBear::ONE;
        invalid[0] += E::from_basis_coefficients_slice(&delta).unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&invalid).unwrap();
        let traces = runner
            .run()
            .expect("host execution ignores nonconstant scalar coefficients");
        if let Ok((proof, _)) = prepared.prove_with_legacy_data(&traces) {
            assert!(
                verifier.verify(&proof, expected_statement).is_err(),
                "coefficient {coefficient}"
            );
        }
    }
    phase("scalar_witness_bus.complete");
}
