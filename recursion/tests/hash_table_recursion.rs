//! Recursive verification of batch proofs whose circuits call the byte-hash tables.

mod common;

use p3_batch_stark::ProverData;
use p3_blake3::Blake3;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{
    DIGEST_LIMBS, KECCAK_STATE_LIMBS, bytes_to_limbs, generate_poseidon2_trace,
    generate_recompose_trace, keccak_state_to_limbs,
};
use p3_circuit_prover::batch_stark_prover::{
    Blake3CompressAirBuilder, Blake3CompressPreprocessor, Blake3CompressProver,
    KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover, TableProver,
    poseidon2_air_builders_for_configs, recompose_air_builders,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking,
};
use p3_keccak::KeccakF;
use p3_lookup::logup::LogUpGadget;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::pcs::fri::{FriVerifierParams, InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::{restore_fri_query_paths, set_fri_mmcs_private_data};
use p3_recursion::verifier::verify_p3_batch_proof_circuit;
use p3_recursion::{
    OpeningTranscript, Poseidon2Config, observe_opened_values, replay_batch_layer_transcript,
};
use p3_symmetric::{CryptographicHasher, Permutation};
use p3_test_utils::koala_bear_params::*;

use crate::common::InnerFriGeneric;

type InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;

/// Plugins that rebuild the layer-0 proof's Keccak-f table, in manifest order.
fn keccak_input_provers() -> Vec<Box<dyn TableProver<MyConfig>>> {
    vec![Box::new(KeccakF1600Prover::<1>)]
}

/// A base-field circuit applying Keccak-f twice, its final state connected to public limbs.
fn prove_keccak_batch() -> (BatchStarkProof<MyConfig>, CircuitProverData<MyConfig>) {
    let state: [u64; 25] =
        core::array::from_fn(|i| 0x0123_4567_89ab_cdef_u64.rotate_left(5 * i as u32));
    let mut expected = state;
    KeccakF.permute_mut(&mut expected);
    KeccakF.permute_mut(&mut expected);

    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_keccak_f1600::<F>();
    let input: Vec<_> = (0..KECCAK_STATE_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    let output: Vec<_> = (0..KECCAK_STATE_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    let once = builder.add_keccak_f1600(&input).unwrap();
    let twice = builder.add_keccak_f1600(&once).unwrap();
    for (&got, &want) in twice.iter().zip(&output) {
        builder.connect(got, want);
    }
    let circuit = builder.build().unwrap();

    let table_packing = TablePacking::new(2, 4);
    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![Box::new(KeccakF1600Preprocessor)];
    let air_builders: Vec<Box<dyn NpoAirBuilder<MyConfig, 1>>> =
        vec![Box::new(KeccakF1600AirBuilder::<1>)];
    let config = make_test_config();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, _, 1>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();
    let public: Vec<F> = keccak_state_to_limbs(&state)
        .into_iter()
        .chain(keccak_state_to_limbs(&expected))
        .map(F::from_u16)
        .collect();
    runner.set_public_inputs(&public).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(config).with_table_packing(table_packing);
    prover.register_table_prover(Box::new(KeccakF1600Prover::<1>));
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    prover.verify_all_tables::<F>(&proof).unwrap();
    (proof, circuit_prover_data)
}

/// Plugins that rebuild the layer-0 proof's BLAKE3 table, in manifest order.
fn blake3_input_provers() -> Vec<Box<dyn TableProver<MyConfig>>> {
    vec![Box::new(Blake3CompressProver::<1>)]
}

/// A base-field circuit hashing 100 bytes with BLAKE3 (two chained compressions), its digest
/// connected to public limbs.
fn prove_blake3_batch() -> (BatchStarkProof<MyConfig>, CircuitProverData<MyConfig>) {
    let message: Vec<u8> = (0..100u8)
        .map(|i| i.wrapping_mul(17).wrapping_add(3))
        .collect();
    let digest = Blake3.hash_iter(message.iter().copied());

    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_blake3_compress::<F>();
    let input: Vec<_> = (0..message.len() / 2)
        .map(|_| builder.public_input())
        .collect();
    let expected: Vec<_> = (0..DIGEST_LIMBS).map(|_| builder.public_input()).collect();
    let got = builder.blake3_limbs::<F>(&input).unwrap();
    for (&got, &want) in got.iter().zip(&expected) {
        builder.connect(got, want);
    }
    let circuit = builder.build().unwrap();

    let table_packing = TablePacking::new(2, 4);
    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> =
        vec![Box::new(Blake3CompressPreprocessor)];
    let air_builders: Vec<Box<dyn NpoAirBuilder<MyConfig, 1>>> =
        vec![Box::new(Blake3CompressAirBuilder::<1>)];
    let config = make_test_config();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, _, 1>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();
    let public: Vec<F> = bytes_to_limbs(&message)
        .into_iter()
        .chain(bytes_to_limbs(&digest))
        .map(F::from_u16)
        .collect();
    runner.set_public_inputs(&public).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(config).with_table_packing(table_packing);
    prover.register_table_prover(Box::new(Blake3CompressProver::<1>));
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    prover.verify_all_tables::<F>(&proof).unwrap();
    (proof, circuit_prover_data)
}

/// A layer-0 proof whose circuit calls Keccak-f[1600] verifies inside a recursive circuit,
/// and that circuit proves and verifies.
#[test]
fn a_keccak_f_batch_proof_verifies_recursively() {
    let (proof, data) = prove_keccak_batch();
    verify_recursively(&proof, &data, &keccak_input_provers());
}

/// A layer-0 proof whose circuit calls the BLAKE3 compression verifies inside a recursive
/// circuit, and that circuit proves and verifies.
#[test]
fn a_blake3_batch_proof_verifies_recursively() {
    let (proof, data) = prove_blake3_batch();
    verify_recursively(&proof, &data, &blake3_input_provers());
}

/// Verifies a D=1 layer-0 batch proof inside a recursive circuit, then proves and verifies that
/// circuit.
fn verify_recursively(
    batch_stark_proof: &BatchStarkProof<MyConfig>,
    circuit_prover_data: &CircuitProverData<MyConfig>,
    input_provers: &[Box<dyn TableProver<MyConfig>>],
) {
    let lookup_gadget = LogUpGadget::new();
    let common = circuit_prover_data.common_data();

    // Now verify the batch STARK proof recursively
    // Use same permutation as proving to ensure Fiat-Shamir transcript compatibility
    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.max_log_arity,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
        scalars.num_queries,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    );
    let config = make_test_config();

    // Extract proof components
    let batch_proof = &batch_stark_proof.proof;

    const TRACE_D: usize = 1; // Proof traces are in base field

    // Public values (empty for all 5 circuit tables: Witness, Const, Public, Alu, Poseidon2)
    let num_tables = common
        .preprocessed
        .as_ref()
        .map(|g| g.instances.len())
        .unwrap_or(0);
    let pis: Vec<Vec<F>> = vec![vec![]; num_tables];

    // Build the recursive verification circuit
    let mut circuit_builder = CircuitBuilder::new();
    let poseidon2_perm = default_koalabear_poseidon2_16();
    circuit_builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
        poseidon2_perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    // Attach verifier without manually building circuit_airs
    let (verifier_inputs, mmcs_op_ids) = verify_p3_batch_proof_circuit::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        LogUpGadget,
        _,
        WIDTH,
        RATE,
        TRACE_D,
    >(
        &config,
        &mut circuit_builder,
        batch_stark_proof,
        &fri_verifier_params,
        common,
        &lookup_gadget,
        Poseidon2Config::KOALA_BEAR_D4_W16,
        input_provers,
    )
    .unwrap();

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Pack values using the builder
    let (public_inputs, private_inputs) = verifier_inputs.pack_values(&pis, batch_proof, common);

    assert_eq!(public_inputs.len(), expected_public_input_len);
    assert!(!public_inputs.is_empty());

    let verification_table_packing = TablePacking::new(1, 8);
    let poseidon2_config = Poseidon2Config::KOALA_BEAR_D4_W16;
    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::new(true)),
    ];
    let mut air_builders = poseidon2_air_builders_for_configs::<_, 4>(vec![
        poseidon2_config.for_challenger(),
        poseidon2_config,
    ]);
    air_builders.extend(recompose_air_builders(1, true));
    let (
        verification_airs_degrees,
        verification_primitive_columns,
        verification_non_primitive_columns,
    ) = get_airs_and_degrees_with_prep::<MyConfig, _, 4>(
        &verification_circuit,
        &verification_table_packing,
        &npo_prep,
        &air_builders,
        ConstraintProfile::Standard,
    )
    .unwrap();
    let (verification_airs, verification_degrees): (Vec<_>, Vec<usize>) =
        verification_airs_degrees.into_iter().unzip();

    // Now run the circuit to generate traces
    let mut runner = verification_circuit.runner();
    runner.set_public_inputs(&public_inputs).unwrap();
    runner.set_private_inputs(&private_inputs).unwrap();

    // Set MMCS private data for the verification circuit. The FRI proof shares one pruned
    // Merkle multiproof across all queries, so the per-query chains the circuit walks are
    // restored from the proof's own verifier transcript first.
    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay_batch_layer_transcript::<MyConfig, TRACE_D>(
        &config,
        batch_stark_proof,
        common,
        input_provers,
    )
    .unwrap();
    let (val_mmcs, fri_params) = test_fri_instance();
    observe_opened_values::<MyConfig>(
        &mut challenger,
        &commitments_with_opening_points,
        fri_params.batch_proof_of_work_bits,
    );
    let claims: Vec<_> = commitments_with_opening_points
        .iter()
        .cloned()
        .map(Into::into)
        .collect();
    let query_paths = restore_fri_query_paths(
        &fri_params,
        &val_mmcs,
        &val_mmcs,
        &batch_stark_proof.proof.opening_proof,
        &mut challenger,
        &claims,
    )
    .unwrap();
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut runner,
        &mmcs_op_ids,
        &query_paths,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
    .unwrap();

    // Run the circuit to generate traces
    let verification_traces = runner.run().unwrap();

    // Create a new config and prover for the verification circuit
    let config3 = make_test_config();

    let verification_prover_data =
        ProverData::from_airs_and_degrees(&config3, &verification_airs, &verification_degrees)
            .unwrap();
    let verification_circuit_prover_data = CircuitProverData::new(
        verification_prover_data,
        verification_primitive_columns,
        verification_non_primitive_columns,
    );

    let mut verification_prover =
        BatchStarkProver::new(config3).with_table_packing(verification_table_packing);
    verification_prover.register_poseidon2_table::<4>(poseidon2_config.for_challenger());
    verification_prover.register_poseidon2_table::<4>(poseidon2_config);
    verification_prover.register_recompose_table::<4>(true);

    // Prove the verification circuit
    let verification_proof = verification_prover
        .prove_all_tables(&verification_traces, &verification_circuit_prover_data)
        .expect("Failed to prove verification circuit");

    // Verify the proof of the verification circuit
    verification_prover
        .verify_all_tables::<Challenge>(&verification_proof)
        .expect("Failed to verify proof of verification circuit");
}

mod through_the_fri_backend {
    use p3_circuit::ExprId;
    use p3_circuit::ops::{NpoTypeId, Poseidon2PermCall};
    use p3_koala_bear::KoalaBear;
    use p3_recursion::PcsRecursionBackend;
    use p3_recursion::challenger::CircuitChallenger;
    use p3_recursion::recursion::{
        BatchOnly, ProveNextLayerParams, RecursionInput, build_and_prove_next_layer,
    };
    use p3_recursion::traits::RecursiveChallenger;
    use p3_test_utils::koala_bear_params::Challenge;

    use super::*;

    type Config = crate::common::KoalaBearD4RecursionConfig;
    const CFG: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D4_W16;

    /// A recursion-style circuit (the default FRI backend's Poseidon2 and recompose tables) that
    /// also applies Keccak-f, proved with the Keccak-f table registered first or last.
    fn prove_with_keccak(
        keccak_first: bool,
    ) -> (
        Config,
        crate::common::KoalaBearD4Backend,
        BatchStarkProof<Config>,
    ) {
        let (config, backend) =
            crate::common::koala_bear_d4_recursion_config_and_backend_with_pow_bits(0);
        let mut circuit = CircuitBuilder::<Challenge>::new();
        circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
            default_koalabear_poseidon2_16(),
        );
        circuit.enable_recompose::<KoalaBear>(generate_recompose_trace::<KoalaBear, Challenge>);
        circuit.enable_keccak_f1600::<KoalaBear>();

        let mut challenger = CircuitChallenger::<16, 8, Poseidon2Config>::new_koalabear();
        for i in 0..8 {
            let value = circuit.alloc_const(Challenge::from_u64(i + 1), "observe");
            RecursiveChallenger::<KoalaBear, Challenge>::observe(
                &mut challenger,
                &mut circuit,
                value,
            );
        }
        for _ in 0..=8 {
            let _ =
                RecursiveChallenger::<KoalaBear, Challenge>::sample(&mut challenger, &mut circuit);
        }
        let ordinary: Vec<ExprId> = (0..CFG.width_ext())
            .map(|i| circuit.alloc_const(Challenge::from_u64(100 + i as u64), "ordinary"))
            .collect();
        circuit
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: CFG,
                new_start: true,
                merkle_path: false,
                mmcs_bit: None,
                mmcs_bit2: None,
                inputs: ordinary.into_iter().map(Some).collect(),
                out_ctl: vec![true; CFG.rate_ext()],
                return_all_outputs: false,
                mmcs_index_sum: None,
                absorb_len: 0,
            })
            .unwrap();
        let state: Vec<ExprId> = (0..KECCAK_STATE_LIMBS)
            .map(|i| {
                circuit.alloc_const(Challenge::from_u64((i as u64 * 911) % 65_536), "keccak_in")
            })
            .collect();
        let permuted = circuit.add_keccak_f1600(&state).unwrap();
        let _ = circuit.add_keccak_f1600(&permuted).unwrap();

        let circuit = circuit.build().unwrap();
        let traces = circuit.runner().run().unwrap();

        let table_packing = TablePacking::new(1, 1);
        let mut preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
            Box::new(Poseidon2Preprocessor),
            Box::new(RecomposePreprocessor::new(true)),
        ];
        preprocessors.push(Box::new(KeccakF1600Preprocessor));
        let mut air_builders: Vec<Box<dyn NpoAirBuilder<Config, 4>>> = Vec::new();
        if keccak_first {
            air_builders.push(Box::new(KeccakF1600AirBuilder::<4>));
        }
        air_builders.extend(poseidon2_air_builders_for_configs::<Config, 4>(vec![
            CFG.for_challenger(),
            CFG,
        ]));
        air_builders.extend(recompose_air_builders::<Config, 4>(1, true));
        if !keccak_first {
            air_builders.push(Box::new(KeccakF1600AirBuilder::<4>));
        }
        let (airs_degrees, primitive_columns, non_primitive_columns) =
            get_airs_and_degrees_with_prep::<Config, Challenge, 4>(
                &circuit,
                &table_packing,
                &preprocessors,
                &air_builders,
                ConstraintProfile::Standard,
            )
            .unwrap();
        let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
        let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &degrees).unwrap();
        let circuit_prover_data =
            CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
        let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
        if keccak_first {
            prover.register_table_prover(Box::new(KeccakF1600Prover::<4>));
        }
        prover.register_poseidon2_table::<4>(CFG.for_challenger());
        prover.register_poseidon2_table::<4>(CFG);
        prover.register_recompose_table::<4>(true);
        if !keccak_first {
            prover.register_table_prover(Box::new(KeccakF1600Prover::<4>));
        }
        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        prover.verify_all_tables::<Challenge>(&proof).unwrap();
        assert!(
            proof
                .non_primitives
                .iter()
                .any(|entry| entry.op_type == NpoTypeId::keccak_f1600())
        );
        (config, backend, proof)
    }

    fn recurses(keccak_first: bool) {
        let (config, backend, proof) = prove_with_keccak(keccak_first);

        // The backend alone does not know the Keccak-f table; the provided
        // `input_table_provers` adds it at its manifest position.
        let manifest: Vec<NpoTypeId> = proof
            .non_primitives
            .iter()
            .map(|entry| entry.op_type.clone())
            .collect();
        let op_types = |provers: Vec<Box<dyn TableProver<Config>>>| -> Vec<NpoTypeId> {
            provers
                .iter()
                .map(|p| TableProver::op_type(p.as_ref()))
                .collect()
        };
        let backend_only = op_types(
            PcsRecursionBackend::<Config, BatchOnly, 4>::non_primitive_input_provers(
                &backend,
                proof.ext_degree,
                &manifest,
            ),
        );
        assert_ne!(backend_only, manifest);
        let with_hash_tables = op_types(
            PcsRecursionBackend::<Config, BatchOnly, 4>::input_table_provers(
                &backend,
                proof.ext_degree,
                &manifest,
            ),
        );
        assert_eq!(with_hash_tables, manifest);

        let input: RecursionInput<'_, Config, BatchOnly> = RecursionInput::BatchStark {
            proof: &proof,
            common_data: &proof.stark_common,
            table_public_inputs: vec![vec![]; proof.proof.opened_values.instances.len()],
        };
        build_and_prove_next_layer(&input, &config, &backend, &ProveNextLayerParams::default())
            .expect("a proof with a Keccak-f table recurses through the FRI backend");
    }

    #[test]
    fn a_keccak_table_registered_last_recurses() {
        recurses(false);
    }

    #[test]
    fn a_keccak_table_registered_first_recurses() {
        recurses(true);
    }
}
