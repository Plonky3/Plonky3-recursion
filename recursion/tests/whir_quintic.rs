//! KoalaBear quintic WHIR proofs with base-field Poseidon1 and Poseidon2 tables.

#[path = "../examples/common/mod.rs"]
mod common;

use common::*;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionBackendForExt};
use p3_recursion::{
    PreparedPcsRecursionBackend, TrustedPcsRecursionBackend, VerifierCircuitResult,
};
use p3_uni_stark::{prove, verify};

macro_rules! quintic_whir_test {
    (
        $module:ident, $perm:ty, $default_perm:path, $perm_config:expr,
        $config_type:ty, $circuit_config:ty, $enable_fn:ident, $gen_trace:ident,
        $params_trait:path, $register_fn:ident
    ) => {
        mod $module {
            // The shared example type macro also declares FRI configs unused in this fixture.
            #![allow(dead_code)]
            use super::*;

            define_field_module_types_quintic!(
                p3_koala_bear::KoalaBear,
                $perm,
                $default_perm,
                $perm_config,
                $circuit_config,
                16,
                8,
                8,
                || p3_test_utils::LiftPermToQuintic::<F, $perm, 16>::new($default_perm()),
                16,
                8,
                $enable_fn,
                $gen_trace,
                $params_trait
            );
            define_whir_module_types!(
                $default_perm,
                $perm_config,
                $circuit_config,
                $enable_fn,
                || p3_test_utils::LiftPermToQuintic::<F, $perm, 16>::new($default_perm()),
                $gen_trace
            );

            type Backend = WhirRecursionBackendForExt<5, 16, 8, $config_type>;

            fn verify_output(
                config: &ConfigWithWhirParams,
                params: &ProveNextLayerParams,
                output: &RecursionOutput<ConfigWithWhirParams>,
            ) {
                assert_eq!(output.0.ext_degree, 5);
                let mut verifier = BatchStarkProver::new(config.clone())
                    .with_table_packing(params.table_packing.clone());
                verifier.$register_fn::<5>($perm_config);
                verifier.register_recompose_table::<5>(true);
                verifier
                    .verify_all_tables::<Challenge>(&output.0)
                    .expect("quintic WHIR recursive batch proof verifies natively");
            }

            #[test]
            fn two_recursive_layers_verify_natively() -> Result<(), VerificationError> {
                fn require_all_traits<B>()
                where
                    B: PcsRecursionBackend<ConfigWithWhirParams, FibonacciAir, 5>
                        + PreparedPcsRecursionBackend<ConfigWithWhirParams, FibonacciAir, 5>
                        + TrustedPcsRecursionBackend<ConfigWithWhirParams, FibonacciAir, 5>,
                {
                }
                require_all_traits::<Backend>();

                let fp = FriParams {
                    log_blowup: 3,
                    max_log_arity: 1,
                    cap_height: 0,
                    log_final_poly_len: 0,
                    commit_pow_bits: 0,
                    query_pow_bits: 0,
                };
                let config = config_with_whir_params(&fp, 16, false, 2);
                let backend =
                    WhirRecursionBackend::<16, 8, _>::new($perm_config).for_extension_degree::<5>();
                let params = ProveNextLayerParams {
                    table_packing: TablePacking::new(1, 4).with_min_trace_height(128),
                    ..Default::default()
                };
                let air = FibonacciAir {};
                const N: usize = 128;
                let (mut a, mut b) = (F::ZERO, F::ONE);
                for _ in 1..N {
                    (a, b) = (b, a + b);
                }
                let statement = vec![F::ZERO, F::ONE, b];
                let proof = prove(&config, &air, generate_trace_rows::<F>(0, 1, N), &statement)
                    .expect("native quintic WHIR leaf proof");
                verify(&config, &air, &proof, &statement).unwrap();
                let parent = build_and_prove_next_layer::<ConfigWithWhirParams, FibonacciAir, _, 5>(
                    &RecursionInput::UniStark {
                        proof: &proof,
                        air: &air,
                        public_inputs: statement.clone(),
                        preprocessed_commit: None,
                    },
                    &config,
                    &backend,
                    &params,
                )?;
                verify_output(&config, &params, &parent);
                assert_eq!(parent.0.non_primitives.len(), 2);
                assert!(
                    parent
                        .0
                        .non_primitives
                        .iter()
                        .any(|entry| entry.op_type == NpoTypeId::recompose_with_coeff_lookups())
                );

                let grandparent =
                    build_and_prove_next_layer::<ConfigWithWhirParams, BatchOnly, _, 5>(
                        &parent.into_recursion_input::<BatchOnly>(),
                        &config,
                        &backend,
                        &params,
                    )?;
                verify_output(&config, &params, &grandparent);

                // A sibling reaches only the MMCS constraints; the transcript stays honest.
                let input = RecursionInput::UniStark {
                    proof: &proof,
                    air: &air,
                    public_inputs: statement,
                    preprocessed_commit: None,
                };
                let (circuit, result) =
                    build_next_layer_circuit::<ConfigWithWhirParams, FibonacciAir, _, 5>(
                        &input, &config, &backend,
                    )?;
                let transcript =
                    p3_recursion::backend::replay_recursion_input_transcript(&config, &input, &[])?;
                let vp = &config.verifier_params;
                let mut paths = p3_recursion::pcs::whir::uni::restore_whir_recursion_paths::<
                    ConfigWithWhirParams,
                    _,
                    _,
                    _,
                    _,
                    _,
                    DIGEST_ELEMS,
                >(
                    &config.mmcs,
                    transcript,
                    &proof.opening_proof,
                    vp.protocol_params(),
                    vp.folding(),
                    vp.variable_order(),
                )
                .expect("honest quintic WHIR Merkle paths");
                let sibling = paths
                    .iter_mut()
                    .flat_map(|path| {
                        path.rounds
                            .iter_mut()
                            .flatten()
                            .chain(path.final_paths.iter_mut())
                    })
                    .find_map(|chain| chain.first_mut())
                    .expect("fixture has a nontrivial Merkle path");
                sibling[0] += F::ONE;
                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&result.pack_public_inputs(&input)?)
                    .unwrap();
                runner
                    .set_private_inputs(&result.pack_private_inputs(&input)?)
                    .unwrap();
                let ids = <_ as VerifierCircuitResult<ConfigWithWhirParams, FibonacciAir>>::op_ids(
                    &result,
                );
                let mut offset = 0;
                for path in &paths {
                    let count = p3_recursion::pcs::whir::uni::whir_round_paths_op_count(path);
                    p3_recursion::pcs::set_whir_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
                        &mut runner,
                        &ids[offset..offset + count],
                        &path.rounds,
                        &path.final_paths,
                        $perm_config,
                    )
                    .unwrap();
                    offset += count;
                }
                assert_eq!(offset, ids.len());
                assert!(matches!(
                    runner.run(),
                    Err(CircuitError::WitnessConflict { .. })
                ));
                Ok(())
            }
        }
    };
}

quintic_whir_test!(
    poseidon2,
    p3_koala_bear::Poseidon2KoalaBear<16>,
    p3_koala_bear::default_koalabear_poseidon2_16,
    Poseidon2Config::KOALA_BEAR_D1_W16,
    Poseidon2Config,
    p3_circuit::ops::KoalaBearD1Width16,
    enable_poseidon2_perm_base,
    generate_poseidon2_trace,
    p3_circuit::ops::Poseidon2Params,
    register_poseidon2_table
);
quintic_whir_test!(
    poseidon1,
    p3_koala_bear::Poseidon1KoalaBear<16>,
    p3_koala_bear::default_koalabear_poseidon1_16,
    Poseidon1Config::KOALA_BEAR_D1_W16,
    Poseidon1Config,
    p3_circuit::ops::poseidon1_perm::KoalaBearD1Width16,
    enable_poseidon1_perm_base,
    generate_poseidon1_trace,
    p3_circuit::ops::Poseidon1Params,
    register_poseidon1_table
);
