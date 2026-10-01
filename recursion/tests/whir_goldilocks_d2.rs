//! A custom Goldilocks D2 WHIR backend and real recursive proof fixture.

#[path = "common/goldilocks_whir_config.rs"]
mod goldilocks_whir_config;

use goldilocks_whir_config::{GoldF, GoldWhirConfig, gold_whir_config};
use p3_circuit::ops::NpoTypeId;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_recursion::backend::whir::{
    CheckedWhirVerifierResult, WhirRecursionBackend, WhirRecursionBackendForExt,
};
use p3_recursion::pcs::whir::uni::packed_digest_len;
use p3_recursion::{
    PcsRecursionBackend, Poseidon2Config, PreparedPcsRecursionBackend, RecursionInput,
    TrustedPcsRecursionBackend, VerificationError, VerifierCircuitResult, build_next_layer_circuit,
};
use p3_uni_stark::{prove, verify};

type GoldBackend = WhirRecursionBackendForExt<2, 8, 4>;

fn gold_backend() -> GoldBackend {
    WhirRecursionBackend::<8, 4>::new(Poseidon2Config::GOLDILOCKS_D2_W8).for_extension_degree::<2>()
}

fn fibonacci_output(a: u64, b: u64, n: usize) -> GoldF {
    let (mut a, mut b) = (GoldF::from_u64(a), GoldF::from_u64(b));
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    b
}

#[test]
fn goldilocks_d2_backend_implements_all_three_recursion_traits() {
    fn require_all_three<B>()
    where
        B: PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>
            + PreparedPcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>
            + TrustedPcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>,
    {
    }
    require_all_three::<GoldBackend>();
}

#[test]
fn goldilocks_d2_manifests_select_shared_output_and_legacy_input() {
    let backend = gold_backend();
    let shared =
        NpoTypeId::poseidon2_perm(Poseidon2Config::GOLDILOCKS_D2_W8.for_shared_challenger_table());
    let challenger = NpoTypeId::poseidon2_perm(Poseidon2Config::GOLDILOCKS_D2_W8.for_challenger());
    let ordinary = NpoTypeId::poseidon2_perm(Poseidon2Config::GOLDILOCKS_D2_W8);
    let coefficient_bound = NpoTypeId::recompose_with_coeff_lookups();

    let output = <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_provers(&backend, 2);
    assert_eq!(
        output
            .iter()
            .map(|prover| prover.op_type())
            .collect::<Vec<_>>(),
        vec![shared.clone(), coefficient_bound.clone()]
    );

    let shared_input = <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_input_provers(&backend, 2, &[shared.clone(), coefficient_bound.clone()]);
    assert_eq!(
        shared_input
            .iter()
            .map(|prover| prover.op_type())
            .collect::<Vec<_>>(),
        vec![shared, coefficient_bound.clone()]
    );

    let legacy_input = <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_input_provers(&backend, 2, &[challenger.clone(), ordinary.clone()]);
    assert_eq!(
        legacy_input
            .iter()
            .map(|prover| prover.op_type())
            .collect::<Vec<_>>(),
        vec![challenger, ordinary, coefficient_bound]
    );

    let air_builders = <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_air_builders(&backend);
    assert_eq!(air_builders.len(), 2);
    assert_eq!(
        <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_preprocessors(&backend).len(),
        2
    );
    assert!(
        <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_provers(&backend, 4).is_empty()
    );
    assert!(
        <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_input_provers(
                &backend,
                4,
                &[NpoTypeId::poseidon2_perm(Poseidon2Config::GOLDILOCKS_D2_W8)]
            )
            .is_empty()
    );
}

#[test]
fn goldilocks_d2_whir_leaf_verifies_natively_and_in_recursive_circuit()
-> Result<(), VerificationError> {
    const N: usize = 1 << 10;
    const FIRST: u64 = (1 << 33) + 7;
    const SECOND: u64 = (1 << 34) + 11;
    let config = gold_whir_config();
    let backend = gold_backend();
    let air = FibonacciAir {};
    let statement = vec![
        GoldF::from_u64(FIRST),
        GoldF::from_u64(SECOND),
        fibonacci_output(FIRST, SECOND, N),
    ];
    assert_eq!(statement[0].as_canonical_u64(), FIRST);
    assert_eq!(statement[1].as_canonical_u64(), SECOND);
    let proof = prove(
        &config,
        &air,
        generate_trace_rows::<GoldF>(FIRST, SECOND, N),
        &statement,
    )
    .expect("Goldilocks WHIR leaf proof");
    verify(&config, &air, &proof, &statement).expect("native Goldilocks WHIR verification");

    assert_eq!(packed_digest_len(4, 2), 2);
    let trace_roots = proof.commitments.trace.clone().into_roots();
    assert_eq!(trace_roots.len(), 1);
    assert!(trace_roots.iter().all(|root| root.len() == 4));

    let input = RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs: statement,
        preprocessed_commit: None,
    };
    let (circuit, result) = build_next_layer_circuit::<GoldWhirConfig, FibonacciAir, GoldBackend, 2>(
        &input, &config, &backend,
    )?;
    assert!(
        !<CheckedWhirVerifierResult<GoldWhirConfig> as VerifierCircuitResult<
            GoldWhirConfig,
            FibonacciAir,
        >>::op_ids(&result)
        .is_empty(),
        "WHIR Merkle checking must be enabled"
    );
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&result.pack_public_inputs(&input)?)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&result.pack_private_inputs(&input)?)
        .map_err(VerificationError::Circuit)?;
    <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        set_private_data_for_result(&backend, &config, &mut runner, &result, &input)
            .map_err(|message| VerificationError::InvalidProofShape(message.into()))?;
    runner.run().map_err(VerificationError::Circuit)?;
    Ok(())
}
