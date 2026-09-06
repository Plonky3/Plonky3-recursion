mod common;

use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
use p3_field::PrimeCharacteristicRing;
use p3_recursion::Poseidon2Config;
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionBackendForExt};
use p3_recursion::recursion::{
    BatchOnly, PcsRecursionBackend, ProveNextLayerParams, RecursionInput,
    build_and_prove_next_layer,
};
use p3_uni_stark::{prove, verify};
use p3_whir::pcs::proof::QueryOpenings;

use crate::common::whir_config::{BbEF, BbF, BbWhirConfig, bb_whir_config};

/// `WhirRecursionBackendForExt<4, ...>` must satisfy the exact `PcsRecursionBackend` bound
/// `recursion.rs`'s pipeline functions require; this fails to compile otherwise.
#[test]
fn whir_recursion_backend_satisfies_the_pcs_recursion_backend_bound() {
    fn assert_bound<B, SC, A>()
    where
        SC: p3_uni_stark::StarkGenericConfig,
        A: p3_recursion::traits::RecursiveAir<
                p3_uni_stark::Val<SC>,
                SC::Challenge,
                p3_lookup::logup::LogUpGadget,
            >,
        B: PcsRecursionBackend<SC, A, 4>,
    {
    }
    assert_bound::<WhirRecursionBackendForExt<4>, BbWhirConfig, FibonacciAir>();
}

fn fibonacci_output(n: usize) -> BbF {
    let (mut a, mut b) = (BbF::ZERO, BbF::ONE);
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}

/// A WHIR-backed uni-STARK proof, verified and PROVEN as a real recursion layer
/// through `WhirRecursionBackend` and the shared `recursion.rs` pipeline -- not
/// merely witness-checked the way the lower-level test helpers in
/// `whir_recursive_pcs.rs` do.
#[test]
fn whir_recursion_backend_proves_a_real_next_layer() {
    let log_n = 10;
    let n = 1 << log_n;
    let trace = generate_trace_rows::<BbF>(0, 1, n);
    let pis = vec![BbF::ZERO, BbF::ONE, fibonacci_output(n)];
    let air = FibonacciAir {};
    let config = bb_whir_config(vec![]);
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());

    let recursion_input = RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs: pis,
        preprocessed_commit: None,
    };

    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let params = ProveNextLayerParams::default();

    let output = build_and_prove_next_layer(&recursion_input, &config, &backend, &params)
        .expect("the recursion layer proves");

    // The recursion layer's own proof must itself verify -- this is the actual "prove it
    // recursively" bar, not just "the circuit's witness was satisfiable". There is no
    // free-standing `verify_batch_stark_proof` entry point; every other recursion
    // example/test in this crate verifies a `build_and_prove_next_layer` output the same way,
    // by registering the same non-primitive tables the backend used (both Poseidon2
    // challenger-shape tables, since `WhirRecursionBackend` always shares the challenger's
    // shape with the MMCS/compression rows, plus recompose) on a fresh `BatchStarkProver` and
    // calling `verify_all_tables`.
    let mut prover = BatchStarkProver::new(config).with_table_packing(params.table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.for_challenger());
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(true);
    prover
        .verify_all_tables::<BbEF>(&output.0)
        .expect("the recursion layer's own proof verifies");
}

/// A second WHIR-backed recursion layer verifies the *first* layer's own batch-STARK proof.
///
/// `RecursionInput::BatchStark` is only ever constructed from a `BatchStarkProver` output
/// (`RecursionOutput::into_recursion_input` is the production path), so batch-STARK support
/// in `WhirRecursionBackend` means exactly this: multi-layer chaining, where layer 2 is a
/// verifier circuit over layer 1's batch proof.
#[test]
fn whir_recursion_backend_proves_a_batch_stark_next_layer() {
    let log_n = 10;
    let n = 1 << log_n;
    let trace = generate_trace_rows::<BbF>(0, 1, n);
    let pis = vec![BbF::ZERO, BbF::ONE, fibonacci_output(n)];
    let air = FibonacciAir {};
    // An empty round schedule lets each WHIR commit derive its own round count from the size
    // of the polynomial being committed, which one config serving three differently-sized
    // roles (the base proof, layer 1's own commit, layer 2's own commit) requires.
    let config = bb_whir_config(vec![]);
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());

    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let params = ProveNextLayerParams::default();

    let layer1 = build_and_prove_next_layer(
        &RecursionInput::UniStark {
            proof: &proof,
            air: &air,
            public_inputs: pis,
            preprocessed_commit: None,
        },
        &config,
        &backend,
        &params,
    )
    .expect("the first recursion layer proves");

    let layer2_input = layer1.into_recursion_input::<BatchOnly>();
    let layer2 = build_and_prove_next_layer(&layer2_input, &config, &backend, &params)
        .expect("the second recursion layer proves over the first layer's batch-STARK proof");

    // As in the single-layer test: the layer's own proof has to verify, registering the same
    // non-primitive tables the backend used.
    let mut prover = BatchStarkProver::new(config).with_table_packing(params.table_packing);
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.for_challenger());
    prover.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    prover.register_recompose_table::<4>(true);
    prover
        .verify_all_tables::<BbEF>(&layer2.0)
        .expect("the second recursion layer's own proof verifies");
}

/// A tampered input proof must be rejected before a next-layer proof is ever produced,
/// through the real `WhirRecursionBackend` pipeline (not the lower-level circuit helpers
/// `whir_recursive_pcs.rs` already covers this way).
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursion_backend_rejects_a_tampered_input_proof() {
    let log_n = 10;
    let n = 1 << log_n;
    let trace = generate_trace_rows::<BbF>(0, 1, n);
    let pis = vec![BbF::ZERO, BbF::ONE, fibonacci_output(n)];
    let air = FibonacciAir {};
    let config = bb_whir_config(vec![]);
    let mut proof = prove(&config, &air, trace, &pis);
    proof.opened_values.quotient_chunks[0][0] += BbEF::ONE;

    let recursion_input = RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs: pis,
        preprocessed_commit: None,
    };

    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();

    build_and_prove_next_layer(
        &recursion_input,
        &config,
        &backend,
        &ProveNextLayerParams::default(),
    )
    .unwrap();
}

/// Builds an honest first WHIR recursion layer over a Fibonacci base proof, ready to be fed
/// (honest or tampered) into a second recursion layer.
fn build_honest_first_layer() -> (
    BbWhirConfig,
    WhirRecursionBackendForExt<4>,
    p3_recursion::recursion::RecursionOutput<BbWhirConfig>,
) {
    let log_n = 10;
    let n = 1 << log_n;
    let trace = generate_trace_rows::<BbF>(0, 1, n);
    let pis = vec![BbF::ZERO, BbF::ONE, fibonacci_output(n)];
    let air = FibonacciAir {};
    let config = bb_whir_config(vec![]);
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());

    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let params = ProveNextLayerParams::default();

    let layer1 = build_and_prove_next_layer(
        &RecursionInput::UniStark {
            proof: &proof,
            air: &air,
            public_inputs: pis,
            preprocessed_commit: None,
        },
        &config,
        &backend,
        &params,
    )
    .expect("the first recursion layer proves");

    (config, backend, layer1)
}

/// Tampering an opened value inside the FIRST layer's own batch-STARK proof -- before it is fed
/// into a SECOND WHIR recursion layer -- must be rejected: the second layer's own verifier
/// circuit connects this STARK-side opened value to the untampered copy carried inside the WHIR
/// PCS proof's own openings, so a mismatch here is a genuine circuit-constraint failure of the
/// second layer's own batch-STARK verification -- the `bound * scale == claimed` binding that
/// ties the two copies together, not a recomputation from the transcript.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursion_backend_rejects_a_tampered_first_layer_opened_value() {
    let (config, backend, mut layer1) = build_honest_first_layer();

    layer1.0.proof.opened_values.instances[0]
        .base_opened_values
        .quotient_chunks[0][0] += BbEF::ONE;

    let layer2_input = layer1.into_recursion_input::<BatchOnly>();
    build_and_prove_next_layer(
        &layer2_input,
        &config,
        &backend,
        &ProveNextLayerParams::default(),
    )
    .unwrap();
}

/// A tampered Merkle sibling digest in the FIRST layer's own batch-STARK proof must fail the
/// SECOND layer's own MMCS check specifically, isolated from any arithmetic check: unlike an
/// opened leaf value, a sibling digest plays no part in any transcript absorption or claimed-value
/// computation the second layer's circuit performs -- it only reaches the circuit through Merkle
/// path verification, so a rejection here can only come from the root-equality connect that check
/// makes. Mirrors `whir_recursive_verifier_rejects_a_tampered_sibling_digest` in
/// `whir_recursive_pcs.rs`, at the batch-STARK backend seam instead of the raw circuit-helper one.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursion_backend_rejects_a_tampered_first_layer_sibling_digest() {
    let (config, backend, mut layer1) = build_honest_first_layer();

    match &mut layer1.0.proof.opening_proof.rounds[0].whir.final_openings {
        QueryOpenings::Base(opening) => opening.proof.sibling_hashes[0][0] += BbF::ONE,
        QueryOpenings::Extension(opening) => opening.proof.sibling_hashes[0][0] += BbF::ONE,
    }

    let layer2_input = layer1.into_recursion_input::<BatchOnly>();
    build_and_prove_next_layer(
        &layer2_input,
        &config,
        &backend,
        &ProveNextLayerParams::default(),
    )
    .unwrap();
}
