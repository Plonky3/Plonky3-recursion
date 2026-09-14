use alloc::vec;

use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove, verify};
use p3_whir::pcs::proof::QueryOpenings;

use super::{WhirRecursionBackend, WhirRecursionBackendForExt};
use crate::Poseidon2Config;
use crate::pcs::whir::uni::acceptance_probe::{Counters, measure};
use crate::prepared::{PreparedInput, PreparedLayer, PreparedSource};
use crate::recursion::{
    PcsRecursionBackend, ProveNextLayerParams, RecursionInput, VerifierCircuitResult,
    build_next_layer_circuit,
};

#[allow(dead_code)]
#[path = "../../../tests/common/whir_config.rs"]
mod whir_config;

use whir_config::{BbF, BbWhirConfig, bb_whir_config};

fn assert_no_later_work(counters: Counters, stage: &str) {
    assert_eq!(
        counters,
        Counters::default(),
        "malformed last WHIR argument reached {stage}: {counters:?}"
    );
}

#[test]
fn checked_caller_rejects_malformed_last_argument_before_all_later_stages() {
    let log_n = 10;
    let n = 1 << log_n;
    let trace = generate_trace_rows::<BbF>(0, 1, n);
    let public_inputs = vec![BbF::ZERO, BbF::ONE, fibonacci_output(n)];
    let air = FibonacciAir {};
    let config = bb_whir_config(vec![]);
    let mut proof = prove(&config, &air, trace, &public_inputs);
    verify(&config, &air, &proof, &public_inputs).expect("the native control proof verifies");
    assert!(
        proof.opening_proof.rounds.len() >= 2,
        "the checked-caller control needs a later commitment"
    );
    let backend: WhirRecursionBackendForExt<4> =
        WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
            .for_extension_degree::<4>();

    let input = RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs: public_inputs.clone(),
        preprocessed_commit: None,
    };
    let ((circuit, result), build_counts) = measure(|| {
        build_next_layer_circuit::<BbWhirConfig, _, _, 4>(&input, &config, &backend)
            .expect("the honest checked caller builds")
    });
    assert!(build_counts.target_new > 0);
    assert!(build_counts.target_challenger > 0);
    assert_eq!(build_counts.get_values, 0);
    assert_eq!(build_counts.get_private_values, 0);
    assert_eq!(build_counts.transcript_replay, 0);
    assert_eq!(build_counts.query_replay, 0);
    assert_eq!(build_counts.restoration, 0);

    let (public_values, public_counts) = measure(|| result.pack_public_inputs(&input));
    assert!(
        !public_values
            .expect("honest public packing succeeds")
            .is_empty()
    );
    assert_eq!(public_counts.get_values, 1);
    assert_eq!(public_counts.get_private_values, 0);

    let (private_values, private_counts) = measure(|| result.pack_private_inputs(&input));
    assert!(
        !private_values
            .expect("honest private packing succeeds")
            .is_empty()
    );
    assert_eq!(private_counts.get_values, 0);
    assert_eq!(private_counts.get_private_values, 1);

    let mut runner = circuit.runner();
    let (setup, setup_counts) =
        measure(|| backend.set_private_data_for_result(&config, &mut runner, &result, &input));
    setup.expect("honest result-aware private setup succeeds");
    assert_eq!(setup_counts.transcript_replay, 1);
    assert_eq!(setup_counts.query_replay, 1);
    assert_eq!(setup_counts.restoration, 1);

    let prepared = PreparedLayer::<BbWhirConfig, FibonacciAir, _, 4>::new(
        PreparedSource::UniStark {
            air: &air,
            proof: &proof,
            public_inputs: &public_inputs,
            preprocessed_commit: None,
        },
        config.clone(),
        backend.clone(),
        ProveNextLayerParams::default(),
    )
    .expect("the honest WHIR reference prepares");

    drop(input);
    let last = proof
        .opening_proof
        .rounds
        .last_mut()
        .expect("the proof has a last WHIR argument");
    match &mut last.whir.final_openings {
        QueryOpenings::Base(opening) => {
            opening.rows.last_mut().unwrap().pop();
        }
        QueryOpenings::Extension(opening) => {
            opening.rows.last_mut().unwrap().pop();
        }
    }
    let malformed = RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs,
        preprocessed_commit: None,
    };

    let (fresh, fresh_counts) = measure(|| {
        build_next_layer_circuit::<BbWhirConfig, _, _, 4>(&malformed, &config, &backend)
    });
    assert!(fresh.is_err());
    assert_no_later_work(fresh_counts, "fresh checked build");

    let (public, public_counts) = measure(|| result.pack_public_inputs(&malformed));
    assert!(public.is_err());
    assert_no_later_work(public_counts, "retained public packing");

    let (private, private_counts) = measure(|| result.pack_private_inputs(&malformed));
    assert!(private.is_err());
    assert_no_later_work(private_counts, "retained private packing");

    let mut runner = circuit.runner();
    let (private_setup, private_setup_counts) =
        measure(|| backend.set_private_data_for_result(&config, &mut runner, &result, &malformed));
    assert!(private_setup.is_err());
    assert_no_later_work(
        private_setup_counts,
        "result-aware transcript replay/restoration",
    );

    let (prepared_result, prepared_counts) = measure(|| {
        prepared.prove(PreparedInput::UniStark {
            proof: &proof,
            public_inputs: match &malformed {
                RecursionInput::UniStark { public_inputs, .. } => public_inputs,
                RecursionInput::BatchStark { .. } => unreachable!(),
            },
            preprocessed_commit: None,
        })
    });
    assert!(prepared_result.is_err());
    assert_no_later_work(prepared_counts, "prepared replacement");
}

fn fibonacci_output<F: PrimeCharacteristicRing + Copy>(n: usize) -> F {
    let (mut a, mut b) = (F::ZERO, F::ONE);
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}
