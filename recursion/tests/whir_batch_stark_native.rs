mod common;

use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::pcs::whir::uni::WhirUniProofTargets;
use p3_recursion::traits::PreparedRecursive;

use crate::common::whir_config::{BB_DIGEST_ELEMS, BbEF, BbF, BbMmcs, bb_whir_config};

/// The value [`generate_trace_rows::<BbF>(0, 1, n)`]'s last row claims as its
/// output, i.e. `F(n)` for the sequence started at `F(0) = 0`, `F(1) = 1`.
fn fibonacci_output(n: usize) -> BbF {
    let (mut a, mut b) = (BbF::ZERO, BbF::ONE);
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}

/// A WHIR-backed `StarkGenericConfig` proves and verifies a two-instance native
/// batch-STARK proof, with no circuit or recursion involved -- confirming
/// `WhirUniPcs`'s generic `Pcs` impl is sufficient for `p3_batch_stark` before any
/// in-circuit batch-STARK work is attempted.
#[test]
fn whir_backed_batch_stark_proves_two_instances() {
    let config = bb_whir_config(vec![4]);
    let air = FibonacciAir {};

    let n1 = 1 << 8;
    let trace1 = generate_trace_rows::<BbF>(0, 1, n1);
    let pis1 = vec![BbF::ZERO, BbF::ONE, fibonacci_output(n1)];

    let n2 = 1 << 9;
    let trace2 = generate_trace_rows::<BbF>(0, 1, n2);
    let pis2 = vec![BbF::ZERO, BbF::ONE, fibonacci_output(n2)];

    let instances = vec![
        StarkInstance {
            air: &air,
            trace: &trace1,
            public_values: pis1.clone(),
        },
        StarkInstance {
            air: &air,
            trace: &trace2,
            public_values: pis2.clone(),
        },
    ];

    let prover_data = ProverData::from_instances(&config, &instances);
    let common = &prover_data.common;
    let proof = prove_batch(&config, &instances, &prover_data);
    let _shape = WhirUniProofTargets::<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>::input_shape(
        &proof.opening_proof,
    )
    .expect("honest batch-STARK WHIR shape capture succeeds");

    let airs = vec![air; 2];
    let pvs = vec![pis1, pis2];
    verify_batch(&config, &airs, &proof, &pvs, common).expect("WHIR-backed batch-STARK verifies");
}
