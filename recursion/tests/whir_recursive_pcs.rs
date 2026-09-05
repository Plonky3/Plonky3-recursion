mod common;

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_commit::Pcs;
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::MerkleCapTargets;
use p3_recursion::pcs::whir::uni::{WhirUniProofTargets, WhirUniVerifierParams};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::traits::RecursivePcs;
use p3_recursion::{Poseidon2Config, VerificationError, verify_p3_uni_proof_circuit};
use p3_sumcheck::layout::{Layout, PrefixProver};
use p3_uni_stark::{StarkGenericConfig, prove, verify};

use crate::common::whir_config::{
    BB_DIGEST_ELEMS, BbEF, BbF, BbMmcs, BbWhirConfig, BbWhirPcs, bb_whir_perm,
    bb_whir_protocol_params,
};

/// The WHIR PCS must satisfy the exact `RecursivePcs` bound
/// `verify_p3_uni_proof_circuit` requires; this fails to compile otherwise.
#[test]
fn whir_pcs_satisfies_the_recursive_pcs_bound() {
    fn assert_bound<P>()
    where
        P: RecursivePcs<
                BbWhirConfig,
                (),
                WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>,
                MerkleCapTargets<BbF, BB_DIGEST_ELEMS>,
                <BbWhirPcs as Pcs<BbEF, <BbWhirConfig as StarkGenericConfig>::Challenger>>::Domain,
            >,
    {
    }
    assert_bound::<BbWhirPcs>();
}

/// Everything a recursive WHIR test needs for one instance.
pub struct WhirSetup {
    pub config: BbWhirConfig,
    pub air: FibonacciAir,
    pub pis: Vec<BbF>,
    pub proof: p3_uni_stark::Proof<BbWhirConfig>,
    pub round_log_inv_rates: Vec<usize>,
}

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

/// Proves a Fibonacci instance under WHIR with the given round schedule.
pub fn build_whir_setup(log_n: usize, round_log_inv_rates: Vec<usize>) -> WhirSetup {
    let n = 1 << log_n;
    let trace = generate_trace_rows::<BbF>(0, 1, n);
    let pis = vec![BbF::ZERO, BbF::ONE, fibonacci_output(n)];
    let air = FibonacciAir {};
    let config = crate::common::whir_config::bb_whir_config(round_log_inv_rates.clone());
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());
    WhirSetup {
        config,
        air,
        pis,
        proof,
        round_log_inv_rates,
    }
}

/// Builds and runs the recursive verifier circuit for `proof` and `pis`.
///
/// `with_mmcs` selects whether in-circuit Merkle path verification runs; when
/// it does, the caller must also supply the restored paths (Task 14 extends
/// this function).
pub fn run_whir_recursive_verifier(
    setup: &WhirSetup,
    proof: &p3_uni_stark::Proof<BbWhirConfig>,
    pis: &[BbF],
) -> Result<(), VerificationError> {
    let mut builder = CircuitBuilder::new();
    builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<BbEF, BabyBearD4Width16>,
        bb_whir_perm(),
    );
    builder.enable_recompose::<BbF>(generate_recompose_trace::<BbF, BbEF>);

    let params = WhirUniVerifierParams::<BbF>::new(
        bb_whir_protocol_params(setup.round_log_inv_rates.clone()),
        PrefixProver::<BbF, BbEF>::variable_order(),
        None,
    );

    let verifier_inputs = StarkVerifierInputsBuilder::<
        BbWhirConfig,
        MerkleCapTargets<BbF, BB_DIGEST_ELEMS>,
        WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>,
    >::allocate(&mut builder, proof, None, pis.len());

    let _op_ids = verify_p3_uni_proof_circuit::<
        FibonacciAir,
        BbWhirConfig,
        MerkleCapTargets<BbF, BB_DIGEST_ELEMS>,
        (),
        WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>,
        _,
        16,
        8,
    >(
        &setup.config,
        &setup.air,
        &mut builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )?;

    let circuit = builder.build()?;
    let mut runner = circuit.runner();
    let (public_inputs, private_inputs) = verifier_inputs.pack_values(pis, proof, &None);
    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;
    runner.run().map_err(VerificationError::Circuit)?;
    Ok(())
}

/// A WHIR-backed uni-STARK proof verifies inside the recursive circuit.
#[test]
fn whir_fibonacci_recursive_verifier_arithmetic_only() -> Result<(), VerificationError> {
    let setup = build_whir_setup(10, vec![4]);
    run_whir_recursive_verifier(&setup, &setup.proof, &setup.pis)
}

/// Wrong public inputs must break a circuit constraint, not merely a native check.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_fibonacci_recursive_verifier_rejects_wrong_public_inputs() {
    let setup = build_whir_setup(10, vec![4]);
    let mut wrong = setup.pis.clone();
    wrong[2] += BbF::ONE;
    run_whir_recursive_verifier(&setup, &setup.proof, &wrong).unwrap();
}
