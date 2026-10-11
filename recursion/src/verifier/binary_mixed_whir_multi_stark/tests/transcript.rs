//! A random native transcript circuit proven with its Keccak table dense and bit-committed.

use p3_circuit_prover::native_bus::KeccakCommitment;

use super::keccak_chain::native_bus;
use super::*;
use crate::challenger::transcript_tests::tower_transcript;

/// The refills of a random Tower128 transcript read swapped digest limbs from native
/// Keccak-f calls. The circuit's traces prove and verify with the Keccak table committed
/// densely and as bits, and the proof does not verify for a changed observation.
#[test]
fn random_transcript_circuits_prove_in_both_modes() {
    let (circuit, statement) = tower_transcript(5, 24);
    let swapped_calls = circuit
        .ops
        .iter()
        .filter(|op| {
            matches!(op, p3_circuit::Op::NonPrimitiveOpWithExecutor { outputs, .. }
                if outputs[0].len() == 116)
        })
        .count();
    assert!(
        swapped_calls > 1,
        "{swapped_calls} refills read swapped limbs"
    );
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let mut wrong = statement.clone();
    wrong[0] += F::ONE;

    for mode in [KeccakCommitment::Dense, KeccakCommitment::Bits] {
        let bus = native_bus(&circuit, mode);
        let config =
            Parameters::new(bus.airs(), bus.log_heights(), bus.keccak_table_index()).config();
        let airs = bus.airs().iter().collect::<Vec<_>>();
        let (proving, verifying) = setup(&config, &airs, &mut challenger()).unwrap();
        let public = bus.public_values(&statement).unwrap();
        let tables = bus
            .traces(&witness)
            .unwrap()
            .into_iter()
            .map(|trace| Table::new(trace.transpose()));
        let proof = prove(
            &config,
            ProverInstances::new(
                airs.iter()
                    .zip(tables)
                    .zip(&public)
                    .map(|((air, table), public)| {
                        ProverInstance::new(*air, table, &proving, public)
                    })
                    .collect(),
            ),
            0,
            &mut challenger(),
        )
        .unwrap();
        let verifies = |public: &[Vec<F>]| {
            verify(
                &config,
                VerifierInstances::new(
                    airs.iter()
                        .zip(bus.log_heights())
                        .zip(public)
                        .map(|((air, &height), public)| {
                            VerifierInstance::new(*air, &verifying, height, public)
                        })
                        .collect(),
                ),
                &proof,
                0,
                &mut challenger(),
            )
            .is_ok()
        };
        assert!(verifies(&public), "{mode:?}");
        assert!(!verifies(&bus.public_values(&wrong).unwrap()), "{mode:?}");
    }
}
