//! Keccak circuit results are proved by native binary hash AIRs and indexed wiring.

use p3_binary_field::BinaryField128;
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::{
    CircuitBuilder,
    ops::{ByteHash, binary_native::BinaryCoordinateField},
};
use p3_circuit_prover::native_binary::NativeBinaryCircuit;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::VerifierLimits;
use p3_symmetric::CryptographicHasher;

type F = BinaryField128;

#[test]
fn native_binary_proof_enforces_keccak_and_its_witness_boundaries() {
    let message = b"abc";
    let digest = Keccak256Hash.hash_iter(message.iter().copied());
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let input = builder.alloc_public_input_array::<3>("message");
    let expected = builder.alloc_public_input_array::<32>("digest");
    let actual = builder.native_keccak256_bytes(&input).unwrap();
    for i in 0..32 {
        builder.connect(actual[i], expected[i]);
    }
    let circuit = builder.build().unwrap();
    let prepared = NativeBinaryCircuit::new(&circuit).unwrap();
    let parameters = |n| BinaryNativePcsParameters {
        config: BinaryPcsConfig::try_new::<F, F>(
            n,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 8,
            },
        )
        .unwrap(),
        hash: ByteHash::Keccak256,
        cap_height: 0,
        max_query_draws: 128,
    };
    let spec = BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables()),
        preprocessed: prepared.preprocessed_variables().map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-keccak-circuit-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec,
        // Indexed reductions and the wide hash AIR share a cumulative budget.
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    let statement: Vec<_> = message
        .iter()
        .chain(&digest)
        .map(|&byte| F::from_raw_coordinates(byte as u128).unwrap())
        .collect();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let proof = prover.prove(&public, traces.clone()).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let mut wrong = public.clone();
    *wrong
        .iter_mut()
        .find(|values| !values.is_empty())
        .unwrap()
        .last_mut()
        .unwrap() += F::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());

    // Fixed positions still match, but one bridge payload disagrees with
    // both canonical providers. Row-local constraints alone would accept it.
    let mut forged = traces;
    forged.last_mut().unwrap().values[101] += F::ONE;
    let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.prove(&public, forged)
    }));
    if let Ok(Ok(forged_proof)) = attempted {
        assert!(authority.verify_native(&forged_proof, &public).is_err());
    }
}
