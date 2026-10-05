//! Complete Poly64 verifier binds product buses, AIR and both PCS openings.

use p3_binary_field::Poly64;
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::native_bus::NativeBusCircuit;
use p3_field::PrimeCharacteristicRing;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::artifact::{
    BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::VerifierLimits;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = Poly64;
type H = NativeBinaryEncoding;
fn run(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

#[test]
fn native_poly_verifier_closes_a_bus_proof_with_trusted_preprocessing() {
    let [a, factor, constant] = [0x8123456789abcdef, 0xfedcba9876543210, 0x8912].map(F::new);
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let expected = b.public_input();
    let private = b.alloc_private_input("factor");
    let product = b.mul(input, private);
    let reused = b.mul(product, input);
    let c = b.define_const(constant);
    let out = b.add(reused, c);
    b.connect(out, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    let parameters = |n| {
        BinaryNativePolyWhirPcsParameters::new(
            n,
            ProtocolParameters {
                security_level: 8,
                pow_bits: 0,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 2,
            },
            ByteHash::Keccak256,
            0,
        )
        .unwrap()
    };
    let spec = BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables()),
        preprocessed: prepared.preprocessed_variables().map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-recursive-verifier-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    let statement = [a, a * factor * a + constant];
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&[factor]).unwrap();
    let proof = prover
        .prove(
            &public,
            prepared
                .traces(&runner.run().unwrap().witness_trace)
                .unwrap(),
        )
        .unwrap();
    assert!(proof.bus.is_some());
    assert!(proof.indexed.is_none());
    let token = authority.verify_native(&proof, &public).unwrap();
    let verifier = authority.recursive_verifier();
    let shape = verifier.input_shape();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let expected: Vec<Vec<_>> = public
        .iter()
        .map(|values| values.iter().map(|_| b.public_input()).collect())
        .collect();
    let targets = shape.allocate_native_targets(&mut b).unwrap();
    let initial: Vec<_> = authority
        .initial_bytes()
        .iter()
        .map(|&byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()))
        .collect();
    let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
        &mut b,
        authority.transcript_hash(),
        &initial,
    )
    .unwrap();
    verifier
        .verify_native(&mut b, ch, &expected, &targets)
        .unwrap();
    let recursive = b.build().unwrap();
    let private = token.native_input().private_native_values(&shape).unwrap();
    let flat: Vec<_> = public.iter().flatten().copied().collect();
    assert!(run(&recursive, &flat, &private));
    let mut wrong = flat.clone();
    wrong[1] += F::ONE;
    assert!(!run(&recursive, &wrong, &private));
    for index in [0, 16, private.len() - 1] {
        let mut wrong = private.clone();
        wrong[index] += F::ONE;
        assert!(!run(&recursive, &flat, &wrong));
    }
}
