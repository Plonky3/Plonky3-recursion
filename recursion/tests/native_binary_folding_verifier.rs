//! A complete native verifier closes a folding MultiStark proof.

use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError};
use p3_circuit_prover::native_bus::NativeBusCircuit;
use p3_field::{ExtensionField, PrimeCharacteristicRing};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::{VerificationError, VerifierLimits};

type F = BinaryField128;
type H = NativeBinaryEncoding;

fn run(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

fn spec<B>(prepared: &NativeBusCircuit<B>, hash: ByteHash) -> BinaryNativeVerifierSpec
where
    B: RecursiveBinaryTowerField + BinaryCoordinateField + p3_binary_dft::EncodableLevel,
    F: ExtensionField<B>,
{
    let parameters = |n| BinaryNativePcsParameters {
        config: BinaryPcsConfig::try_new::<B, F>(
            n,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 8,
            },
        )
        .unwrap(),
        hash,
        cap_height: 0,
        max_query_draws: 128,
    };
    BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables()),
        preprocessed: prepared.preprocessed_variables().map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-folding-verifier-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    }
}

#[test]
fn native_verifier_closes_a_folding_bus_proof_with_trusted_preprocessing() {
    close_bus_proof::<F>();
}

#[test]
fn tower32_folding_child_is_closed_in_a_tower128_verifier() {
    close_bus_proof::<BinaryField32>();
}

#[test]
fn blake3_pcs_child_is_rejected_before_constraints() {
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let out = b.mul(input, input);
    let expected = b.public_input();
    b.connect(out, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    let setup = |hash| {
        BinaryNativeAuthority::<F, F, _>::setup(
            prepared.airs().to_vec(),
            prepared.log_heights().to_vec(),
            spec(&prepared, hash),
            &VerifierLimits::default(),
        )
        .unwrap()
        .1
    };
    let unsupported = |error: &VerificationError| {
        matches!(
            error,
            VerificationError::CircuitBuilder(
                CircuitBuilderError::UnsupportedNonPrimitiveOp { .. }
            )
        )
    };
    let authority = setup(ByteHash::Blake3);
    let verifier = authority.recursive_verifier();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let error = verifier
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap_err();
    assert!(unsupported(&error), "{error}");
    // Inputs shaped by a Keccak twin still cannot reach any BLAKE3 constraint.
    let twin = setup(ByteHash::Keccak256);
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let targets = twin
        .recursive_verifier()
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap();
    let ch = BinaryTower128Challenger::new(ByteHash::Keccak256);
    let public: Vec<Vec<_>> = verifier
        .input_shape()
        .public_value_counts()
        .map(|count| {
            (0..count)
                .map(|_| {
                    let e = b.public_input();
                    b.native_tower128_from_expr(e)
                })
                .collect()
        })
        .collect();
    let before = b.construction_usage().unwrap();
    let error = verifier
        .verify_native(&mut b, ch, &public, &targets)
        .unwrap_err();
    assert!(unsupported(&error), "{error}");
    assert_eq!(b.construction_usage().unwrap(), before);
}

fn close_bus_proof<B>()
where
    B: RecursiveBinaryTowerField
        + BinaryCoordinateField
        + p3_binary_dft::EncodableLevel
        + p3_binary_pcs::FoldAlphabet<F>
        + p3_field::PackedValue<Value = B>,
    F: ExtensionField<B> + p3_binary_pcs::ChallengeField<B>,
{
    let mask = u128::MAX >> (128 - B::RAW_BITS);
    let [a, factor, constant] = [0x8123456789abcdef, 0xfedcba9876543210, 0x8912]
        .map(|raw| B::from_raw_coordinates(raw & mask).unwrap());
    let mut b = CircuitBuilder::<B>::new();
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
    assert!(prepared.preprocessed_variables().is_some());
    let (prover, authority) = BinaryNativeAuthority::<B, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared, ByteHash::Keccak256),
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
    let token = authority.verify_native(&proof, &public).unwrap();
    let verifier = authority.recursive_verifier();
    let shape = verifier.input_shape();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let expected: Vec<Vec<_>> = public
        .iter()
        .map(|values| {
            values
                .iter()
                .map(|_| {
                    let e = b.public_input();
                    b.native_tower128_from_expr(e)
                })
                .collect()
        })
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
    let flat: Vec<_> = public
        .iter()
        .flatten()
        .map(|value| F::from_repr(value.raw_coordinates()))
        .collect();
    assert!(run(&recursive, &flat, &private));
    let mut wrong = flat.clone();
    wrong[1] += F::ONE;
    assert!(!run(&recursive, &wrong, &private));
    if B::RAW_BITS < 128 {
        let mut high = flat.clone();
        high[0] += F::from_repr(1u128 << B::RAW_BITS);
        assert!(!run(&recursive, &high, &private));
    }
    for index in [0, 16, private.len() / 2, private.len() - 1] {
        let mut wrong = private.clone();
        wrong[index] += F::ONE;
        assert!(!run(&recursive, &flat, &wrong));
    }
}
