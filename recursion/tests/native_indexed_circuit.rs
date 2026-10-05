//! Native indexed proofs enforce compact circuit wiring across committed tables.

use p3_air::BaseAir;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::{Circuit, CircuitBuilder, ops::ByteHash};
use p3_circuit_prover::indexed::IndexedCircuit;
use p3_field::PrimeCharacteristicRing;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::VerifierLimits;

type F = BinaryField128;

fn circuit(constant: F) -> Circuit<F> {
    let mut builder = CircuitBuilder::new();
    let input = builder.public_input();
    let expected = builder.public_input();
    let private = builder.alloc_private_input("factor");
    let product = builder.mul(input, private);
    // Repeated reads have no field-valued integer multiplicity.
    let reused = builder.mul(product, input);
    let constant = builder.define_const(constant);
    let out = builder.add(reused, constant);
    builder.connect(out, expected);
    builder.build().unwrap()
}

fn spec(prepared: &IndexedCircuit<F>) -> BinaryNativeVerifierSpec {
    let parameters = |variables, hash, cap_height| BinaryNativePcsParameters {
        config: BinaryPcsConfig::try_new::<F, F>(
            variables,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 8,
            },
        )
        .unwrap(),
        hash,
        cap_height,
        max_query_draws: 128,
    };
    BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables(), ByteHash::Blake3, 0),
        preprocessed: prepared
            .preprocessed_variables()
            .map(|n| parameters(n, ByteHash::Keccak256, 1)),
        transcript_hash: ByteHash::Blake3,
        initial_bytes: b"native-indexed-circuit-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    }
}

#[test]
fn native_proof_binds_all_operands_outputs_and_fixed_preprocessing() {
    let [a, b, constant] = [0x1234567, 0xdeadbeef, 0xabcd].map(F::from_repr);
    let circuit = circuit(constant);
    let prepared = IndexedCircuit::new(&circuit).unwrap();
    let statement = [a, a * b * a + constant];
    let public = prepared.public_values(&statement).unwrap();
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared),
        &VerifierLimits::default(),
    )
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&[b]).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let proof = prover.prove(&public, traces.clone()).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let mut wrong = public.clone();
    wrong.last_mut().unwrap()[1] += F::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());

    // Keep the multiplication row locally valid while disconnecting its
    // operand and output payloads from the canonical witness provider.
    let pp = prepared.airs()[1].preprocessed_trace().unwrap();
    let row = pp
        .values
        .chunks(pp.width)
        .position(|row| row[8] == F::ONE)
        .unwrap();
    let mut forged = traces;
    let gate = &mut forged[1].values[row * 10..(row + 1) * 10];
    gate[5] += F::ONE;
    gate[9] = gate[5] * gate[6];
    let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.prove(&public, forged)
    }));
    if let Ok(Ok(forged_proof)) = attempted {
        assert!(authority.verify_native(&forged_proof, &public).is_err());
    }

    let changed = IndexedCircuit::new(&self::circuit(constant + F::ONE)).unwrap();
    let (_, other_authority) = BinaryNativeAuthority::<F, F, _>::setup(
        changed.airs().to_vec(),
        changed.log_heights().to_vec(),
        spec(&changed),
        &VerifierLimits::default(),
    )
    .unwrap();
    assert_ne!(
        authority.canonical_verifier_bytes(),
        other_authority.canonical_verifier_bytes()
    );
    assert!(other_authority.verify_native(&proof, &public).is_err());
}

#[test]
fn indexed_circuit_proves_over_poly64_with_poly192_challenges() {
    use p3_binary_field::Poly64;
    use p3_recursion::artifact::{
        BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    };
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};
    let mut builder = CircuitBuilder::<Poly64>::new();
    let input = builder.public_input();
    let expected = builder.public_input();
    let factor = builder.alloc_private_input("factor");
    let product = builder.mul(input, factor);
    builder.connect(product, expected);
    let circuit = builder.build().unwrap();
    let prepared = IndexedCircuit::new(&circuit).unwrap();
    let [a, b] = [0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210].map(Poly64::new);
    let statement = [a, a * b];
    let public = prepared.public_values(&statement).unwrap();
    let parameters = |variables| {
        BinaryNativePolyWhirPcsParameters::new(
            variables,
            ProtocolParameters {
                starting_log_inv_rate: 2,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                security_level: 24,
                pow_bits: 0,
            },
            ByteHash::Blake3,
            0,
        )
        .unwrap()
    };
    let spec = BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables()),
        preprocessed: prepared.preprocessed_variables().map(parameters),
        transcript_hash: ByteHash::Blake3,
        initial_bytes: b"native-poly-indexed-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 16,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&[b]).unwrap();
    let proof = prover
        .prove(
            &public,
            prepared
                .traces(&runner.run().unwrap().witness_trace)
                .unwrap(),
        )
        .unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let mut wrong = public;
    wrong.last_mut().unwrap()[1] += Poly64::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());
}
