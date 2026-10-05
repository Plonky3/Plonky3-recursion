//! Native product buses bind every fixed circuit occurrence without pushforwards.

use p3_air::{BaseAir, check_constraints};
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit_prover::native_bus::NativeBusCircuit;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::VerifierLimits;
use p3_symmetric::CryptographicHasher;

type F = BinaryField128;

fn spec(prepared: &NativeBusCircuit<F>) -> BinaryNativeVerifierSpec {
    spec_dimensions(prepared.main_variables(), prepared.preprocessed_variables())
}

fn spec_dimensions(main: usize, preprocessed: Option<usize>) -> BinaryNativeVerifierSpec {
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
    BinaryNativeVerifierSpec {
        main: parameters(main),
        preprocessed: preprocessed.map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-bus-circuit-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 4,
    }
}

#[test]
fn composed_circuits_cannot_cross_match_public_witnesses() {
    let constants = [
        F::from_repr(0x8123456789abcdef),
        F::from_repr(0xfedcba9876543210),
    ];
    let circuits: Vec<_> = constants
        .iter()
        .map(|&constant| {
            let mut b = CircuitBuilder::<F>::new();
            let public = b.public_input();
            let value = b.define_const(constant);
            b.connect(value, public);
            b.build().unwrap()
        })
        .collect();
    let prepared: Vec<_> = circuits
        .iter()
        .zip(["left", "right"])
        .map(|(circuit, namespace)| NativeBusCircuit::new(circuit, namespace).unwrap())
        .collect();
    let airs: Vec<_> = prepared
        .iter()
        .flat_map(|p| p.airs().iter().cloned())
        .collect();
    let heights: Vec<_> = prepared
        .iter()
        .flat_map(|p| p.log_heights().iter().copied())
        .collect();
    let main_cells: usize = airs
        .iter()
        .zip(&heights)
        .map(|(air, &log)| air.width() << log)
        .sum();
    let pp_cells: usize = airs
        .iter()
        .zip(&heights)
        .map(|(air, &log)| air.preprocessed_width() << log)
        .sum();
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        airs.clone(),
        heights,
        spec_dimensions(
            main_cells.next_power_of_two().ilog2() as usize,
            Some(pp_cells.next_power_of_two().ilog2() as usize),
        ),
        &VerifierLimits::default(),
    )
    .unwrap();
    let mut traces = Vec::new();
    let mut public = Vec::new();
    for ((circuit, prepared), constant) in circuits.iter().zip(&prepared).zip(constants) {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[constant]).unwrap();
        traces.extend(
            prepared
                .traces(&runner.run().unwrap().witness_trace)
                .unwrap(),
        );
        public.extend(prepared.public_values(&[constant]).unwrap());
    }
    let proof = prover.prove(&public, traces.clone()).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let public_tables: Vec<_> = airs
        .iter()
        .enumerate()
        .filter_map(|(i, air)| (air.num_public_values() != 0).then_some(i))
        .collect();
    let [left, right] = public_tables.as_slice() else {
        panic!("two public tables")
    };
    traces.swap(*left, *right);
    public.swap(*left, *right);
    for ((air, trace), expected) in airs.iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, expected);
    }
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.prove(&public, traces)
    }));
    if let Ok(Ok(proof)) = attempt {
        assert!(authority.verify_native(&proof, &public).is_err());
    }
}

#[test]
fn native_product_bus_authenticates_repeated_gate_reads() {
    let [a, factor, constant] = [0x8123456789abcdef, 0xfedcba9876543210, 0x8912].map(F::from_repr);
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
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared),
        &VerifierLimits::default(),
    )
    .unwrap();
    let statement = [a, a * factor * a + constant];
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&[factor]).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let proof = prover.prove(&public, traces.clone()).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    assert!(proof.indexed.is_none());
    assert!(proof.bus.is_some());
    let mut wrong = public.clone();
    *wrong
        .iter_mut()
        .find(|v| !v.is_empty())
        .unwrap()
        .last_mut()
        .unwrap() += F::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());
    // A different row-local multiplication still reads the fixed original IDs.
    let gate = traces.iter().position(|trace| trace.width == 5).unwrap();
    let pp = prepared.airs()[gate].preprocessed_trace().unwrap();
    let row = pp
        .values
        .chunks_exact(12)
        .position(|row| row[8] == F::ONE)
        .unwrap();
    let mut forged = traces;
    let payload = &mut forged[gate].values[5 * row..5 * (row + 1)];
    payload[0] += F::ONE;
    payload[4] = payload[0] * payload[1];
    check_constraints(&prepared.airs()[gate], &forged[gate], &[]);
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.prove(&public, forged)
    }));
    if let Ok(Ok(proof)) = attempt {
        assert!(authority.verify_native(&proof, &public).is_err());
    }
}

#[test]
fn native_product_buses_authenticate_keccak_call_boundaries() {
    let message = b"abc";
    let digest = Keccak256Hash.hash_iter(message.iter().copied());
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let input = b.alloc_public_input_array::<3>("message");
    let expected = b.alloc_public_input_array::<32>("digest");
    let actual = b.native_keccak256_bytes(&input).unwrap();
    for i in 0..32 {
        b.connect(actual[i], expected[i]);
    }
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared),
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
    assert!(proof.indexed.is_none());
    assert!(proof.bus.is_some());
    authority.verify_native(&proof, &public).unwrap();
    let mut wrong = public.clone();
    *wrong
        .iter_mut()
        .find(|v| !v.is_empty())
        .unwrap()
        .last_mut()
        .unwrap() += F::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());
    // Each boundary keeps its frozen tag and witness IDs. Swapping payloads
    // cannot substitute an unordered pair of genuine permutation boundaries.
    let mut forged = traces;
    let bridge = forged.last_mut().unwrap();
    for i in 0..100 {
        bridge.values.swap(i, 100 + i);
    }
    check_constraints(prepared.airs().last().unwrap(), bridge, &[]);
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.prove(&public, forged)
    }));
    if let Ok(Ok(proof)) = attempt {
        assert!(authority.verify_native(&proof, &public).is_err());
    }
}

#[test]
fn product_bus_circuit_proves_over_poly64_with_poly192_challenges() {
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
    let prepared = NativeBusCircuit::new(&circuit, "poly").unwrap();
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
            ByteHash::Keccak256,
            0,
        )
        .unwrap()
    };
    let spec = BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables()),
        preprocessed: prepared.preprocessed_variables().map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-poly-bus-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
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
