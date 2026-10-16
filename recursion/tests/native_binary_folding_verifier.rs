//! A complete native verifier closes a folding MultiStark proof.

use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, NativeTower128Target};
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError, NpoTypeId};
use p3_circuit_prover::native_bus::NativeBusCircuit;
use p3_field::{ExtensionField, PrimeCharacteristicRing};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativeGroupedAuthority, BinaryNativeGroupedPcsParameters,
    BinaryNativeGroupedVerifierSpec, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::pcs::binary::{BinaryCodewordGrouping, RecursiveBinaryTowerField};
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
    spec_with_hashes(prepared, hash, hash)
}

fn spec_with_hashes<B>(
    prepared: &NativeBusCircuit<B>,
    main_hash: ByteHash,
    preprocessed_hash: ByteHash,
) -> BinaryNativeVerifierSpec
where
    B: RecursiveBinaryTowerField + BinaryCoordinateField + p3_binary_dft::EncodableLevel,
    F: ExtensionField<B>,
{
    let parameters = |n, hash| BinaryNativePcsParameters {
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
        main: parameters(prepared.main_variables(), main_hash),
        preprocessed: prepared
            .preprocessed_variables()
            .map(|n| parameters(n, preprocessed_hash)),
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

/// Whether `error` refuses a native Blake3 compression the builder does not
/// allow.
fn needs_native_blake3(error: &VerificationError) -> bool {
    matches!(
        error,
        VerificationError::CircuitBuilder(CircuitBuilderError::OpNotAllowed { op })
            if *op == NpoTypeId::native_blake3_compress()
    )
}

/// The native host evaluates Blake3, so a Blake3 PCS child's inputs allocate,
/// while its verifier needs the native Blake3 compression, which a builder
/// with only native Keccak-f does not allow.
#[test]
fn blake3_pcs_child_needs_the_native_blake3_compression() {
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let out = b.mul(input, input);
    let expected = b.public_input();
    b.connect(out, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    let (_, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared, ByteHash::Blake3),
        &VerifierLimits::default(),
    )
    .unwrap();
    let verifier = authority.recursive_verifier();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let targets = verifier
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
    let error = verifier
        .verify_native(&mut b, ch, &public, &targets)
        .unwrap_err();
    assert!(needs_native_blake3(&error), "{error}");
}

/// A Keccak main commitment with a Blake3 preprocessed one: the preprocessed
/// opening alone needs the native Blake3 compression.
#[test]
fn blake3_preprocessed_pcs_needs_the_native_blake3_compression() {
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let expected = b.public_input();
    let private = b.alloc_private_input("factor");
    let product = b.mul(input, private);
    let reused = b.mul(product, input);
    let c = b.define_const(F::from_raw_coordinates(0x8912).unwrap());
    let out = b.add(reused, c);
    b.connect(out, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    assert!(prepared.preprocessed_variables().is_some());
    let (_, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec_with_hashes(&prepared, ByteHash::Keccak256, ByteHash::Blake3),
        &VerifierLimits::default(),
    )
    .unwrap();
    let verifier = authority.recursive_verifier();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let targets = verifier
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
    let error = verifier
        .verify_native(&mut b, ch, &public, &targets)
        .unwrap_err();
    assert!(needs_native_blake3(&error), "{error}");
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

/// Coset-leaf groupings at every PCS site, with sixteen-symbol cosets where
/// the table has at least four variables. `preprocessed_base` overrides the
/// preprocessing base grouping.
fn grouped_spec<B>(
    prepared: &NativeBusCircuit<B>,
    preprocessed_base: BinaryCodewordGrouping,
) -> BinaryNativeGroupedVerifierSpec
where
    B: RecursiveBinaryTowerField + BinaryCoordinateField + p3_binary_dft::EncodableLevel,
    F: ExtensionField<B>,
{
    let parameters = |n: usize, base_grouping| BinaryNativeGroupedPcsParameters {
        pcs: BinaryNativePcsParameters {
            config: BinaryPcsConfig::try_new_with_folding::<B, F>(
                n,
                BinaryPcsParams {
                    log_inv_rate: 2,
                    pow_bits: 0,
                    security_level: 8,
                },
                n.min(4),
            )
            .unwrap(),
            hash: ByteHash::Keccak256,
            cap_height: 0,
            max_query_draws: 128,
        },
        base_grouping,
        round_grouping: BinaryCodewordGrouping::Folding,
    };
    BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables(), BinaryCodewordGrouping::Folding),
        preprocessed: prepared
            .preprocessed_variables()
            .map(|n| parameters(n, preprocessed_base)),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-grouped-folding-verifier-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    }
}

#[test]
fn native_verifier_closes_a_grouped_folding_bus_proof_with_coset_leaves() {
    close_grouped_bus_proof::<F>();
}

#[test]
fn tower32_grouped_folding_child_is_closed_in_a_tower128_verifier() {
    close_grouped_bus_proof::<BinaryField32>();
}

#[test]
fn grouped_preprocessing_without_coset_leaves_is_rejected_before_constraints() {
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let expected = b.public_input();
    let private = b.alloc_private_input("factor");
    let product = b.mul(input, private);
    let c = b.define_const(F::from_raw_coordinates(0x8912).unwrap());
    let out = b.add(product, c);
    b.connect(out, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    let n = prepared.preprocessed_variables().unwrap();
    assert!(
        n >= 2,
        "preprocessing must fold cosets wider than two symbols"
    );
    let setup = |preprocessed_base| {
        BinaryNativeGroupedAuthority::<F, F, _>::setup(
            prepared.airs().to_vec(),
            prepared.log_heights().to_vec(),
            grouped_spec(&prepared, preprocessed_base),
            &VerifierLimits::default(),
        )
        .unwrap()
        .1
    };
    // Two-symbol leaves split every preprocessing base coset; the main
    // commitment keeps coset leaves.
    let authority = setup(BinaryCodewordGrouping::Message(2));
    let verifier = authority.recursive_verifier();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let error = verifier
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap_err();
    assert!(
        matches!(error, VerificationError::InvalidProofShape(_)),
        "{error}"
    );
    // Inputs shaped by a coset-leaf twin still cannot reach any constraint.
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let targets = setup(BinaryCodewordGrouping::Folding)
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
    assert!(
        matches!(error, VerificationError::InvalidProofShape(_)),
        "{error}"
    );
    assert_eq!(b.construction_usage().unwrap(), before);
}

fn close_grouped_bus_proof<B>()
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
    let (prover, authority) = BinaryNativeGroupedAuthority::<B, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        grouped_spec(&prepared, BinaryCodewordGrouping::Folding),
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
    let preprocessed = targets.preprocessed_opening.as_ref().unwrap();
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
    assert!(run(&recursive, &flat, &private), "honest grouped child");
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
        assert!(!run(&recursive, &flat, &wrong), "private input {index}");
    }
    // The first base and round rows of the trusted preprocessing opening,
    // located by their allocated targets. That opening is checked after the
    // main opening's queries, through the continuation.
    let private_index = |row: &NativeTower128Target| {
        let witness = recursive.expr_to_widx[&row.as_expr()];
        recursive
            .private_input_rows
            .iter()
            .position(|&row| row == witness)
            .unwrap()
    };
    let rows = [
        ("base", &preprocessed.base_rows[0]),
        ("round", &preprocessed.rounds[0].rows[0]),
    ];
    for (name, row) in rows {
        let mut wrong = private.clone();
        wrong[private_index(row)] += F::ONE;
        assert!(
            !run(&recursive, &flat, &wrong),
            "first preprocessed {name} row"
        );
    }
}
