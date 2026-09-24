//! The Keccak-f[1600] non-primitive operation executes exactly the native permutation.

use p3_baby_bear::BabyBear;
use p3_circuit::ops::{
    KECCAK_LANES, KECCAK_STATE_LIMBS, keccak_limbs_to_state, keccak_state_to_limbs,
};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitError, ExprId};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

type EF4 = BinomialExtensionField<BabyBear, 4>;
type EF2 = BinomialExtensionField<Goldilocks, 2>;

fn sample_state(seed: u64) -> [u64; KECCAK_LANES] {
    core::array::from_fn(|i| {
        (seed ^ 0x9e37_79b9_7f4a_7c15)
            .wrapping_mul(i as u64 + 1)
            .rotate_left(i as u32 * 5)
    })
}

fn permuted(mut state: [u64; KECCAK_LANES]) -> [u64; KECCAK_LANES] {
    KeccakF.permute_mut(&mut state);
    state
}

fn limb_values<F: PrimeCharacteristicRing>(state: &[u64; KECCAK_LANES]) -> Vec<F> {
    keccak_state_to_limbs(state)
        .iter()
        .map(|&limb| F::from_u16(limb))
        .collect()
}

/// Reads tagged output limbs back into a state.
fn probe_state<BF, F>(traces: &p3_circuit::Traces<F>, prefix: &str) -> [u64; KECCAK_LANES]
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    let limbs: [u16; KECCAK_STATE_LIMBS] = core::array::from_fn(|i| {
        let value = traces
            .probe(&format!("{prefix}{i}"))
            .expect("output is traced");
        let coeffs = <F as BasedVectorSpace<BF>>::as_basis_coefficients_slice(value);
        assert!(
            coeffs[1..].iter().all(|c| c.is_zero()),
            "limbs are base-field"
        );
        u16::try_from(coeffs[0].as_canonical_u64()).expect("limbs fit 16 bits")
    });
    keccak_limbs_to_state(&limbs)
}

/// Two chained calls, the second on the first's output, match two native permutations.
fn chained_calls_match_native<BF, F>()
where
    BF: PrimeField64,
    F: ExtensionField<BF> + Eq + core::hash::Hash,
{
    let state = sample_state(7);
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_keccak_f1600::<BF>();
    let inputs: Vec<ExprId> = (0..KECCAK_STATE_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    let once = builder.add_keccak_f1600(&inputs).unwrap();
    let twice = builder.add_keccak_f1600(&once).unwrap();
    for (i, (&a, &b)) in once.iter().zip(&twice).enumerate() {
        builder.tag(a, format!("once_{i}")).unwrap();
        builder.tag(b, format!("twice_{i}")).unwrap();
    }

    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&limb_values::<F>(&state)).unwrap();
    let traces = runner.run().expect("an honest Keccak-f circuit runs");

    assert_eq!(probe_state::<BF, F>(&traces, "once_"), permuted(state));
    assert_eq!(
        probe_state::<BF, F>(&traces, "twice_"),
        permuted(permuted(state))
    );

    let trace = traces
        .non_primitive_trace::<p3_circuit::ops::KeccakF1600Trace>(
            &p3_circuit::ops::NpoTypeId::keccak_f1600(),
        )
        .expect("the run records a Keccak-f trace");
    assert_eq!(trace.operations.len(), 2);
    assert_eq!(trace.operations[0].input, state);
    assert_eq!(trace.operations[1].input, trace.operations[0].output);
}

#[test]
fn chained_calls_match_native_over_baby_bear() {
    chained_calls_match_native::<BabyBear, BabyBear>();
}

#[test]
fn chained_calls_match_native_over_a_quartic_extension() {
    chained_calls_match_native::<BabyBear, EF4>();
}

#[test]
fn chained_calls_match_native_over_goldilocks_quadratic() {
    chained_calls_match_native::<Goldilocks, EF2>();
}

/// Runs one call on the given limb values and returns the run result.
fn run_single_call(values: &[EF4]) -> Result<(), CircuitError> {
    let mut builder = CircuitBuilder::<EF4>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let inputs: Vec<ExprId> = (0..KECCAK_STATE_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    builder.add_keccak_f1600(&inputs).unwrap();
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(values)?;
    runner.run().map(drop)
}

#[test]
fn a_limb_of_sixteen_bits_or_more_is_rejected() {
    let mut values = limb_values::<EF4>(&sample_state(3));
    values[17] = EF4::from_u32(1 << 16);
    assert!(matches!(
        run_single_call(&values),
        Err(CircuitError::InvalidNonPrimitiveOpInput { .. })
    ));
}

#[test]
fn a_limb_outside_the_base_field_is_rejected() {
    let mut values = limb_values::<EF4>(&sample_state(3));
    values[0] = EF4::from_basis_coefficients_fn(|i| BabyBear::from_usize(i + 1));
    assert!(matches!(
        run_single_call(&values),
        Err(CircuitError::InvalidNonPrimitiveOpInput { .. })
    ));
}

#[test]
fn the_operation_must_be_enabled_and_take_a_full_state() {
    let mut builder = CircuitBuilder::<EF4>::new();
    let inputs: Vec<ExprId> = (0..KECCAK_STATE_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    assert!(matches!(
        builder.add_keccak_f1600(&inputs),
        Err(CircuitBuilderError::OpNotAllowed { .. })
    ));

    builder.enable_keccak_f1600::<BabyBear>();
    assert!(matches!(
        builder.add_keccak_f1600(&inputs[..KECCAK_STATE_LIMBS - 1]),
        Err(CircuitBuilderError::NonPrimitiveOpArity { .. })
    ));
}

mod keccak256_compress {
    use p3_circuit::ops::{KECCAK256_DIGEST_LIMBS, bytes_to_limbs};
    use p3_keccak::Keccak256Hash;
    use p3_symmetric::{CompressionFunctionFromHasher, PseudoCompressionFunction};

    use super::*;

    type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;

    fn digest(seed: u8) -> [u8; 32] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(seed).rotate_left(3))
    }

    fn limb_values(digest: &[u8; 32]) -> Vec<EF4> {
        bytes_to_limbs(digest)
            .into_iter()
            .map(EF4::from_u16)
            .collect()
    }

    fn probe_digest(traces: &p3_circuit::Traces<EF4>, prefix: &str) -> Vec<u16> {
        (0..KECCAK256_DIGEST_LIMBS)
            .map(|i| {
                let value = traces.probe(&format!("{prefix}{i}")).unwrap();
                let coeffs =
                    <EF4 as BasedVectorSpace<BabyBear>>::as_basis_coefficients_slice(value);
                u16::try_from(coeffs[0].as_canonical_u64()).unwrap()
            })
            .collect()
    }

    fn digest_inputs(builder: &mut CircuitBuilder<EF4>) -> Vec<ExprId> {
        (0..KECCAK256_DIGEST_LIMBS)
            .map(|_| builder.public_input())
            .collect()
    }

    /// A four-leaf Merkle root built in-circuit equals the native Keccak-256 compression tree.
    #[test]
    fn a_merkle_root_matches_native_keccak256_compression() {
        let leaves = [digest(1), digest(2), digest(3), digest(4)];
        let compress = Compress::new(Keccak256Hash);
        let left = compress.compress([leaves[0], leaves[1]]);
        let right = compress.compress([leaves[2], leaves[3]]);
        let root = compress.compress([left, right]);

        let mut builder = CircuitBuilder::<EF4>::new();
        builder.enable_keccak_f1600::<BabyBear>();
        let inputs: Vec<Vec<ExprId>> = (0..4).map(|_| digest_inputs(&mut builder)).collect();
        let l = builder.keccak256_compress(&inputs[0], &inputs[1]).unwrap();
        let r = builder.keccak256_compress(&inputs[2], &inputs[3]).unwrap();
        let top = builder.keccak256_compress(&l, &r).unwrap();
        for (i, (&a, &b)) in l.iter().zip(&top).enumerate() {
            builder.tag(a, format!("left_{i}")).unwrap();
            builder.tag(b, format!("root_{i}")).unwrap();
        }

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        let public: Vec<EF4> = leaves.iter().flat_map(limb_values).collect();
        runner.set_public_inputs(&public).unwrap();
        let traces = runner.run().unwrap();

        assert_eq!(probe_digest(&traces, "left_"), bytes_to_limbs(&left));
        assert_eq!(probe_digest(&traces, "root_"), bytes_to_limbs(&root));
    }

    #[test]
    fn a_digest_of_the_wrong_width_is_rejected() {
        let mut builder = CircuitBuilder::<EF4>::new();
        builder.enable_keccak_f1600::<BabyBear>();
        let full = digest_inputs(&mut builder);
        assert!(matches!(
            builder.keccak256_compress(&full, &full[1..]),
            Err(CircuitBuilderError::NonPrimitiveOpArity { .. })
        ));
    }
}

mod keccak256_sponge {
    use p3_circuit::ops::{KECCAK256_DIGEST_LIMBS, bytes_to_limbs};
    use p3_keccak::Keccak256Hash;
    use p3_symmetric::{CryptographicHasher, SerializingHasher};

    use super::*;

    fn digest_limbs<BF, F>(traces: &p3_circuit::Traces<F>) -> Vec<u16>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        (0..KECCAK256_DIGEST_LIMBS)
            .map(|i| {
                let value = traces.probe(&format!("digest_{i}")).unwrap();
                let coeffs = <F as BasedVectorSpace<BF>>::as_basis_coefficients_slice(value);
                u16::try_from(coeffs[0].as_canonical_u64()).unwrap()
            })
            .collect()
    }

    fn tag_digest<F: p3_field::Field + Eq + core::hash::Hash>(
        builder: &mut CircuitBuilder<F>,
        digest: &[ExprId],
    ) {
        for (i, &limb) in digest.iter().enumerate() {
            builder.tag(limb, format!("digest_{i}")).unwrap();
        }
    }

    /// Byte messages across every block boundary case hash to the native Keccak-256 digest.
    #[test]
    fn byte_messages_match_native_keccak256() {
        for len in [0usize, 2, 64, 134, 136, 200, 282] {
            let message: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let native = Keccak256Hash.hash_iter(message.iter().copied());

            let mut builder = CircuitBuilder::<EF4>::new();
            builder.enable_keccak_f1600::<BabyBear>();
            let limbs: Vec<ExprId> = (0..len / 2).map(|_| builder.public_input()).collect();
            let digest = builder.keccak256_limbs::<BabyBear>(&limbs).unwrap();
            tag_digest(&mut builder, &digest);

            let circuit = builder.build().unwrap();
            let mut runner = circuit.runner();
            let public: Vec<EF4> = bytes_to_limbs(&message)
                .into_iter()
                .map(EF4::from_u16)
                .collect();
            runner.set_public_inputs(&public).unwrap();
            let traces = runner.run().unwrap();
            assert_eq!(
                digest_limbs::<BabyBear, EF4>(&traces),
                bytes_to_limbs(&native),
                "message of {len} bytes"
            );
        }
    }

    fn field_elements_match_serializing_hasher<BF, F>(counts: &[usize])
    where
        BF: PrimeField64,
        F: ExtensionField<BF> + Eq + core::hash::Hash,
    {
        let hasher = SerializingHasher::new(Keccak256Hash);
        for &count in counts {
            // Include values near the modulus so both limbs of each element are exercised.
            let row: Vec<BF> = (0..count)
                .map(|i| BF::NEG_ONE - BF::from_usize(i * 1_000_003))
                .collect();
            let native: [u8; 32] = hasher.hash_iter(row.iter().copied());

            let mut builder = CircuitBuilder::<F>::new();
            builder.enable_keccak_f1600::<BF>();
            let inputs: Vec<ExprId> = (0..count).map(|_| builder.public_input()).collect();
            let digest = builder.keccak256_field_elements::<BF>(&inputs).unwrap();
            tag_digest(&mut builder, &digest);

            let circuit = builder.build().unwrap();
            let mut runner = circuit.runner();
            let public: Vec<F> = row.iter().map(|&x| F::from(x)).collect();
            runner.set_public_inputs(&public).unwrap();
            let traces = runner.run().unwrap();
            assert_eq!(
                digest_limbs::<BF, F>(&traces),
                bytes_to_limbs(&native),
                "row of {count} elements"
            );
        }
    }

    #[test]
    fn baby_bear_rows_match_the_serializing_hasher() {
        // 33 elements fill one block with room for padding; 34 spill into a second.
        field_elements_match_serializing_hasher::<BabyBear, EF4>(&[1, 33, 34, 70]);
    }

    #[test]
    fn goldilocks_rows_match_the_serializing_hasher() {
        field_elements_match_serializing_hasher::<Goldilocks, EF2>(&[1, 16, 17, 40]);
    }
}
