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
