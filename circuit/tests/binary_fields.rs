//! The circuit builder and runner over fields of characteristic 2.
//!
//! Plonky3 0.7/0.8 added the binary tower `GF(2) ⊂ … ⊂ GF(2^128)` and `GF(2^128)` in the GHASH
//! polynomial basis. The primitive circuit layer (constants, inputs, ALU ops, connections) only
//! needs field arithmetic, so it must run over those fields unchanged; gadgets that read field
//! elements as integers must refuse them instead of silently keeping only parities.

use core::hash::Hash;

use p3_binary_field::{BinaryField8, BinaryField32, BinaryField64, BinaryField128, Gf2, Ghash128};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitError};
use p3_field::Field;

/// Two nonzero elements that differ whenever the field has more than two elements.
fn operands<F: Field>() -> (F, F) {
    let a = F::GENERATOR.exp_u64(7) + F::ONE;
    let b = F::GENERATOR.exp_u64(11);
    if a.is_zero() { (F::ONE, b) } else { (a, b) }
}

/// Every primitive op evaluates to its native value, and characteristic-2 identities hold.
fn primitive_ops_match_native_arithmetic<F>()
where
    F: Field + Eq + Hash,
{
    let (a, b) = operands::<F>();
    assert!(!b.is_zero());

    let mut builder = CircuitBuilder::<F>::new();
    let a_t = builder.public_input();
    let b_t = builder.public_input();
    let bit_t = builder.public_input();
    builder.assert_bool(bit_t);

    let sum = builder.add(a_t, b_t);
    let diff = builder.sub(a_t, b_t);
    let prod = builder.mul(a_t, b_t);
    let quot = builder.div(a_t, b_t);
    let double = builder.add(a_t, a_t);
    let frobenius = builder.exp_power_of_2(a_t, 3);
    let fused = builder.mul_add(a_t, b_t, a_t);
    let selected = builder.select(bit_t, a_t, b_t);
    let cross = builder.inner_product(&[a_t, b_t], &[b_t, a_t]);
    let three = builder.define_const(F::from_u8(3));
    let scaled = builder.mul(a_t, three);

    // In characteristic 2, `x - y = x + y`, so the difference is connectable to the sum.
    builder.connect(sum, diff);

    for (tag, expr) in [
        ("sum", sum),
        ("prod", prod),
        ("quot", quot),
        ("double", double),
        ("frobenius", frobenius),
        ("fused", fused),
        ("selected", selected),
        ("cross", cross),
        ("scaled", scaled),
    ] {
        builder.tag(expr, tag).unwrap();
    }

    let circuit = builder.build().expect("a primitive binary circuit builds");
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[a, b, F::ONE]).unwrap();
    let traces = runner.run().expect("an honest binary witness runs");

    let probe = |tag: &str| *traces.probe(tag).expect("every tagged value is traced");
    assert_eq!(probe("sum"), a + b);
    assert_eq!(probe("prod"), a * b);
    assert_eq!(probe("quot") * b, a);
    assert_eq!(probe("double"), F::ZERO, "2a = 0 in characteristic 2");
    assert_eq!(probe("frobenius"), a.exp_power_of_2(3));
    assert_eq!(probe("fused"), a * b + a);
    assert_eq!(probe("selected"), a);
    assert_eq!(probe("cross"), F::ZERO, "ab + ba = 2ab = 0");
    // `from_u8` goes through the prime subfield GF(2), so 3 embeds as 1.
    assert_eq!(probe("scaled"), a);
}

/// A connection between distinct values is a witness conflict, not a silent pass.
fn distinct_connection_is_rejected<F>()
where
    F: Field + Eq + Hash,
{
    let (a, b) = operands::<F>();
    if a == b {
        return;
    }
    let mut builder = CircuitBuilder::<F>::new();
    let a_t = builder.public_input();
    let b_t = builder.public_input();
    builder.connect(a_t, b_t);
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    // Connected public inputs share one witness slot, so the conflict surfaces as soon as the
    // second value is written.
    let result = runner
        .set_public_inputs(&[a, b])
        .and_then(|()| runner.run().map(drop));
    assert!(matches!(result, Err(CircuitError::WitnessConflict { .. })));
}

/// The runner forwards `BoolCheck` values and leaves `b·(b − 1) = 0` to the ALU AIR, so bits
/// run cleanly, and the AIR's polynomial vanishes on exactly the bits of a binary field too.
fn booleanity_holds_on_exactly_the_bits<F>()
where
    F: Field + Eq + Hash,
{
    let mut builder = CircuitBuilder::<F>::new();
    let bit_t = builder.public_input();
    builder.assert_bool(bit_t);
    let circuit = builder.build().unwrap();
    for bit in [F::ZERO, F::ONE] {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[bit]).unwrap();
        runner.run().expect("a bit passes the booleanity check");
        assert!((bit * (bit - F::ONE)).is_zero());
    }

    // `x^2 + x` has at most two roots, and 0 and 1 are both of them.
    let (a, b) = operands::<F>();
    for x in [a, b, a * b + F::ONE] {
        if x != F::ZERO && x != F::ONE {
            assert!(!(x * (x - F::ONE)).is_zero());
        }
    }
}

macro_rules! binary_field_suite {
    ($($name:ident => $field:ty),* $(,)?) => {$(
        mod $name {
            use super::*;

            #[test]
            fn primitive_ops_match_native_arithmetic() {
                super::primitive_ops_match_native_arithmetic::<$field>();
            }

            #[test]
            fn distinct_connection_is_rejected() {
                super::distinct_connection_is_rejected::<$field>();
            }

            #[test]
            fn booleanity_holds_on_exactly_the_bits() {
                super::booleanity_holds_on_exactly_the_bits::<$field>();
            }
        }
    )*};
}

binary_field_suite! {
    gf2 => Gf2,
    binary_field_8 => BinaryField8,
    binary_field_32 => BinaryField32,
    binary_field_64 => BinaryField64,
    binary_field_128 => BinaryField128,
    ghash_128 => Ghash128,
}

#[test]
fn integer_bit_recomposition_refuses_characteristic_two() {
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    let bits: Vec<_> = (0..8).map(|_| builder.public_input()).collect();
    assert!(matches!(
        builder.reconstruct_index_from_bits::<BinaryField8>(&bits),
        Err(CircuitBuilderError::CharacteristicTwoUnsupported {
            operation: "reconstruct_index_from_bits",
        })
    ));
    assert!(matches!(
        builder.reconstruct_index_from_bits::<BinaryField128>(&bits),
        Err(CircuitBuilderError::CharacteristicTwoUnsupported { .. })
    ));
}
