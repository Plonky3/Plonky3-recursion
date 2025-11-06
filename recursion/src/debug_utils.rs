//! Debug utilities for circuit verification
//!
//! These utilities are only compiled in debug builds and help verify that
//! circuit witness generation produces expected values.

use p3_circuit::CircuitBuilder;
use p3_field::Field;

use crate::Target;

/// Debug helper: Connect a target to a known constant value to verify it matches.
///
/// Only active in debug builds. Will cause WitnessConflict if the target doesn't
/// match the expected value during witness generation.
///
/// # Example
/// ```ignore
/// debug_connect_to_const(circuit, alpha, expected_alpha, "alpha");
/// ```
#[cfg(debug_assertions)]
pub fn debug_connect_to_const<F: Field>(
    circuit: &mut CircuitBuilder<F>,
    target: Target,
    expected_value: F,
    label: &str,
) {
    extern crate std;
    // Use a non-aliasing equality check: target - const == 0.
    // This avoids directly aliasing `target` to a pooled constant witness, which
    // can accidentally merge unrelated values in large circuits.
    let const_target = circuit.add_const(expected_value);
    let diff = circuit.sub(target, const_target);
    std::println!("[DEBUG] Asserting {} equals {:?}", label, expected_value);
    circuit.assert_zero(diff);
}

#[cfg(not(debug_assertions))]
#[inline]
pub fn debug_connect_to_const<F: Field>(
    _circuit: &mut CircuitBuilder<F>,
    _target: Target,
    _expected_value: F,
    _label: &str,
) {
    // No-op in release builds
}

/// Debug helper: Assert two targets are equal using a non-aliasing constraint.
///
/// Implemented as (a - b) == 0 to avoid DSU aliasing hazards when comparing against
/// pooled constants. In release builds, this is a no-op.
#[cfg(debug_assertions)]
pub fn debug_assert_equal<F: Field>(
    circuit: &mut CircuitBuilder<F>,
    a: Target,
    b: Target,
    label: &str,
) {
    extern crate std;
    std::println!("[DEBUG] Asserting equality: {}", label);
    let diff = circuit.sub(a, b);
    circuit.assert_zero(diff);
}

#[cfg(not(debug_assertions))]
#[inline]
pub fn debug_assert_equal<F: Field>(
    _circuit: &mut CircuitBuilder<F>,
    _a: Target,
    _b: Target,
    _label: &str,
) {
    // No-op in release builds
}

/// Construct an extension field element from a small u32 value.
///
/// This is useful for creating constant values in debug assertions when
/// the field doesn't have a `from_canonical_u32` method.
///
/// # Example
/// ```ignore
/// let expected_query_index = make_ef_from_u32::<SC::Challenge>(34);
/// ```
pub fn make_ef_from_u32<F: Field>(val: u32) -> F {
    let mut result = F::ZERO;
    for _ in 0..val {
        result += F::ONE;
    }
    result
}

/// Construct an extension field element from just the first coefficient (base field value).
///
/// For extension fields like `BinomialExtensionField<F, D>`, this constructs
/// a value with only the first coefficient set: `[c0, 0, 0, 0]`.
///
/// This is useful for quick debug checks where we only care about the first coefficient.
///
/// # Example
/// ```ignore
/// // Check if first coefficient is 1166891090
/// let expected = make_ef_from_first_coeff::<SC::Challenge>(1166891090);
/// debug_connect_to_const(circuit, target, expected, "first_coeff_check");
/// ```
pub fn make_ef_from_first_coeff<F: Field>(first_coeff: u32) -> F {
    // Efficiently build base field value from u32 using binary representation
    let mut result = F::ZERO;
    let mut power = F::ONE;
    let mut val = first_coeff;

    while val > 0 {
        if val & 1 == 1 {
            result += power;
        }
        power = power + power; // double
        val >>= 1;
    }

    // For extension fields, this creates [first_coeff, 0, 0, 0]
    result
}

/// Construct a full extension field element from all 4 coefficients.
///
/// For extension fields like `BinomialExtensionField<F, 4>`, this constructs
/// a value with all coefficients: `[c0, c1, c2, c3]`.
///
/// This works by treating the extension field as a polynomial over the base field
/// and constructing it as: c0 + c1*X + c2*X^2 + c3*X^3 where X is the extension element.
///
/// # Example
/// ```ignore
/// // Create extension field value [1557334986, 1684563227, 883541554, 1191661034]
/// let expected = make_ef_from_coeffs::<SC::Challenge>(&[1557334986, 1684563227, 883541554, 1191661034]);
/// debug_connect_to_const(circuit, target, expected, "full_ef_check");
/// ```
pub fn make_ef_from_coeffs<BaseField, F>(coeffs: &[u32; 4]) -> F
where
    BaseField: Field,
    F: p3_field::BasedVectorSpace<BaseField>,
{
    // Build each base field coefficient from u32 and construct extension field
    F::from_basis_coefficients_fn(|i| {
        let val = coeffs[i];
        let mut coeff = BaseField::ZERO;
        let mut power = BaseField::ONE;
        let mut v = val;

        while v > 0 {
            if v & 1 == 1 {
                coeff += power;
            }
            power = power + power;
            v >>= 1;
        }
        coeff
    })
}
