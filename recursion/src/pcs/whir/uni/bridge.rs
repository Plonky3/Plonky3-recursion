//! Expressing a univariate opening as a multilinear equality claim.
//!
//! Commit a univariate polynomial of degree `< 2^k` by its coefficient vector,
//! read as the hypercube evaluations of a `k`-variate multilinear `f`. Writing
//! `Y = (z^(2^(k-1)), …, z^2, z)` for the big-endian power expansion of the
//! opening point,
//!
//! ```text
//! p(z) = sum_b c_b * z^int(b) = sum_b f(b) * select(Y, b)
//! ```
//!
//! and, substituting `X_i = Y_i / (1 + Y_i)` so that `1 - X_i = 1/(1 + Y_i)`,
//!
//! ```text
//! eq(X, b) = select(Y, b) / prod_i (1 + Y_i)
//! p(z)     = scale(z) * f(X),      scale(z) = prod_i (1 + Y_i)
//! ```
//!
//! `scale(z)` is the all-ones polynomial `sum_{j < 2^k} z^j`, so the
//! substitution is defined exactly when `z` is not a `2^k`-th root of unity —
//! the same out-of-domain condition a STARK opening point already satisfies.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::Field;
use p3_multilinear_util::point::Point;

use crate::Target;
use crate::pcs::whir::gadgets::expand_from_univariate;

/// Substituted equality point and its scale for a univariate opening at `zeta`.
///
/// Returns `(X, scale)` with `p(zeta) == scale * f(X)` for the multilinear `f`
/// whose hypercube evaluations are `p`'s coefficients.
///
/// # Panics
/// Panics if `1 + zeta^(2^i)` is zero for some `i < num_variables`, i.e. if
/// `zeta` is a `2^num_variables`-th root of unity. Callers open at a
/// transcript-sampled out-of-domain point, where this cannot happen.
pub fn univariate_eq_point<EF: Field>(zeta: EF, num_variables: usize) -> (Point<EF>, EF) {
    let powers = Point::<EF>::expand_from_univariate(zeta, num_variables);
    let mut scale = EF::ONE;
    let coords: Vec<EF> = powers
        .as_slice()
        .iter()
        .map(|&y| {
            let denom = EF::ONE + y;
            assert!(
                !denom.is_zero(),
                "opening point is a root of unity of the committed size"
            );
            scale *= denom;
            y * denom.inverse()
        })
        .collect();
    (Point::new(coords), scale)
}

/// In-circuit counterpart of [`univariate_eq_point`].
///
/// Returns the `num_variables` coordinates of `X` followed by `scale`. Costs
/// `num_variables - 1` squarings, `num_variables` divisions and
/// `num_variables - 1` multiplications.
pub fn univariate_eq_point_circuit<F: Field>(
    builder: &mut CircuitBuilder<F>,
    zeta: Target,
    num_variables: usize,
) -> (Vec<Target>, Target) {
    let one = builder.define_const(F::ONE);
    if num_variables == 0 {
        return (Vec::new(), one);
    }

    let powers = expand_from_univariate(builder, zeta, num_variables);
    let mut denoms = Vec::with_capacity(num_variables);
    let mut coords = Vec::with_capacity(num_variables);
    for &y in &powers {
        let denom = builder.add(one, y);
        coords.push(builder.alloc_div(y, denom, "whir uni bridge coord"));
        denoms.push(denom);
    }
    let scale = builder.mul_many(&denoms);
    (coords, scale)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_multilinear_util::poly::Poly;
    use proptest::prelude::*;

    use super::{univariate_eq_point, univariate_eq_point_circuit};
    use crate::pcs::whir::test_util::eval_gadget_multi;

    type BF = BabyBear;
    type EF = BinomialExtensionField<BF, 4>;

    /// Horner evaluation of `coeffs` at `z`: the univariate meaning of the
    /// coefficient-multilinear.
    fn horner(coeffs: &[EF], z: EF) -> EF {
        coeffs.iter().rev().fold(EF::ZERO, |acc, &c| acc * z + c)
    }

    #[test]
    fn zero_variables_is_the_empty_point_and_unit_scale() {
        let (x, scale) = univariate_eq_point::<EF>(EF::from_u32(5), 0);
        assert!(x.as_slice().is_empty());
        assert_eq!(scale, EF::ONE);
    }

    #[test]
    fn scale_is_the_all_ones_polynomial() {
        // scale(z) = prod_i (1 + z^(2^i)) = sum_{j<2^k} z^j.
        let z = EF::from_u32(37);
        let k = 5;
        let (_, scale) = univariate_eq_point(z, k);
        let expected: EF = (0..(1u64 << k)).map(|j| z.exp_u64(j)).sum();
        assert_eq!(scale, expected);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// The defining identity: a univariate opening equals `scale` times the
        /// multilinear extension of the coefficients at the substituted point.
        #[test]
        fn prop_identity_holds(k in 1usize..7, z in 2u32..1_000_000, seed in any::<u64>()) {
            let z = EF::from_u32(z);
            // z must not be a 2^k-th root of unity; a small random base field
            // element lifted to EF cannot be one for these k, and z != 1.
            let coeffs: Vec<EF> = (0..(1usize << k))
                .map(|i| EF::from_u64(seed.wrapping_mul(i as u64 + 1) % 1_000_003))
                .collect();

            let (x, scale) = univariate_eq_point(z, k);
            let mle = Poly::new(coeffs.clone()).eval_ext::<BF>(&x);
            prop_assert_eq!(horner(&coeffs, z), scale * mle);
        }

        /// The circuit gadget agrees with the native function coordinate by
        /// coordinate, including the scale.
        #[test]
        fn prop_circuit_matches_native(k in 1usize..7, z in 2u32..1_000_000) {
            let z = EF::from_u32(z);
            let (x, scale) = univariate_eq_point(z, k);

            let got = eval_gadget_multi(&[z], |b, ins| {
                let (xs, s) = univariate_eq_point_circuit(b, ins[0], k);
                let mut out = xs;
                out.push(s);
                out
            });

            prop_assert_eq!(got.len(), k + 1);
            for (i, coord) in x.as_slice().iter().enumerate() {
                prop_assert_eq!(got[i], *coord);
            }
            prop_assert_eq!(got[k], scale);
        }
    }
}
