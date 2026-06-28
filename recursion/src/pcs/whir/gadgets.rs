//! Multilinear-polynomial arithmetic gadgets used by the WHIR verifier.
//!
//! Each gadget reproduces, gate-for-gate, the field formula of its native
//! counterpart so the recursive verifier computes byte-identical values:
//!
//! - [`expand_from_univariate`] mirrors `p3_multilinear_util::point::Point::expand_from_univariate`
//! - [`eq_eval`] mirrors `Point::eval_eq` / `Point::eq_poly`
//! - [`select_eval`] mirrors `Point::select_poly`

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::Field;

use crate::Target;

/// Lifts a univariate point `z` to the `num_variables`-dimensional multilinear
/// point `[z^(2^(n-1)), …, z^2, z]`.
///
/// This is the big-endian convention of the native
/// `Point::expand_from_univariate`: coordinate `n-1` holds `z`, coordinate `0`
/// holds `z^(2^(n-1))`. Costs `num_variables - 1` squarings. Returns an empty
/// vector when `num_variables == 0`.
pub fn expand_from_univariate<F: Field>(
    builder: &mut CircuitBuilder<F>,
    z: Target,
    num_variables: usize,
) -> Vec<Target> {
    if num_variables == 0 {
        return Vec::new();
    }

    // Build [z, z^2, z^4, …, z^(2^(n-1))] by repeated squaring, then reverse
    // into the big-endian order the native point uses.
    let mut res = Vec::with_capacity(num_variables);
    let mut cur = z;
    res.push(cur);
    for _ in 1..num_variables {
        cur = builder.mul(cur, cur);
        res.push(cur);
    }
    res.reverse();
    res
}

/// Evaluates the multilinear equality polynomial
/// `eq(a, b) = ∏_i (a_i·b_i + (1-a_i)·(1-b_i))`.
///
/// Each factor is computed as `2·a_i·b_i - a_i - b_i + 1`, the algebraic
/// identity the native `Point::eval_eq` uses. The product of zero factors is
/// `1`.
///
/// # Panics
/// Panics if `a` and `b` have different lengths.
pub fn eq_eval<F: Field>(builder: &mut CircuitBuilder<F>, a: &[Target], b: &[Target]) -> Target {
    assert_eq!(a.len(), b.len(), "eq_eval: point length mismatch");

    let one = builder.define_const(F::ONE);
    let terms: Vec<Target> = a
        .iter()
        .zip(b)
        .map(|(&ai, &bi)| {
            // 2·ai·bi - ai - bi + 1
            let two_ai = builder.add(ai, ai);
            let two_ai_bi = builder.mul(two_ai, bi);
            let t = builder.sub(two_ai_bi, ai);
            let t = builder.sub(t, bi);
            builder.add(t, one)
        })
        .collect();
    builder.mul_many(&terms)
}

/// Evaluates the selection polynomial `select(point, z)` that the WHIR verifier
/// uses to turn a univariate opening into a multilinear weight.
///
/// Mirrors `Point::select_poly`: the coordinates of `point` are consumed in
/// reverse order and paired with the powers `z, z^2, z^4, …` (squaring `z` each
/// step), producing `∏_k (point[n-1-k]·(z^(2^k) - 1) + 1)`. The product of zero
/// factors is `1`.
pub fn select_eval<F: Field>(
    builder: &mut CircuitBuilder<F>,
    point: &[Target],
    z: Target,
) -> Target {
    let one = builder.define_const(F::ONE);
    let n = point.len();
    if n == 0 {
        return one;
    }

    let mut var = z;
    let mut terms = Vec::with_capacity(n);
    for (k, &coord) in point.iter().rev().enumerate() {
        // term = coord·(var - 1) + 1
        let var_minus_one = builder.sub(var, one);
        let term = builder.mul_add(coord, var_minus_one, one);
        terms.push(term);
        // The final coordinate needs no further power of z.
        if k + 1 < n {
            var = builder.mul(var, var);
        }
    }
    builder.mul_many(&terms)
}

/// Evaluates a polynomial with coefficients `evals` at `z` using Horner's method.
///
/// Mirrors `Poly::iter().copied().horner(z)` from `p3_field::HornerIter`:
/// computes `evals[0] + z·(evals[1] + z·(evals[2] + … + z·evals[n-1]))` = `Σ_i evals[i]·z^i`.
///
/// This is the direct check used by `SelectStatement::verify(final_poly)` in the native
/// WHIR verifier: the final-polynomial hypercube evaluations are treated as univariate
/// coefficients, and the equality `fold == horner(final_poly, domain_gen^idx)` is asserted
/// for each final STIR query.
pub fn horner_eval<F: Field>(
    builder: &mut CircuitBuilder<F>,
    evals: &[Target],
    z: Target,
) -> Target {
    let n = evals.len();
    if n == 0 {
        return builder.define_const(F::ZERO);
    }
    let mut acc = evals[n - 1];
    for &c in evals[..n - 1].iter().rev() {
        acc = builder.mul_add(acc, z, c);
    }
    acc
}

/// Evaluates the multilinear extension defined by `evals` (hypercube
/// evaluations in lexicographic order) at `point`.
///
/// Mirrors `Poly::eval_base` / `Poly::eval_ext`:
/// `f(point) = Σ_x eq(x, point)·evals[x]`. Coordinate `point[0]` is the most
/// significant variable, so each fold combines the first and second halves of
/// the current table as `f0[j] + point[i]·(f1[j] - f0[j])`. Costs
/// `evals.len() - 1` interpolation steps.
///
/// # Panics
/// Panics unless `evals.len() == 2^point.len()`.
pub fn eval_multilinear<F: Field>(
    builder: &mut CircuitBuilder<F>,
    evals: &[Target],
    point: &[Target],
) -> Target {
    assert_eq!(
        evals.len(),
        1usize << point.len(),
        "eval_multilinear: evals length must be 2^point.len()"
    );

    let mut cur = evals.to_vec();
    for &p in point {
        let half = cur.len() / 2;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            // f0[j] + p·(f1[j] - f0[j]) = (1 - p)·f0[j] + p·f1[j].
            let diff = builder.sub(cur[half + j], cur[j]);
            next.push(builder.mul_add(p, diff, cur[j]));
        }
        cur = next;
    }
    cur[0]
}

/// Combines `values` with successive powers of `base`: `Σ_i values[i]·base^i`,
/// evaluated by Horner's rule.
///
/// This is the batching primitive WHIR uses to fold many opening values or
/// constraints together with powers of a single combination scalar (the native
/// `α`/`γ` batching). The empty combination is `0`.
pub fn eval_powers_combination<F: Field>(
    builder: &mut CircuitBuilder<F>,
    values: &[Target],
    base: Target,
) -> Target {
    // Horner from the highest-degree term: acc ← acc·base + values[i].
    let mut iter = values.iter().rev();
    match iter.next() {
        None => builder.define_const(F::ZERO),
        Some(&hi) => {
            let mut acc = hi;
            for &v in iter {
                acc = builder.mul_add(acc, base, v);
            }
            acc
        }
    }
}

/// Raises the compile-time constant `base` to the power encoded by the
/// little-endian boolean `bits`: `base^(Σ_i bits[i]·2^i)`.
///
/// Computes `∏_i (1 + bits[i]·(base^(2^i) - 1))`, where the `base^(2^i)` are
/// folded in as circuit constants, so each bit costs one fused multiply-add and
/// the product costs `bits.len() - 1` multiplications. The empty product is `1`.
///
/// WHIR uses this to map a STIR query index to its two-adic domain point
/// `folded_domain_gen^index` (a pure subgroup power; the WHIR query domain has
/// no coset shift).
///
/// The `bits` MUST each be boolean. Callers obtain them from the challenger's
/// bit sampling, which already enforces booleanity, so this gadget does not
/// re-constrain them.
pub fn pow_const_base<F: Field>(
    builder: &mut CircuitBuilder<F>,
    base: F,
    bits: &[Target],
) -> Target {
    let one = builder.define_const(F::ONE);
    if bits.is_empty() {
        return one;
    }

    let mut power = base; // base^(2^i) for the current bit.
    let mut factors = Vec::with_capacity(bits.len());
    for (i, &bit) in bits.iter().enumerate() {
        // bit·(power - 1) + 1  ==  power if bit == 1 else 1.
        let coeff = builder.define_const(power - F::ONE);
        factors.push(builder.mul_add(bit, coeff, one));
        if i + 1 < bits.len() {
            power = power.square();
        }
    }
    builder.mul_many(&factors)
}

/// Evaluates a WHIR constraint's weight polynomial at `point`.
///
/// Mirrors `p3_sumcheck`'s `Constraint::combine` weight, batching equality and
/// selection statements with successive powers of `gamma`:
/// ```text
/// W(point) = Σ_i γ^i·eq(point, eq_points[i]) + Σ_j γ^{n_eq+j}·select(point, sel_scalars[j])
/// ```
/// where `n_eq = eq_points.len()`. Each entry of `eq_points` is a multilinear
/// point with the same length as `point`; each `sel_scalars` entry is a
/// univariate point. The empty constraint evaluates to `0`.
///
/// `point` is the local evaluation point: callers that slice/reverse a global
/// challenge per the constraint's variable order must do so before calling.
pub fn eval_constraint_weight<F: Field>(
    builder: &mut CircuitBuilder<F>,
    point: &[Target],
    eq_points: &[&[Target]],
    sel_scalars: &[Target],
    gamma: Target,
) -> Target {
    // Equality terms first (powers γ^0..), then selection terms (powers γ^{n_eq}..),
    // matching the native batching order; `eval_powers_combination` supplies the
    // successive powers of γ.
    let mut values = Vec::with_capacity(eq_points.len() + sel_scalars.len());
    for &z in eq_points {
        values.push(eq_eval(builder, point, z));
    }
    for &z in sel_scalars {
        values.push(select_eval(builder, point, z));
    }
    eval_powers_combination(builder, &values, gamma)
}

// ─── Multi-constraint weight evaluation ──────────────────────────────────────

/// Per-constraint data for the in-circuit `eval_constraints_poly` computation.
///
/// One entry is built for each constraint (initial + one per intermediate WHIR round).
/// The caller fills these incrementally during the round loop and passes the complete
/// list to [`eval_constraints_poly_circuit`] at the end of `verify_whir_circuit`.
pub struct ConstraintWeightData {
    /// Number of multilinear variables in this constraint's polynomial.
    pub num_variables: usize,
    /// Multilinear OOD evaluation points (length `num_variables` each).
    pub eq_points: Vec<Vec<Target>>,
    /// Univariate STIR domain scalars (one per STIR query in this round).
    pub sel_scalars: Vec<Target>,
    /// Batching challenge `γ` used to combine eq and sel contributions.
    pub gamma: Target,
}

/// Evaluates the full WHIR constraint-weight polynomial at the accumulated
/// folding randomness, mirroring `VariableOrder::eval_constraints_poly`.
///
/// For each constraint `c` with `num_variables_c = k`:
/// - **Prefix**: `local_r = all_r[n-k..]` (last k elements).
/// - **Suffix**: `local_r = all_r[n-k..].reversed()`.
///
/// Calls [`eval_constraint_weight`] on each local slice, then sums the results.
pub fn eval_constraints_poly_circuit<F: Field>(
    builder: &mut CircuitBuilder<F>,
    all_r: &[Target],
    constraints: &[ConstraintWeightData],
    is_suffix: bool,
) -> Target {
    let n = all_r.len();
    let zero = builder.define_const(F::ZERO);
    let mut total = zero;
    for c in constraints {
        let k = c.num_variables.min(n);
        let local_r_slice = &all_r[n - k..];
        let local_r: Vec<Target> = if is_suffix {
            local_r_slice.iter().copied().rev().collect()
        } else {
            local_r_slice.to_vec()
        };
        let eq_refs: Vec<&[Target]> = c.eq_points.iter().map(|v| v.as_slice()).collect();
        let w = eval_constraint_weight(builder, &local_r, &eq_refs, &c.sel_scalars, c.gamma);
        total = builder.add(total, w);
    }
    total
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::CircuitBuilder;
    use p3_field::{PrimeCharacteristicRing, TwoAdicField};
    use p3_multilinear_util::point::Point;
    use p3_multilinear_util::poly::Poly;
    use proptest::prelude::*;

    use super::{
        eq_eval, eval_constraint_weight, eval_multilinear, eval_powers_combination,
        expand_from_univariate, pow_const_base, select_eval,
    };
    use crate::Target;
    use crate::pcs::whir::test_util::{eval_gadget, eval_gadget_multi};

    type F = BabyBear;

    fn f(x: u32) -> F {
        F::from_u32(x)
    }

    #[test]
    fn expand_empty_is_empty() {
        let mut builder = CircuitBuilder::<F>::new();
        let z = builder.public_input();
        assert!(expand_from_univariate(&mut builder, z, 0).is_empty());
    }

    #[test]
    fn select_empty_is_one() {
        // An empty point yields the constant 1.
        let got = eval_gadget(&[f(123)], |b, ins| select_eval(b, &[], ins[0]));
        assert_eq!(got, F::ONE);
    }

    #[test]
    fn select_single_coord_is_affine_in_z() {
        // point = [p]; select = p·(z - 1) + 1.
        let p = f(9);
        let z = f(40);
        let got = eval_gadget(&[p, z], |b, ins| select_eval(b, &ins[0..1], ins[1]));
        let expected = Point::new(alloc::vec![p]).select_poly::<F>(z);
        assert_eq!(got, expected);
        assert_eq!(expected, p * (z - F::ONE) + F::ONE);
    }

    #[test]
    fn eval_multilinear_constant_case() {
        // Zero variables: the table has one entry, returned as-is.
        let c = f(77);
        let got = eval_gadget(&[c], |b, ins| eval_multilinear(b, &ins[0..1], &[]));
        assert_eq!(got, c);
    }

    #[test]
    fn eval_multilinear_linear_case() {
        // One variable: f([a, b])(x) = a + x·(b - a).
        let (a, b, x) = (f(3), f(10), f(5));
        let got = eval_gadget(&[a, b, x], |bld, ins| {
            eval_multilinear(bld, &ins[0..2], &ins[2..3])
        });
        assert_eq!(got, a + x * (b - a));
    }

    #[test]
    fn powers_combination_known() {
        // 2 + 3·10 + 5·100 + 7·1000 = 7532.
        let vals = [f(2), f(3), f(5), f(7)];
        let base = f(10);
        let got = eval_gadget(&[vals[0], vals[1], vals[2], vals[3], base], |b, ins| {
            eval_powers_combination(b, &ins[0..4], ins[4])
        });
        assert_eq!(got, f(7532));
    }

    #[test]
    fn powers_combination_empty_is_zero() {
        let got = eval_gadget(&[f(9)], |b, ins| eval_powers_combination(b, &[], ins[0]));
        assert_eq!(got, F::ZERO);
    }

    #[test]
    fn pow_const_base_small_integer() {
        // base = 3, index = 5 (LE bits [1, 0, 1]) -> 3^5 = 243.
        let base = f(3);
        let bits = [F::ONE, F::ZERO, F::ONE];
        let got = eval_gadget(&bits, |b, ins| pow_const_base(b, base, ins));
        assert_eq!(got, f(243));
    }

    #[test]
    fn pow_const_base_uses_generator() {
        // Realistic use: a two-adic generator raised to an index via its bits.
        let base = F::two_adic_generator(10);
        let idx = 0b1011_0010u64;
        let bits: Vec<F> = (0..8).map(|i| F::from_bool((idx >> i) & 1 == 1)).collect();
        let got = eval_gadget(&bits, |b, ins| pow_const_base(b, base, ins));
        assert_eq!(got, base.exp_u64(idx));
    }

    #[test]
    fn pow_const_base_empty_is_one() {
        let got = eval_gadget(&[], |b, _ins| pow_const_base(b, f(7), &[]));
        assert_eq!(got, F::ONE);
    }

    #[test]
    fn constraint_weight_eq_only_single() {
        // A single equality constraint has weight W = γ^0·eq(X, z) = eq(X, z).
        let (x0, x1, z0, z1, gamma) = (f(2), f(3), f(5), f(7), f(11));
        let got = eval_gadget(&[x0, x1, z0, z1, gamma], |b, ins| {
            let (x, rest) = ins.split_at(2);
            eval_constraint_weight(b, x, &[&rest[0..2]], &[], rest[2])
        });
        let expected = Point::new(alloc::vec![x0, x1]).eq_poly(&Point::new(alloc::vec![z0, z1]));
        assert_eq!(got, expected);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// `expand_from_univariate` matches the native point for dims 1..=6.
        #[test]
        fn prop_expand_matches_native(z in 0u32..1_000_000, n in 1usize..7) {
            let zf = f(z);
            let native = Point::<F>::expand_from_univariate(zf, n);
            let got = eval_gadget_multi(&[zf], |b, ins| expand_from_univariate(b, ins[0], n));
            prop_assert_eq!(got.as_slice(), native.as_slice());
        }

        /// `eq_eval` matches `Point::eq_poly` for equal-length random points.
        #[test]
        fn prop_eq_matches_native(
            (a, b) in (1usize..7).prop_flat_map(|n| (
                proptest::collection::vec(0u32..1_000_000, n),
                proptest::collection::vec(0u32..1_000_000, n),
            ))
        ) {
            let n = a.len();
            let av: Vec<F> = a.iter().map(|&x| f(x)).collect();
            let bv: Vec<F> = b.iter().map(|&x| f(x)).collect();

            let native = Point::new(av.clone()).eq_poly(&Point::new(bv.clone()));

            let mut inputs = av;
            inputs.extend(bv);
            let got = eval_gadget(&inputs, |bld, ins| {
                let (a_t, b_t) = ins.split_at(n);
                eq_eval(bld, a_t, b_t)
            });
            prop_assert_eq!(got, native);
        }

        /// `select_eval` matches `Point::select_poly` (reversed-iteration order).
        #[test]
        fn prop_select_matches_native(
            point in proptest::collection::vec(0u32..1_000_000, 1..7),
            z in 0u32..1_000_000,
        ) {
            let pv: Vec<F> = point.iter().map(|&x| f(x)).collect();
            let zf = f(z);
            let n = pv.len();

            let native = Point::new(pv.clone()).select_poly::<F>(zf);

            let mut inputs = pv;
            inputs.push(zf);
            let got = eval_gadget(&inputs, |bld, ins| {
                let (p_t, z_t) = ins.split_at(n);
                select_eval(bld, p_t, z_t[0])
            });
            prop_assert_eq!(got, native);
        }

        /// `eval_multilinear` matches `Poly::eval_base` (the unique MLE).
        #[test]
        fn prop_eval_multilinear_matches_native(
            (evals, point) in (1usize..6).prop_flat_map(|k| (
                proptest::collection::vec(0u32..1_000_000, 1usize << k),
                proptest::collection::vec(0u32..1_000_000, k),
            ))
        ) {
            let n_ev = evals.len();
            let ev: Vec<F> = evals.iter().map(|&x| f(x)).collect();
            let pt: Vec<F> = point.iter().map(|&x| f(x)).collect();

            let native = Poly::new(ev.clone()).eval_base::<F>(&Point::new(pt.clone()));

            let mut inputs = ev;
            inputs.extend(pt);
            let got = eval_gadget(&inputs, |bld, ins| {
                let (e_t, p_t) = ins.split_at(n_ev);
                eval_multilinear(bld, e_t, p_t)
            });
            prop_assert_eq!(got, native);
        }

        /// `eval_powers_combination` matches a direct `Σ values[i]·base^i`.
        #[test]
        fn prop_powers_combination_matches_native(
            (vals, base) in (1usize..7).prop_flat_map(|n| (
                proptest::collection::vec(0u32..1_000_000, n),
                0u32..1_000_000,
            ))
        ) {
            let n = vals.len();
            let vv: Vec<F> = vals.iter().map(|&x| f(x)).collect();
            let base = f(base);

            let mut native = F::ZERO;
            let mut power = F::ONE;
            for &v in &vv {
                native += v * power;
                power *= base;
            }

            let mut inputs = vv;
            inputs.push(base);
            let got = eval_gadget(&inputs, |b, ins| {
                let (v_t, base_t) = ins.split_at(n);
                eval_powers_combination(b, v_t, base_t[0])
            });
            prop_assert_eq!(got, native);
        }

        /// `pow_const_base` matches `base.exp_u64(index)` for the bit-encoded index.
        #[test]
        fn prop_pow_const_base_matches_native(
            nbits in 1usize..12,
            index in any::<u64>(),
            base in 1u32..1_000_000,
        ) {
            let idx = index % (1u64 << nbits);
            let base = f(base);
            let bits: Vec<F> = (0..nbits).map(|i| F::from_bool((idx >> i) & 1 == 1)).collect();

            let native = base.exp_u64(idx);
            let got = eval_gadget(&bits, |b, ins| pow_const_base(b, base, ins));
            prop_assert_eq!(got, native);
        }

        /// `eval_constraint_weight` matches the native batched eq/select formula.
        #[test]
        fn prop_constraint_weight_matches_native(
            (k, x, eq_pts, sel, gamma) in (1usize..4).prop_flat_map(|k| (
                Just(k),
                proptest::collection::vec(0u32..100_000, k),
                proptest::collection::vec(proptest::collection::vec(0u32..100_000, k), 0..3),
                proptest::collection::vec(0u32..100_000, 0..3),
                0u32..100_000,
            ))
        ) {
            let xv: Vec<F> = x.iter().map(|&v| f(v)).collect();
            let eqv: Vec<Vec<F>> = eq_pts
                .iter()
                .map(|p| p.iter().map(|&v| f(v)).collect())
                .collect();
            let selv: Vec<F> = sel.iter().map(|&v| f(v)).collect();
            let g = f(gamma);

            // Native reference: Σ_i γ^i·eq(X, z_eq_i) + Σ_j γ^{n_eq+j}·select(X, z_sel_j).
            let xp = Point::new(xv.clone());
            let mut values = Vec::new();
            for z in &eqv {
                values.push(xp.eq_poly(&Point::new(z.clone())));
            }
            for &z in &selv {
                values.push(xp.select_poly::<F>(z));
            }
            let mut native = F::ZERO;
            let mut power = F::ONE;
            for v in &values {
                native += *v * power;
                power *= g;
            }

            // Circuit inputs: X (k), eq points flattened (n_eq·k), sel (n_sel), gamma.
            let n_eq = eqv.len();
            let n_sel = selv.len();
            let mut inputs = xv;
            for z in &eqv {
                inputs.extend(z.iter().copied());
            }
            inputs.extend(selv.iter().copied());
            inputs.push(g);

            let got = eval_gadget(&inputs, |b, ins| {
                let x_t = &ins[0..k];
                let eq_slices: Vec<&[Target]> =
                    (0..n_eq).map(|i| &ins[k + i * k..k + (i + 1) * k]).collect();
                let sel_start = k + n_eq * k;
                let sel_t = &ins[sel_start..sel_start + n_sel];
                let gamma_t = ins[sel_start + n_sel];
                eval_constraint_weight(b, x_t, &eq_slices, sel_t, gamma_t)
            });
            prop_assert_eq!(got, native);
        }
    }
}
