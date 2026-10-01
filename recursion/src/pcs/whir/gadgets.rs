//! Multilinear-polynomial arithmetic gadgets used by the WHIR verifier.
//!
//! Each gadget reproduces the field formula of its native counterpart so the
//! recursive verifier computes identical values:
//!
//! - [`expand_from_univariate`] mirrors `p3_multilinear_util::point::Point::expand_from_univariate`
//! - [`eq_eval`] mirrors `Point::eval_eq`
//! - [`select_eval`] mirrors `Point::eval_select`

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
/// Each factor is computed as `(2·a_i - 1)·b_i + (1 - a_i)`. The affine
/// terms depending only on `a` are shared across equalities at the same point.
/// Literal Boolean coordinates of `b` are factored separately, so column
/// selectors share the entire equality product for their common local point.
/// The product of zero factors is `1`.
///
/// # Panics
/// Panics if `a` and `b` have different lengths.
pub fn eq_eval<F: Field>(builder: &mut CircuitBuilder<F>, a: &[Target], b: &[Target]) -> Target {
    assert_eq!(a.len(), b.len(), "eq_eval: point length mismatch");

    let zero = builder.define_const(F::ZERO);
    let one = builder.define_const(F::ONE);
    let mut selectors = Vec::new();
    let mut terms = Vec::new();
    for (&ai, &bi) in a.iter().zip(b) {
        if bi == one {
            selectors.push(ai);
        } else if bi == zero {
            selectors.push(builder.sub(one, ai));
        } else {
            let two_ai = builder.add(ai, ai);
            let slope = builder.sub(two_ai, one);
            let complement = builder.sub(one, ai);
            terms.push(builder.mul_add(slope, bi, complement));
        }
    }
    let local_eq = builder.mul_many(&terms);
    let selector_eq = builder.mul_many(&selectors);
    builder.mul(local_eq, selector_eq)
}

/// Evaluates the selection polynomial `select(point, z)` that the WHIR verifier
/// uses to turn a univariate opening into a multilinear weight.
///
/// Mirrors `Point::eval_select`: the coordinates of `point` are consumed in
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
        // term = coord·var + (1 - coord), sharing the complement across scalars.
        let complement = builder.sub(one, coord);
        let term = builder.mul_add(coord, var, complement);
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

/// Combines multilinear leaf evaluations at a shared point with successive powers
/// of `gamma`. The empty combination is zero.
pub(crate) fn eval_multilinear_batched<F: Field>(
    builder: &mut CircuitBuilder<F>,
    leaves: &[&[Target]],
    point: &[Target],
    gamma: Target,
) -> Target {
    let Some(last) = leaves.last() else {
        return builder.define_const(F::ZERO);
    };
    let width = 1usize << point.len();
    assert!(
        leaves.iter().all(|leaf| leaf.len() == width),
        "multilinear batch leaf width mismatch"
    );

    // Evaluation at a fixed point is linear in the leaf values. Combine each
    // column first, then pay for only one multilinear interpolation.
    let combined: Vec<_> = (0..width)
        .map(|column| {
            leaves[..leaves.len() - 1]
                .iter()
                .rev()
                .fold(last[column], |acc, leaf| {
                    builder.mul_add(acc, gamma, leaf[column])
                })
        })
        .collect();
    eval_multilinear(builder, &combined, point)
}

/// Equality weights in lexicographic hypercube order, with `point[0]` most
/// significant. A caller evaluating many leaves at this point can share them.
pub(crate) fn multilinear_eq_weights<F: Field>(
    builder: &mut CircuitBuilder<F>,
    point: &[Target],
) -> Vec<Target> {
    let mut weights = alloc::vec![builder.define_const(F::ONE)];
    for &coordinate in point {
        let mut next = Vec::with_capacity(2 * weights.len());
        for weight in weights {
            let right = builder.mul(weight, coordinate);
            let left = builder.sub(weight, right);
            next.extend([left, right]);
        }
        weights = next;
    }
    weights
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
/// Complete Boolean selector blocks are factored before batching; other
/// equality points retain their individual evaluation.
pub fn eval_constraint_weight<F: Field>(
    builder: &mut CircuitBuilder<F>,
    point: &[Target],
    eq_points: &[&[Target]],
    sel_scalars: &[Target],
    gamma: Target,
) -> Target {
    assert!(
        eq_points.iter().all(|z| z.len() == point.len()),
        "eq_eval: point length mismatch"
    );
    let selections: Vec<_> = sel_scalars
        .iter()
        .map(|&z| select_eval(builder, point, z))
        .collect();
    let mut acc =
        (!selections.is_empty()).then(|| eval_powers_combination(builder, &selections, gamma));
    if eq_points.is_empty() {
        return acc.unwrap_or_else(|| builder.define_const(F::ZERO));
    }

    let zero = builder.define_const(F::ZERO);
    let one = builder.define_const(F::ONE);
    let mut blocks = Vec::new();
    let mut start = 0;
    while start < eq_points.len() {
        let (width, coordinates) = boolean_eq_block(&eq_points[start..], zero, one);
        blocks.push((start, width, coordinates));
        start += width;
    }

    // gamma_powers[i] = γ^(2^i), shared by every block and its Horner shift.
    let mut gamma_powers = alloc::vec![gamma];
    for (start, width, coordinates) in blocks.into_iter().rev() {
        let bits = coordinates.len();
        while gamma_powers.len() <= bits {
            let last = *gamma_powers.last().unwrap();
            gamma_powers.push(builder.mul(last, last));
        }

        let block_weight = if bits == 0 {
            eq_eval(builder, point, eq_points[start])
        } else {
            let mut fixed_a = Vec::with_capacity(point.len() - bits);
            let mut fixed_b = Vec::with_capacity(point.len() - bits);
            for (coordinate, (&a, &b)) in point.iter().zip(eq_points[start]).enumerate() {
                if !coordinates.contains(&coordinate) {
                    fixed_a.push(a);
                    fixed_b.push(b);
                }
            }
            let fixed_eq = eq_eval(builder, &fixed_a, &fixed_b);
            let factors: Vec<_> = coordinates
                .iter()
                .enumerate()
                .map(|(bit, &coordinate)| {
                    let r = point[coordinate];
                    let complement = builder.sub(one, r);
                    builder.mul_add(r, gamma_powers[bit], complement)
                })
                .collect();
            let selector_weight = builder.mul_many(&factors);
            builder.mul(fixed_eq, selector_weight)
        };

        // A block of B terms shifts the later statements by γ^B, preserving
        // the native equality-before-selection order and every batching power.
        debug_assert_eq!(width, 1usize << bits);
        acc = Some(acc.map_or(block_weight, |later| {
            builder.mul_add(later, gamma_powers[bits], block_weight)
        }));
    }
    acc.unwrap()
}

/// Recognizes a dyadic Boolean subcube in statement order. The coordinate
/// introduced at doubling step i is bit i of the statement's within-block index.
/// All other coordinates must match across corresponding lower/upper halves.
fn boolean_eq_block(points: &[&[Target]], zero: Target, one: Target) -> (usize, Vec<usize>) {
    let first = points[0];
    let mut width = 1;
    let mut coordinates = Vec::new();
    while width <= points.len() / 2 {
        let mut differences = first
            .iter()
            .zip(points[width])
            .enumerate()
            .filter_map(|(coordinate, (&a, &b))| (a != b).then_some(coordinate));
        let Some(coordinate) = differences.next() else {
            break;
        };
        if differences.next().is_some()
            || first[coordinate] != zero
            || points[width][coordinate] != one
            || coordinates.contains(&coordinate)
        {
            break;
        }
        let matches =
            points[..width]
                .iter()
                .zip(&points[width..2 * width])
                .all(|(&lower, &upper)| {
                    lower[coordinate] == zero
                        && upper[coordinate] == one
                        && lower
                            .iter()
                            .zip(upper)
                            .enumerate()
                            .all(|(i, (a, b))| i == coordinate || a == b)
                });
        if !matches {
            break;
        }
        coordinates.push(coordinate);
        width *= 2;
    }
    (width, coordinates)
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
    /// Exponent of `γ` weighting the first statement.
    ///
    /// Mirrors `p3_sumcheck::constraints::Constraint`'s `initial_power`: `0` for the
    /// initial constraint, `1` for every round constraint, which carries an existing
    /// claim at `γ^0` so its fresh statements start at `γ^1`.
    pub initial_power: usize,
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
        let mut w = eval_constraint_weight(builder, &local_r, &eq_refs, &c.sel_scalars, c.gamma);
        for _ in 0..c.initial_power {
            w = builder.mul(w, c.gamma);
        }
        total = builder.add(total, w);
    }
    total
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::CircuitBuilder;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, TwoAdicField};
    use p3_multilinear_util::point::Point;
    use p3_multilinear_util::poly::Poly;
    use proptest::prelude::*;

    use super::{
        eq_eval, eval_constraint_weight, eval_multilinear, eval_multilinear_batched,
        eval_powers_combination, expand_from_univariate, multilinear_eq_weights, pow_const_base,
        select_eval,
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
        let expected = Point::<F>::eval_select(z, &[p]);
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
        let expected = Point::<F>::eval_eq(&[x0, x1], &[z0, z1]);
        assert_eq!(got, expected);
    }

    #[test]
    fn shared_equality_point_reuses_affine_terms() {
        let mut builder = CircuitBuilder::<F>::new();
        let point: Vec<_> = (0..4).map(|_| builder.public_input()).collect();
        for _ in 0..8 {
            let other: Vec<_> = (0..4).map(|_| builder.public_input()).collect();
            eq_eval(&mut builder, &point, &other);
        }
        let circuit = builder.build().unwrap();
        let alu_ops = circuit
            .ops
            .iter()
            .filter(|op| matches!(op, p3_circuit::ops::Op::Alu { .. }))
            .count();
        // Three shared affine operations per coordinate, one FMA per pair,
        // and three multiplications per four-coordinate equality.
        assert!(
            alu_ops <= 12 + 8 * 7,
            "equality batch uses {alu_ops} ALU operations"
        );
    }

    #[test]
    fn boolean_selectors_share_the_local_equality_product() {
        for selectors_first in [true, false] {
            let mut builder = CircuitBuilder::<F>::new();
            let point: Vec<_> = (0..8).map(|_| builder.public_input()).collect();
            let local: Vec<_> = (0..4).map(|_| builder.public_input()).collect();
            for selector in 0..16 {
                let mut other: Vec<_> = (0..4)
                    .map(|bit| builder.define_const(F::from_bool((selector >> (3 - bit)) & 1 != 0)))
                    .collect();
                if selectors_first {
                    other.extend_from_slice(&local);
                } else {
                    other.splice(..0, local.iter().copied());
                }
                let result = eq_eval(&mut builder, &point, &other);
                builder
                    .tag(result, alloc::format!("selector{selector}"))
                    .unwrap();
            }
            let circuit = builder.build().unwrap();
            let alu_ops = circuit
                .ops
                .iter()
                .filter(|op| matches!(op, p3_circuit::ops::Op::Alu { .. }))
                .count();
            // Shared local equality: 19 ops; four selector complements, 28 trie
            // products for the 16 selectors, and one final product per selector.
            assert!(
                alu_ops <= 67,
                "selector equality batch uses {alu_ops} ALU operations"
            );

            let inputs: Vec<_> = (2..14).map(F::from_u32).collect();
            let mut runner = circuit.runner();
            runner.set_public_inputs(&inputs).unwrap();
            let traces = runner.run().unwrap();
            for selector in 0..16 {
                let mut other: Vec<_> = (0..4)
                    .map(|bit| F::from_bool((selector >> (3 - bit)) & 1 != 0))
                    .collect();
                if selectors_first {
                    other.extend_from_slice(&inputs[8..]);
                } else {
                    other.splice(..0, inputs[8..].iter().copied());
                }
                assert_eq!(
                    *traces.probe(&alloc::format!("selector{selector}")).unwrap(),
                    Point::<F>::eval_eq(&inputs[..8], &other)
                );
            }
        }
    }

    #[test]
    fn boolean_equality_blocks_reduce_batching_work() {
        for selectors_first in [false, true] {
            let mut builder = CircuitBuilder::<F>::new();
            let point: Vec<_> = (0..10).map(|_| builder.public_input()).collect();
            let local: Vec<_> = (0..4).map(|_| builder.public_input()).collect();
            let gamma = builder.public_input();
            let points: Vec<Vec<_>> = (0..64)
                .map(|selector| {
                    let bits: Vec<_> = (0..6)
                        .map(|bit| builder.define_const(F::from_bool((selector >> bit) & 1 != 0)))
                        .collect();
                    if selectors_first {
                        [bits.as_slice(), local.as_slice()].concat()
                    } else {
                        [local.as_slice(), bits.as_slice()].concat()
                    }
                })
                .collect();
            let refs: Vec<_> = points.iter().map(Vec::as_slice).collect();
            let out = eval_constraint_weight(&mut builder, &point, &refs, &[], gamma);
            builder.tag(out, "out").unwrap();
            let circuit = builder.build().unwrap();
            let alu_ops = circuit
                .ops
                .iter()
                .filter(|op| matches!(op, p3_circuit::ops::Op::Alu { .. }))
                .count();
            assert!(
                alu_ops <= 60,
                "Boolean equality batch uses {alu_ops} ALU operations"
            );

            for gamma in [F::ZERO, F::ONE, f(17)] {
                let mut inputs: Vec<_> = (2..16).map(F::from_u32).collect();
                inputs.push(gamma);
                let mut expected = F::ZERO;
                let mut power = F::ONE;
                for selector in 0..64 {
                    let bits: Vec<_> = (0..6)
                        .map(|bit| F::from_bool((selector >> bit) & 1 != 0))
                        .collect();
                    let other = if selectors_first {
                        [bits.as_slice(), &inputs[10..14]].concat()
                    } else {
                        [&inputs[10..14], bits.as_slice()].concat()
                    };
                    expected += power * Point::<F>::eval_eq(&inputs[..10], &other);
                    power *= gamma;
                }
                let mut runner = circuit.runner();
                runner.set_public_inputs(&inputs).unwrap();
                let traces = runner.run().unwrap();
                assert_eq!(*traces.probe("out").unwrap(), expected);
            }
        }
    }

    #[test]
    fn boolean_equality_blocks_match_mixed_layouts_and_fallbacks() {
        use p3_sumcheck::strategy::VariableOrder;

        use crate::pcs::whir::uni::plan::{StackedPlan, canonical_layout_strategy, padded_arity};

        type EF = BinomialExtensionField<F, 4>;
        let extension = |seed| EF::from_basis_coefficients_fn(|i| F::from_usize(seed + 3 * i));
        let shapes = [(15, 80), (14, 5), (13, 166), (12, 3)];
        for order in [VariableOrder::Prefix, VariableOrder::Suffix] {
            let strategy = canonical_layout_strategy(order);
            let plan = StackedPlan::new_with_strategy(
                &shapes.map(|(arity, width)| (padded_arity(arity, 4), width)),
                strategy,
            );
            let n = plan.num_variables;
            for perturb in [false, true] {
                for gamma in [EF::ZERO, EF::ONE, extension(17)] {
                    let mut inputs: Vec<_> = (0..n).map(|i| extension(i + 2)).collect();
                    let mut native_points = Vec::new();
                    let mut local_ranges = Vec::new();
                    for placement in &plan.placements {
                        let arity = shapes[placement.table_idx].0;
                        for opening in 0..2 {
                            let start = inputs.len();
                            inputs.extend((0..arity).map(|i| extension(start + opening + i)));
                            let range = start..inputs.len();
                            for selector in &placement.selectors {
                                native_points.push(selector.lift_with_strategy(
                                    &inputs[range.clone()],
                                    EF::ZERO,
                                    EF::ONE,
                                    strategy,
                                ));
                            }
                            local_ranges.push(range);
                        }
                    }
                    // OOD points remain individual statements after the selector blocks.
                    let ood_start = inputs.len();
                    inputs.extend((0..2 * n).map(|i| extension(ood_start + i)));
                    native_points.extend(inputs[ood_start..].chunks(n).map(<[_]>::to_vec));
                    let selector_coordinate = if strategy.reverse_selectors {
                        shapes[plan.placements[0].table_idx].0
                    } else {
                        0
                    };
                    if perturb {
                        native_points[4][selector_coordinate] =
                            EF::ONE - native_points[4][selector_coordinate];
                    }
                    let selection_start = inputs.len();
                    inputs.extend([extension(23), extension(29), gamma]);
                    let mut expected = EF::ZERO;
                    let mut power = EF::ONE;
                    for other in &native_points {
                        expected += power * Point::<EF>::eval_eq(&inputs[..n], other);
                        power *= gamma;
                    }
                    for &scalar in &inputs[selection_start..selection_start + 2] {
                        expected += power * Point::<EF>::eval_select(scalar, &inputs[..n]);
                        power *= gamma;
                    }
                    let actual = eval_gadget(&inputs, |builder, targets| {
                        let zero = builder.define_const(EF::ZERO);
                        let one = builder.define_const(EF::ONE);
                        let mut points = Vec::new();
                        let mut ranges = local_ranges.iter();
                        for placement in &plan.placements {
                            for _ in 0..2 {
                                let local = &targets[ranges.next().unwrap().clone()];
                                points.extend(placement.selectors.iter().map(|selector| {
                                    selector.lift_with_strategy(local, zero, one, strategy)
                                }));
                            }
                        }
                        points.extend(
                            targets[ood_start..selection_start]
                                .chunks(n)
                                .map(<[_]>::to_vec),
                        );
                        if perturb {
                            let bit = &mut points[4][selector_coordinate];
                            *bit = if *bit == zero { one } else { zero };
                        }
                        let refs: Vec<_> = points.iter().map(Vec::as_slice).collect();
                        eval_constraint_weight(
                            builder,
                            &targets[..n],
                            &refs,
                            &targets[selection_start..selection_start + 2],
                            targets[selection_start + 2],
                        )
                    });
                    assert_eq!(actual, expected, "order {order:?}, perturb {perturb}");
                }
            }
        }
    }

    #[test]
    fn shared_selection_point_reuses_complements() {
        let mut builder = CircuitBuilder::<F>::new();
        let point: Vec<_> = (0..4).map(|_| builder.public_input()).collect();
        for _ in 0..8 {
            let scalar = builder.public_input();
            select_eval(&mut builder, &point, scalar);
        }
        let circuit = builder.build().unwrap();
        let alu_ops = circuit
            .ops
            .iter()
            .filter(|op| matches!(op, p3_circuit::ops::Op::Alu { .. }))
            .count();
        // Four shared complements; per scalar, three squarings, four FMAs,
        // and three multiplications.
        assert!(
            alu_ops <= 4 + 8 * 10,
            "selection batch uses {alu_ops} ALU operations"
        );
    }

    #[test]
    fn batched_multilinear_folding_matches_native_weighted_evaluations() {
        type EF = BinomialExtensionField<F, 4>;
        let extension =
            |seed: usize| EF::from_basis_coefficients_fn(|i| F::from_usize(seed + 3 * i));
        for dimensions in 0..=4 {
            let width = 1usize << dimensions;
            for queries in [0, 1, 2, 3, 8] {
                let leaves: Vec<Vec<EF>> = (0..queries)
                    .map(|q| (0..width).map(|i| extension(7 + 11 * q + i * i)).collect())
                    .collect();
                for reverse in [false, true] {
                    let mut point: Vec<_> = (0..dimensions).map(|i| extension(3 + i)).collect();
                    if reverse {
                        point.reverse();
                    }
                    for gamma in [EF::ZERO, EF::ONE, extension(13)] {
                        let mut power = EF::ONE;
                        let mut expected = EF::ZERO;
                        for leaf in &leaves {
                            expected += power
                                * Poly::new(leaf.clone()).eval_ext::<F>(&Point::new(point.clone()));
                            power *= gamma;
                        }
                        let mut inputs: Vec<_> = leaves.iter().flatten().copied().collect();
                        inputs.extend_from_slice(&point);
                        inputs.push(gamma);
                        let actual = eval_gadget(&inputs, |builder, targets| {
                            let leaf_targets: Vec<_> =
                                targets[..queries * width].chunks(width).collect();
                            eval_multilinear_batched(
                                builder,
                                &leaf_targets,
                                &targets[queries * width..queries * width + dimensions],
                                targets[targets.len() - 1],
                            )
                        });
                        assert_eq!(
                            actual, expected,
                            "dimensions {dimensions}, queries {queries}, reverse {reverse}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn batched_multilinear_folding_reduces_alu_work() {
        let mut builder = CircuitBuilder::<F>::new();
        let point: Vec<_> = (0..4).map(|_| builder.public_input()).collect();
        let leaves: Vec<Vec<_>> = (0..24)
            .map(|_| (0..16).map(|_| builder.public_input()).collect())
            .collect();
        let leaf_refs: Vec<_> = leaves.iter().map(Vec::as_slice).collect();
        let gamma = builder.public_input();
        eval_multilinear_batched(&mut builder, &leaf_refs, &point, gamma);
        let circuit = builder.build().unwrap();
        let alu_ops = circuit
            .ops
            .iter()
            .filter(|op| matches!(op, p3_circuit::ops::Op::Alu { .. }))
            .count();
        // Batch 24 values in each of 16 columns, then perform 15 interpolations.
        assert!(
            alu_ops <= 16 * 23 + 2 * 15,
            "leaf batch uses {alu_ops} ALU operations"
        );
    }

    #[test]
    fn shared_multilinear_weights_match_native_and_boolean_corners() {
        type EF = BinomialExtensionField<F, 4>;
        for dimensions in 0..=4 {
            let width = 1usize << dimensions;
            let point: Vec<_> = (0..dimensions)
                .map(|j| EF::from_basis_coefficients_fn(|i| F::from_usize(2 + j + 7 * i)))
                .collect();
            let weights = eval_gadget_multi(&point, |builder, targets| {
                multilinear_eq_weights(builder, targets)
            });
            for (index, &weight) in weights.iter().enumerate() {
                let corner: Vec<_> = (0..dimensions)
                    .map(|j| EF::from_bool((index >> (dimensions - 1 - j)) & 1 != 0))
                    .collect();
                assert_eq!(weight, Point::<EF>::eval_eq(&point, &corner));
                let at_corner = eval_gadget_multi(&corner, |builder, targets| {
                    multilinear_eq_weights(builder, targets)
                });
                assert_eq!(
                    at_corner,
                    (0..width)
                        .map(|j| EF::from_bool(j == index))
                        .collect::<Vec<_>>()
                );
            }
            let values: Vec<_> = (0..width)
                .map(|j| EF::from_basis_coefficients_fn(|i| F::from_usize(3 + j * j + 5 * i)))
                .collect();
            let native = Poly::new(values.clone()).eval_ext::<F>(&Point::new(point.clone()));
            let mut inputs = point;
            inputs.extend(values);
            let actual = eval_gadget(&inputs, |builder, targets| {
                let weights = multilinear_eq_weights(builder, &targets[..dimensions]);
                builder.inner_product(&weights, &targets[dimensions..])
            });
            assert_eq!(actual, native);
        }
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

            let native = Point::<F>::eval_eq(&av, &bv);

            let mut inputs = av;
            inputs.extend(bv);
            let got = eval_gadget(&inputs, |bld, ins| {
                let (a_t, b_t) = ins.split_at(n);
                eq_eval(bld, a_t, b_t)
            });
            prop_assert_eq!(got, native);
        }

        /// `select_eval` matches `Point::eval_select` (reversed-iteration order).
        #[test]
        fn prop_select_matches_native(
            point in proptest::collection::vec(0u32..1_000_000, 1..7),
            z in 0u32..1_000_000,
        ) {
            let pv: Vec<F> = point.iter().map(|&x| f(x)).collect();
            let zf = f(z);
            let n = pv.len();

            let native = Point::<F>::eval_select(zf, &pv);

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
            let mut values = Vec::new();
            for z in &eqv {
                values.push(Point::<F>::eval_eq(&xv, z));
            }
            for &z in &selv {
                values.push(Point::<F>::eval_select(z, &xv));
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
