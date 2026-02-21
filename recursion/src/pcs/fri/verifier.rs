#![allow(clippy::too_many_arguments)]
#![allow(clippy::option_if_let_else)]

use alloc::collections::btree_map::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::iter;

use hashbrown::HashMap;
use p3_circuit::op::Poseidon2Config;
use p3_circuit::{CircuitBuilder, NonPrimitiveOpId};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField64, TwoAdicField};
use p3_matrix::Dimensions;
use p3_util::zip_eq::zip_eq;

use super::{FriProofTargets, InputProofTargets};
use crate::Target;
use crate::pcs::{verify_batch_circuit, verify_batch_circuit_from_extension_opened};
use crate::traits::{ComsWithOpeningsTargets, Recursive, RecursiveExtensionMmcs, RecursiveMmcs};
use crate::verifier::{ObservableCommitment, VerificationError};

/// Pack lifted base field targets into packed extension field targets for MMCS verification.
///
/// Converts N targets (each representing a lifted base field element `EF([v, 0, 0, 0])`)
/// into ceil(N / EF::DIMENSION) targets (each representing a packed extension element).
///
/// For `BinomialExtensionField<F, D>`, the packing is:
/// `packed[i] = lifted[i*D] + lifted[i*D+1]*X + lifted[i*D+2]*X^2 + ...`
/// where `X` is the extension basis element.
fn pack_lifted_to_ext<F, EF>(builder: &mut CircuitBuilder<EF>, lifted: &[Target]) -> Vec<Target>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
{
    if lifted.is_empty() {
        return Vec::new();
    }

    let d = EF::DIMENSION;

    // Get the extension basis elements: {1, X, X^2, ..., X^(D-1)}
    let basis: Vec<EF> = (0..d)
        .map(|i| {
            let mut coeffs = vec![F::ZERO; d];
            coeffs[i] = F::ONE;
            EF::from_basis_coefficients_slice(&coeffs).expect("valid basis element")
        })
        .collect();

    // Lift basis elements to circuit constants once and reuse across all chunks.
    let basis_consts: Vec<Target> = basis.iter().map(|b| builder.add_const(*b)).collect();

    // Add a zero constant for padding partial chunks
    let zero = builder.add_const(EF::ZERO);

    lifted
        .chunks(d)
        .map(|chunk| {
            // packed = chunk[0]*basis[0] + chunk[1]*basis[1] + ... + chunk[D-1]*basis[D-1]
            // Since basis[0] = 1, start with chunk[0]
            let mut packed = chunk[0];
            for j in 1..d {
                let val = if j < chunk.len() { chunk[j] } else { zero };
                let term = builder.mul(val, basis_consts[j]);
                packed = builder.add(packed, term);
            }
            packed
        })
        .collect()
}

/// Per-phase configuration for the FRI fold chain.
#[derive(Clone, Debug)]
pub struct FoldPhaseConfig {
    pub beta: Target,
    /// Packed extension field sibling evaluations (arity - 1 values).
    pub siblings: Vec<Target>,
    pub roll_in: Option<Target>,
}

/// Optimized one-hot computation for 2 bits.
fn one_hot_from_two_bits<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    b0: Target,
    b1: Target,
) -> [Target; 4] {
    let one = builder.add_const(EF::ONE);
    let nb0 = builder.sub(one, b0);
    let nb1 = builder.sub(one, b1);

    let h0 = builder.mul(nb0, nb1); // 00
    let h1 = builder.mul(b0, nb1); // 01
    let h2 = builder.mul(nb0, b1); // 10
    let h3 = builder.mul(b0, b1); // 11

    [h0, h1, h2, h3]
}

/// Optimized one-hot computation for 3 bits.
fn one_hot_from_three_bits<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    b0: Target,
    b1: Target,
    b2: Target,
) -> [Target; 8] {
    let one = builder.add_const(EF::ONE);
    let nb0 = builder.sub(one, b0);
    let nb1 = builder.sub(one, b1);
    let nb2 = builder.sub(one, b2);

    // Shared products for (b1, b2).
    let t00 = builder.mul(nb1, nb2); // b1=0, b2=0
    let t01 = builder.mul(nb1, b2); // b1=0, b2=1
    let t10 = builder.mul(b1, nb2); // b1=1, b2=0
    let t11 = builder.mul(b1, b2); // b1=1, b2=1

    // Index j = b0 + 2*b1 + 4*b2 (little-endian).
    let h0 = builder.mul(nb0, t00); // 0,0,0 -> j=0
    let h1 = builder.mul(b0, t00); // 1,0,0 -> j=1
    let h2 = builder.mul(nb0, t10); // 0,1,0 -> j=2
    let h3 = builder.mul(b0, t10); // 1,1,0 -> j=3
    let h4 = builder.mul(nb0, t01); // 0,0,1 -> j=4
    let h5 = builder.mul(b0, t01); // 1,0,1 -> j=5
    let h6 = builder.mul(nb0, t11); // 0,1,1 -> j=6
    let h7 = builder.mul(b0, t11); // 1,1,1 -> j=7

    [h0, h1, h2, h3, h4, h5, h6, h7]
}

/// Optimized one-hot computation for 4 bits, using two 2-bit one-hots.
fn one_hot_from_four_bits<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    bits: &[Target],
) -> Vec<Target> {
    debug_assert_eq!(bits.len(), 4);
    let low = one_hot_from_two_bits(builder, bits[0], bits[1]);
    let high = one_hot_from_two_bits(builder, bits[2], bits[3]);

    let mut result = Vec::with_capacity(16);
    for j in 0..16 {
        let low_idx = j & 3;
        let high_idx = j >> 2;
        let val = builder.mul(low[low_idx], high[high_idx]);
        result.push(val);
    }
    result
}

/// Compute a one-hot encoding from `log_arity` index bits.
/// Returns a vector of `2^log_arity` targets where `result[j] = 1` iff j matches the
/// integer value of the input bits (little-endian).
fn one_hot_from_bits<EF: Field>(builder: &mut CircuitBuilder<EF>, bits: &[Target]) -> Vec<Target> {
    let log_arity = bits.len();
    let arity = 1usize << log_arity;

    match log_arity {
        0 => {
            // Degenerate case: arity 1, always index 0.
            vec![builder.add_const(EF::ONE)]
        }
        1 => {
            // One bit: [!b0, b0]
            let one = builder.add_const(EF::ONE);
            let b0 = bits[0];
            let nb0 = builder.sub(one, b0);
            vec![nb0, b0]
        }
        2 => {
            let [h0, h1, h2, h3] = one_hot_from_two_bits(builder, bits[0], bits[1]);
            vec![h0, h1, h2, h3]
        }
        3 => {
            let [h0, h1, h2, h3, h4, h5, h6, h7] =
                one_hot_from_three_bits(builder, bits[0], bits[1], bits[2]);
            vec![h0, h1, h2, h3, h4, h5, h6, h7]
        }
        4 => one_hot_from_four_bits(builder, bits),
        _ => {
            let one = builder.add_const(EF::ONE);
            // Precompute negations of bits once to avoid rebuilding `1 - bit` inside the inner loop for every index j.
            let not_bits: Vec<Target> = bits.iter().map(|&bit| builder.sub(one, bit)).collect();

            let mut one_hot = Vec::with_capacity(arity);
            for j in 0..arity {
                let mut product = one;
                for (k, &bit) in bits.iter().enumerate() {
                    if (j >> k) & 1 == 1 {
                        product = builder.mul(product, bit);
                    } else {
                        product = builder.mul(product, not_bits[k]);
                    }
                }
                one_hot.push(product);
            }
            one_hot
        }
    }
}

/// Reconstruct the full evaluation row from `folded` + `siblings` using the index bits.
///
/// `index_in_group_bits` are the `log_arity` lowest bits of the current start_index.
/// The native verifier does:
///   evals[index_in_group] = folded; evals[j] = siblings[...] for j != index_in_group
///
/// This circuit version uses a one-hot encoding to place values correctly.
fn reconstruct_evals<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    folded: Target,
    siblings: &[Target],
    index_in_group_bits: &[Target],
) -> Vec<Target> {
    builder.push_scope("fri_reconstruct_evals");
    let log_arity = index_in_group_bits.len();
    let arity = 1usize << log_arity;
    debug_assert_eq!(siblings.len(), arity - 1);

    let one_hot = one_hot_from_bits(builder, index_in_group_bits);

    // Compute cumulative sum: cum[j] = sum(one_hot[0..=j]) ∈ {0, 1}
    let mut cum = Vec::with_capacity(arity);
    cum.push(one_hot[0]);
    for j in 1..arity {
        cum.push(builder.add(cum[j - 1], one_hot[j]));
    }

    // For each position j:
    //   if one_hot[j] = 1: evals[j] = folded
    //   if one_hot[j] = 0 and cum[j] = 0: evals[j] = siblings[j]     (j < index_in_group)
    //   if one_hot[j] = 0 and cum[j] = 1: evals[j] = siblings[j-1]   (j > index_in_group)
    let mut evals = Vec::with_capacity(arity);
    for j in 0..arity {
        let left_idx = if j > 0 { j - 1 } else { 0 };
        let right_idx = if j < arity - 1 { j } else { arity - 2 };
        let actual_sibling = builder.select(cum[j], siblings[left_idx], siblings[right_idx]);
        let eval_j = builder.select(one_hot[j], folded, actual_sibling);
        evals.push(eval_j);
    }

    builder.pop_scope();
    evals
}

/// Compute the subgroup evaluation points for a single FRI fold phase.
///
/// Returns `(xs, subgroup_start)` where:
/// - `xs[i] = subgroup_start * omega^{br(i)}` are the `arity` evaluation points
///   in bit-reversed order,
/// - `omega = two_adic_generator(log_arity)`,
/// - `subgroup_start = two_adic_generator(log_folded_height + log_arity)^{rev(parent_index)}`.
///
/// When `precomputed_subgroup_start` is `Some`, the select-mul chain for
/// `subgroup_start` is skipped and the provided value is used directly.
fn compute_subgroup_points<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    index_bits: &[Target],
    bits_consumed: usize,
    log_arity: usize,
    log_folded_height: usize,
    precomputed_subgroup_start: Option<Target>,
) -> (Vec<Target>, Target)
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("fri_compute_subgroup_points");

    let arity = 1usize << log_arity;

    let subgroup_start = if let Some(ss) = precomputed_subgroup_start {
        ss
    } else {
        // Parent index bits start after index_in_group bits
        let parent_offset = bits_consumed + log_arity;

        // Compute subgroup_start = g_big^{reverse_bits_len(parent_index, log_folded_height)}
        let g_big = F::two_adic_generator(log_folded_height + log_arity);
        let one = builder.add_const(EF::ONE);

        let g_big_pows: Vec<Target> = if log_folded_height > 0 {
            iter::successors(Some(g_big), |&prev| Some(prev.square()))
                .take(log_folded_height)
                .map(|p| builder.add_const(EF::from(p)))
                .collect()
        } else {
            Vec::new()
        };

        let mut ss = one;
        if log_folded_height > 0 {
            for j in 0..log_folded_height {
                let bit = index_bits[parent_offset + log_folded_height - 1 - j];
                let multiplier = builder.select(bit, g_big_pows[j], one);
                ss = builder.mul(ss, multiplier);
            }
        }
        ss
    };

    // Compute xs[i] = subgroup_start * omega^{br(i)}
    let omega = F::two_adic_generator(log_arity);
    let omega_br_consts: Vec<Target> = (0..arity)
        .map(|i| {
            let br_i = p3_util::reverse_bits_len(i, log_arity);
            let omega_br = omega.exp_u64(br_i as u64);
            builder.add_const(EF::from(omega_br))
        })
        .collect();

    let mut xs = Vec::with_capacity(arity);
    for &omega_br_const in omega_br_consts.iter() {
        let xi = builder.mul(subgroup_start, omega_br_const);
        xs.push(xi);
    }

    builder.pop_scope();
    (xs, subgroup_start)
}

/// Precompute Lagrange denominator inverses for a given FRI arity, in the
/// canonical subgroup with `subgroup_start = 1`.
///
/// For `xs0[i] = omega^{br(i)}` where `omega = two_adic_generator(log_arity)`,
/// returns `denom_inv[i] = 1 / ∏_{j != i} (xs0[i] - xs0[j])` lifted to `EF`.
fn precompute_lagrange_denominator_inverses<F, EF>(log_arity: usize) -> Vec<EF>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    let arity = 1usize << log_arity;
    let omega = F::two_adic_generator(log_arity);

    // Canonical subgroup points xs0[i] = omega^{br(i)} in EF.
    let mut xs0 = Vec::with_capacity(arity);
    for i in 0..arity {
        let br_i = p3_util::reverse_bits_len(i, log_arity);
        let g_i = omega.exp_u64(br_i as u64);
        xs0.push(EF::from(g_i));
    }

    let mut denom_inv = Vec::with_capacity(arity);
    for i in 0..arity {
        let mut denom = EF::ONE;
        for j in 0..arity {
            if j == i {
                continue;
            }
            denom *= xs0[i] - xs0[j];
        }
        // denom should never be zero for distinct xs0.
        let inv = denom.inverse();
        denom_inv.push(inv);
    }

    denom_inv
}

/// Optimized Lagrange interpolation for small arities (`log_arity` 2, 3, 4).
///
/// This uses:
/// - a batch inversion for `diffs[i] = z - xs[i]` (one division),
/// - a single inversion for `subgroup_start^{arity-1}`,
/// - precomputed denominator inverses from the canonical subgroup, scaled
///   by `subgroup_start^{-(arity-1)}` in-circuit.
fn lagrange_interpolate_small<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    xs: &[Target],
    ys: &[Target],
    z: Target,
    subgroup_start: Target,
    log_arity: usize,
) -> Target
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    let arity = 1usize << log_arity;
    debug_assert_eq!(xs.len(), arity);
    debug_assert_eq!(ys.len(), arity);

    // diffs[i] = z - xs[i]
    let mut diffs = Vec::with_capacity(arity);
    for &xi in xs {
        diffs.push(builder.sub(z, xi));
    }

    // L(z) = ∏ diffs[i]
    let mut l_z = diffs[0];
    for d in &diffs[1..] {
        l_z = builder.mul(l_z, *d);
    }

    // Batch inversion of diffs: inv_diffs[i] = 1 / (z - xs[i])
    let one = builder.add_const(EF::ONE);
    let mut prefix = Vec::with_capacity(arity);
    prefix.push(diffs[0]);
    for i in 1..arity {
        let prod = builder.mul(prefix[i - 1], diffs[i]);
        prefix.push(prod);
    }

    // Single division for the inverse of the total product.
    let mut inv_total = builder.div(one, prefix[arity - 1]);

    let mut inv_diffs = vec![inv_total; arity];
    // Standard batch inversion backward sweep:
    for i in (0..arity).rev() {
        let prev = if i == 0 { one } else { prefix[i - 1] };
        inv_diffs[i] = builder.mul(inv_total, prev);
        inv_total = builder.mul(inv_total, diffs[i]);
    }

    // Compute subgroup_start^{arity-1} and its inverse.
    // arity-1 = 2^log_arity - 1 is all-ones in binary, so use the recurrence
    // r_1 = s, r_{i+1} = r_i^2 * s which converges in log_arity-1 steps.
    let mut s_pow = subgroup_start;
    for _ in 1..log_arity {
        s_pow = builder.mul(s_pow, s_pow);
        s_pow = builder.mul(s_pow, subgroup_start);
    }
    let inv_s_pow = builder.div(one, s_pow);

    // Precomputed canonical denominator inverses (in EF).
    let denom_inv_consts = precompute_lagrange_denominator_inverses::<F, EF>(log_arity);
    debug_assert_eq!(denom_inv_consts.len(), arity);

    // Pre-lift all denominator inverse constants once before the loop
    let denom_inv_targets: Vec<Target> = denom_inv_consts
        .iter()
        .map(|&c| builder.add_const(c))
        .collect();

    // result = sum_i ys[i] * L(z)/(z - xs[i]) * (1 / denom[i])
    // where 1/denom[i] = denom_inv_consts[i] * subgroup_start^{-(arity-1)}.
    let mut accumulator = builder.add_const(EF::ZERO);
    for i in 0..arity {
        let partial_num = builder.mul(l_z, inv_diffs[i]);
        let scaled_y = builder.mul(ys[i], partial_num);

        let term = builder.mul(scaled_y, denom_inv_targets[i]);

        accumulator = builder.add(accumulator, term);
    }

    // Apply the common factor subgroup_start^{-(arity-1)} once at the end.
    builder.mul(accumulator, inv_s_pow)
}

/// Precompute `subgroup_start` for every FRI phase within a single query.
///
/// All phases compute `g_i^{rev(parent_index_i)}` where
/// `g_i = two_adic_generator(log_current_height_i)`. Because the reversed parent
/// bits for phase `i` are a prefix of phase 0's bits, and
/// `g_i = g_0^{2^{cumulative_bits_i}}`, we derive later phases from the
/// intermediate of phase 0's chain:
/// `subgroup_start_i = (g_0^{N_i})^{2^{cumulative_bits_i}}`.
fn precompute_subgroup_starts<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    index_bits: &[Target],
    log_max_height: usize,
    log_arities: &[usize],
    cumulative_bits: &[usize],
) -> Vec<Target>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    let num_phases = log_arities.len();
    let one = builder.add_const(EF::ONE);

    // log_folded_height[i] = log_max_height - cumulative_bits[i+1]
    let log_folded_heights: Vec<usize> = (0..num_phases)
        .map(|i| log_max_height - cumulative_bits[i + 1])
        .collect();

    let max_chain_len = log_folded_heights[0];

    if max_chain_len == 0 {
        builder.pop_scope();
        return vec![one; num_phases];
    }

    let g_0 = F::two_adic_generator(log_max_height);
    let powers_of_g: Vec<_> = iter::successors(Some(g_0), |&prev| Some(prev.square()))
        .take(max_chain_len)
        .map(|p| builder.add_const(EF::from(p)))
        .collect();

    let parent_offset_0 = cumulative_bits[1]; // = log_arities[0]

    let mut capture_at: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, &lf) in log_folded_heights
        .iter()
        .enumerate()
        .take(num_phases)
        .skip(1)
    {
        if lf > 0 {
            capture_at.entry(lf).or_default().push(i);
        }
    }

    let mut g_pow = one;
    let mut result = vec![one; num_phases];

    for j in 0..max_chain_len {
        let bit = index_bits[parent_offset_0 + max_chain_len - 1 - j];
        let multiplier = builder.select(bit, powers_of_g[j], one);
        g_pow = builder.mul(g_pow, multiplier);

        let bits_done = j + 1;
        if let Some(phase_indices) = capture_at.get(&bits_done) {
            for &phase_i in phase_indices {
                result[phase_i] = builder.exp_power_of_2(g_pow, cumulative_bits[phase_i]);
            }
        }
    }

    // Phase 0: full chain, cumulative_bits[0] = 0, no squaring.
    result[0] = g_pow;

    result
}

/// Precompute and cache powers `beta^{2^k}` for all fold phases.
fn precompute_beta_powers_per_phase<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    betas: &[Target],
    log_arities: &[usize],
) -> Vec<Target> {
    builder.push_scope("fri_precompute_betas");

    debug_assert_eq!(betas.len(), log_arities.len());
    let result = betas
        .iter()
        .zip(log_arities.iter())
        .map(|(&beta, &log_arity)| builder.exp_power_of_2(beta, log_arity))
        .collect();

    builder.pop_scope();
    result
}

/// Lagrange interpolation in circuit: evaluate the interpolating polynomial at `z`.
///
/// Given evaluation points xs[0..n] and values ys[0..n], computes
/// the unique polynomial p of degree < n passing through (xs[i], ys[i])
/// and returns p(z).
fn lagrange_interpolate_circuit<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    xs: &[Target],
    ys: &[Target],
    z: Target,
) -> Target {
    let n = xs.len();
    debug_assert_eq!(n, ys.len());

    // Compute diffs[i] = z - xs[i]
    let diffs: Vec<Target> = xs.iter().map(|&xi| builder.sub(z, xi)).collect();

    // Compute L(z) = prod(diffs)
    let mut l_z = diffs[0];
    for &d in &diffs[1..] {
        l_z = builder.mul(l_z, d);
    }

    // For each i, compute:
    //   partial_num[i] = L(z) / diffs[i]  (Lagrange numerator without the y)
    //   denom[i] = prod_{j!=i} (xs[i] - xs[j])
    //   term[i] = ys[i] * partial_num[i] / denom[i]
    //
    // result = sum(term[i])
    let mut result = builder.add_const(EF::ZERO);
    for i in 0..n {
        // partial_num[i] = L(z) / (z - xs[i])
        let partial_num = builder.div(l_z, diffs[i]);

        // denom[i] = prod_{j!=i} (xs[i] - xs[j])
        let denom = xs.iter().enumerate().filter(|&(j, _)| j != i).fold(
            builder.add_const(EF::ONE),
            |acc, (_, &xj)| {
                let diff = builder.sub(xs[i], xj);
                builder.mul(acc, diff)
            },
        );

        // term = ys[i] * partial_num / denom
        let num_term = builder.mul(ys[i], partial_num);
        let term = builder.div(num_term, denom);

        result = builder.add(result, term);
    }

    result
}

/// Perform a single FRI fold phase with arbitrary arity.
///
/// Reconstructs the full evaluation row, computes evaluation points,
/// performs Lagrange interpolation at beta, and applies optional roll-in.
///
/// When `precomputed_evals` is `Some`, those evals are reused instead of
/// rebuilding them via `reconstruct_evals`.
fn fold_one_phase<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    folded: Target,
    siblings: &[Target],
    beta: Target,
    index_bits: &[Target],
    bits_consumed: usize,
    log_arity: usize,
    log_current_height: usize,
    roll_in: Option<Target>,
    precomputed_beta_pow: Option<Target>,
    precomputed_evals: Option<&[Target]>,
    precomputed_subgroup_start: Option<Target>,
) -> Target
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("fri_fold_one_phase");

    let log_folded_height = log_current_height - log_arity;
    let index_in_group_bits = &index_bits[bits_consumed..bits_consumed + log_arity];

    // For arity 2, use the optimized formula
    if log_arity == 1 {
        let sibling = siblings[0];
        let one = builder.add_const(EF::ONE);
        let neg_half = builder.add_const(EF::NEG_ONE * EF::ONE.halve());
        let sibling_is_right = builder.sub(one, index_bits[bits_consumed]);

        let e0 = builder.select(sibling_is_right, folded, sibling);
        let x0 = precomputed_subgroup_start.unwrap_or_else(|| {
            compute_x0_from_index_bits_general::<F, EF>(
                builder,
                index_bits,
                bits_consumed,
                log_folded_height,
            )
        });
        let inv = builder.div(neg_half, x0);

        let d = builder.sub(sibling, folded);
        let two_b = builder.add(sibling_is_right, sibling_is_right);
        let two_b_m1 = builder.sub(two_b, one);
        let e1_minus_e0 = builder.mul(two_b_m1, d);

        let beta_minus_x0 = builder.sub(beta, x0);
        let t = builder.mul(beta_minus_x0, e1_minus_e0);
        let t_inv = builder.mul(t, inv);
        let mut new_folded = builder.add(e0, t_inv);

        if let Some(ro) = roll_in {
            let beta_sq = precomputed_beta_pow.unwrap_or_else(|| builder.mul(beta, beta));
            let add_term = builder.mul(beta_sq, ro);
            new_folded = builder.add(new_folded, add_term);
        }
        builder.pop_scope();
        return new_folded;
    }

    // General path: Lagrange interpolation
    let owned_evals;
    let evals: &[Target] = match precomputed_evals {
        Some(e) => e,
        None => {
            owned_evals = reconstruct_evals(builder, folded, siblings, index_in_group_bits);
            &owned_evals
        }
    };

    let (xs, subgroup_start) = compute_subgroup_points::<F, EF>(
        builder,
        index_bits,
        bits_consumed,
        log_arity,
        log_folded_height,
        precomputed_subgroup_start,
    );

    // For small arities (2, 4, 8, 16), use the optimized interpolation that
    // avoids rebuilding denominators in-circuit.
    let mut new_folded = if (2..=4).contains(&log_arity) {
        lagrange_interpolate_small::<F, EF>(builder, &xs, evals, beta, subgroup_start, log_arity)
    } else {
        lagrange_interpolate_circuit(builder, &xs, evals, beta)
    };

    // Roll-in: folded += beta^{2^log_arity} * roll_in
    if let Some(ro) = roll_in {
        let beta_pow =
            precomputed_beta_pow.unwrap_or_else(|| builder.exp_power_of_2(beta, log_arity));
        let add_term = builder.mul(beta_pow, ro);
        new_folded = builder.add(new_folded, add_term);
    }

    builder.pop_scope();
    new_folded
}

/// Compute x0 for arity-2 folding from index bits (generalized for variable bits_consumed).
///
/// x0 = two_adic_generator(log_folded_height + 1)^{reverse_bits_len(parent_index, log_folded_height)}
fn compute_x0_from_index_bits_general<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    index_bits: &[Target],
    bits_consumed: usize,
    log_folded_height: usize,
) -> Target
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    let g = F::two_adic_generator(log_folded_height + 1);
    let pows: Vec<EF> = iter::successors(Some(g), |&prev| Some(prev.square()))
        .take(log_folded_height)
        .map(EF::from)
        .collect();

    // Pre-lift all powers to circuit constants once
    let pow_consts: Vec<Target> = pows.iter().map(|p| builder.add_const(*p)).collect();

    let one = builder.add_const(EF::ONE);
    let mut res = one;

    let parent_offset = bits_consumed + 1;
    let k = log_folded_height;

    for j in 0..k {
        let bit = index_bits[parent_offset + k - 1 - j];
        let diff = builder.sub(pow_consts[j], one);
        let diff_bit = builder.mul(diff, bit);
        let gate = builder.add(one, diff_bit);
        res = builder.mul(res, gate);
    }

    res
}

/// Perform the full FRI fold chain with variable arity per phase.
fn fold_chain_circuit<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    initial_folded_eval: Target,
    index_bits: &[Target],
    phases: &[FoldPhaseConfig],
    log_arities: &[usize],
    cumulative_bits: &[usize],
    beta_pows_per_phase: &[Target],
) -> Target
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("fold_chain_circuit");

    let log_max_height = index_bits.len();

    let subgroup_starts = precompute_subgroup_starts::<F, EF>(
        builder,
        index_bits,
        log_max_height,
        log_arities,
        cumulative_bits,
    );

    let mut folded = initial_folded_eval;
    let mut bits_consumed = 0usize;
    let mut log_current_height = log_max_height;

    for (i, phase) in phases.iter().enumerate() {
        let log_arity = log_arities[i];
        folded = fold_one_phase::<F, EF>(
            builder,
            folded,
            &phase.siblings,
            phase.beta,
            index_bits,
            bits_consumed,
            log_arity,
            log_current_height,
            phase.roll_in,
            Some(beta_pows_per_phase[i]),
            None,
            Some(subgroup_starts[i]),
        );
        bits_consumed += log_arity;
        log_current_height -= log_arity;
    }

    builder.pop_scope();
    folded
}

/// Evaluate a polynomial at a point `x` using Horner's method.
/// Given coefficients [c0, c1, c2, ...], compute `p(x) = c0 + x*(c1 + x*(c2 + ...))`.
fn evaluate_polynomial<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    coefficients: &[Target],
    point: Target,
) -> Target {
    builder.push_scope("evaluate_polynomial");

    assert!(
        !coefficients.is_empty(),
        "we should have at least a constant polynomial"
    );
    if coefficients.len() == 1 {
        return coefficients[0];
    }

    let mut result = coefficients[coefficients.len() - 1];
    for &coeff in coefficients.iter().rev().skip(1) {
        result = builder.mul(result, point);
        result = builder.add(result, coeff);
    }

    builder.pop_scope(); // close `evaluate_polynomial` scope
    result
}

/// Precompute powers `g^{2^j}` (as circuit constants) for a two-adic generator of the
/// given height. The result can be shared across queries.
fn precompute_two_adic_powers<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    log_height: usize,
) -> Vec<Target>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("fri_precompute_two_adic_powers");

    let g = F::two_adic_generator(log_height);
    let result = iter::successors(Some(g), |&prev| Some(prev.square()))
        .take(log_height)
        .map(|p| builder.add_const(EF::from(p)))
        .collect();

    builder.pop_scope();
    result
}

/// Compute the final query point after all FRI folding rounds.
///
/// After consuming `total_bits_consumed` bits through all fold phases, the remaining
/// bits form the domain index for the final polynomial evaluation.
fn compute_final_query_point<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    index_bits: &[Target],
    log_max_height: usize,
    total_bits_consumed: usize,
    powers_of_g: &[Target],
) -> Target
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("compute_final_query_point");

    let domain_index_bits: Vec<Target> = index_bits[total_bits_consumed..log_max_height].to_vec();

    // Pad bits and reverse
    let mut reversed_bits = vec![builder.add_const(EF::ZERO); total_bits_consumed];
    reversed_bits.extend(domain_index_bits.iter().rev().copied());

    let one = builder.add_const(EF::ONE);
    let mut result = one;
    for (&bit, &power) in reversed_bits.iter().zip(powers_of_g.iter()) {
        let multiplier = builder.select(bit, power, one);
        result = builder.mul(result, multiplier);
    }

    builder.pop_scope();
    result
}

/// Precompute evaluation points for all unique heights.
///
/// Runs a single select-mul chain for the tallest height's reversed index bits and derives
/// smaller heights via `exp_power_of_2` on captured intermediates.
fn precompute_evaluation_points<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    unique_heights_desc: &[usize],
    index_bits: &[Target],
    log_global_max_height: usize,
) -> BTreeMap<usize, Target>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("precompute_evaluation_points");

    debug_assert!(
        !unique_heights_desc.is_empty(),
        "must have at least one height"
    );
    debug_assert!(
        unique_heights_desc.windows(2).all(|w| w[0] > w[1]),
        "heights must be sorted in strictly descending order"
    );

    let h_max = unique_heights_desc[0];
    let bits_reduced = log_global_max_height - h_max;
    let rev_bits: Vec<Target> = index_bits[bits_reduced..bits_reduced + h_max]
        .iter()
        .rev()
        .copied()
        .collect();

    let g = F::two_adic_generator(h_max);
    let powers_of_g: Vec<_> = iter::successors(Some(g), |&prev| Some(prev.square()))
        .take(h_max)
        .map(|p| builder.add_const(EF::from(p)))
        .collect();

    let capture_set: BTreeMap<usize, ()> =
        unique_heights_desc[1..].iter().map(|&h| (h, ())).collect();

    let one = builder.add_const(EF::ONE);
    let generator = builder.alloc_const(EF::from(F::GENERATOR), "coset_generator");
    let mut g_pow = one;
    let mut result = BTreeMap::new();

    for i in 0..h_max {
        let multiplier = builder.select(rev_bits[i], powers_of_g[i], one);
        g_pow = builder.mul(g_pow, multiplier);

        let bits_done = i + 1;
        if capture_set.contains_key(&bits_done) {
            let derived = builder.exp_power_of_2(g_pow, h_max - bits_done);
            let x = builder.alloc_mul(generator, derived, "eval_point");
            result.insert(bits_done, x);
        }
    }

    let x_max = builder.alloc_mul(generator, g_pow, "eval_point");
    result.insert(h_max, x_max);

    builder.pop_scope(); // close `precompute_evaluation_points` scope
    result
}

/// Compute reduced opening for a single matrix in circuit form (EF-field).
///
/// Uses Horner's method to evaluate the polynomial in alpha without an explicit
/// alpha-power chain, saving one multiplication per column.
fn compute_single_reduced_opening<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    opened_values: &[Target], // Values at evaluation point x
    point_values: &[Target],  // Values at challenge point z
    alpha_pow: Target,        // Current alpha power (for this height)
    alpha: Target,            // Alpha challenge
    alpha_powers_set: &mut HashMap<usize, Target>,
    inv_z_minus_x: Target, // 1 / (z - x), shared across matrices at same (height, z)
) -> (Target, Target) // (new_alpha_pow, reduced_opening_contrib)
{
    builder.push_scope("compute_single_reduced_opening");

    let n = opened_values.len();

    if n == 0 {
        let zero = builder.add_const(EF::ZERO);
        builder.pop_scope();
        return (alpha_pow, zero);
    }

    // Compute all diffs: diff[i] = p_at_z[i] - p_at_x[i]
    let diffs: Vec<Target> = opened_values
        .iter()
        .zip(point_values.iter())
        .map(|(&p_at_x, &p_at_z)| builder.sub(p_at_z, p_at_x))
        .collect();

    // Horner's method: evaluate sum_{i=0}^{n-1} alpha^i * diff[i] as
    //   inner = diff[n-1]
    //   inner = inner * alpha + diff[n-2]
    //   ...
    //   inner = inner * alpha + diff[0]
    let mut inner = diffs[n - 1];
    for i in (0..n - 1).rev() {
        let prod = builder.mul(inner, alpha);
        inner = builder.add(prod, diffs[i]);
    }

    // reduced_opening = alpha_pow * inner * (1 / (z - x))
    let numerator = builder.mul(alpha_pow, inner);
    let reduced_opening = builder.mul(numerator, inv_z_minus_x);

    // Advance alpha_pow by alpha^n using square-and-multiply
    let alpha_n = if let Some(alpha_n) = alpha_powers_set.get(&n) {
        *alpha_n
    } else {
        let alpha_n = circuit_exp_by_constant(builder, alpha, n);
        alpha_powers_set.insert(n, alpha_n);
        alpha_n
    };
    let new_alpha_pow = builder.mul(alpha_pow, alpha_n);

    builder.pop_scope();
    (new_alpha_pow, reduced_opening)
}

/// Computes `base^n` in-circuit using square-and-multiply.
///
/// Cost: `floor(log2(n)) + popcount(n) - 1` multiplications.
fn circuit_exp_by_constant<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    base: Target,
    n: usize,
) -> Target {
    debug_assert!(n > 0);
    if n == 1 {
        return base;
    }
    let num_bits = usize::BITS - n.leading_zeros();
    // Start from the MSB (already implicit as `base`), process remaining bits top-down.
    let mut result = base;
    for i in (0..num_bits - 1).rev() {
        result = builder.mul(result, result);
        if (n >> i) & 1 == 1 {
            result = builder.mul(result, base);
        }
    }
    result
}

/// Compute reduced openings grouped **by height** with **per-height alpha powers**,
/// Returns a vector of (log_height, ro) sorted by descending height, plus the MMCS op IDs.
///
/// Reference (Plonky3): `p3_fri::verifier::open_input`
#[allow(clippy::type_complexity)]
fn open_input<F, EF, Comm>(
    builder: &mut CircuitBuilder<EF>,
    log_global_max_height: usize,
    index_bits: &[Target],
    alpha: Target,
    log_blowup: usize,
    commitments_with_opening_points: &ComsWithOpeningsTargets<Comm, TwoAdicMultiplicativeCoset<F>>,
    batch_opened_values: &[Vec<Vec<Target>>], // Per batch -> per matrix -> per column
    permutation_config: Option<Poseidon2Config>,
    pre_packed_input_caps: Option<&[Vec<Vec<Target>>]>,
) -> Result<(Vec<(usize, Target)>, Vec<NonPrimitiveOpId>), VerificationError>
where
    F: Field + TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    Comm: ObservableCommitment,
{
    builder.push_scope("open_input");

    for &b in index_bits {
        builder.assert_bool(b);
    }
    debug_assert_eq!(
        index_bits.len(),
        log_global_max_height,
        "index_bits.len() must equal log_global_max_height"
    );

    // Collect unique heights across all matrices and precompute evaluation points.
    let unique_heights_desc: Vec<usize> = {
        let mut heights: Vec<usize> = commitments_with_opening_points
            .iter()
            .flat_map(|(_, mats)| {
                mats.iter()
                    .map(|(domain, _)| domain.log_size() + log_blowup)
            })
            .collect();
        heights.sort_unstable();
        heights.dedup();
        heights.reverse();
        heights
    };

    let eval_points = if unique_heights_desc.is_empty() {
        BTreeMap::new()
    } else {
        precompute_evaluation_points::<F, EF>(
            builder,
            &unique_heights_desc,
            index_bits,
            log_global_max_height,
        )
    };

    // height -> (alpha_pow_for_this_height, ro_sum_for_this_height)
    let mut reduced_openings = BTreeMap::<usize, (Target, Target)>::new();
    let mut mmcs_op_ids = Vec::new();

    // Process each batch
    for (batch_idx, ((batch_commit, mats), batch_openings)) in zip_eq(
        commitments_with_opening_points.iter(),
        batch_opened_values.iter(),
        VerificationError::InvalidProofShape(
            "Opened values and commitments count must match".to_string(),
        ),
    )?
    .enumerate()
    {
        // Recursive MMCS verification for this batch
        if let Some(perm_config) = permutation_config {
            // Use pre-packed cap if available, otherwise pack on the fly
            let commitment_cap: Vec<Vec<Target>> = if let Some(pre_packed) = pre_packed_input_caps {
                pre_packed[batch_idx].clone()
            } else {
                let lifted_commitment = batch_commit.to_observation_targets();
                let packed_commitment_flat =
                    pack_lifted_to_ext::<F, EF>(builder, &lifted_commitment);
                let rate_ext = perm_config.rate_ext();
                packed_commitment_flat
                    .chunks(rate_ext)
                    .map(|c| c.to_vec())
                    .collect()
            };

            let dimensions: Vec<Dimensions> = mats
                .iter()
                .map(|(domain, _)| Dimensions {
                    height: 1 << (domain.log_size() + log_blowup),
                    width: 0,
                })
                .collect();

            let op_ids = verify_batch_circuit::<F, EF>(
                builder,
                perm_config,
                &commitment_cap,
                &dimensions,
                index_bits,
                batch_openings,
            )
            .map_err(|e| {
                VerificationError::InvalidProofShape(format!(
                    "MMCS verification failed for batch {batch_idx}: {e:?}"
                ))
            })?;
            mmcs_op_ids.extend(op_ids);
        }

        let mut alpha_powers_set = HashMap::new();
        let mut inv_z_minus_x_cache: HashMap<(usize, Target), Target> = HashMap::new();

        // For each matrix in the batch
        for (mat_idx, ((mat_domain, mat_points_and_values), mat_opening)) in zip_eq(
            mats.iter(),
            batch_openings.iter(),
            VerificationError::InvalidProofShape(format!(
                "batch {batch_idx}: opened_values and point_values count must match"
            )),
        )?
        .enumerate()
        {
            let log_height = mat_domain.log_size() + log_blowup;

            let x = eval_points[&log_height];

            // Initialize / fetch per-height (alpha_pow, ro)
            let (alpha_pow_h, ro_h) = reduced_openings
                .entry(log_height)
                .or_insert_with(|| (builder.add_const(EF::ONE), builder.add_const(EF::ZERO)));

            // Process each (z, ps_at_z) pair for this matrix
            for (z, ps_at_z) in mat_points_and_values {
                if mat_opening.len() != ps_at_z.len() {
                    return Err(VerificationError::InvalidProofShape(format!(
                        "batch {batch_idx} mat {mat_idx}: opened_values columns must match point_values columns"
                    )));
                }

                let inv_z_minus_x =
                    *inv_z_minus_x_cache
                        .entry((log_height, *z))
                        .or_insert_with(|| {
                            let z_minus_x = builder.sub(*z, x);
                            let one = builder.add_const(EF::ONE);
                            builder.div(one, z_minus_x)
                        });

                let (new_alpha_pow_h, ro_contrib) = compute_single_reduced_opening(
                    builder,
                    mat_opening,
                    ps_at_z,
                    *alpha_pow_h,
                    alpha,
                    &mut alpha_powers_set,
                    inv_z_minus_x,
                );

                *ro_h = builder.add(*ro_h, ro_contrib);
                *alpha_pow_h = new_alpha_pow_h;
            }
        }

        // `reduced_openings` would have a log_height = log_blowup entry only if there was a
        // trace matrix of height 1. In this case `f` is constant, so `(f(zeta) - f(x))/(zeta - x)`
        // must equal `0`.
        if let Some((_ap, ro0)) = reduced_openings.get(&log_blowup) {
            let zero = builder.add_const(EF::ZERO);
            builder.connect(*ro0, zero);
        }
    }

    builder.pop_scope(); // close `open_input` scope

    // Into descending (height, ro) list
    let reduced_list: Vec<_> = reduced_openings
        .into_iter()
        .rev()
        .map(|(h, (_ap, ro))| (h, ro))
        .collect();
    Ok((reduced_list, mmcs_op_ids))
}

/// Verify FRI arithmetic in-circuit with optional MMCS verification.
///
/// Supports variable-arity FRI folding: each phase may fold by a different arity
/// determined by `log_arities` extracted from the proof.
///
/// When `permutation_config` is `Some`, this function performs full recursive MMCS
/// verification for both input batch openings and commit-phase openings.
/// When `None`, only arithmetic verification is performed (for testing).
///
/// Returns the list of non-primitive operation IDs that require private data
/// (Merkle sibling values) to be set by the runner.
///
/// Reference (Plonky3): `p3_fri::verifier::verify_fri`
pub fn verify_fri_circuit<F, EF, RecMmcs, Inner, Witness, Comm>(
    builder: &mut CircuitBuilder<EF>,
    fri_proof_targets: &FriProofTargets<F, EF, RecMmcs, InputProofTargets<F, EF, Inner>, Witness>,
    alpha: Target,
    betas: &[Target],
    index_bits_per_query: &[Vec<Target>],
    commitments_with_opening_points: &ComsWithOpeningsTargets<Comm, TwoAdicMultiplicativeCoset<F>>,
    log_blowup: usize,
    permutation_config: Option<Poseidon2Config>,
) -> Result<Vec<NonPrimitiveOpId>, VerificationError>
where
    F: Field + TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    RecMmcs::Commitment: ObservableCommitment,
    Inner: RecursiveMmcs<F, EF>,
    Witness: Recursive<EF>,
    Comm: ObservableCommitment,
{
    builder.push_scope("verify_fri");

    let num_phases = betas.len();
    let num_queries = fri_proof_targets.query_proofs.len();
    let log_arities = &fri_proof_targets.log_arities;

    let total_log_reduction: usize = log_arities.iter().sum();

    tracing::debug!(
        "verify_fri_circuit: num_phases={}, num_queries={}, log_blowup={}, log_arities={:?}",
        num_phases,
        num_queries,
        log_blowup,
        log_arities,
    );

    // Validate shape.
    if num_phases != fri_proof_targets.commit_phase_commits.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "betas length must equal number of commit-phase commitments: expected {}, got {}",
            num_phases,
            fri_proof_targets.commit_phase_commits.len()
        )));
    }

    if num_phases != fri_proof_targets.commit_pow_witnesses.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "Number of commit-phase commitments must equal number of commit-phase pow witnesses: expected {}, got {}",
            num_phases,
            fri_proof_targets.commit_pow_witnesses.len()
        )));
    }

    if log_arities.len() != num_phases {
        return Err(VerificationError::InvalidProofShape(format!(
            "log_arities length must equal number of phases: expected {}, got {}",
            num_phases,
            log_arities.len()
        )));
    }

    if num_queries != index_bits_per_query.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "index_bits_per_query length must equal number of query proofs: expected {}, got {}",
            num_queries,
            index_bits_per_query.len()
        )));
    }

    let log_max_height = index_bits_per_query[0].len();
    if index_bits_per_query
        .iter()
        .any(|v| v.len() != log_max_height)
    {
        return Err(VerificationError::InvalidProofShape(
            "all index_bits_per_query entries must have same length".to_string(),
        ));
    }

    if betas.is_empty() {
        return Err(VerificationError::InvalidProofShape(
            "FRI must have at least one fold phase".to_string(),
        ));
    }

    // With variable arity: log_max_height = total_log_reduction + log_final_poly_len + log_blowup
    let log_final_poly_len = log_max_height
        .checked_sub(total_log_reduction)
        .and_then(|x| x.checked_sub(log_blowup))
        .ok_or_else(|| {
            VerificationError::InvalidProofShape(
                "Invalid FRI parameters: log_max_height too small for given log_arities"
                    .to_string(),
            )
        })?;

    let expected_final_poly_len = 1 << log_final_poly_len;
    let actual_final_poly_len = fri_proof_targets.final_poly.len();

    if actual_final_poly_len != expected_final_poly_len {
        return Err(VerificationError::InvalidProofShape(format!(
            "Final polynomial length mismatch: expected 2^{log_final_poly_len} = {expected_final_poly_len}, got {actual_final_poly_len}"
        )));
    }

    // Precompute cumulative bits consumed after each phase.
    // cumulative_bits[i] = sum(log_arities[0..i])
    let mut cumulative_bits = Vec::with_capacity(num_phases + 1);
    cumulative_bits.push(0usize);
    for &la in log_arities {
        cumulative_bits.push(cumulative_bits.last().unwrap() + la);
    }

    // Precompute the folded height after each phase for roll-in mapping.
    // folded_height_after[i] = log_max_height - cumulative_bits[i+1]
    let folded_height_after: Vec<usize> = (0..num_phases)
        .map(|i| log_max_height - cumulative_bits[i + 1])
        .collect();

    // Precompute shared beta powers and generator powers used across queries.
    let beta_pows_per_phase = precompute_beta_powers_per_phase(builder, betas, log_arities);
    let powers_of_g_final = precompute_two_adic_powers::<F, EF>(builder, log_max_height);

    // Pre-pack commitment caps once so they can be reused across all queries.
    // Each input batch commitment and each commit-phase commitment is packed from
    // lifted representation to extension representation a single time.
    let pre_packed_input_caps: Option<Vec<Vec<Vec<Target>>>> =
        permutation_config.map(|perm_config| {
            let rate_ext = perm_config.rate_ext();
            commitments_with_opening_points
                .iter()
                .map(|(commit, _)| {
                    let lifted = commit.to_observation_targets();
                    let packed = pack_lifted_to_ext::<F, EF>(builder, &lifted);
                    packed.chunks(rate_ext).map(|c| c.to_vec()).collect()
                })
                .collect()
        });

    let pre_packed_commit_caps: Option<Vec<Vec<Vec<Target>>>> =
        permutation_config.map(|perm_config| {
            let rate_ext = perm_config.rate_ext();
            fri_proof_targets
                .commit_phase_commits
                .iter()
                .map(|commit| {
                    let lifted = commit.to_observation_targets();
                    let packed = pack_lifted_to_ext::<F, EF>(builder, &lifted);
                    packed.chunks(rate_ext).map(|c| c.to_vec()).collect()
                })
                .collect()
        });

    // Collect all MMCS operation IDs for private data setting
    let mut all_mmcs_op_ids = Vec::new();

    // For each query, extract opened values from proof and compute reduced openings and fold.
    for (q, query_proof) in fri_proof_targets.query_proofs.iter().enumerate() {
        builder.push_scope("verify_fri_query");
        let batch_opened_values: Vec<Vec<Vec<Target>>> = query_proof
            .input_proof
            .iter()
            .map(|batch| batch.opened_values.clone())
            .collect();

        // Arithmetic `open_input` to get (height, ro) descending, plus MMCS op IDs
        let (reduced_by_height, input_mmcs_ops) = open_input::<F, EF, Comm>(
            builder,
            log_max_height,
            &index_bits_per_query[q],
            alpha,
            log_blowup,
            commitments_with_opening_points,
            &batch_opened_values,
            permutation_config,
            pre_packed_input_caps.as_deref(),
        )?;
        all_mmcs_op_ids.extend(input_mmcs_ops);

        if reduced_by_height.is_empty() {
            return Err(VerificationError::InvalidProofShape(
                "No reduced openings; did you commit to zero polynomials?".to_string(),
            ));
        }
        if reduced_by_height[0].0 != log_max_height {
            return Err(VerificationError::InvalidProofShape(format!(
                "First reduced opening must be at max height {}, got {}",
                log_max_height, reduced_by_height[0].0
            )));
        }
        let initial_folded_eval = reduced_by_height[0].1;

        // Pack sibling values for each phase (variable count per phase).
        let sibling_values_per_phase: Vec<Vec<Target>> = query_proof
            .commit_phase_openings
            .iter()
            .map(|opening| opening.sibling_values_packed(builder))
            .collect();

        if sibling_values_per_phase.len() != num_phases {
            return Err(VerificationError::InvalidProofShape(format!(
                "commit_phase_openings count must match phases: expected {}, got {}",
                num_phases,
                sibling_values_per_phase.len()
            )));
        }

        // Build height-aligned roll-ins using variable-arity cumulative bits.
        let mut roll_ins: Vec<Option<Target>> = vec![None; num_phases];
        for &(h, ro) in reduced_by_height.iter().skip(1) {
            // Find the phase whose folded height matches h
            let phase_idx = folded_height_after.iter().position(|&fh| fh == h);
            if let Some(i) = phase_idx {
                if roll_ins[i].is_some() {
                    return Err(VerificationError::InvalidProofShape(format!(
                        "duplicate roll-in for phase {i} (height {h})",
                    )));
                }
                roll_ins[i] = Some(ro);
            } else {
                let zero = builder.add_const(EF::ZERO);
                builder.connect(ro, zero);
            }
        }

        // Compute the final query point using total bits consumed
        builder.push_scope("compute_final_query_point");
        let final_query_point = compute_final_query_point::<F, EF>(
            builder,
            &index_bits_per_query[q],
            log_max_height,
            total_log_reduction,
            &powers_of_g_final,
        );
        builder.pop_scope();

        let final_poly_eval =
            evaluate_polynomial(builder, &fri_proof_targets.final_poly, final_query_point);

        // Commit-phase MMCS verification with variable arity.
        // When MMCS verification is active, the fold chain is computed as part of
        // the MMCS loop (each phase calls fold_one_phase), so the final
        // current_folded is connected directly to final_poly_eval — no separate
        // fold_chain_circuit call is needed.
        // When MMCS verification is not active (no Poseidon2 table), we fall back
        // to fold_chain_circuit for the arithmetic fold constraint.
        if let Some(perm_config) = permutation_config {
            let subgroup_starts = precompute_subgroup_starts::<F, EF>(
                builder,
                &index_bits_per_query[q],
                log_max_height,
                log_arities,
                &cumulative_bits,
            );

            let mut current_folded = initial_folded_eval;
            let mut bits_consumed = 0usize;
            let mut log_current_height = log_max_height;

            for (phase_idx, (commit, _opening)) in fri_proof_targets
                .commit_phase_commits
                .iter()
                .zip(query_proof.commit_phase_openings.iter())
                .enumerate()
            {
                let log_arity = log_arities[phase_idx];
                let arity = 1usize << log_arity;
                let log_folded_height = log_current_height - log_arity;
                let siblings = &sibling_values_per_phase[phase_idx];

                // Skip MMCS verification for height 0 (no Merkle tree)
                if log_folded_height == 0 {
                    current_folded = fold_one_phase::<F, EF>(
                        builder,
                        current_folded,
                        siblings,
                        betas[phase_idx],
                        &index_bits_per_query[q],
                        bits_consumed,
                        log_arity,
                        log_current_height,
                        roll_ins[phase_idx],
                        Some(beta_pows_per_phase[phase_idx]),
                        None,
                        Some(subgroup_starts[phase_idx]),
                    );
                    bits_consumed += log_arity;
                    log_current_height = log_folded_height;
                    continue;
                }

                builder.push_scope("fri_commit_phase_mmcs");

                // Build full evaluation row once; reused for both MMCS and folding.
                let index_in_group_bits =
                    &index_bits_per_query[q][bits_consumed..bits_consumed + log_arity];
                let evals =
                    reconstruct_evals(builder, current_folded, siblings, index_in_group_bits);

                // Use pre-packed commit-phase cap
                let commitment_cap: Vec<Vec<Target>> =
                    if let Some(ref pre_packed) = pre_packed_commit_caps {
                        pre_packed[phase_idx].clone()
                    } else {
                        let lifted_commitment = commit.to_observation_targets();
                        let packed_commitment_flat =
                            pack_lifted_to_ext::<F, EF>(builder, &lifted_commitment);
                        let rate_ext = perm_config.rate_ext();
                        packed_commitment_flat
                            .chunks(rate_ext)
                            .map(|c| c.to_vec())
                            .collect()
                    };

                // Dimensions: width = arity, height = 2^log_folded_height
                let folded_height = 1usize << log_folded_height;
                let dimensions = vec![Dimensions {
                    height: folded_height,
                    width: arity,
                }];

                // Parent index bits start after index_in_group bits
                let parent_bit_start = bits_consumed + log_arity;
                let parent_bit_end = (parent_bit_start + log_folded_height).min(log_max_height);
                let zero = builder.add_const(EF::ZERO);

                let mut parent_index_bits: Vec<Target> =
                    index_bits_per_query[q][parent_bit_start..parent_bit_end].to_vec();
                while parent_index_bits.len() < log_folded_height {
                    parent_index_bits.push(zero);
                }

                let evals_for_mmcs = vec![evals.clone()];

                let commit_phase_ops = verify_batch_circuit_from_extension_opened::<F, EF>(
                    builder,
                    perm_config,
                    &commitment_cap,
                    &dimensions,
                    &parent_index_bits,
                    &evals_for_mmcs,
                )
                .map_err(|e| {
                    VerificationError::InvalidProofShape(format!(
                        "Commit-phase MMCS verification failed for query {q}, phase {phase_idx}: {e:?}"
                    ))
                })?;
                all_mmcs_op_ids.extend(commit_phase_ops);

                // Fold reusing the pre-built evals and subgroup_start
                current_folded = fold_one_phase::<F, EF>(
                    builder,
                    current_folded,
                    siblings,
                    betas[phase_idx],
                    &index_bits_per_query[q],
                    bits_consumed,
                    log_arity,
                    log_current_height,
                    roll_ins[phase_idx],
                    Some(beta_pows_per_phase[phase_idx]),
                    Some(&evals),
                    Some(subgroup_starts[phase_idx]),
                );

                bits_consumed += log_arity;
                log_current_height = log_folded_height;

                builder.pop_scope(); // close fri_commit_phase_mmcs
            }

            // The MMCS loop already computed the full fold chain; connect directly.
            builder.connect(current_folded, final_poly_eval);
        } else {
            // No MMCS verification — use fold_chain_circuit for the arithmetic constraint.
            let mut fold_phases = Vec::with_capacity(num_phases);
            for i in 0..num_phases {
                fold_phases.push(FoldPhaseConfig {
                    beta: betas[i],
                    siblings: sibling_values_per_phase[i].clone(),
                    roll_in: roll_ins[i],
                });
            }

            builder.push_scope("fri_fold_chain_no_mmcs query");
            let folded_eval = fold_chain_circuit::<F, EF>(
                builder,
                initial_folded_eval,
                &index_bits_per_query[q],
                &fold_phases,
                log_arities,
                &cumulative_bits,
                &beta_pows_per_phase,
            );
            builder.pop_scope();
            builder.connect(folded_eval, final_poly_eval);
        }

        builder.pop_scope(); // close verify_fri_query
    }

    builder.pop_scope();

    Ok(all_mmcs_op_ids)
}
