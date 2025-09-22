//! Arithmetic-only FRI fold gadget (arity-2) for Plonky3-style verification.
//! - Implements the fold chain from `verify_query` (MMCS/PoW/transcript handled elsewhere).
//! - Assumes final polynomial length == 1 (constant), enforced by caller via equality.
//! - Generic over `F: Field` with odd characteristic (uses 1/2).

use alloc::vec::Vec;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::Field;

/// Canonical circuit target type used across recursive components.
pub type Target = ExprId;

/// Inputs for one FRI fold phase (matches the values used by the verifier per round).
#[derive(Clone, Debug)]
pub struct FoldPhaseInputsTarget {
    /// Per-phase challenge β (sampled after observing that layer's commitment).
    pub beta: Target,
    /// Subgroup point x₀ for this phase (the other point is x₁ = −x₀).
    pub x0: Target,
    /// Sibling evaluation at the opposite child index.
    pub e_sibling: Target,
    /// Boolean {0,1}. Equals 1 iff sibling occupies evals[1] (the "right" slot).
    /// In Plonky3 this is 1 − (domain_index & 1) at this phase.
    pub sibling_is_right: Target,
    /// Optional reduced opening to roll in at this height (added as β² · roll_in).
    pub roll_in: Option<Target>,
}

/// Perform the arity-2 FRI fold chain with optional roll-ins.
/// Starts from the initial reduced opening at max height; returns the final folded value.
///
/// Interpolation step (per phase):
///   folded ← e0 + (β − x0)·(e1 − e0)·(x1 − x0)^{-1}, with x1 = −x0
///           = e0 + (β − x0)·(e1 − e0)·(−1/2)·x0^{-1}
pub fn fold_row_chain<F: Field>(
    builder: &mut CircuitBuilder<F>,
    initial_folded_eval: Target,
    phases: &[FoldPhaseInputsTarget],
) -> Target {
    let mut folded = initial_folded_eval;

    let one = builder.add_const(F::ONE);
    let neg_one = builder.add_const(F::NEG_ONE);

    // Precompute constants: 2^{-1} and −1/2.
    let two = builder.add_const(F::ONE + F::ONE);
    let two_inv = builder.div(one, two);              // 1/2
    let neg_half = builder.mul(neg_one, two_inv);     // −1/2

    for FoldPhaseInputsTarget { beta, x0, e_sibling, sibling_is_right, roll_in } in phases.iter().cloned() {
        // Decide (e0, e1) without branching:
        // sibling_right = 1 ⇒ evals = [folded, e_sibling]
        // sibling_right = 0 ⇒ evals = [e_sibling, folded]
        let one_minus = builder.sub(one, sibling_is_right);
        let e0 = builder.add(
            builder.mul(one_minus, e_sibling),
            builder.mul(sibling_is_right, folded),
        );
        let e1 = builder.add(
            builder.mul(one_minus, folded),
            builder.mul(sibling_is_right, e_sibling),
        );

        // inv = (x1 − x0)^{-1} = (−2x0)^{-1} = (−1/2) * x0^{-1}
        let inv_x0 = builder.div(one, x0);
        let inv = builder.mul(neg_half, inv_x0);

        // folded = e0 + (β − x0) * (e1 − e0) * inv
        let beta_minus_x0 = builder.sub(beta, x0);
        let e1_minus_e0 = builder.sub(e1, e0);
        let t = builder.mul(beta_minus_x0, e1_minus_e0);
        folded = builder.add(e0, builder.mul(t, inv));

        // Optional roll-in: folded += β² · roll_in
        if let Some(ro) = roll_in {
            let beta_sq = builder.mul(beta, beta);
            folded = builder.add(folded, builder.mul(beta_sq, ro));
        }
    }

    folded
}

/// Arithmetic-only version of Plonky3 `verify_query`:
/// - Applies the fold chain and enforces equality to the provided final constant value.
/// - Caller must supply `initial_folded_eval` (the reduced opening at max height).
pub fn verify_query<F: Field>(
    builder: &mut CircuitBuilder<F>,
    initial_folded_eval: Target,
    phases: &[FoldPhaseInputsTarget],
    final_value: Target,
) {
    let folded_eval = fold_row_chain(builder, initial_folded_eval, phases);
    builder.connect(folded_eval, final_value);
}

/// Constrain each element of `bits` to be boolean: b ∈ {0,1}.
pub fn constrain_bits_boolean<F: Field>(builder: &mut CircuitBuilder<F>, bits: &[Target]) {
    let one = builder.add_const(F::ONE);
    for &b in bits {
        let b_minus_one = builder.sub(b, one);
        builder.assert_zero(builder.mul(b, b_minus_one));
    }
}

/// Reconstruct an integer (as a field element) from little-endian bits:
///   index = Σ b_i · 2^i
pub fn reconstruct_index_from_bits<F: Field>(
    builder: &mut CircuitBuilder<F>,
    bits: &[Target],
) -> Target {
    let mut acc = builder.add_const(F::ZERO);
    let mut pow2 = builder.add_const(F::ONE);
    for &b in bits {
        acc = builder.add(acc, builder.mul(b, pow2));
        pow2 = builder.add(pow2, pow2); // *= 2
    }
    acc
}

/// Compute x₀ for phase `i` from the query index bits and a caller-provided power ladder.
///
/// For phase with folded height `k` (log_folded_height), caller must pass:
///   `pows = [g^{2^0}, g^{2^1}, ..., g^{2^{k-1}}]`
/// where `g = two_adic_generator(k + 1)` (note the +1 for arity-2).
///
/// We use bit window `bits[i+1 .. i+1+k]` (little-endian), but multiplied in reverse to match
/// `reverse_bits_len(index >> (i+1), k)` semantics from the verifier.
fn compute_x0_from_index_bits<F: Field>(
    builder: &mut CircuitBuilder<F>,
    index_bits: &[Target],
    phase: usize,
    pows: &[F],
) -> Target {
    let one = builder.add_const(F::ONE);
    let mut res = one;

    // Bits window: offset = i+1, length = pows.len() = k
    let offset = phase + 1;
    let k = pows.len();

    // Multiply powers gated by reversed bits: ∏_j g^{2^j · bit_rev[j]}
    for j in 0..k {
        let bit = index_bits[offset + k - 1 - j]; // reversed
        let pow_const = builder.add_const(pows[j]);
        // Gate: (1 + (pow - 1) * bit)
        let gate = builder.add(one, builder.mul(builder.sub(pow_const, one), bit));
        res = builder.mul(res, gate);
    }
    res
}

/// Build and verify the fold chain from index bits:
/// - `index_bits`: little-endian query index bits (must be boolean-constrained by caller).
/// - `betas`/`sibling_values`/`roll_ins`: per-phase arrays.
/// - `pows_per_phase[i]`: power ladder for the generator at that phase (see `compute_x0_from_index_bits`).
#[allow(clippy::too_many_arguments)]
pub fn verify_query_from_index_bits<F: Field>(
    builder: &mut CircuitBuilder<F>,
    initial_folded_eval: Target,
    index_bits: &[Target],
    betas: &[Target],
    sibling_values: &[Target],
    roll_ins: &[Option<Target>],
    pows_per_phase: &[Vec<F>],
    final_value: Target,
) {
    let num_phases = betas.len();
    debug_assert_eq!(sibling_values.len(), num_phases, "sibling_values len mismatch");
    debug_assert_eq!(roll_ins.len(), num_phases, "roll_ins len mismatch");
    debug_assert_eq!(pows_per_phase.len(), num_phases, "pows_per_phase len mismatch");

    let one = builder.add_const(F::ONE);

    // Assemble per-phase inputs
    let mut phases = Vec::with_capacity(num_phases);
    for i in 0..num_phases {
        // x0 from bits (using the appropriate generator ladder for this phase)
        let x0 = compute_x0_from_index_bits(builder, index_bits, i, &pows_per_phase[i]);

        // sibling_is_right = 1 − (index_bit[i])
        let raw_bit = index_bits[i];
        let sibling_is_right = builder.sub(one, raw_bit);

        phases.push(FoldPhaseInputsTarget {
            beta: betas[i],
            x0,
            e_sibling: sibling_values[i],
            sibling_is_right,
            roll_in: roll_ins[i],
        });
    }

    verify_query(builder, initial_folded_eval, &phases, final_value);
}
