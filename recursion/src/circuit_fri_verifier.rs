use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::Field;

use crate::Target;

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
/// Interpolation per phase:
///   folded ← e0 + (β − x0)·(e1 − e0)·(x1 − x0)^{-1}, with x1 = −x0
///           = e0 + (β − x0)·(e1 − e0)·(−1/2)·x0^{-1}
pub fn fold_row_chain<F: Field>(
    builder: &mut CircuitBuilder<F>,
    initial_folded_eval: Target,
    phases: &[FoldPhaseInputsTarget],
) -> Target {
    let mut folded = initial_folded_eval;

    let one = builder.add_const(F::ONE);

    // Precompute constants as field constants: 2^{-1} and −1/2.
    let two_inv_val = (F::ONE + F::ONE).inverse(); // 1/2
    let neg_half = builder.add_const(F::NEG_ONE * two_inv_val); // −1/2

    for FoldPhaseInputsTarget {
        beta,
        x0,
        e_sibling,
        sibling_is_right,
        roll_in,
    } in phases.iter().cloned()
    {
        // TODO: MMCS batch verification needed for each phase.

        // e0 = select(bit, folded, e_sibling)
        let e0 = builder.select(sibling_is_right, folded, e_sibling);

        // inv = (x1 − x0)^{-1} = (−2x0)^{-1} = (−1/2) / x0
        let inv = builder.div(neg_half, x0);

        // e1 − e0 = (2b − 1) · (e_sibling − folded)
        let d = builder.sub(e_sibling, folded);
        let two_b = builder.add(sibling_is_right, sibling_is_right);
        let two_b_minus_one = builder.sub(two_b, one);
        let e1_minus_e0 = builder.mul(two_b_minus_one, d);

        // t = (β − x0) * (e1 − e0)
        let beta_minus_x0 = builder.sub(beta, x0);
        let t = builder.mul(beta_minus_x0, e1_minus_e0);

        // folded = e0 + t * inv
        let t_inv = builder.mul(t, inv);
        folded = builder.add(e0, t_inv);

        // Optional roll-in: folded += β² · roll_in
        if let Some(ro) = roll_in {
            let beta_sq = builder.mul(beta, beta);
            let add_term = builder.mul(beta_sq, ro);
            folded = builder.add(folded, add_term);
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
    // TODO: Support higher-degree final polynomial by evaluating it at the query point
    // using provided coefficients instead of a single constant `final_value`.
    let folded_eval = fold_row_chain(builder, initial_folded_eval, phases);
    builder.connect(folded_eval, final_value);
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

    for j in 0..k {
        let bit = index_bits[offset + k - 1 - j]; // reversed
        let pow_const = builder.add_const(pows[j]);
        let diff = builder.sub(pow_const, one);
        let diff_bit = builder.mul(diff, bit);
        let gate = builder.add(one, diff_bit);
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
    debug_assert_eq!(
        sibling_values.len(),
        num_phases,
        "sibling_values len mismatch"
    );
    debug_assert_eq!(roll_ins.len(), num_phases, "roll_ins len mismatch");
    debug_assert_eq!(
        pows_per_phase.len(),
        num_phases,
        "pows_per_phase len mismatch"
    );

    let one = builder.add_const(F::ONE);

    let mut phases_vec = Vec::with_capacity(num_phases);
    for i in 0..num_phases {
        // x0 from bits (using the appropriate generator ladder for this phase)
        let x0 = compute_x0_from_index_bits(builder, index_bits, i, &pows_per_phase[i]);

        // sibling_is_right = 1 − (index_bit[i])
        let raw_bit = index_bits[i];
        let sibling_is_right = builder.sub(one, raw_bit);

        phases_vec.push(FoldPhaseInputsTarget {
            beta: betas[i],
            x0,
            e_sibling: sibling_values[i],
            sibling_is_right,
            roll_in: roll_ins[i],
        });
    }

    verify_query(builder, initial_folded_eval, &phases_vec, final_value);
}
