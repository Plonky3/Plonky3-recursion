use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{Field, PrimeCharacteristicRing};

/// Canonical circuit target type used across recursive components.
pub type Target = ExprId;

/// Inputs needed for one FRI fold phase in-circuit.
///
/// Maps 1:1 to the values used inside Plonky3 `verifier::verify_query` for each round:
/// - `beta`: per‑phase challenge sampled after observing the commit.
/// - `x0`: subgroup point for the phase (we interpolate between x0 and x1 = −x0).
/// - `e_sibling`: sibling evaluation value from the proof at the sibling index.
/// - `sibling_is_right`: boolean target in {0,1}; equals 1 iff sibling occupies `evals[1]` (right).
///   In terms of index bits: `sibling_is_right = 1 − bit[phase]`.
/// - `roll_in`: optional reduced opening added as `beta^2 * roll_in`.
#[derive(Clone, Debug)]
pub struct FoldPhaseInputsTarget {
    pub beta: Target,
    pub x0: Target,
    pub e_sibling: Target,
    pub sibling_is_right: Target,
    pub roll_in: Option<Target>,
}

/// Perform the FRI folding chain arithmetic with optional roll‑ins.
///
/// Starts from the initial reduced opening at the maximum height, then for each phase:
/// - Interpolates between (x0, e0) and (x1, e1) at `beta`, where `x1 = −x0` and `e0` is the
///   current folded evaluation.
/// - Optionally adds a roll‑in term `beta^2 * roll_in` for that height.
///
///   Returns the final folded evaluation after all phases.
///
///   Corresponds to repeatedly applying `TwoAdicFriFolding::fold_row` in Plonky3.
pub fn fold_row_chain<F: Field>(
    builder: &mut CircuitBuilder<F>,
    initial_folded_eval: Target,
    phases: &[FoldPhaseInputsTarget],
) -> Target {
    let mut folded = initial_folded_eval;
    let neg_one = builder.add_const(F::NEG_ONE);
    let one = builder.add_const(F::ONE);

    for FoldPhaseInputsTarget {
        beta,
        x0,
        e_sibling,
        sibling_is_right,
        roll_in,
    } in phases.iter().cloned()
    {
        // x1 = -x0
        let x1 = builder.mul(neg_one, x0);

        // Determine (e0, e1) ordering based on sibling position.
        // If sibling_is_right == 1, then evals = [folded, e_sibling]
        // If sibling_is_right == 0, then evals = [e_sibling, folded]
        // e0 = evals[0], e1 = evals[1]
        let one_minus_bit = builder.sub(one, sibling_is_right);
        let e0_l = builder.mul(one_minus_bit, e_sibling);
        let e0_r = builder.mul(sibling_is_right, folded);
        let e0 = builder.add(e0_l, e0_r);
        let e1_l = builder.mul(one_minus_bit, folded);
        let e1_r = builder.mul(sibling_is_right, e_sibling);
        let e1 = builder.add(e1_l, e1_r);

        // Interpolation: e0 + (beta - x0) * (e1 - e0) * (x1 - x0)^(-1)
        let beta_minus_x0 = builder.sub(beta, x0);
        let e1_minus_e0 = builder.sub(e1, e0);
        let x1_minus_x0 = builder.sub(x1, x0);

        // inv = 1 / (x1 - x0)
        let inv = builder.div(one, x1_minus_x0);
        let t = builder.mul(beta_minus_x0, e1_minus_e0);
        let intermediate = builder.mul(t, inv);
        folded = builder.add(e0, intermediate);

        // Optional roll-in: folded += beta^2 * ro
        if let Some(ro) = roll_in {
            let beta_sq = builder.mul(beta, beta);
            let add_term = builder.mul(beta_sq, ro);
            folded = builder.add(folded, add_term);
        }
    }

    folded
}

/// Arithmetic‑only circuit version of Plonky3 `verify_query`.
///
/// - Starts from `initial_folded_eval` (reduced opening at the maximum height).
/// - Applies the folding chain using `phases` (one per commit phase).
/// - Enforces equality by connecting the folded result to `final_value`.
///
/// Omits MMCS verifications, challenger transcript logic, and PoW checks (to be added separately).
pub fn verify_query<F: Field>(
    builder: &mut CircuitBuilder<F>,
    initial_folded_eval: Target,
    phases: &[FoldPhaseInputsTarget],
    final_value: Target,
) {
    let folded_eval = fold_row_chain(builder, initial_folded_eval, phases);
    builder.connect(folded_eval, final_value);
}

/// Maximum number of index bits supported for query index decomposition.
pub const MAX_INDEX_BITS: usize = 32;

/// Constrain a list of targets to be boolean bits: for each `b`, enforce `b · (b − 1) = 0`.
pub fn constrain_bits_boolean<F: Field>(builder: &mut CircuitBuilder<F>, bits: &[Target]) {
    for &b in bits {
        let one = builder.add_const(F::ONE);
        let b_minus_one = builder.sub(b, one);
        let prod = builder.mul(b, b_minus_one);
        builder.assert_zero(prod);
    }
}

/// Reconstruct an integer index target from its little‑endian bit decomposition:
///   `index = Σ_{i=0..n−1} bits[i] · 2^i`.
pub fn reconstruct_index_from_bits<F: Field>(
    builder: &mut CircuitBuilder<F>,
    bits: &[Target],
) -> Target {
    let mut acc = builder.add_const(F::ZERO);
    let mut pow2 = builder.add_const(F::ONE);
    for &b in bits {
        let term = builder.mul(b, pow2);
        acc = builder.add(acc, term);
        // pow2 *= 2
        pow2 = builder.add(pow2, pow2);
    }
    acc
}

/// Return a reversed slice of the index bits for the given (`offset`, `len`) window.
///
/// This corresponds to `reverse_bits_len(index >> offset, len)` in Plonky3 — i.e. the bits of the
/// per‑phase `domain_index` in reverse order.
pub fn reversed_bits_window(bits: &[Target], offset: usize, len: usize) -> Vec<Target> {
    (0..len).map(|j| bits[offset + len - 1 - j]).collect()
}

/// Compute a gated exponentiation product: `result = Π_j pows[j]^{bits_rev[j]}`.
///
/// Implemented via multiplicative gating (no branching):
///   `res *= (1 + (pow_j − 1) · bit_j)`.
/// Caller provides the constant subgroup powers for the appropriate generator.
pub fn gated_exp_product<F: Field>(
    builder: &mut CircuitBuilder<F>,
    pows: &[F],
    bits_rev: &[Target],
) -> Target {
    debug_assert_eq!(pows.len(), bits_rev.len());
    let one = builder.add_const(F::ONE);
    let mut res = one;
    for (j, &bit) in bits_rev.iter().enumerate() {
        let pow_const = builder.add_const(pows[j]);
        let diff = builder.sub(pow_const, one);
        let diff_mul_bit = builder.mul(diff, bit);
        let gate = builder.add(one, diff_mul_bit);
        res = builder.mul(res, gate);
    }
    res
}

/// Convenience: raw parity bit for phase `i` is `bit[i]` (for `domain_index % 2`).
/// The “right‑sibling” flag used by folding is `1 − bit[i]`.
pub fn sibling_is_right_bit(bits: &[Target], phase: usize) -> Target {
    bits[phase]
}

// Note: We intentionally do not provide a helper which allocates proof-dependent
// values (e.g., bits or index) as constants. Callers should pass these as public
// inputs or witness values, then use `constrain_bits_boolean` and
// `reconstruct_index_from_bits` to constrain them as needed.

/// Compute x0 for a given phase from index bits and a provided generator power ladder.
///
/// - `index_bits`: little‑endian bits of the query index (one target per bit).
/// - `offset`: number of low bits to skip (typically `phase + 1`).
/// - `pows`: constant powers `[g^{2^0}, g^{2^1}, ..., g^{2^{k-1}}]`, where `k` is the
///   current `log_folded_height`.
pub fn compute_x0_from_bits_and_pows<F: Field>(
    builder: &mut CircuitBuilder<F>,
    index_bits: &[Target],
    offset: usize,
    pows: &[F],
) -> Target {
    let bits_rev = reversed_bits_window(index_bits, offset, pows.len());
    gated_exp_product(builder, pows, &bits_rev)
}

/// Build and verify the fold chain for a FRI query using index bits to derive x0 and parity.
///
/// - `index_bits`: little‑endian query index bits.
/// - `log_max_height`: total height H for this query (rounds + log_blowup + log_final_poly_len).
/// - `betas`: per‑phase β targets.
/// - `sibling_values`: per‑phase sibling evaluation targets.
/// - `roll_ins`: per‑phase optional reduced opening targets.
/// - `pows_per_phase`: per‑phase generator power ladders `[g^{2^0}, ..., g^{2^{k-1}}]`.
#[allow(clippy::too_many_arguments)]
pub fn verify_query_from_index_bits<F: Field + PrimeCharacteristicRing>(
    builder: &mut CircuitBuilder<F>,
    initial_folded_eval: Target,
    index_bits: &[Target],
    _log_max_height: usize,
    betas: &[Target],
    sibling_values: &[Target],
    roll_ins: &[Option<Target>],
    pows_per_phase: &[Vec<F>],
    final_value: Target,
) {
    let num_phases = betas.len();
    debug_assert_eq!(sibling_values.len(), num_phases);
    debug_assert_eq!(roll_ins.len(), num_phases);
    debug_assert_eq!(pows_per_phase.len(), num_phases);

    let one = builder.add_const(F::ONE);
    let phase_inputs: Vec<FoldPhaseInputsTarget> = (0..num_phases)
        .map(|i| {
            let x0 = compute_x0_from_bits_and_pows(builder, index_bits, i + 1, &pows_per_phase[i]);
            let raw_bit = sibling_is_right_bit(index_bits, i);
            let is_right = builder.sub(one, raw_bit); // 1 − bit[i]
            FoldPhaseInputsTarget {
                beta: betas[i],
                x0,
                e_sibling: sibling_values[i],
                sibling_is_right: is_right,
                roll_in: roll_ins[i],
            }
        })
        .collect();

    verify_query(builder, initial_folded_eval, &phase_inputs, final_value);
}
