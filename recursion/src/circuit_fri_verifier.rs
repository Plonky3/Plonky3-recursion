use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::{ExtensionField, Field, TwoAdicField};

use crate::Target;
use crate::recursive_pcs::FriProofTargets;
use crate::recursive_traits::{Recursive, RecursiveExtensionMmcs};

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
fn fold_row_chain<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    initial_folded_eval: Target,
    phases: &[FoldPhaseInputsTarget],
) -> Target {
    let mut folded = initial_folded_eval;

    let one = builder.add_const(EF::ONE);

    // Precompute constants as field constants: 2^{-1} and −1/2.
    let two_inv_val = (EF::ONE + EF::ONE).inverse(); // 1/2
    let neg_half = builder.add_const(EF::NEG_ONE * two_inv_val); // −1/2

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
fn verify_query<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
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
fn compute_x0_from_index_bits<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    index_bits: &[Target],
    phase: usize,
    pows: &[EF],
) -> Target {
    let one = builder.add_const(EF::ONE);
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
fn verify_query_from_index_bits<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    initial_folded_eval: Target,
    index_bits: &[Target],
    betas: &[Target],
    sibling_values: &[Target],
    roll_ins: &[Option<Target>],
    pows_per_phase: &[Vec<EF>],
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

    let one = builder.add_const(EF::ONE);

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

/// Compute evaluation point x from domain height and reversed reduced index bits in the circuit field EF.
/// x = GENERATOR * two_adic_generator(log_height)^{rev_reduced_index}
fn compute_evaluation_point<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    log_height: usize,
    rev_reduced_index_bits: &[Target],
) -> Target
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField, // circuit field
{
    // Precompute powers of the two-adic generator (in the base field), then lift to EF.
    let h = F::two_adic_generator(log_height);
    let mut powers_e = Vec::with_capacity(rev_reduced_index_bits.len());
    let mut current_f = h;
    for _ in 0..rev_reduced_index_bits.len() {
        powers_e.push(builder.add_const(EF::from(current_f)));
        current_f = current_f.square();
    }

    // Compute h^{rev_reduced_index} via gated multiplication
    let one = builder.add_const(EF::ONE);
    let mut result = one;
    for (i, &bit) in rev_reduced_index_bits.iter().enumerate() {
        builder.assert_bool(bit);
        let diff = builder.sub(powers_e[i], one);
        let diff_bit = builder.mul(diff, bit);
        let multiplier = builder.add(one, diff_bit);
        result = builder.mul(result, multiplier);
    }

    // Multiply by the coset generator (also lifted to EF)
    let generator = builder.add_const(EF::from(F::GENERATOR));
    builder.mul(generator, result)
}

/// Compute reduced opening for a single matrix in circuit form (EF-field).
/// ro += alpha_pow * (p_at_z - p_at_x) * (z - x)^{-1}; and alpha_pow *= alpha (per column)
fn compute_single_reduced_opening<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    opened_values: &[Target], // Values at evaluation point x
    point_values: &[Target],  // Values at challenge point z
    evaluation_point: Target, // x
    challenge_point: Target,  // z
    alpha_pow: Target,        // Current alpha power (for this height)
    alpha: Target,            // Alpha challenge
) -> (Target, Target) {
    // (new_alpha_pow, reduced_opening_contrib)
    let mut reduced_opening = builder.add_const(EF::ZERO);
    let mut current_alpha_pow = alpha_pow;

    // quotient = (z - x)^{-1}
    let z_minus_x = builder.sub(challenge_point, evaluation_point);
    let one = builder.add_const(EF::ONE);
    let quotient = builder.div(one, z_minus_x);

    for (&p_at_x, &p_at_z) in opened_values.iter().zip(point_values.iter()) {
        // diff = p_at_z - p_at_x
        let diff = builder.sub(p_at_z, p_at_x);

        // term = alpha_pow * diff * quotient
        let alpha_diff = builder.mul(current_alpha_pow, diff);
        let term = builder.mul(alpha_diff, quotient);

        reduced_opening = builder.add(reduced_opening, term);

        // advance alpha power for the *next column in this height*
        current_alpha_pow = builder.mul(current_alpha_pow, alpha);
    }

    (current_alpha_pow, reduced_opening)
}

/// Compute reduced openings grouped **by height** with **per-height alpha powers**, as in the real verifier.
/// Returns a vector of (log_height, ro) sorted by descending height.
///
/// Notes:
/// - `index_bits` is the full query index as little-endian bits; length must be `log_max_height`.
/// - For each matrix (domain), bits_reduced = log_max_height - log_height;
///   use the window of length `log_height`, then reverse those bits for the eval point.
#[allow(clippy::too_many_arguments)]
fn compute_reduced_openings_by_height<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    batch_opened_values: &[Vec<Target>], // Opened values per matrix
    domains_log_sizes: &[usize],         // Log size of each domain (base, before blowup)
    challenge_points: &[Target],         // z per matrix
    challenge_point_values: &[Vec<Target>], // f(z) per matrix (columns)
    alpha: Target,                       // batch combination challenge
    index_bits: &[Target],               // query index (little-endian)
    log_blowup: usize,                   // blowup factor (log)
    log_max_height: usize,               // global max height
) -> Vec<(usize, Target)>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    // height -> (alpha_pow_for_this_height, ro_sum_for_this_height)
    use alloc::collections::BTreeMap;
    let mut by_height: BTreeMap<usize, (Target, Target)> = BTreeMap::new();

    // Sanity: bits are boolean
    for &b in index_bits {
        builder.assert_bool(b);
    }
    debug_assert_eq!(
        index_bits.len(),
        log_max_height,
        "index_bits.len() must equal log_max_height"
    );

    for (mat_idx, &log_domain_size) in domains_log_sizes.iter().enumerate() {
        let log_height = log_domain_size + log_blowup;

        // bits_reduced = log_max_height - log_height
        let bits_reduced = log_max_height - log_height;

        // Take the next log_height bits, then reverse to match reverse_bits_len semantics
        let height_bits = &index_bits[bits_reduced..bits_reduced + log_height];
        let mut rev_bits = height_bits.to_vec();
        rev_bits.reverse();

        // Compute evaluation point x in the circuit field using base field two-adic generator
        let x = compute_evaluation_point::<F, EF>(builder, log_height, &rev_bits);

        // Initialize / fetch per-height (alpha_pow, ro)
        let (alpha_pow_h, ro_h) = by_height
            .entry(log_height)
            .or_insert((builder.add_const(EF::ONE), builder.add_const(EF::ZERO)));

        // Compute this matrix's contribution to ro at this height
        let (new_alpha_pow_h, ro_contrib) = compute_single_reduced_opening(
            builder,
            &batch_opened_values[mat_idx],
            &challenge_point_values[mat_idx],
            x,
            challenge_points[mat_idx],
            *alpha_pow_h,
            alpha,
        );

        // Accumulate and store updated per-height state
        *ro_h = builder.add(*ro_h, ro_contrib);
        *alpha_pow_h = new_alpha_pow_h;
    }

    // Into descending (height, ro) list
    let mut v: Vec<(usize, Target)> = by_height
        .into_iter()
        .map(|(h, (_ap, ro))| (h, ro))
        .collect();
    v.sort_by(|a, b| b.0.cmp(&a.0)); // descending by height
    v
}

/// Verify FRI arithmetic in-circuit.
#[allow(clippy::too_many_arguments)]
pub fn verify_fri_circuit<F, EF, RecMmcs, InputProof, Witness>(
    builder: &mut CircuitBuilder<EF>,
    fri_proof_targets: &FriProofTargets<F, EF, RecMmcs, InputProof, Witness>,
    alpha: Target,
    betas: &[Target],
    index_bits: &[Target],
    opened_values: &[Vec<Target>],
    challenge_points: &[Target],
    challenge_point_values: &[Vec<Target>],
    domains_log_sizes: &[usize],
    log_blowup: usize,
) where
    F: Field + TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    InputProof: Recursive<EF>,
    Witness: Recursive<EF>,
{
    let num_phases = betas.len();
    let log_max_height = index_bits.len();

    // Basic shape checks
    assert!(!betas.is_empty(), "FRI must have at least one fold phase");
    assert_eq!(
        opened_values.len(),
        challenge_point_values.len(),
        "opened_values/challenge_point_values shape mismatch"
    );
    assert_eq!(
        opened_values.len(),
        domains_log_sizes.len(),
        "opened_values/domains_log_sizes shape mismatch"
    );
    for row in opened_values {
        assert!(!row.is_empty(), "each matrix must have at least one column");
    }

    // 1) Compute reduced openings grouped by height (descending order)
    let reduced_by_height: Vec<(usize, Target)> = compute_reduced_openings_by_height::<F, EF>(
        builder,
        opened_values,
        domains_log_sizes,
        challenge_points,
        challenge_point_values,
        alpha,
        index_bits,
        log_blowup,
        log_max_height,
    );

    // Must have at least the max-height entry
    assert!(
        !reduced_by_height.is_empty(),
        "No reduced openings; did you commit to zero polynomials?"
    );
    assert_eq!(
        reduced_by_height[0].0, log_max_height,
        "First reduced opening must be at max height"
    );

    // 2) Initialize running fold with the max-height reduced opening
    let initial_folded_eval = reduced_by_height[0].1;

    // 3) Extract sibling values from FRI proof targets (for the first query)
    //    (MMCS checks omitted; we assume `fri_proof_targets` is bound elsewhere)
    let query_proof = &fri_proof_targets.query_proofs[0];
    let sibling_values: Vec<Target> = query_proof
        .commit_phase_openings
        .iter()
        .map(|opening| opening.sibling_value)
        .collect();
    assert_eq!(
        sibling_values.len(),
        num_phases,
        "sibling_values must match number of betas/phases"
    );

    // 4) Build height-aligned roll-ins for each phase:
    //
    // Phase i folds from height (log_max_height - i) down to (log_max_height - i - 1).
    // If we have a reduced opening `ro` at height h, we must add it at the phase i where:
    //     h == log_max_height - i - 1  =>  i = log_max_height - 1 - h
    //
    // We skip the first entry (max height), which was used to seed `folded`.
    let mut roll_ins: Vec<Option<Target>> = vec![None; num_phases];
    for &(h, ro) in reduced_by_height.iter().skip(1) {
        let i = log_max_height
            .checked_sub(1)
            .and_then(|x| x.checked_sub(h))
            .expect("height->phase mapping underflow");
        if i < num_phases {
            // sum multiple ROs that may land on the same phase
            roll_ins[i] = Some(match roll_ins[i] {
                None => ro,
                Some(prev) => builder.add(prev, ro),
            });
        } else {
            // Should not happen in a well-shaped proof; if it does, force ro == 0
            // so we don't silently drop it.
            let zero = builder.add_const(EF::ZERO);
            builder.connect(ro, zero);
        }
    }

    // 5) Grab the final polynomial (constant case expected here).
    let final_poly_len = fri_proof_targets.final_poly.len();
    assert_eq!(
        final_poly_len, 1,
        "This circuit assumes a constant final polynomial (len=1). Got len={final_poly_len}"
    );
    let final_value = fri_proof_targets.final_poly[0];

    // 6) Precompute two-adic generator ladders for each phase (in circuit field EF).
    //
    // For phase i, folded height k = log_max_height - i - 1.
    // Use generator g = two_adic_generator(k + 1) and ladder [g^{2^0},...,g^{2^{k-1}}].
    let pows_per_phase: Vec<Vec<EF>> = (0..num_phases)
        .map(|i| {
            let k = log_max_height.saturating_sub(i + 1);
            if k == 0 {
                return Vec::new();
            }
            let g_f = F::two_adic_generator(k + 1);
            let mut ladder = Vec::with_capacity(k);
            let mut cur = g_f;
            for _ in 0..k {
                ladder.push(EF::from(cur));
                cur = cur.square();
            }
            ladder
        })
        .collect();

    // 7) Perform the complete FRI folding arithmetic in-circuit
    verify_query_from_index_bits(
        builder,
        initial_folded_eval,
        index_bits,
        betas,
        &sibling_values,
        &roll_ins,
        &pows_per_phase,
        final_value,
    );
}
