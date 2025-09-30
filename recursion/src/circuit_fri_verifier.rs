use alloc::collections::btree_map::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::iter;

use p3_circuit::CircuitBuilder;
use p3_field::{ExtensionField, Field, TwoAdicField};

use crate::Target;
use crate::recursive_pcs::{FriProofTargets, InputProofTargets};
use crate::recursive_traits::{Recursive, RecursiveExtensionMmcs, RecursiveMmcs};

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
/// All arithmetic is over the circuit field `EF`.
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
    let two_inv_val = EF::ONE.halve(); // 1/2
    let neg_half = builder.add_const(EF::NEG_ONE * two_inv_val); // −1/2

    for FoldPhaseInputsTarget {
        beta,
        x0,
        e_sibling,
        sibling_is_right,
        roll_in,
    } in phases.iter().cloned()
    {
        // TODO(mmcs): MMCS batch verification needed for each phase.

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
    EF: ExtensionField<F>,
{
    // Build power-of-two ladder for two-adic generator g: [g, g^2, g^4, ...]
    let g = F::two_adic_generator(log_height);
    let powers_of_g: Vec<_> = iter::successors(Some(g), |&prev| Some(prev.square()))
        .take(rev_reduced_index_bits.len())
        .map(|p| builder.add_const(EF::from(p)))
        .collect();

    // Compute g^{rev_reduced_index} using the provided reversed bits
    let one = builder.add_const(EF::ONE);
    let mut g_pow_index = one;
    for (&bit, &power) in rev_reduced_index_bits.iter().zip(&powers_of_g) {
        let multiplier = builder.select(bit, power, one);
        g_pow_index = builder.mul(g_pow_index, multiplier);
    }

    // Multiply by the coset generator (also lifted to EF) to get x
    let generator = builder.add_const(EF::from(F::GENERATOR));
    builder.mul(generator, g_pow_index)
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
) -> (Target, Target) // (new_alpha_pow, reduced_opening_contrib)
{
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
///
/// Reference (Plonky3): `p3_fri::verifier::open_input`
#[allow(clippy::too_many_arguments)]
fn compute_reduced_openings_by_height<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    batch_opened_values: &[Vec<Target>], // Opened values per matrix (flattened across all batches)
    domains_log_sizes: &[usize],         // Log size of each matrix domain (base, before blowup)
    challenge_points: &[Target],         // z per matrix
    challenge_point_values: &[Vec<Target>], // f(z) per matrix (columns)
    alpha: Target,                       // batch combination challenge
    index_bits: &[Target],               // query index (little-endian)
    log_blowup: usize,                   // blowup factor (log)
    log_max_height: usize,               // global max height
) -> Vec<(usize, Target)>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    // TODO(challenger): Indices should be sampled from a RecursiveChallenger, not passed in.
    for &b in index_bits {
        builder.assert_bool(b);
    }
    debug_assert_eq!(
        index_bits.len(),
        log_max_height,
        "index_bits.len() must equal log_max_height"
    );
    debug_assert_eq!(batch_opened_values.len(), domains_log_sizes.len());
    debug_assert_eq!(batch_opened_values.len(), challenge_points.len());
    debug_assert_eq!(batch_opened_values.len(), challenge_point_values.len());

    // height -> (alpha_pow_for_this_height, ro_sum_for_this_height)
    let mut by_height: BTreeMap<usize, (Target, Target)> = BTreeMap::new();

    for (mat_idx, &log_domain_size) in domains_log_sizes.iter().enumerate() {
        let log_height = log_domain_size + log_blowup;
        let bits_reduced = log_max_height - log_height;

        // Take the next log_height bits, then reverse to match reverse_bits_len semantics
        let rev_bits: Vec<Target> = index_bits[bits_reduced..bits_reduced + log_height]
            .iter()
            .rev()
            .copied()
            .collect();

        // Compute evaluation point x in the circuit field using base field two-adic generator
        let x = compute_evaluation_point::<F, EF>(builder, log_height, &rev_bits);

        // Initialize / fetch per-height (alpha_pow, ro)
        let (alpha_pow_h, ro_h) = by_height
            .entry(log_height)
            .or_insert((builder.add_const(EF::ONE), builder.add_const(EF::ZERO)));

        let opened_values = &batch_opened_values[mat_idx];
        let point_values = &challenge_point_values[mat_idx];
        assert_eq!(
            opened_values.len(),
            point_values.len(),
            "opened_values columns must match challenge_point_values columns",
        );

        // ro contribution for this matrix
        let (new_alpha_pow_h, ro_contrib) = compute_single_reduced_opening(
            builder,
            opened_values,
            point_values,
            x,
            challenge_points[mat_idx],
            *alpha_pow_h,
            alpha,
        );

        // Accumulate and store updated per-height state
        *ro_h = builder.add(*ro_h, ro_contrib);
        *alpha_pow_h = new_alpha_pow_h;
    }

    // Optional native check mirrored in open_input:
    // If there's an entry at height == log_blowup (trace height 1), it must be zero.
    if let Some((_ap, ro0)) = by_height.get(&log_blowup) {
        let zero = builder.add_const(EF::ZERO);
        builder.connect(*ro0, zero);
    }

    // Into descending (height, ro) list
    by_height
        .into_iter()
        .rev()
        .map(|(h, (_ap, ro))| (h, ro))
        .collect()
}

/// Verify FRI arithmetic in-circuit.
///
/// TODO:
/// - Challenge/indices generation lives in the outer verifier. Keep this
///   function purely arithmetic and take `alpha`, `betas`, and
///   `index_bits_per_query` as inputs.
/// - Enforce FRI parameters (final_poly_len, num_queries) as in the native verifier.
/// - Add recursive MMCS verification for both input openings (`open_input`) and
///   per-phase commitments.
///
/// Reference (Plonky3): `p3_fri::verifier::verify_fri`
#[allow(clippy::too_many_arguments)]
pub fn verify_fri_circuit<F, EF, RecMmcs, Inner, Witness>(
    builder: &mut CircuitBuilder<EF>,
    fri_proof_targets: &FriProofTargets<F, EF, RecMmcs, InputProofTargets<F, EF, Inner>, Witness>,
    alpha: Target,
    betas: &[Target],
    index_bits_per_query: &[Vec<Target>],
    // TODO: Change interface to accept `ComsWithOpeningsTargets`.
    // Flattened across batches:
    challenge_points: &[Target],
    challenge_point_values: &[Vec<Target>],
    domains_log_sizes: &[usize],
    log_blowup: usize,
) where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    Inner: RecursiveMmcs<F, EF>,
    Witness: Recursive<EF>,
{
    let num_phases = betas.len();
    let num_queries = fri_proof_targets.query_proofs.len();
    // Sanity: number of betas must match number of commit phases.
    assert_eq!(
        num_phases,
        fri_proof_targets.commit_phase_commits.len(),
        "betas length must equal number of commit-phase commitments"
    );
    assert_eq!(
        num_queries,
        index_bits_per_query.len(),
        "index_bits_per_query length must equal number of query proofs"
    );
    let log_max_height = index_bits_per_query[0].len();
    assert!(
        index_bits_per_query
            .iter()
            .all(|v| v.len() == log_max_height),
        "all index_bits_per_query entries must have same length"
    );

    // Basic shape checks
    assert!(!betas.is_empty(), "FRI must have at least one fold phase");

    // Fail fast if final polynomial is not constant (current circuit assumes len=1)
    let final_poly_len = fri_proof_targets.final_poly.len();
    assert_eq!(
        final_poly_len, 1,
        "This circuit assumes a constant final polynomial (len=1). Got len={final_poly_len}"
    );
    let final_value = fri_proof_targets.final_poly[0];

    // 1) Precompute two-adic generator ladders for each phase (in circuit field EF).
    //
    // For phase i, folded height k = log_max_height - i - 1.
    // Use generator g = two_adic_generator(k + 1) and ladder [g^{2^0},...,g^{2^{k-1}}].
    let pows_per_phase: Vec<Vec<EF>> = (0..num_phases)
        .map(|i| {
            let k = log_max_height.saturating_sub(i + 1);
            if k == 0 {
                return Vec::new();
            }
            let g = F::two_adic_generator(k + 1);
            iter::successors(Some(g), |&prev| Some(prev.square()))
                .take(k)
                .map(EF::from)
                .collect()
        })
        .collect();

    // 2) For each query, flatten **all batches** then compute reduced openings and fold.
    for (q, query_proof) in fri_proof_targets.query_proofs.iter().enumerate() {
        // (a) Flatten opened values across all batches in the order p3_fri::open_input visits them.
        let mut opened_values_flat: Vec<Vec<Target>> = Vec::new();
        for batch in &query_proof.input_proof {
            opened_values_flat.extend(batch.opened_values.iter().cloned());
        }

        // Shape checks vs flattened public inputs
        assert_eq!(
            opened_values_flat.len(),
            challenge_point_values.len(),
            "opened_values (flattened) must match number of challenge_point_values (flattened)"
        );
        assert_eq!(
            opened_values_flat.len(),
            domains_log_sizes.len(),
            "opened_values (flattened) must match domains_log_sizes (flattened)"
        );
        assert_eq!(
            opened_values_flat.len(),
            challenge_points.len(),
            "opened_values (flattened) must match challenge_points (flattened)"
        );

        // (b) Arithmetic `open_input` to get (height, ro) descending
        let reduced_by_height = compute_reduced_openings_by_height::<F, EF>(
            builder,
            &opened_values_flat,
            domains_log_sizes,
            challenge_points,
            challenge_point_values,
            alpha,
            &index_bits_per_query[q],
            log_blowup,
            log_max_height,
        );

        // Must have the max-height entry at the front
        assert!(
            !reduced_by_height.is_empty(),
            "No reduced openings; did you commit to zero polynomials?"
        );
        assert_eq!(
            reduced_by_height[0].0, log_max_height,
            "First reduced opening must be at max height"
        );
        let initial_folded_eval = reduced_by_height[0].1;

        // (c) Sibling values for this query (one per phase)
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

        // (d) Build height-aligned roll-ins for each phase (desc heights -> phases)
        let mut roll_ins: Vec<Option<Target>> = vec![None; num_phases];
        for &(h, ro) in reduced_by_height.iter().skip(1) {
            // height -> phase index mapping
            let i = log_max_height
                .checked_sub(1)
                .and_then(|x| x.checked_sub(h))
                .expect("height->phase mapping underflow");
            if i < num_phases {
                // There should be at most one roll-in per phase since `reduced_by_height`
                // aggregates all matrices at the same height already (and we only support a
                // single input batch). Multiple entries mapping to the same phase indicate an
                // invariant violation.
                assert!(
                    roll_ins[i].is_none(),
                    "duplicate roll-in for phase {i} (height {h})",
                );
                roll_ins[i] = Some(ro);
            } else {
                // If a height is below final folded height, it should be unused; connect to zero.
                let zero = builder.add_const(EF::ZERO);
                builder.connect(ro, zero);
            }
        }

        // (e) Perform the fold chain and connect to the (constant) final polynomial value
        verify_query_from_index_bits(
            builder,
            initial_folded_eval,
            &index_bits_per_query[q],
            betas,
            &sibling_values,
            &roll_ins,
            &pows_per_phase,
            final_value,
        );
    }
}
