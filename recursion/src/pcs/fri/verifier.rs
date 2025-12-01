use alloc::collections::btree_map::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::iter;

use p3_circuit::CircuitBuilder;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_util::zip_eq::zip_eq;

use super::{FriProofTargets, InputProofTargets};
use crate::Target;
use crate::traits::{ComsWithOpeningsTargets, Recursive, RecursiveExtensionMmcs, RecursiveMmcs};
use crate::verifier::VerificationError;

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
    builder.push_scope("fold_row_chain");

    let mut folded = initial_folded_eval;

    let one = builder.alloc_const(EF::ONE, "1");

    // Precompute constants as field constants: 2^{-1} and −1/2.
    let two_inv_val = EF::ONE.halve(); // 1/2
    let neg_half = builder.alloc_const(EF::NEG_ONE * two_inv_val, "−1/2"); // −1/2

    for FoldPhaseInputsTarget {
        beta,
        x0,
        e_sibling,
        sibling_is_right,
        roll_in,
    } in phases.iter().cloned()
    {
        // TODO: Add recursive MMCS batch verification for this commit phase:
        // Verify the sibling value against the commitment at the parent index.

        // e0 = select(bit, folded, e_sibling)
        let e0 = builder.select(sibling_is_right, folded, e_sibling);

        // inv = (x1 − x0)^{-1} = (−2x0)^{-1} = (−1/2) / x0
        let inv = builder.alloc_div(neg_half, x0, "inv");

        // e1 − e0 = (2b − 1) · (e_sibling − folded)
        let d = builder.alloc_sub(e_sibling, folded, "d");
        let two_b = builder.alloc_add(sibling_is_right, sibling_is_right, "two_b");
        let two_b_minus_one = builder.alloc_sub(two_b, one, "two_b_minus_one");
        let e1_minus_e0 = builder.alloc_mul(two_b_minus_one, d, "e1_minus_e0");

        // t = (β − x0) * (e1 − e0)
        let beta_minus_x0 = builder.alloc_sub(beta, x0, "beta_minus_x0");
        let t = builder.alloc_mul(beta_minus_x0, e1_minus_e0, "t");

        // folded = e0 + t * inv
        let t_inv = builder.alloc_mul(t, inv, "t_inv");
        folded = builder.alloc_add(e0, t_inv, "folded 1");

        // Optional roll-in: folded += β² · roll_in
        if let Some(ro) = roll_in {
            let beta_sq = builder.alloc_mul(beta, beta, "beta_sq");
            let add_term = builder.alloc_mul(beta_sq, ro, "add_term");
            folded = builder.alloc_add(folded, add_term, "folded 2");
        }
    }

    builder.pop_scope(); // close `fold_row_chain` scope
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

/// Arithmetic-only version of Plonky3 `verify_query`:
/// - Applies the fold chain and enforces equality to the provided final polynomial evaluation.
/// - Caller must supply `initial_folded_eval` (the reduced opening at max height).
fn verify_query<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    initial_folded_eval: Target,
    phases: &[FoldPhaseInputsTarget],
    final_value: Target,
) {
    builder.push_scope("verify_query");
    let folded_eval = fold_row_chain(builder, initial_folded_eval, phases);
    builder.connect(folded_eval, final_value);
    builder.pop_scope(); // close `verify_query` scope
}

/// Compute the final query point after all FRI folding rounds.
/// This is the point at which the final polynomial should be evaluated.
fn compute_final_query_point<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    index_bits: &[Target],
    log_max_height: usize,
    num_phases: usize,
) -> Target
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("compute_final_query_point");

    // Extract the bits that form domain_index (bits [num_phases..log_max_height]) after `num_phases` folds
    let domain_index_bits: Vec<Target> = index_bits[num_phases..log_max_height].to_vec();

    // Pad bits and reverse
    let mut reversed_bits = vec![builder.add_const(EF::ZERO); num_phases];
    reversed_bits.extend(domain_index_bits.iter().rev().copied());

    // Compute g^{reversed_index}
    let g = F::two_adic_generator(log_max_height);
    let powers_of_g: Vec<_> = iter::successors(Some(g), |&prev| Some(prev.square()))
        .take(log_max_height)
        .map(|p| builder.add_const(EF::from(p)))
        .collect();

    let one = builder.add_const(EF::ONE);
    let mut result = one;
    for (&bit, &power) in reversed_bits.iter().zip(&powers_of_g) {
        let multiplier = builder.select(bit, power, one);
        result = builder.mul(result, multiplier);
    }

    builder.pop_scope(); // close `compute_final_query_point` scope
    result
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
    builder.push_scope("compute_x0_from_index_bits");

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

    builder.pop_scope(); // close `compute_x0_from_index_bits` scope
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
    builder.push_scope("verify_query_from_index_bits");

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
    builder.pop_scope(); // close `verify_query_from_index_bits` scope
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
    builder.push_scope("compute_evaluation_point");

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
    let generator = builder.alloc_const(EF::from(F::GENERATOR), "coset_generator");
    let eval_point = builder.alloc_mul(generator, g_pow_index, "eval_point");

    builder.pop_scope(); // close `compute_evaluation_point` scope
    eval_point
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
    builder.push_scope("compute_single_reduced_opening");

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

    builder.pop_scope(); // close `compute_single_reduced_opening` scope
    (current_alpha_pow, reduced_opening)
}

/// Compute reduced openings grouped **by height** with **per-height alpha powers**,
/// Returns a vector of (log_height, ro) sorted by descending height.
///
/// Reference (Plonky3): `p3_fri::verifier::open_input`
#[allow(clippy::too_many_arguments)]
fn open_input<F, EF, Comm>(
    builder: &mut CircuitBuilder<EF>,
    log_global_max_height: usize,
    index_bits: &[Target],
    alpha: Target,
    log_blowup: usize,
    commitments_with_opening_points: &ComsWithOpeningsTargets<Comm, TwoAdicMultiplicativeCoset<F>>,
    batch_opened_values: &[Vec<Vec<Target>>], // Per batch -> per matrix -> per column
) -> Result<Vec<(usize, Target)>, VerificationError>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("open_input");

    // TODO(challenger): Indices should be sampled from a RecursiveChallenger, not passed in.
    for &b in index_bits {
        builder.assert_bool(b);
    }
    debug_assert_eq!(
        index_bits.len(),
        log_global_max_height,
        "index_bits.len() must equal log_global_max_height"
    );

    // height -> (alpha_pow_for_this_height, ro_sum_for_this_height)
    let mut reduced_openings = BTreeMap::<usize, (Target, Target)>::new();

    // Process each batch
    for (batch_idx, ((_batch_commit, mats), batch_openings)) in zip_eq(
        commitments_with_opening_points.iter(),
        batch_opened_values.iter(),
        VerificationError::InvalidProofShape(
            "Opened values and commitments count must match".to_string(),
        ),
    )?
    .enumerate()
    {
        // TODO: Add recursive MMCS verification here for this batch:
        // Verify batch_openings against _batch_commit at the computed reduced_index.

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

            let bits_reduced = log_global_max_height - log_height;
            let rev_bits: Vec<Target> = index_bits[bits_reduced..bits_reduced + log_height]
                .iter()
                .rev()
                .copied()
                .collect();

            // Compute evaluation point x
            let x = compute_evaluation_point::<F, EF>(builder, log_height, &rev_bits);

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

                let (new_alpha_pow_h, ro_contrib) = compute_single_reduced_opening(
                    builder,
                    mat_opening,
                    ps_at_z,
                    x,
                    *z,
                    *alpha_pow_h,
                    alpha,
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
    Ok(reduced_openings
        .into_iter()
        .rev()
        .map(|(h, (_ap, ro))| (h, ro))
        .collect())
}

/// Verify FRI arithmetic in-circuit.
///
/// TODO:
/// - Challenge/indices generation lives in the outer verifier. Keep this
///   function purely arithmetic and take `alpha`, `betas`, and
///   `index_bits_per_query` as inputs.
/// - Add recursive MMCS verification for both input openings (`open_input`) and
///   per-phase commitments.
///
/// Reference (Plonky3): `p3_fri::verifier::verify_fri`
#[allow(clippy::too_many_arguments)]
pub fn verify_fri_circuit<F, EF, RecMmcs, Inner, Witness, Comm>(
    builder: &mut CircuitBuilder<EF>,
    fri_proof_targets: &FriProofTargets<F, EF, RecMmcs, InputProofTargets<F, EF, Inner>, Witness>,
    alpha: Target,
    betas: &[Target],
    index_bits_per_query: &[Vec<Target>],
    commitments_with_opening_points: &ComsWithOpeningsTargets<Comm, TwoAdicMultiplicativeCoset<F>>,
    log_blowup: usize,
) -> Result<(), VerificationError>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    Inner: RecursiveMmcs<F, EF>,
    Witness: Recursive<EF>,
{
    builder.push_scope("verify_fri");

    let num_phases = betas.len();
    let num_queries = fri_proof_targets.query_proofs.len();

    // Validate shape.
    if num_phases != fri_proof_targets.commit_phase_commits.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "betas length must equal number of commit-phase commitments: expected {}, got {}",
            num_phases,
            fri_proof_targets.commit_phase_commits.len()
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

    // Compute the expected final polynomial length from FRI parameters
    // log_max_height = num_phases + log_final_poly_len + log_blowup
    // So: log_final_poly_len = log_max_height - num_phases - log_blowup
    let log_final_poly_len = log_max_height
        .checked_sub(num_phases)
        .and_then(|x| x.checked_sub(log_blowup))
        .ok_or_else(|| {
            VerificationError::InvalidProofShape(
                "Invalid FRI parameters: log_max_height too small".to_string(),
            )
        })?;

    let expected_final_poly_len = 1 << log_final_poly_len;
    let actual_final_poly_len = fri_proof_targets.final_poly.len();

    //  Check the final polynomial length.
    if actual_final_poly_len != expected_final_poly_len {
        return Err(VerificationError::InvalidProofShape(format!(
            "Final polynomial length mismatch: expected 2^{log_final_poly_len} = {expected_final_poly_len}, got {actual_final_poly_len}"
        )));
    }

    // Precompute two-adic generator ladders for each phase (in circuit field EF).
    //
    // For phase i, folded height k = log_max_height - i - 1.
    // Use generator g = two_adic_generator(k + 1) and ladder [g^{2^0},...,g^{2^{k-1}}].
    let pows_per_phase: Vec<Vec<EF>> = (0..num_phases)
        .map(|i| {
            // `k` is the height of the folded domain after `i` rounds of folding.
            let k = log_max_height.saturating_sub(i + 1);
            if k == 0 {
                return Vec::new();
            }
            let g = F::two_adic_generator(k + 1);
            // Create the power ladder [g, g^2, g^4, ...].
            iter::successors(Some(g), |&prev| Some(prev.square()))
                .take(k)
                .map(EF::from)
                .collect()
        })
        .collect();

    // For each query, extract opened values from proof and compute reduced openings and fold.
    for (q, query_proof) in fri_proof_targets.query_proofs.iter().enumerate() {
        // Extract opened values from the input_proof (batch openings)
        // Structure: Vec<BatchOpening> where each BatchOpening has Vec<Vec<Target>> (matrices -> columns)
        let batch_opened_values: Vec<Vec<Vec<Target>>> = query_proof
            .input_proof
            .iter()
            .map(|batch| batch.opened_values.clone())
            .collect();

        // Arithmetic `open_input` to get (height, ro) descending
        let reduced_by_height = open_input::<F, EF, Comm>(
            builder,
            log_max_height,
            &index_bits_per_query[q],
            alpha,
            log_blowup,
            commitments_with_opening_points,
            &batch_opened_values,
        )?;

        // Must have the max-height entry at the front

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

        // Sibling values for this query (one per phase)
        let sibling_values: Vec<Target> = query_proof
            .commit_phase_openings
            .iter()
            .map(|opening| opening.sibling_value)
            .collect();

        if sibling_values.len() != num_phases {
            return Err(VerificationError::InvalidProofShape(format!(
                "sibling_values must match number of betas/phases: expected {}, got {}",
                num_phases,
                sibling_values.len()
            )));
        }

        // Build height-aligned roll-ins for each phase (desc heights -> phases)
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
                if roll_ins[i].is_some() {
                    return Err(VerificationError::InvalidProofShape(format!(
                        "duplicate roll-in for phase {i} (height {h})",
                    )));
                }
                roll_ins[i] = Some(ro);
            } else {
                // If a height is below final folded height, it should be unused; connect to zero.
                let zero = builder.add_const(EF::ZERO);
                builder.connect(ro, zero);
            }
        }

        // Compute the final query point for this query and evaluate the final polynomial
        let final_query_point = compute_final_query_point::<F, EF>(
            builder,
            &index_bits_per_query[q],
            log_max_height,
            num_phases,
        );

        let final_poly_eval =
            evaluate_polynomial(builder, &fri_proof_targets.final_poly, final_query_point);

        // Perform the fold chain and connect to the evaluated final polynomial value
        verify_query_from_index_bits(
            builder,
            initial_folded_eval,
            &index_bits_per_query[q],
            betas,
            &sibling_values,
            &roll_ins,
            &pows_per_phase,
            final_poly_eval,
        );

        builder.pop_scope(); // close `verify_fri` scope
    }

    Ok(())
}
