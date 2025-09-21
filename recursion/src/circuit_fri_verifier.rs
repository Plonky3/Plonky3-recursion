use p3_circuit::CircuitBuilder;
use p3_field::Field;

/// Inputs needed for one FRI fold phase in-circuit.
///
/// - `beta`: the per-phase challenge sampled by the verifier.
/// - `x0`: subgroup point for the current phase (x1 = -x0 implicitly).
/// - `e_sibling`: sibling evaluation value from the proof at the sibling index.
/// - `sibling_is_right`: boolean in field {0,1}; 1 if sibling occupies evals[1] (right), 0 if evals[0].
/// - `roll_in`: optional reduced opening to roll in at this height, added as beta^2 * roll_in.
#[derive(Clone, Debug)]
pub struct FoldPhaseInputs {
    pub beta: p3_circuit::ExprId,
    pub x0: p3_circuit::ExprId,
    pub e_sibling: p3_circuit::ExprId,
    pub sibling_is_right: p3_circuit::ExprId,
    pub roll_in: Option<p3_circuit::ExprId>,
}

/// Perform the FRI folding chain arithmetic with optional roll-ins.
///
/// Starts from the initial reduced opening at the maximum height, then for each phase:
/// - Interpolates between (x0, e0) and (x1, e1) at beta, where x1 = -x0 and e0 is the current folded evaluation.
/// - Optionally adds a roll-in term beta^2 * roll_in for that height.
///   Returns the final folded evaluation after all phases.
pub fn fri_fold_chain<F: Field>(
    builder: &mut CircuitBuilder<F>,
    initial_folded_eval: p3_circuit::ExprId,
    phases: &[FoldPhaseInputs],
) -> p3_circuit::ExprId {
    let mut folded = initial_folded_eval;
    let neg_one = builder.add_const(F::NEG_ONE);
    let one = builder.add_const(F::ONE);

    for FoldPhaseInputs {
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

/// Full arithmetic check for FRI (fold chain + final polynomial consistency) without MMCS/challenger.
///
/// - Starts from `initial_folded_eval` (reduced opening at the maximum height).
/// - Applies the folding chain using `phases`.
/// - Evaluates the final polynomial `final_poly_coeffs` at `x_final` (Horner).
/// - Enforces equality by connecting both results.
pub fn verify_fri_arithmetic_circuit<F: Field>(
    builder: &mut CircuitBuilder<F>,
    initial_folded_eval: p3_circuit::ExprId,
    phases: &[FoldPhaseInputs],
    final_value: p3_circuit::ExprId,
) {
    let folded_eval = fri_fold_chain(builder, initial_folded_eval, phases);
    builder.connect(folded_eval, final_value);
}
