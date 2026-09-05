//! Turning STARK opening claims into the WHIR verifier's batched constraint.
//!
//! `p3_sumcheck`'s layout verifier records each opening as an equality claim on
//! the stacked polynomial, lifts it into the stacked variable space with the
//! column's boolean selector prefix, and batches everything with powers of a
//! single challenge `alpha`. This module does the same in-circuit, so the
//! recursive verifier can hand `verify_whir_circuit` the same constraint and
//! claimed sum the native verifier forms.
//!
//! Two orderings are reproduced exactly: concrete openings are walked in
//! placement order (largest table first) before the out-of-domain claims, and
//! the flattened equality points receive the batching powers in that same
//! order.

use alloc::format;
use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, CircuitBuilderError, NonPrimitiveOpId};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};

use crate::Target;
use crate::pcs::whir::gadgets::{ConstraintWeightData, eval_powers_combination};
use crate::pcs::whir::uni::bridge::univariate_eq_point_circuit;
use crate::pcs::whir::uni::plan::{PaddedArity, StackedPlan, padded_arity};
use crate::pcs::whir::uni::recursive_pcs::{DummyChallenger, WhirUniVerifierParams};
use crate::pcs::whir::uni::targets::WhirRoundTargets;
use crate::traits::{ComsWithOpeningsTargets, RecursiveChallenger};
use crate::verifier::{ObservableCommitment, VerificationError};

/// One committed matrix's public opening shape.
pub struct MatrixOpenings<'a> {
    /// Unpadded log2 height of the committed matrix.
    pub log_height: usize,
    /// Opening points and the claimed univariate values at each.
    pub points: &'a [(Target, Vec<Target>)],
}

/// The constraint and claimed sum one commitment round hands to WHIR.
pub struct RoundClaims {
    /// Batched equality constraint over the stacked polynomial.
    pub constraint: ConstraintWeightData,
    /// Initial claimed sumcheck value.
    pub claimed_eval: Target,
    /// Arity of the stacked polynomial for this commitment.
    pub stacked_num_variables: usize,
}

/// Assembles one commitment round's WHIR claim.
///
/// `round_evals[b]` holds the multilinear values the proof binds for opening
/// batch `b`, in `iter_openings()` order (matrix-major, then point). Each is
/// tied to the STARK's claimed univariate value by
/// `bound * scale == claimed`, the bridge identity, so a prover cannot
/// substitute a different value than the one the STARK constrains.
///
/// # Soundness precondition
/// Every concrete opening's point (`m.points[i].0`, substituted here via
/// `univariate_eq_point_circuit`) must already be bound in the transcript
/// before this function runs, exactly as native `add_claim_at` requires of
/// its caller. This function only absorbs the opening *values* (via
/// `observe_ext_slice`); it never absorbs or otherwise binds the points
/// themselves.
///
/// # Errors
/// Never returns `Err` today: every `RecursiveChallenger` operation this
/// function calls (`sample_ext`, `observe_ext`, `observe_ext_slice`) is
/// infallible. The `Result` return type matches the fallible
/// `RecursiveChallenger` methods used elsewhere (e.g. `verify_whir_circuit`),
/// so callers can compose both behind one error-handling path.
///
/// # Panics
/// Panics if `round_evals`'s shape disagrees with `matrices`, or if a
/// matrix's opening points claim differing widths: every point of one matrix
/// must open exactly that matrix's declared column count (taken from its
/// first point), since `StackedPlan` allocates one selector per column and a
/// narrower or wider point would otherwise leave a column's claim silently
/// out of the batched constraint instead of failing loudly.
pub fn build_round_claims<BF, EF, Ch>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut Ch,
    matrices: &[MatrixOpenings<'_>],
    round_evals: &[Vec<Target>],
    initial_ood_answers: &[Target],
    folding: usize,
) -> Result<RoundClaims, CircuitBuilderError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF>,
    Ch: RecursiveChallenger<BF, EF>,
{
    let shapes: Vec<(PaddedArity, usize)> = matrices
        .iter()
        .map(|m| {
            let width = m.points.first().map_or(0, |(_, values)| values.len());
            (padded_arity(m.log_height, folding), width)
        })
        .collect();
    let plan = StackedPlan::new(&shapes);

    // Substituted equality point and scale per (matrix, point), plus the
    // bound-value binding. Batch indices follow matrix-major, then point order.
    let mut batch = 0usize;
    let mut local_points: Vec<Vec<Vec<Target>>> = Vec::with_capacity(matrices.len());
    for (matrix_idx, m) in matrices.iter().enumerate() {
        let width = shapes[matrix_idx].1;
        let arity = padded_arity(m.log_height, folding).get();
        let mut per_point = Vec::with_capacity(m.points.len());
        for (zeta, claimed) in m.points {
            assert_eq!(
                claimed.len(),
                width,
                "ragged opening width for matrix {matrix_idx}: a point claims {} columns, \
                 but the matrix's declared width (from its first point) is {width}; every \
                 point of one matrix must open the same columns, since `StackedPlan` \
                 allocates exactly one selector per column",
                claimed.len(),
            );
            let (x, scale) = univariate_eq_point_circuit(circuit, *zeta, arity);
            let bound = &round_evals[batch];
            assert_eq!(bound.len(), claimed.len(), "opening width mismatch");
            for (&b, &c) in bound.iter().zip(claimed) {
                let rescaled = circuit.mul(b, scale);
                circuit.connect(rescaled, c);
            }
            per_point.push(x);
            batch += 1;
        }
        local_points.push(per_point);
    }

    // Out-of-domain claims: one sampled univariate point per answer, expanded
    // over the whole stacked space, then the answer absorbed.
    let mut ood_points: Vec<Vec<Target>> = Vec::with_capacity(initial_ood_answers.len());
    for &answer in initial_ood_answers {
        let univariate = challenger.sample_ext(circuit);
        ood_points.push(crate::pcs::whir::gadgets::expand_from_univariate(
            circuit,
            univariate,
            plan.num_variables,
        ));
        challenger.observe_ext(circuit, answer);
    }

    // Concrete claims absorb their bound values, matching `add_claim_at`.
    for batch_values in round_evals {
        challenger.observe_ext_slice(circuit, batch_values);
    }

    let alpha = challenger.sample_ext(circuit);

    // Placement order drives both the batched sum and the equality-point order.
    let zero = circuit.define_const(EF::ZERO);
    let one = circuit.define_const(EF::ONE);
    let mut ordered_values: Vec<Target> = Vec::new();
    let mut eq_points: Vec<Vec<Target>> = Vec::new();
    for placement in &plan.placements {
        let m = placement.table_idx;
        let first_batch = round_evals_offset(matrices, m);
        for (point_idx, local) in local_points[m].iter().enumerate() {
            let batch_of_matrix = first_batch + point_idx;
            for (col, selector) in placement.selectors.iter().enumerate() {
                ordered_values.push(round_evals[batch_of_matrix][col]);
                eq_points.push(selector.lift_prefix(local, zero, one));
            }
        }
    }
    for (&answer, point) in initial_ood_answers.iter().zip(ood_points) {
        ordered_values.push(answer);
        eq_points.push(point);
    }

    let claimed_eval = eval_powers_combination(circuit, &ordered_values, alpha);

    Ok(RoundClaims {
        constraint: ConstraintWeightData {
            num_variables: plan.num_variables,
            eq_points,
            sel_scalars: Vec::new(),
            gamma: alpha,
        },
        claimed_eval,
        stacked_num_variables: plan.num_variables,
    })
}

/// Index of matrix `m`'s first opening batch in `iter_openings()` order.
fn round_evals_offset(matrices: &[MatrixOpenings<'_>], m: usize) -> usize {
    matrices[..m].iter().map(|x| x.points.len()).sum()
}

/// Arity of the stacked polynomial a commitment's opening shapes would
/// produce, mirroring `build_round_claims`'s internal `StackedPlan`
/// derivation.
///
/// Needed ahead of calling [`build_round_claims`] itself: deriving this
/// commitment's `WhirVerifierParams` — and so cross-checking the proof's
/// self-reported shape against it, see [`verify_whir_uni_circuit`] — requires
/// the arity, but `build_round_claims` only returns it after it has already
/// consumed the OOD-answer slice and driven the challenger.
fn stacked_num_variables(matrices: &[MatrixOpenings<'_>], folding: usize) -> usize {
    let shapes: Vec<(PaddedArity, usize)> = matrices
        .iter()
        .map(|m| {
            let width = m.points.first().map_or(0, |(_, values)| values.len());
            (padded_arity(m.log_height, folding), width)
        })
        .collect();
    StackedPlan::new(&shapes).num_variables
}

/// Verifies every commitment's WHIR argument in-circuit.
///
/// Each commitment is handled independently against the running transcript,
/// in the order the STARK verifier supplies it. Per commitment, this
/// function first derives that commitment's own `WhirVerifierParams` (from
/// its opening shapes) and cross-checks the proof's self-reported allocation
/// sizes against it — `WhirUniProofTargets`'s own allocation trusts the
/// proof's shape, so this is where that trust gets verified — before
/// assembling claims with [`build_round_claims`] and replaying the
/// proximity argument with
/// [`verify_whir_circuit`](crate::pcs::whir::verify_whir_circuit). The
/// commitment cap is not observed here — the STARK verifier absorbs each
/// commitment before sampling its own challenges, exactly as
/// `PrescribedPointPcs::verify_at` expects.
///
/// # Errors
/// Returns [`VerificationError::InvalidProofShape`] if the proof carries a
/// different number of WHIR arguments than there are commitments, if a
/// commitment's initial OOD answer count, initial sumcheck round count, or
/// final polynomial length disagrees with what its own stacked arity
/// requires, or if a circuit operation fails.
pub fn verify_whir_uni_circuit<BF, EF, Ch, Comm>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut Ch,
    params: &WhirUniVerifierParams<BF>,
    commitments_with_opening_points: &ComsWithOpeningsTargets<Comm, TwoAdicMultiplicativeCoset<BF>>,
    rounds: &[WhirRoundTargets],
) -> Result<Vec<NonPrimitiveOpId>, VerificationError>
where
    BF: PrimeField64 + TwoAdicField,
    EF: ExtensionField<BF> + TwoAdicField,
    Ch: RecursiveChallenger<BF, EF>,
    Comm: ObservableCommitment,
{
    if rounds.len() != commitments_with_opening_points.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR proof carries {} arguments for {} commitments",
            rounds.len(),
            commitments_with_opening_points.len()
        )));
    }

    let mut op_ids = Vec::new();
    for ((commitment, matrices), round) in commitments_with_opening_points.iter().zip(rounds) {
        let openings: Vec<MatrixOpenings<'_>> = matrices
            .iter()
            .map(|(domain, points)| MatrixOpenings {
                log_height: domain.log_size(),
                points: points.as_slice(),
            })
            .collect();

        let stacked_num_variables = stacked_num_variables(&openings, params.folding);
        let vp = params.round_params::<EF, DummyChallenger<BF>>(stacked_num_variables)?;

        // The commitment fixes how many initial OOD answers exist; a wrong
        // count would desync Fiat-Shamir instead of being rejected, exactly
        // as native `verify_at` guards against (`InitialOodAnswerCountMismatch`).
        if round.whir.initial_ood_answers.len() != vp.commitment_ood_samples {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR commitment expects {} initial OOD answers, proof supplies {}",
                vp.commitment_ood_samples,
                round.whir.initial_ood_answers.len()
            )));
        }

        // The initial sumcheck folds `min(folding, stacked_num_variables)`
        // variables — the first entry `FoldingFactor::Constant`'s own
        // `compute_folding_schedule` produces for this arity — so a
        // differently-sized `round_polys` would desync Fiat-Shamir the same
        // way a wrong OOD count would.
        let expected_initial_rounds = params.folding.min(stacked_num_variables);
        if round.whir.initial_sumcheck.round_polys.len() != expected_initial_rounds {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR initial sumcheck expects {expected_initial_rounds} rounds for a \
                 {stacked_num_variables}-variable stacked polynomial, proof supplies {}",
                round.whir.initial_sumcheck.round_polys.len()
            )));
        }

        // The final polynomial's hypercube evaluation count is fixed by the
        // number of variables left after all folding.
        let expected_final_poly_len = 1usize << vp.final_poly_num_variables;
        if round.whir.final_poly.len() != expected_final_poly_len {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR final polynomial expects {expected_final_poly_len} evaluations \
                 ({} variables), proof supplies {}",
                vp.final_poly_num_variables,
                round.whir.final_poly.len()
            )));
        }

        let claims = build_round_claims::<BF, EF, Ch>(
            circuit,
            challenger,
            &openings,
            &round.evals,
            &round.whir.initial_ood_answers,
            params.folding,
        )
        .map_err(|e| VerificationError::InvalidProofShape(format!("{e:?}")))?;
        debug_assert_eq!(claims.stacked_num_variables, stacked_num_variables);

        // The MMCS gadget wants each cap entry as packed extension targets; the
        // commitment's observation targets are lifted base scalars.
        let cap: Vec<Vec<Target>> = match params.permutation_config {
            Some(perm) => {
                let lifted = commitment.to_observation_targets();
                crate::pcs::fri::commitment_cap_rows_from_lifted::<BF, EF>(circuit, perm, &lifted)
            }
            None => alloc::vec![alloc::vec![circuit.define_const(EF::ZERO)]],
        };

        let round_ops = crate::pcs::whir::verify_whir_circuit::<BF, EF, Ch>(
            circuit,
            challenger,
            &vp,
            &round.whir,
            &cap,
            claims.constraint,
            claims.claimed_eval,
        )
        .map_err(|e| VerificationError::InvalidProofShape(format!("{e:?}")))?;
        op_ids.extend(round_ops);
    }

    Ok(op_ids)
}

#[cfg(test)]
pub(crate) mod tests_support {
    use alloc::collections::VecDeque;
    use alloc::format;
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_circuit::{CircuitBuilder, CircuitBuilderError};
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;

    use super::{MatrixOpenings, build_round_claims};
    use crate::Target;
    use crate::traits::RecursiveChallenger;

    type BF = BabyBear;
    type EF = BinomialExtensionField<BF, 4>;

    /// Returns the extension challenges in a fixed order and ignores observations.
    struct StubChallenger {
        ext: VecDeque<EF>,
    }

    impl RecursiveChallenger<BF, EF> for StubChallenger {
        fn observe(&mut self, _: &mut CircuitBuilder<EF>, _: Target) {}
        fn observe_ext(&mut self, _: &mut CircuitBuilder<EF>, _: Target) {}
        fn sample(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
            circuit.define_const(EF::ZERO)
        }
        fn sample_ext(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
            let v = self.ext.pop_front().expect("stub exhausted");
            circuit.define_const(v)
        }
        fn sample_bits(
            &mut self,
            _: &mut CircuitBuilder<EF>,
            _: usize,
        ) -> Result<Vec<Target>, CircuitBuilderError> {
            Ok(Vec::new())
        }
        fn check_pow_witness(
            &mut self,
            _: &mut CircuitBuilder<EF>,
            _: usize,
            _: Target,
        ) -> Result<(), CircuitBuilderError> {
            Ok(())
        }
        fn clear(&mut self, _: &mut CircuitBuilder<EF>) {}
    }

    /// What [`claimed_eval_via_circuit`] witnesses out of the built circuit.
    pub(crate) struct CircuitClaims {
        /// The witnessed `claimed_eval`.
        pub(crate) claimed_eval: EF,
        /// The witnessed coordinates of `constraint.eq_points`, in order.
        pub(crate) eq_points: Vec<Vec<EF>>,
        /// `constraint.num_variables`.
        pub(crate) num_variables: usize,
    }

    /// Builds the claim circuit for the given shapes and returns the witnessed
    /// `claimed_eval` and `constraint.eq_points`.
    ///
    /// `ood_seeds` must be the exact univariate values the native reference's
    /// challenger sampled for its OOD claims (see the caller: it peeks them
    /// from a cloned challenger before calling `add_virtual_eval`), so that
    /// the constraint's OOD equality points are directly comparable to the
    /// native `Verifier::constraint`'s, not merely its claimed sum.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn claimed_eval_via_circuit(
        shapes: &[(usize, usize)],
        points_per_matrix: &[Vec<EF>],
        folding: usize,
        ood: &[EF],
        ood_seeds: &[EF],
        evals: &[Vec<EF>],
        alpha: EF,
        stacked_num_variables: usize,
    ) -> CircuitClaims {
        assert_eq!(ood.len(), ood_seeds.len());
        let mut ext: VecDeque<EF> = ood_seeds.iter().copied().collect();
        ext.push_back(alpha);
        let mut challenger = StubChallenger { ext };

        let mut builder = CircuitBuilder::<EF>::new();
        let mut point_targets: Vec<Vec<(Target, Vec<Target>)>> = Vec::new();
        let mut batch = 0usize;
        for (m, zetas) in points_per_matrix.iter().enumerate() {
            let mut per_point = Vec::new();
            for &zeta in zetas {
                let zeta_t = builder.define_const(zeta);
                let scale = super::super::bridge::univariate_eq_point::<EF>(
                    zeta,
                    super::super::plan::padded_arity(shapes[m].0, folding).get(),
                )
                .1;
                let claimed: Vec<Target> = evals[batch]
                    .iter()
                    .map(|&v| builder.define_const(v * scale))
                    .collect();
                per_point.push((zeta_t, claimed));
                batch += 1;
            }
            point_targets.push(per_point);
        }

        let round_evals: Vec<Vec<Target>> = evals
            .iter()
            .map(|b| b.iter().map(|&v| builder.define_const(v)).collect())
            .collect();
        let ood_targets: Vec<Target> = ood.iter().map(|&v| builder.define_const(v)).collect();

        let matrices: Vec<MatrixOpenings<'_>> = shapes
            .iter()
            .zip(&point_targets)
            .map(|(&(log_height, _), pts)| MatrixOpenings {
                log_height,
                points: pts.as_slice(),
            })
            .collect();

        let claims = build_round_claims::<BF, EF, _>(
            &mut builder,
            &mut challenger,
            &matrices,
            &round_evals,
            &ood_targets,
            folding,
        )
        .unwrap();
        assert_eq!(claims.stacked_num_variables, stacked_num_variables);
        let num_variables = claims.constraint.num_variables;
        builder.tag(claims.claimed_eval, "claimed").unwrap();
        let point_lens: Vec<usize> = claims.constraint.eq_points.iter().map(Vec::len).collect();
        for (i, point) in claims.constraint.eq_points.iter().enumerate() {
            for (j, &coord) in point.iter().enumerate() {
                builder.tag(coord, format!("eq_{i}_{j}")).unwrap();
            }
        }

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).unwrap();
        let traces = runner.run().unwrap();
        let claimed_eval = *traces.probe("claimed").unwrap();
        let eq_points: Vec<Vec<EF>> = point_lens
            .iter()
            .enumerate()
            .map(|(i, &len)| {
                (0..len)
                    .map(|j| *traces.probe(&format!("eq_{i}_{j}")).unwrap())
                    .collect()
            })
            .collect();

        CircuitClaims {
            claimed_eval,
            eq_points,
            num_variables,
        }
    }

    /// Builds a single-matrix, single-point, zero-OOD claim circuit whose
    /// opening claim is one field element off from `bound * scale` — the
    /// bridge identity [`build_round_claims`] enforces via `circuit.mul` +
    /// `circuit.connect` — and returns the built circuit's own `run()`
    /// result instead of unwrapping it, so the caller can assert on the
    /// failure.
    pub(crate) fn tampered_claim_rejected_by_circuit(
        log_height: usize,
        folding: usize,
        zeta: EF,
        bound_value: EF,
    ) -> Result<(), p3_circuit::CircuitError> {
        let scale = super::super::bridge::univariate_eq_point::<EF>(
            zeta,
            super::super::plan::padded_arity(log_height, folding).get(),
        )
        .1;

        let mut builder = CircuitBuilder::<EF>::new();
        let zeta_t = builder.define_const(zeta);
        let bound_t = builder.define_const(bound_value);
        // Deliberately wrong: the honest claim is `bound_value * scale`.
        let wrong_claimed = builder.define_const(bound_value * scale + EF::ONE);

        let points = [(zeta_t, alloc::vec![wrong_claimed])];
        let matrices = [MatrixOpenings {
            log_height,
            points: &points,
        }];
        let round_evals = alloc::vec![alloc::vec![bound_t]];

        let mut challenger = StubChallenger {
            ext: alloc::vec![EF::ZERO].into(),
        };
        build_round_claims::<BF, EF, _>(
            &mut builder,
            &mut challenger,
            &matrices,
            &round_evals,
            &[],
            folding,
        )
        .unwrap();

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).unwrap();
        runner.run().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::{DuplexChallenger, FieldChallenger};
    use p3_circuit::{CircuitBuilder, CircuitBuilderError};
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_sumcheck::constraints::Statements;
    use p3_sumcheck::layout::{Layout, PrefixProver, Verifier};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::{MatrixOpenings, build_round_claims};
    use crate::Target;
    use crate::pcs::whir::uni::pcs::round_schedule;
    use crate::traits::RecursiveChallenger;

    type BF = BabyBear;
    type EF = BinomialExtensionField<BF, 4>;

    /// The in-circuit claim assembly must reproduce the native layout
    /// verifier's batched sum bit for bit, including the alpha-power order.
    ///
    /// This is the check that catches a placement-order or column-order bug,
    /// which would otherwise surface only as an opaque final-identity failure
    /// deep inside `verify_whir_circuit`. It also compares the constraint's
    /// `eq_points` against the native `Verifier::constraint`, so an OOD
    /// eq-point construction bug (invisible to the sum alone, since
    /// `eq_points` never feeds `claimed_eval`) is caught too.
    #[test]
    fn claimed_eval_matches_the_native_layout_verifier() {
        // Two matrices, the smaller one declared first so placement order and
        // declaration order differ.
        let shapes = [(5usize, 1usize), (6usize, 2usize)];
        let folding = 4;
        let zeta = EF::from_u32(101);
        let zeta_next = EF::from_u32(103);
        let points_per_matrix = vec![vec![zeta], vec![zeta, zeta_next]];
        let schedule = round_schedule::<BF, EF>(&shapes, &points_per_matrix, folding);

        // Deterministic stand-in evaluation values and OOD answers.
        let ood: Vec<EF> = vec![EF::from_u32(7)];
        let evals: Vec<Vec<EF>> = vec![
            vec![EF::from_u32(11)],
            vec![EF::from_u32(13), EF::from_u32(17)],
            vec![EF::from_u32(19), EF::from_u32(23)],
        ];

        // Native reference.
        let mut ch = DuplexChallenger::<BF, Poseidon2BabyBear<16>, 16, 8>::new(
            Poseidon2BabyBear::<16>::new_from_rng_128(&mut SmallRng::seed_from_u64(1)),
        );
        let mut lv = Verifier::<BF, EF>::new(
            &schedule.protocol.table_shapes(),
            PrefixProver::<BF, EF>::strategy(),
        );
        // `add_virtual_eval` samples its OOD point internally from `ch`; peek
        // the exact value it will draw from a clone taken right before the
        // call, so the circuit side can be fed the same OOD seed instead of
        // an arbitrary stand-in. Sampling from the clone does not disturb
        // `ch`'s own state, so the real call below draws the identical value.
        let mut ood_seeds: Vec<EF> = Vec::with_capacity(ood.len());
        for &e in &ood {
            let seed: EF = ch.clone().sample_algebra_element();
            ood_seeds.push(seed);
            lv.add_virtual_eval(e, &mut ch);
        }
        for (((table_idx, batch), point), values) in schedule
            .protocol
            .iter_openings()
            .zip(&schedule.points)
            .zip(&evals)
        {
            let batch_evals = p3_sumcheck::OpeningBatch::new(values.clone(), Vec::new());
            lv.add_claim_at(table_idx, batch, point, &batch_evals, &mut ch)
                .unwrap();
        }
        let alpha: EF = ch.sample_algebra_element();
        let native_sum = lv.sum(alpha);
        let native_constraint = lv.constraint(alpha);

        // Flatten every Eq-group's points, in batching order (the same flat
        // order `Constraint`'s challenge powers advance over). No `Next` or
        // `Select` groups are ever emitted here (no successor claims are
        // recorded), so filtering to `Eq` drops nothing.
        let native_eq_points: Vec<Vec<EF>> = native_constraint
            .statements()
            .iter()
            .flat_map(|s| match s {
                Statements::Eq(eq) => eq.iter().map(|(p, _)| p.as_slice().to_vec()).collect(),
                _ => Vec::new(),
            })
            .collect();

        // In-circuit: drive the same values through `build_round_claims` with a
        // challenger stub returning the same OOD seeds and the same alpha.
        let got = super::tests_support::claimed_eval_via_circuit(
            &shapes,
            &points_per_matrix,
            folding,
            &ood,
            &ood_seeds,
            &evals,
            alpha,
            schedule.stacked_num_variables,
        );
        assert_eq!(got.claimed_eval, native_sum);
        assert_eq!(got.num_variables, native_constraint.num_variables());
        assert_eq!(got.eq_points, native_eq_points);
    }

    /// `build_round_claims`'s `circuit.mul` + `circuit.connect` binding
    /// `bound * scale == claimed` (the bridge tying a STARK opening value to
    /// the WHIR argument's bound multilinear value) is the only place in the
    /// entire recursive verifier that constrains this identity: under WHIR,
    /// opened values are never pre-observed into the transcript
    /// (`PRE_OBSERVES_OPENED_VALUES = false`), so without this connect the
    /// only other thing tying an opened value down is the outer AIR-level
    /// `connect(folded_mul, quotient)` in `verifier/stark.rs`, which does not
    /// see the WHIR-side `bound` value at all. Deleting this connect leaves
    /// every test in this workspace passing (confirmed by deletion during
    /// review), so this test pins the identity in isolation, with no prover
    /// run required: a `claimed` value one field element off from
    /// `bound * scale` must fail with `WitnessConflict`.
    #[test]
    fn build_round_claims_rejects_a_claim_that_does_not_match_bound_times_scale() {
        let err = super::tests_support::tampered_claim_rejected_by_circuit(
            5,
            4,
            EF::from_u32(101),
            EF::from_u32(11),
        )
        .expect_err("a claimed value off from bound * scale must be rejected");
        assert!(
            matches!(err, p3_circuit::CircuitError::WitnessConflict { .. }),
            "expected WitnessConflict, got {err:?}"
        );
    }

    /// A never-invoked challenger stub for tests that panic before any
    /// Fiat-Shamir interaction happens.
    struct NeverCalledChallenger;

    impl RecursiveChallenger<BF, EF> for NeverCalledChallenger {
        fn observe(&mut self, _: &mut CircuitBuilder<EF>, _: Target) {
            unreachable!("build_round_claims must reject the ragged shape before this call")
        }
        fn observe_ext(&mut self, _: &mut CircuitBuilder<EF>, _: Target) {
            unreachable!("build_round_claims must reject the ragged shape before this call")
        }
        fn sample(&mut self, _: &mut CircuitBuilder<EF>) -> Target {
            unreachable!("build_round_claims must reject the ragged shape before this call")
        }
        fn sample_ext(&mut self, _: &mut CircuitBuilder<EF>) -> Target {
            unreachable!("build_round_claims must reject the ragged shape before this call")
        }
        fn sample_bits(
            &mut self,
            _: &mut CircuitBuilder<EF>,
            _: usize,
        ) -> Result<Vec<Target>, CircuitBuilderError> {
            unreachable!("build_round_claims must reject the ragged shape before this call")
        }
        fn check_pow_witness(
            &mut self,
            _: &mut CircuitBuilder<EF>,
            _: usize,
            _: Target,
        ) -> Result<(), CircuitBuilderError> {
            unreachable!("build_round_claims must reject the ragged shape before this call")
        }
        fn clear(&mut self, _: &mut CircuitBuilder<EF>) {
            unreachable!("build_round_claims must reject the ragged shape before this call")
        }
    }

    /// A matrix whose first opening point claims fewer columns than a later
    /// point must be rejected loudly: `StackedPlan` sizes that matrix's
    /// selectors from the first point's width, so a later, wider point would
    /// otherwise have its extra column's claim silently excluded from the
    /// batched constraint instead of failing.
    #[test]
    #[should_panic(expected = "ragged opening width")]
    fn ragged_opening_widths_panic_instead_of_dropping_a_column() {
        let mut builder = CircuitBuilder::<EF>::new();
        let z0 = builder.define_const(EF::from_u32(11));
        let z1 = builder.define_const(EF::from_u32(13));
        let v0 = builder.define_const(EF::from_u32(1));
        let v1 = builder.define_const(EF::from_u32(2));
        let v2 = builder.define_const(EF::from_u32(3));

        // First point claims 1 column; second point claims 2.
        let points = [(z0, vec![v0]), (z1, vec![v1, v2])];
        let matrices = [MatrixOpenings {
            log_height: 3,
            points: &points,
        }];
        let round_evals = vec![vec![v0], vec![v1, v2]];

        let mut challenger = NeverCalledChallenger;
        let _ = build_round_claims::<BF, EF, _>(
            &mut builder,
            &mut challenger,
            &matrices,
            &round_evals,
            &[],
            4,
        );
    }

    /// A round's verifier params must be derived for the arity the claim
    /// assembly computed, and must carry the requested MMCS mode.
    #[test]
    fn round_params_track_the_stacked_arity_and_mmcs_mode() {
        use p3_circuit::ops::Poseidon2Config;
        use p3_sumcheck::layout::{Layout, PrefixProver};
        use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};

        use crate::pcs::whir::uni::recursive_pcs::WhirUniVerifierParams;

        let protocol_params = ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![4],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        };

        let arithmetic_only = WhirUniVerifierParams::<BF>::new(
            protocol_params.clone(),
            PrefixProver::<BF, EF>::variable_order(),
            None,
        );
        let vp = arithmetic_only
            .round_params::<EF, DuplexChallenger<BF, Poseidon2BabyBear<16>, 16, 8>>(12)
            .expect("non-saturating STIR query counts at this arity");
        assert_eq!(vp.num_variables, 12);
        assert!(vp.permutation_config.is_none());

        let with_mmcs = WhirUniVerifierParams::<BF>::new(
            protocol_params,
            PrefixProver::<BF, EF>::variable_order(),
            Some(Poseidon2Config::BABY_BEAR_D4_W16.into()),
        );
        let vp = with_mmcs
            .round_params::<EF, DuplexChallenger<BF, Poseidon2BabyBear<16>, 16, 8>>(12)
            .expect("non-saturating STIR query counts at this arity");
        assert!(vp.permutation_config.is_some());
        assert_eq!(vp.n_rounds(), 1);
    }

    /// Hand-built `commitments_with_opening_points` shape for driver tests
    /// that never reach a real prover.
    type TestCommitments = Vec<(
        Target,
        Vec<(
            p3_field::coset::TwoAdicMultiplicativeCoset<BF>,
            Vec<(Target, Vec<Target>)>,
        )>,
    )>;

    fn test_whir_uni_verifier_params() -> super::WhirUniVerifierParams<BF> {
        use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};

        let protocol_params = ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![4],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        };
        super::WhirUniVerifierParams::<BF>::new(
            protocol_params,
            PrefixProver::<BF, EF>::variable_order(),
            None,
        )
    }

    /// A WHIR argument count that disagrees with the commitment count must be
    /// rejected before either slice is otherwise touched.
    #[test]
    fn commitment_and_round_count_mismatch_is_rejected() {
        use p3_field::coset::TwoAdicMultiplicativeCoset;

        use crate::traits::ComsWithOpeningsTargets;
        use crate::verifier::VerificationError;

        let params = test_whir_uni_verifier_params();
        let mut builder = CircuitBuilder::<EF>::new();
        let commitment = builder.define_const(EF::ZERO);
        let commitments_with_opening_points: TestCommitments = vec![(commitment, Vec::new())];
        let coms: &ComsWithOpeningsTargets<Target, TwoAdicMultiplicativeCoset<BF>> =
            &commitments_with_opening_points;

        let result = super::verify_whir_uni_circuit::<BF, EF, _, Target>(
            &mut builder,
            &mut NeverCalledChallenger,
            &params,
            coms,
            // Zero WHIR arguments for one commitment: a length mismatch.
            &[],
        );

        assert!(matches!(
            result,
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    /// A commitment whose proof declares a different number of initial OOD
    /// answers than its own stacked arity requires must be rejected — a wrong
    /// count would otherwise silently desync every later Fiat-Shamir sample
    /// instead of failing.
    #[test]
    fn initial_ood_answer_count_mismatch_is_rejected() {
        use p3_field::coset::TwoAdicMultiplicativeCoset;

        use crate::pcs::whir::targets::{SumcheckDataTargets, WhirProofTargets};
        use crate::pcs::whir::uni::targets::WhirRoundTargets;
        use crate::traits::ComsWithOpeningsTargets;
        use crate::verifier::VerificationError;

        let params = test_whir_uni_verifier_params();

        // One matrix, single column: stacked_num_variables == LOG_HEIGHT (already
        // above the folding factor, so no further padding), matching the arity
        // `round_params_track_the_stacked_arity_and_mmcs_mode` already exercises
        // against this same `protocol_params`.
        const LOG_HEIGHT: usize = 12;
        let expected_ood = params
            .round_params::<EF, DuplexChallenger<BF, Poseidon2BabyBear<16>, 16, 8>>(LOG_HEIGHT)
            .expect("non-saturating STIR query counts at this arity")
            .commitment_ood_samples;

        let mut builder = CircuitBuilder::<EF>::new();
        let commitment = builder.define_const(EF::ZERO);
        let zeta = builder.define_const(EF::ZERO);
        let value = builder.define_const(EF::ZERO);
        let domain = TwoAdicMultiplicativeCoset::new(BF::ONE, LOG_HEIGHT).unwrap();
        let commitments_with_opening_points: TestCommitments =
            vec![(commitment, vec![(domain, vec![(zeta, vec![value])])])];
        let coms: &ComsWithOpeningsTargets<Target, TwoAdicMultiplicativeCoset<BF>> =
            &commitments_with_opening_points;

        // Deliberately wrong by construction, regardless of `expected_ood`'s value.
        let wrong_ood_answers = (0..=expected_ood)
            .map(|_| builder.define_const(EF::ZERO))
            .collect::<Vec<_>>();
        let round = WhirRoundTargets {
            evals: alloc::vec![alloc::vec![value]],
            whir: WhirProofTargets {
                initial_ood_answers: wrong_ood_answers,
                initial_sumcheck: SumcheckDataTargets {
                    round_polys: Vec::new(),
                    pow_witnesses: Vec::new(),
                },
                rounds: Vec::new(),
                final_poly: Vec::new(),
                final_pow_witness: builder.define_const(EF::ZERO),
                final_queries: Vec::new(),
                final_sumcheck: None,
            },
        };

        let result = super::verify_whir_uni_circuit::<BF, EF, _, Target>(
            &mut builder,
            &mut NeverCalledChallenger,
            &params,
            coms,
            core::slice::from_ref(&round),
        );

        assert!(matches!(
            result,
            Err(VerificationError::InvalidProofShape(_))
        ));
    }
}
