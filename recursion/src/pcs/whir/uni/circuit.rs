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

use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_field::{ExtensionField, PrimeField64};

use crate::Target;
use crate::pcs::whir::gadgets::{ConstraintWeightData, eval_powers_combination};
use crate::pcs::whir::uni::bridge::univariate_eq_point_circuit;
use crate::pcs::whir::uni::plan::{PaddedArity, StackedPlan, padded_arity};
use crate::traits::RecursiveChallenger;

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
}
