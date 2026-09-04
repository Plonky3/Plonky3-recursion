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
/// # Errors
/// Returns an error if the challenger fails to produce a challenge.
///
/// # Panics
/// Panics if `round_evals`'s shape disagrees with `matrices`.
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
    for m in matrices {
        let arity = padded_arity(m.log_height, folding).get();
        let mut per_point = Vec::with_capacity(m.points.len());
        for (zeta, claimed) in m.points {
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

    /// Builds the claim circuit for the given shapes and returns the witnessed
    /// `claimed_eval`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn claimed_eval_via_circuit(
        shapes: &[(usize, usize)],
        points_per_matrix: &[Vec<EF>],
        folding: usize,
        ood: &[EF],
        evals: &[Vec<EF>],
        alpha: EF,
        stacked_num_variables: usize,
    ) -> EF {
        // The native reference samples its OOD points from the transcript; feed
        // the circuit the same ones by reproducing them here from `alpha`'s
        // stub sequence: OOD univariate points first, then alpha.
        let mut ext: VecDeque<EF> = VecDeque::new();
        for i in 0..ood.len() {
            ext.push_back(EF::from_u32(1_000 + i as u32));
        }
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
        builder.tag(claims.claimed_eval, "claimed").unwrap();

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[]).unwrap();
        let traces = runner.run().unwrap();
        *traces.probe("claimed").unwrap()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::{DuplexChallenger, FieldChallenger};
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_sumcheck::layout::{Layout, PrefixProver, Verifier};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use crate::pcs::whir::uni::pcs::round_schedule;

    type BF = BabyBear;
    type EF = BinomialExtensionField<BF, 4>;

    /// The in-circuit claim assembly must reproduce the native layout
    /// verifier's batched sum bit for bit, including the alpha-power order.
    ///
    /// This is the check that catches a placement-order or column-order bug,
    /// which would otherwise surface only as an opaque final-identity failure
    /// deep inside `verify_whir_circuit`.
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
        for &e in &ood {
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

        // In-circuit: drive the same values through `build_round_claims` with a
        // challenger stub returning the same alpha and the same OOD points.
        let got = super::tests_support::claimed_eval_via_circuit(
            &shapes,
            &points_per_matrix,
            folding,
            &ood,
            &evals,
            alpha,
            schedule.stacked_num_variables,
        );
        assert_eq!(got, native_sum);
    }
}
