//! Selection of ALU table packing (lane count and packed-Horner arity `K`).
//!
//! The recursive verifier's ALU is dominated by the FRI batched reduced opening, whose row
//! count and per-row width both depend on the lane count and packed-Horner arity. The best
//! choice is extension- and proof-size dependent, and in a recursion chain it couples to the
//! next layer: a wider ALU at layer `N` commits more columns, and the layer `N+1` verifier
//! reduce-opens one Horner op per opened column per query, which inflates *its* ALU. The
//! objective here charges both this layer's own padded trace area and that next-layer feedback,
//! so it does not over-buy width the way a purely local area objective would.

use alloc::vec::Vec;

use p3_circuit::ops::PrimitiveOpType;
use p3_circuit::{Circuit, CircuitError};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

use crate::air::{AluAir, AluExtMulKind};

/// Default `(lanes, K)` grid for ALU packing search: lane counts 2..=4 crossed with
/// packed-Horner arities 4, 8, 12. The default `(3, 4)` (tuned for the binomial degree-4
/// KoalaBear baseline) is included so a re-tune never regresses below it.
pub const DEFAULT_ALU_TUNE_CANDIDATES: &[(usize, usize)] = &[
    (2, 4),
    (3, 4),
    (4, 4),
    (2, 8),
    (3, 8),
    (4, 8),
    (3, 12),
    (4, 12),
];

/// A selected ALU table packing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AluPacking {
    /// Number of independent ALU ops packed per trace row.
    pub lanes: usize,
    /// Number of consecutive HornerAcc steps packed per row on lane 0 (`>= 2`).
    pub horner_packed_steps: usize,
}

/// Scored evaluation of one `(lanes, K)` candidate for the ALU table.
#[derive(Clone, Copy, Debug)]
pub struct AluPackingScore {
    /// Number of independent ALU ops packed per trace row.
    pub lanes: usize,
    /// Number of consecutive HornerAcc steps packed per row on lane 0.
    pub horner_packed_steps: usize,
    /// Logical (unpadded) ALU row count for this packing.
    pub rows: usize,
    /// Row count after padding to a power of two and the FRI minimum height.
    pub padded_rows: usize,
    /// Total committed columns per row (main + preprocessed).
    pub width: usize,
    /// Padded trace area of this layer's ALU table, in cells.
    pub own_area: u64,
    /// Estimated extra reduced-opening area this ALU induces at the next recursion layer.
    pub feedback: u64,
    /// Combined objective (`own_area + feedback`); lower is better.
    pub objective: u64,
}

/// Score one ALU packing candidate against the feedback-aware objective.
///
/// `alu_preprocessed` is the per-op preprocessed selector data (one
/// [`AluAir::preprocessed_lane_width`] stride per logical op), exactly as handed to
/// [`AluAir::from_reduction_with_preprocessed`]. `num_queries` is the FRI query count, which
/// sets the weight of the next-layer feedback term; `min_height` is the FRI minimum trace
/// height. The row count is exact (it runs the real ALU schedule); the width is the AIR's
/// real `total_width + preprocessed_width`.
pub fn score_alu_packing<F: Field + PrimeCharacteristicRing + Copy, const D: usize>(
    alu_preprocessed: &[F],
    ext_mul_kind: AluExtMulKind<F>,
    min_height: usize,
    num_queries: usize,
    lanes: usize,
    horner_packed_steps: usize,
) -> AluPackingScore {
    assert!(lanes >= 1, "lane count must be non-zero");
    assert!(
        horner_packed_steps >= 2,
        "horner_packed_steps must be at least 2"
    );

    let num_ops = alu_preprocessed.len() / AluAir::<F, D>::preprocessed_lane_width();
    let air = AluAir::<F, D>::from_reduction_with_preprocessed(
        num_ops,
        lanes,
        ext_mul_kind,
        alu_preprocessed.to_vec(),
        horner_packed_steps,
    );

    let rows = air.scheduled_entry_count().div_ceil(lanes).max(1);
    let padded_rows = rows.next_power_of_two().max(min_height).max(1);
    let width = air.total_width() + air.preprocessed_width();

    let own_area = padded_rows as u64 * width as u64;
    // The ALU is opened at zeta and zeta_next, so it contributes `2 * width` columns to the
    // next layer's reduced opening: `num_queries` Horner ops per opened column, packed
    // `horner_packed_steps` per row, each row `width` cells wide (the next layer's ALU has the
    // same width at the recursion fixed point).
    let opened_cols = 2 * width as u64;
    let feedback = num_queries as u64 * opened_cols * width as u64 / horner_packed_steps as u64;
    let objective = own_area + feedback;

    AluPackingScore {
        lanes,
        horner_packed_steps,
        rows,
        padded_rows,
        width,
        own_area,
        feedback,
        objective,
    }
}

/// Score every `(lanes, K)` candidate, sorted by ascending objective (best first).
pub fn score_alu_packings<F: Field + PrimeCharacteristicRing + Copy, const D: usize>(
    alu_preprocessed: &[F],
    ext_mul_kind: AluExtMulKind<F>,
    min_height: usize,
    num_queries: usize,
    candidates: &[(usize, usize)],
) -> Vec<AluPackingScore> {
    let mut scores: Vec<AluPackingScore> = candidates
        .iter()
        .map(|&(lanes, k)| {
            score_alu_packing::<F, D>(
                alu_preprocessed,
                ext_mul_kind,
                min_height,
                num_queries,
                lanes,
                k,
            )
        })
        .collect();
    scores.sort_by_key(|s| s.objective);
    scores
}

/// Recommend the `(lanes, K)` minimizing the feedback-aware objective over `candidates`.
pub fn recommend_alu_packing<F: Field + PrimeCharacteristicRing + Copy, const D: usize>(
    alu_preprocessed: &[F],
    ext_mul_kind: AluExtMulKind<F>,
    min_height: usize,
    num_queries: usize,
    candidates: &[(usize, usize)],
) -> AluPacking {
    let best = candidates
        .iter()
        .map(|&(lanes, k)| {
            score_alu_packing::<F, D>(
                alu_preprocessed,
                ext_mul_kind,
                min_height,
                num_queries,
                lanes,
                k,
            )
        })
        .min_by_key(|s| s.objective)
        .expect("candidate list must be non-empty");
    AluPacking {
        lanes: best.lanes,
        horner_packed_steps: best.horner_packed_steps,
    }
}

/// Build the per-op ALU preprocessed buffer the scheduler needs from a built `circuit`.
///
/// The schedule and row count depend on each op's HornerAcc selector and its witness indices
/// (`compute_schedule` packs consecutive Horner ops that share a `b` index with contiguous
/// indices). Multiplicity columns do not affect scheduling and are left zero, which lets this skip
/// the full multiplicity preprocessing.
///
/// Raw ALU preprocessed (per op, see `Circuit::generate_preprocessed_columns`):
/// `[sel_add, sel_bool, sel_muladd, sel_horner, a_idx, b_idx, c_idx, out_idx, ...]` (12 columns).
/// The 13-column `AluPrepLaneCols` the scheduler reads is
/// `[mult_a, sel_add, sel_bool, sel_muladd, sel_horner, a_idx, b_idx, c_idx, out_idx, ...]`, so the
/// first 8 raw columns map to scheduler columns `1..9`.
fn alu_schedule_prep<F, EF, const D: usize>(circuit: &Circuit<EF>) -> Result<Vec<F>, CircuitError>
where
    F: Field + PrimeCharacteristicRing + Copy,
    EF: ExtensionField<F>,
{
    const RAW_LANE: usize = 12;
    const RAW_SCHEDULE_COLS: usize = 8;

    let preprocessed = circuit.generate_preprocessed_columns::<D>()?;
    let alu_raw = &preprocessed.primitive[PrimitiveOpType::Alu as usize];
    let lane_13 = AluAir::<F, D>::preprocessed_lane_width();
    let num_ops = alu_raw.len() / RAW_LANE;
    let mut prep = alloc::vec![F::ZERO; num_ops * lane_13];
    for op in 0..num_ops {
        let (r, w) = (op * RAW_LANE, op * lane_13);
        for j in 0..RAW_SCHEDULE_COLS {
            if let Some(v) = alu_raw[r + j].as_base() {
                prep[w + 1 + j] = v;
            }
        }
    }
    Ok(prep)
}

/// Recommend ALU packing for a recursive verification `circuit`, deriving the ALU schedule from
/// the circuit's preprocessed columns.
///
/// `ext_mul_kind` selects the extension reduction (it affects only the AIR width, not scheduling),
/// `min_height` is the FRI minimum trace height, and `num_queries` weights the next-layer feedback
/// term.
///
/// # Errors
/// Returns an error if preprocessed column generation fails for `circuit`.
pub fn recommend_alu_packing_for_circuit<F, EF, const D: usize>(
    circuit: &Circuit<EF>,
    ext_mul_kind: AluExtMulKind<F>,
    min_height: usize,
    num_queries: usize,
    candidates: &[(usize, usize)],
) -> Result<AluPacking, CircuitError>
where
    F: Field + PrimeCharacteristicRing + Copy,
    EF: ExtensionField<F>,
{
    let prep = alu_schedule_prep::<F, EF, D>(circuit)?;
    Ok(recommend_alu_packing::<F, D>(
        &prep,
        ext_mul_kind,
        min_height,
        num_queries,
        candidates,
    ))
}

/// Score all candidates for a circuit (sorted best-first); diagnostic counterpart of
/// [`recommend_alu_packing_for_circuit`].
///
/// # Errors
/// Returns an error if preprocessed column generation fails for `circuit`.
pub fn score_alu_packings_for_circuit<F, EF, const D: usize>(
    circuit: &Circuit<EF>,
    ext_mul_kind: AluExtMulKind<F>,
    min_height: usize,
    num_queries: usize,
    candidates: &[(usize, usize)],
) -> Result<Vec<AluPackingScore>, CircuitError>
where
    F: Field + PrimeCharacteristicRing + Copy,
    EF: ExtensionField<F>,
{
    let prep = alu_schedule_prep::<F, EF, D>(circuit)?;
    Ok(score_alu_packings::<F, D>(
        &prep,
        ext_mul_kind,
        min_height,
        num_queries,
        candidates,
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::air::AluAir;

    /// Build a per-op ALU preprocessed buffer with `num` HornerAcc ops (one long chain).
    ///
    /// `sel_horner` is column index 4 within each [`AluAir::preprocessed_lane_width`] stride
    /// (see `AluPrepLaneCols`); setting it marks the op as a HornerAcc step.
    fn horner_preprocessed(num: usize) -> Vec<BabyBear> {
        let lane = AluAir::<BabyBear, 4>::preprocessed_lane_width();
        let mut prep = vec![BabyBear::ZERO; num * lane];
        for i in 0..num {
            prep[i * lane + 4] = BabyBear::ONE;
        }
        prep
    }

    #[test]
    fn rows_are_non_increasing_in_k() {
        let prep = horner_preprocessed(4000);
        let kind = AluExtMulKind::<BabyBear>::Binomial { w: BabyBear::ONE };
        let score = |k| score_alu_packing::<BabyBear, 4>(&prep, kind, 1, 54, 3, k);
        // Packing more Horner steps per row never increases the row count.
        assert!(score(8).rows <= score(4).rows);
        assert!(score(16).rows <= score(8).rows);
    }

    #[test]
    fn width_grows_with_k_and_lanes() {
        let prep = horner_preprocessed(1000);
        let kind = AluExtMulKind::<BabyBear>::Binomial { w: BabyBear::ONE };
        let s = |l, k| score_alu_packing::<BabyBear, 4>(&prep, kind, 1, 54, l, k);
        assert!(s(3, 8).width > s(3, 4).width);
        assert!(s(4, 4).width > s(3, 4).width);
    }

    #[test]
    fn feedback_scales_with_queries_and_vanishes_at_zero() {
        let prep = horner_preprocessed(2000);
        let kind = AluExtMulKind::<BabyBear>::Binomial { w: BabyBear::ONE };
        let many = score_alu_packing::<BabyBear, 4>(&prep, kind, 1, 100, 3, 4);
        let few = score_alu_packing::<BabyBear, 4>(&prep, kind, 1, 10, 3, 4);
        assert!(many.feedback > few.feedback);
        let none = score_alu_packing::<BabyBear, 4>(&prep, kind, 1, 0, 3, 4);
        assert_eq!(none.feedback, 0);
        assert_eq!(none.objective, none.own_area);
    }

    #[test]
    fn recommend_returns_objective_argmin() {
        let prep = horner_preprocessed(5000);
        let kind = AluExtMulKind::<BabyBear>::Binomial { w: BabyBear::ONE };
        let candidates = [(3, 2), (3, 4), (3, 8), (4, 4), (4, 8)];
        let scored = score_alu_packings::<BabyBear, 4>(&prep, kind, 64, 54, &candidates);
        let pick = recommend_alu_packing::<BabyBear, 4>(&prep, kind, 64, 54, &candidates);
        let best = scored.first().unwrap();
        assert_eq!(pick.lanes, best.lanes);
        assert_eq!(pick.horner_packed_steps, best.horner_packed_steps);
    }

    #[test]
    fn feedback_penalty_can_outrank_minimal_own_area() {
        // Two candidates with comparable own area but different widths: the wider one should be
        // penalized once the next-layer feedback term is included.
        let prep = horner_preprocessed(8000);
        let kind = AluExtMulKind::<BabyBear>::Binomial { w: BabyBear::ONE };
        let narrow = score_alu_packing::<BabyBear, 4>(&prep, kind, 64, 54, 3, 8);
        let wide = score_alu_packing::<BabyBear, 4>(&prep, kind, 64, 54, 3, 16);
        // If the wide candidate has >= own area, it must also lose on the full objective.
        if wide.own_area >= narrow.own_area {
            assert!(wide.objective > narrow.objective);
        }
    }
}
