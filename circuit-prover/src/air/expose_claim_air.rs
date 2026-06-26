//! [`ExposeClaimAir`] surfaces N chosen witness values as table public values,
//! BOUND to the genuine witnesses via the `WitnessChecks` bus.
//!
//! This is a verified public-output channel for a recursive circuit: given any
//! set of in-circuit witnesses (each one SENT on the `WitnessChecks` bus by the
//! table that created it — a primitive `PublicAir`, an ALU output, a Poseidon2
//! limb, etc.), this table READS each of them back (reader multiplicity `-1`)
//! into a main column and constrains the table's public value for that lane to
//! equal the value it read. Because the read is bus-bound to the genuine witness,
//! and the public value is locally constrained to the read, the host-readable
//! `non_primitives[].public_values` are provably the genuine in-circuit values —
//! not free prover-chosen scalars.
//!
//! A common use is to surface an aggregate's running state (a chain head, a
//! Merkle root, a step counter, a running hash) out of a fold so a light client
//! can read it; but the channel is generic over which witnesses are exposed.
//!
//! # Column layout (per lane = per exposed value)
//!
//! **Main columns** (D per lane): `v_0, ..., v_{D-1}` — the value read off the bus.
//!
//! **Preprocessed columns** per lane: `witness_idx`, `read_mult` (2 columns).
//!
//! **Public values**: one base-field public value per lane, in lane order.
//!
//! # Constraints (per lane)
//!
//! - Receive the FULL `[witness_idx, v_0, ..., v_{D-1}]` ext tuple on `WitnessChecks`
//!   with multiplicity `read_mult` — bus-bound to the genuine witness the creating
//!   table sent, so `v_1..v_{D-1}` cannot be freely chosen by the prover.
//! - `public_value[lane] == v_0` (coeff-0 of the read cell is the host-readable claim),
//!   gated by the active-lane selector so padding rows do not force it to zero.
//! - The higher coeffs `v_1..v_{D-1}` are NOT constrained to zero: a witness may pack
//!   genuinely-nonzero base lanes into one ext element (e.g. a Poseidon2 output limb),
//!   so forcing them to zero would receive a different tuple than was sent and unbalance
//!   the global bus. Their soundness comes from the bus binding, not a local zero check.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;

use super::expose_claim_columns::{EXPOSE_CLAIM_PREP_LANE_COL_MAP, EXPOSE_CLAIM_PREP_LANE_WIDTH};

/// AIR for the exposed-claim table.
///
/// All lanes pack into a single row (the table has exactly `num_claims` lanes
/// and one logical row), so the public values line up with the lanes directly.
#[derive(Debug, Clone)]
pub struct ExposeClaimAir<F, const D: usize> {
    /// Number of claim values (= lanes = number of public values).
    pub(crate) num_claims: usize,
    pub(crate) preprocessed: Vec<F>,
    pub(crate) min_height: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> ExposeClaimAir<F, D> {
    /// Main trace width per lane: D columns (the read value).
    pub const fn lane_width() -> usize {
        D
    }

    /// Preprocessed width per lane: `[witness_idx, read_mult]`.
    pub const fn preprocessed_lane_width() -> usize {
        EXPOSE_CLAIM_PREP_LANE_WIDTH
    }

    /// Create a new `ExposeClaimAir` with the given preprocessed data.
    pub fn new_with_preprocessed(
        num_claims: usize,
        preprocessed: Vec<F>,
        min_height: usize,
    ) -> Self {
        Self {
            num_claims: num_claims.max(1),
            preprocessed,
            min_height,
            _phantom: PhantomData,
        }
    }

    /// Build the single-row main trace matrix from the exposed-claim rows, padded to the SAME
    /// `min_height` the preprocessed trace ([`Self::preprocessed_trace`]) and the reported table
    /// degree use — matching the convention of the sibling single-row tables (`ConstAir`,
    /// `PublicAir`, `RecomposeAir`), which all take a `min_height` and pad to it. (The batch prover
    /// re-pads non-primitive traces to `min_height` downstream regardless, so this is a defensive
    /// consistency fix at the source rather than a behavioural change to the committed proof.)
    #[instrument(skip_all, name = "ExposeClaimAir::build_trace")]
    pub fn trace_to_matrix(
        rows: &[p3_circuit::ops::expose_claim::ExposeClaimCircuitRow<F>],
        min_height: usize,
    ) -> RowMajorMatrix<F> {
        let lane_w = Self::lane_width();
        let num_claims = rows.len().max(1);
        let row_width = num_claims * lane_w;

        let mut values = F::zero_vec(row_width);
        for (lane, row) in rows.iter().enumerate() {
            // Reproduce the FULL witness value (all `D` coefficients), so the
            // `WitnessChecks` receive tuple matches the tuple the creator sent. A
            // base-field witness contributes `(value, 0, ..., 0)`; a Poseidon2 output
            // limb contributes its 4 genuinely-nonzero base lanes. (`read_coeffs` is
            // populated by the trace generator; empty only on degenerate rows, where
            // we fall back to the coeff-0 embedding.)
            if row.read_coeffs.is_empty() {
                values[lane * lane_w] = row.value;
            } else {
                for (j, &c) in row.read_coeffs.iter().take(lane_w).enumerate() {
                    values[lane * lane_w + j] = c;
                }
            }
        }

        let mut mat = RowMajorMatrix::new(values, row_width);
        // Pad to `min_height` (power-of-two), matching `preprocessed_trace` + the reported degree.
        mat.pad_to_min_power_of_two_height(min_height, F::ZERO);
        mat
    }
}

impl<F: Field, const D: usize> BaseAir<F> for ExposeClaimAir<F, D> {
    fn width(&self) -> usize {
        self.num_claims * D
    }

    fn num_public_values(&self) -> usize {
        self.num_claims
    }

    fn preprocessed_width(&self) -> usize {
        self.num_claims * Self::preprocessed_lane_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = self.num_claims * Self::preprocessed_lane_width();
        let mut mat = RowMajorMatrix::from_flat_padded(self.preprocessed.to_vec(), width, F::ZERO);
        mat.pad_to_min_power_of_two_height(self.min_height, F::ZERO);
        Some(mat)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: AirBuilder + InteractionBuilder, const D: usize> Air<AB> for ExposeClaimAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let pis = builder.public_values().to_vec();

        let lane_w = Self::lane_width();
        let prep_lane_w = Self::preprocessed_lane_width();

        for lane in 0..self.num_claims {
            let main_off = lane * lane_w;
            let prep_off = lane * prep_lane_w;

            let witness_idx: AB::Expr =
                prep_local[prep_off + EXPOSE_CLAIM_PREP_LANE_COL_MAP.witness_idx].into();
            let read_mult: AB::Expr =
                prep_local[prep_off + EXPOSE_CLAIM_PREP_LANE_COL_MAP.read_mult].into();

            // Receive the witness cell off the WitnessChecks bus. The reader
            // multiplicity (`-1` per active lane) is matched by the writer
            // `PublicAir` send, keeping the bus balanced.
            let mut values: Vec<AB::Expr> = Vec::with_capacity(1 + D);
            values.push(witness_idx);
            for j in 0..D {
                values.push(main_local[main_off + j].into());
            }
            builder.push_interaction("WitnessChecks", values, Count::bounded(read_mult.clone(), 1));

            // Active-lane selector: `-read_mult` is `1` on a real lane (read_mult
            // == -1) and `0` on a padding row (read_mult == 0). All local
            // constraints below are GATED by it so padding rows (which carry zero
            // main columns) do not force the nonzero public value to zero.
            let active: AB::Expr = AB::Expr::ZERO - read_mult;

            // Bind the table's host-exposed public value to coeff-0 of the value
            // read off the bus: `active * (public_value[lane] - v_0) == 0`.
            //
            // The higher coefficients `v_1..v_{D-1}` are NOT constrained to zero: the
            // read cell carries the FULL witness value so its `WitnessChecks` receive
            // tuple matches the tuple the creating table sent (a Poseidon2 output limb
            // packs 4 genuinely-nonzero base lanes into one ext element; forcing them
            // to zero here would receive a different tuple than was sent, unbalancing
            // the global bus). Only coeff-0 is exposed as the host-readable claim, and
            // it is bus-bound to the genuine witness — which is the soundness property.
            let pv: AB::Expr = pis[lane].into();
            let v0: AB::Expr = main_local[main_off].into();
            builder.assert_zero(active.clone() * (pv - v0));
        }
    }
}
