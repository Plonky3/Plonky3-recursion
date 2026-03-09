//! [`RecomposeAir`] defines the AIR for the recompose NPO table.
//!
//! Each row packs D base-field witnesses into one extension-field witness.
//! Multiple operations can be packed side-by-side as independent lanes.
//! There are zero local constraints — correctness is enforced entirely
//! by the output cross-table lookup on the WitnessChecks bus.
//!
//! # Column layout (per lane)
//!
//! **Main columns** (D per lane): `v_0, v_1, ..., v_{D-1}` — the base-field coefficient values.
//!
//! **Preprocessed columns** (2 per lane):
//! - `output_idx`: D-scaled witness ID for the output EF witness
//! - `out_mult`: ext_reads\[wid\] for real rows, 0 for padding
//!
//! # CTL lookups (1 per lane per row)
//!
//! **Receive** `[output_idx, v_0, ..., v_{D-1}]` with multiplicity `out_mult`
//!
//! No input lookups are needed: the output lookup alone constrains the main trace
//! values because the output witness is aliased (via `connect`) to the original
//! extension-field element, so consumers verify the correct tuple.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, SymbolicExpression};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::{LookupAir, LookupInput};
use p3_matrix::dense::RowMajorMatrix;

use super::utils::{create_direct_preprocessed_trace, create_symbolic_variables};

/// AIR for the recompose (BF→EF packing) table.
///
/// Zero local constraints — all correctness is via CTL bus.
#[derive(Debug, Clone)]
pub struct RecomposeAir<F, const D: usize> {
    pub(crate) lanes: usize,
    pub(crate) preprocessed: Vec<F>,
    pub(crate) num_lookup_columns: usize,
    pub(crate) min_height: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> RecomposeAir<F, D> {
    /// Main trace width per lane: D columns (one per BF coefficient).
    pub const fn lane_width() -> usize {
        D
    }

    /// Preprocessed width per lane: 1 output index + 1 out_mult.
    pub const fn preprocessed_lane_width() -> usize {
        2
    }

    /// Create a new `RecomposeAir` with the given preprocessed data and lane count.
    pub fn new_with_preprocessed(lanes: usize, preprocessed: Vec<F>, min_height: usize) -> Self {
        Self {
            lanes: lanes.max(1),
            preprocessed,
            num_lookup_columns: 0,
            min_height,
            _phantom: PhantomData,
        }
    }

    /// Build the main trace matrix from recompose circuit rows with lane packing.
    pub fn trace_to_matrix(
        rows: &[p3_circuit::ops::recompose::RecomposeCircuitRow<F>],
        lanes: usize,
    ) -> RowMajorMatrix<F> {
        let lane_w = Self::lane_width();
        let row_width = lanes * lane_w;
        let num_ops = rows.len();
        let num_rows = num_ops.div_ceil(lanes).max(1);

        let mut values = F::zero_vec(num_rows * row_width);

        for (op_idx, row) in rows.iter().enumerate() {
            let r = op_idx / lanes;
            let l = op_idx % lanes;
            let base = r * row_width + l * lane_w;
            for (j, &val) in row.values.iter().enumerate() {
                values[base + j] = val;
            }
        }

        let mut mat = RowMajorMatrix::new(values, row_width);
        mat.pad_to_power_of_two_height(F::ZERO);
        mat
    }
}

impl<F: Field, const D: usize> BaseAir<F> for RecomposeAir<F, D> {
    fn width(&self) -> usize {
        self.lanes * Self::lane_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(create_direct_preprocessed_trace(
            &self.preprocessed,
            Self::preprocessed_lane_width(),
            self.lanes,
            self.min_height,
        ))
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for RecomposeAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, _builder: &mut AB) {}
}

impl<F: Field, const D: usize> LookupAir<F> for RecomposeAir<F, D> {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_idx = self.num_lookup_columns;
        self.num_lookup_columns += 1;
        vec![new_idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let mut lookups = Vec::new();
        self.num_lookup_columns = 0;

        let total_main_width = self.lanes * Self::lane_width();
        let total_prep_width = self.lanes * Self::preprocessed_lane_width();

        let (symbolic_main, symbolic_preprocessed) =
            create_symbolic_variables::<F>(total_prep_width, total_main_width, self.lanes, 0);

        for lane in 0..self.lanes {
            let main_off = lane * Self::lane_width();
            let prep_off = lane * Self::preprocessed_lane_width();

            let output_idx = SymbolicExpression::from(symbolic_preprocessed[prep_off]);
            let out_mult = SymbolicExpression::from(symbolic_preprocessed[prep_off + 1]);

            let mut values = vec![output_idx];
            for j in 0..D {
                values.push(SymbolicExpression::from(symbolic_main[main_off + j]));
            }

            let inp: LookupInput<F> = (values, out_mult, Direction::Receive);
            lookups.push(LookupAir::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &[inp],
            ));
        }

        lookups
    }
}
