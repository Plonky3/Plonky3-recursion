//! Column layout for [`super::expose_claim_air::ExposeClaimAir`] preprocessed traces.
//!
//! One lane per exposed claim value. Each lane carries the witness index whose
//! value is read off the `WitnessChecks` bus (reader multiplicity `-1`) and
//! surfaced as a table public value.

use core::mem::{size_of, transmute};

use super::column_layout::column_indices;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExposeClaimPrepLaneCols<T: Copy> {
    /// D-scaled base-field index of the witness whose value this lane reads.
    pub witness_idx: T,
    /// Reader multiplicity for the `WitnessChecks` receive (always `-1` for an
    /// active lane, `0` for padding).
    pub read_mult: T,
}

pub(crate) const EXPOSE_CLAIM_PREP_LANE_WIDTH: usize =
    size_of::<ExposeClaimPrepLaneCols<u8>>();

const fn expose_claim_prep_lane_col_map() -> ExposeClaimPrepLaneCols<usize> {
    let indices = column_indices::<EXPOSE_CLAIM_PREP_LANE_WIDTH>();
    unsafe {
        transmute::<[usize; EXPOSE_CLAIM_PREP_LANE_WIDTH], ExposeClaimPrepLaneCols<usize>>(indices)
    }
}

pub(crate) const EXPOSE_CLAIM_PREP_LANE_COL_MAP: ExposeClaimPrepLaneCols<usize> =
    expose_claim_prep_lane_col_map();

const _: () = assert!(
    size_of::<ExposeClaimPrepLaneCols<usize>>()
        == EXPOSE_CLAIM_PREP_LANE_WIDTH * size_of::<usize>()
);
