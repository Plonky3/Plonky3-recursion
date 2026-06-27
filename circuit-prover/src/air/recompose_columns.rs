//! Column layout for [`super::recompose_air::RecomposeAir`] preprocessed traces.

use core::mem::{size_of, transmute};

use super::column_layout::column_indices;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecomposePrepLaneCols<T: Copy> {
    pub output_idx: T,
    pub out_mult: T,
}

pub(crate) const RECOMPOSE_PREP_LANE_WIDTH: usize = size_of::<RecomposePrepLaneCols<u8>>();

const fn recompose_prep_lane_col_map() -> RecomposePrepLaneCols<usize> {
    let indices = column_indices::<RECOMPOSE_PREP_LANE_WIDTH>();
    unsafe {
        transmute::<[usize; RECOMPOSE_PREP_LANE_WIDTH], RecomposePrepLaneCols<usize>>(indices)
    }
}

pub(crate) const RECOMPOSE_PREP_LANE_COL_MAP: RecomposePrepLaneCols<usize> =
    recompose_prep_lane_col_map();

const _: () = assert!(
    size_of::<RecomposePrepLaneCols<usize>>() == RECOMPOSE_PREP_LANE_WIDTH * size_of::<usize>()
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recompose_prep_lane_width() {
        assert_eq!(RECOMPOSE_PREP_LANE_WIDTH, 2);
    }

    #[test]
    fn test_recompose_prep_lane_col_map_output_idx() {
        assert_eq!(RECOMPOSE_PREP_LANE_COL_MAP.output_idx, 0);
    }

    #[test]
    fn test_recompose_prep_lane_col_map_out_mult() {
        assert_eq!(RECOMPOSE_PREP_LANE_COL_MAP.out_mult, 1);
    }

    #[test]
    fn test_recompose_prep_lane_cols_eq() {
        let a = RecomposePrepLaneCols {
            output_idx: 5u8,
            out_mult: 9u8,
        };
        let b = RecomposePrepLaneCols {
            output_idx: 5u8,
            out_mult: 9u8,
        };
        assert_eq!(a, b);
    }
}
