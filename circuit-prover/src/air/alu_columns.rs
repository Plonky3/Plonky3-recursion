//! Column layout for [`super::alu_air::AluAir`] main and preprocessed traces.

use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};

use super::column_layout::column_indices;

/// Preprocessed columns for one ALU lane (13 base-field columns).
#[repr(C)]
pub(crate) struct AluPrepLaneCols<T> {
    pub mult_a: T,
    pub sel_add: T,
    pub sel_bool: T,
    pub sel_muladd: T,
    pub sel_horner: T,
    pub a_idx: T,
    pub b_idx: T,
    pub c_idx: T,
    pub out_idx: T,
    pub mult_b: T,
    pub mult_out: T,
    pub a_is_reader: T,
    pub c_is_reader: T,
}

/// Extra preprocessed columns for one packed-Horner step `t` in `1..K-1`.
#[repr(C)]
pub(crate) struct AluPackedHornerStepPrepCols<T> {
    pub a_idx: T,
    pub c_idx: T,
    pub a_reader: T,
    pub c_reader: T,
}

/// Main trace columns for one ALU lane: `a`, `b`, `c`, `out` (each `D` base coefficients).
#[repr(C)]
pub(crate) struct AluMainLaneCols<T, const D: usize> {
    pub a: [T; D],
    pub b: [T; D],
    pub c: [T; D],
    pub out: [T; D],
}

/// Column 0 of the global extra preprocessed region (packed Horner selector).
pub(crate) const EXTRA_PREP_SEL_PACKED: usize = 0;

pub(crate) const PREP_LANE_WIDTH: usize = size_of::<AluPrepLaneCols<u8>>();

pub(crate) const PACKED_HORNER_STEP_PREP_WIDTH: usize =
    size_of::<AluPackedHornerStepPrepCols<u8>>();

#[inline]
pub(crate) const fn extra_prep_a_idx_for_step(t: usize) -> usize {
    1 + PACKED_HORNER_STEP_PREP_WIDTH * (t - 1)
}

/// Width of global extra preprocessed columns for K-step packed Horner (`K >= 2`).
#[inline]
pub(crate) const fn horner_extra_prep_width(k: usize) -> usize {
    1 + PACKED_HORNER_STEP_PREP_WIDTH * (k - 1)
}

pub(crate) const fn alu_main_lane_width<const D: usize>() -> usize {
    size_of::<AluMainLaneCols<u8, D>>()
}

const _ALU_PREP_LANE_COL_MAP: AluPrepLaneCols<usize> = {
    let indices = column_indices::<PREP_LANE_WIDTH>();
    unsafe { transmute::<[usize; PREP_LANE_WIDTH], AluPrepLaneCols<usize>>(indices) }
};

const _PACKED_STEP_COL_MAP: AluPackedHornerStepPrepCols<usize> = {
    let indices = column_indices::<PACKED_HORNER_STEP_PREP_WIDTH>();
    unsafe {
        transmute::<[usize; PACKED_HORNER_STEP_PREP_WIDTH], AluPackedHornerStepPrepCols<usize>>(
            indices,
        )
    }
};

impl<T> Borrow<AluPrepLaneCols<T>> for [T] {
    fn borrow(&self) -> &AluPrepLaneCols<T> {
        assert_eq!(self.len(), PREP_LANE_WIDTH);
        let (prefix, cols, suffix) = unsafe { self.align_to::<AluPrepLaneCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(cols.len(), 1);
        &cols[0]
    }
}

impl<T> BorrowMut<AluPrepLaneCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut AluPrepLaneCols<T> {
        assert_eq!(self.len(), PREP_LANE_WIDTH);
        let (prefix, cols, suffix) = unsafe { self.align_to_mut::<AluPrepLaneCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(cols.len(), 1);
        &mut cols[0]
    }
}

impl<T> Borrow<AluPackedHornerStepPrepCols<T>> for [T] {
    fn borrow(&self) -> &AluPackedHornerStepPrepCols<T> {
        assert_eq!(self.len(), PACKED_HORNER_STEP_PREP_WIDTH);
        let (prefix, cols, suffix) = unsafe { self.align_to::<AluPackedHornerStepPrepCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(cols.len(), 1);
        &cols[0]
    }
}

impl<T> BorrowMut<AluPackedHornerStepPrepCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut AluPackedHornerStepPrepCols<T> {
        assert_eq!(self.len(), PACKED_HORNER_STEP_PREP_WIDTH);
        let (prefix, cols, suffix) =
            unsafe { self.align_to_mut::<AluPackedHornerStepPrepCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(cols.len(), 1);
        &mut cols[0]
    }
}

impl<T, const D: usize> Borrow<AluMainLaneCols<T, D>> for [T] {
    fn borrow(&self) -> &AluMainLaneCols<T, D> {
        assert_eq!(self.len(), alu_main_lane_width::<D>());
        let (prefix, cols, suffix) = unsafe { self.align_to::<AluMainLaneCols<T, D>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(cols.len(), 1);
        &cols[0]
    }
}

impl<T, const D: usize> BorrowMut<AluMainLaneCols<T, D>> for [T] {
    fn borrow_mut(&mut self) -> &mut AluMainLaneCols<T, D> {
        assert_eq!(self.len(), alu_main_lane_width::<D>());
        let (prefix, cols, suffix) = unsafe { self.align_to_mut::<AluMainLaneCols<T, D>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(cols.len(), 1);
        &mut cols[0]
    }
}

const _: () = assert!(size_of::<AluPrepLaneCols<usize>>() == PREP_LANE_WIDTH * size_of::<usize>());
const _: () = assert!(
    size_of::<AluPackedHornerStepPrepCols<usize>>()
        == PACKED_HORNER_STEP_PREP_WIDTH * size_of::<usize>()
);
const _: () = assert!(_ALU_PREP_LANE_COL_MAP.b_idx == _ALU_PREP_LANE_COL_MAP.a_idx + 1);
const _: () = assert!(_ALU_PREP_LANE_COL_MAP.c_idx == _ALU_PREP_LANE_COL_MAP.b_idx + 1);
const _: () = assert!(_ALU_PREP_LANE_COL_MAP.out_idx == _ALU_PREP_LANE_COL_MAP.c_idx + 1);
const _: () = assert!(_PACKED_STEP_COL_MAP.c_idx == _PACKED_STEP_COL_MAP.a_idx + 1);
const _: () = assert!(_PACKED_STEP_COL_MAP.a_reader == _PACKED_STEP_COL_MAP.c_idx + 1);
const _: () = assert!(_PACKED_STEP_COL_MAP.c_reader == _PACKED_STEP_COL_MAP.a_reader + 1);
const _: () = assert!(size_of::<AluMainLaneCols<u8, 1>>() == 4);
const _: () = assert!(PACKED_HORNER_STEP_PREP_WIDTH == 4);
