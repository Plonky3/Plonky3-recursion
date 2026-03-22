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

/// Global extra preprocessed columns for double-step HornerAcc (after all lanes).
#[repr(C)]
pub(crate) struct AluExtraPrepCols<T> {
    pub sel_double: T,
    pub a1_idx: T,
    pub c1_idx: T,
    pub a1_reader: T,
    pub c1_reader: T,
}

/// Main trace columns for one ALU lane: `a`, `b`, `c`, `out` (each `D` base coefficients).
#[repr(C)]
pub(crate) struct AluMainLaneCols<T, const D: usize> {
    pub a: [T; D],
    pub b: [T; D],
    pub c: [T; D],
    pub out: [T; D],
}

/// Trailing main-trace columns for double-step HornerAcc on lane 0: `int`, `a1`, `c1`.
#[repr(C)]
pub(crate) struct AluMainHornerExtraCols<T, const D: usize> {
    pub int: [T; D],
    pub a1: [T; D],
    pub c1: [T; D],
}

pub(crate) const PREP_LANE_WIDTH: usize = size_of::<AluPrepLaneCols<u8>>();
pub(crate) const EXTRA_PREP_WIDTH: usize = size_of::<AluExtraPrepCols<u8>>();

pub(crate) const fn alu_main_lane_width<const D: usize>() -> usize {
    size_of::<AluMainLaneCols<u8, D>>()
}

pub(crate) const fn alu_main_horner_extra_width<const D: usize>() -> usize {
    size_of::<AluMainHornerExtraCols<u8, D>>()
}

const _ALU_PREP_LANE_COL_MAP: AluPrepLaneCols<usize> = {
    let indices = column_indices::<PREP_LANE_WIDTH>();
    unsafe { transmute::<[usize; PREP_LANE_WIDTH], AluPrepLaneCols<usize>>(indices) }
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

impl<T> Borrow<AluExtraPrepCols<T>> for [T] {
    fn borrow(&self) -> &AluExtraPrepCols<T> {
        assert_eq!(self.len(), EXTRA_PREP_WIDTH);
        let (prefix, cols, suffix) = unsafe { self.align_to::<AluExtraPrepCols<T>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(cols.len(), 1);
        &cols[0]
    }
}

impl<T> BorrowMut<AluExtraPrepCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut AluExtraPrepCols<T> {
        assert_eq!(self.len(), EXTRA_PREP_WIDTH);
        let (prefix, cols, suffix) = unsafe { self.align_to_mut::<AluExtraPrepCols<T>>() };
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

impl<T, const D: usize> Borrow<AluMainHornerExtraCols<T, D>> for [T] {
    fn borrow(&self) -> &AluMainHornerExtraCols<T, D> {
        assert_eq!(self.len(), alu_main_horner_extra_width::<D>());
        let (prefix, cols, suffix) = unsafe { self.align_to::<AluMainHornerExtraCols<T, D>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(cols.len(), 1);
        &cols[0]
    }
}

impl<T, const D: usize> BorrowMut<AluMainHornerExtraCols<T, D>> for [T] {
    fn borrow_mut(&mut self) -> &mut AluMainHornerExtraCols<T, D> {
        assert_eq!(self.len(), alu_main_horner_extra_width::<D>());
        let (prefix, cols, suffix) = unsafe { self.align_to_mut::<AluMainHornerExtraCols<T, D>>() };
        debug_assert!(prefix.is_empty(), "alignment should match");
        debug_assert!(suffix.is_empty(), "alignment should match");
        debug_assert_eq!(cols.len(), 1);
        &mut cols[0]
    }
}

const _: () = assert!(size_of::<AluPrepLaneCols<usize>>() == PREP_LANE_WIDTH * size_of::<usize>());
const _: () =
    assert!(size_of::<AluExtraPrepCols<usize>>() == EXTRA_PREP_WIDTH * size_of::<usize>());
const _: () = assert!(_ALU_PREP_LANE_COL_MAP.b_idx == _ALU_PREP_LANE_COL_MAP.a_idx + 1);
const _: () = assert!(_ALU_PREP_LANE_COL_MAP.c_idx == _ALU_PREP_LANE_COL_MAP.b_idx + 1);
const _: () = assert!(_ALU_PREP_LANE_COL_MAP.out_idx == _ALU_PREP_LANE_COL_MAP.c_idx + 1);
const _: () = assert!(size_of::<AluMainLaneCols<u8, 1>>() == 4);
const _: () = assert!(size_of::<AluMainHornerExtraCols<u8, 1>>() == 3);
