use core::mem::{size_of, transmute};

use super::column_layout::column_indices;
pub const BLAKE3_CV_LEN: usize = 16;
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blake3Columns<T> {
    pub is_use_job_key: T,
    pub is_use_commitment_hash: T,
    pub is_hash_output: T,
    pub is_cv_in: T,
    pub is_new_blake: T,
    pub is_last_round: T,
    pub is_msg_mat: T,
    pub is_msg_jackpot: T,
    pub is_msg_aux_data: T,
    pub is_msg_cv: T,

    pub uint8_data: [T; 8],

    pub blake3_msg_buffer: [T; 32],

    pub cv_or_tweak_prep: T,
    pub cv_in: [T; 16],
    pub blake3_msg: [T; 32],
    pub blake3_round: [Blake3State<T>; 4],

    pub cv_out: [T; 16],
    pub cv_out_freq: T,

    pub stark_row_idx: T,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blake3State<T> {
    pub row1: [T; 8],
    pub row2: [[T; 32]; 4],
    pub row3: [T; 8],
    pub row4: [[T; 32]; 4],
}

pub const NUM_COLUMNS: usize = size_of::<Blake3Columns<u8>>();

const fn blake3_col_map() -> Blake3Columns<usize> {
    let indices = column_indices::<NUM_COLUMNS>();
    unsafe { transmute::<[usize; NUM_COLUMNS], Blake3Columns<usize>>(indices) }
}

pub const BLAKE3_COL_MAP: Blake3Columns<usize> = blake3_col_map();

const _: () = assert!(size_of::<Blake3Columns<usize>>() == NUM_COLUMNS * size_of::<usize>());

/// Preprocessed columns for Blake3Air: 16 output witness indices + 16 multiplicities.
///
/// Each cv_out limb gets its own `(out_idx, out_mult)` pair, giving 16 receive
/// lookups per row on the WitnessChecks bus. On non-output rows all values are zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake3PrepCols<T: Copy> {
    pub out_idx: [T; BLAKE3_CV_LEN],
    pub out_mult: [T; BLAKE3_CV_LEN],
}

pub const BLAKE3_PREP_WIDTH: usize = size_of::<Blake3PrepCols<u8>>();

const fn blake3_prep_col_map() -> Blake3PrepCols<usize> {
    let indices = column_indices::<BLAKE3_PREP_WIDTH>();
    unsafe { transmute::<[usize; BLAKE3_PREP_WIDTH], Blake3PrepCols<usize>>(indices) }
}

pub const BLAKE3_PREP_COL_MAP: Blake3PrepCols<usize> = blake3_prep_col_map();

const _: () = assert!(size_of::<Blake3PrepCols<usize>>() == BLAKE3_PREP_WIDTH * size_of::<usize>());
