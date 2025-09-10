use std::borrow::{Borrow, BorrowMut};
use std::marker::PhantomData;

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

pub struct AddEvent<F, const R: usize = 1>(pub FieldOpEvent<F, R>);
pub struct SubEvent<F, const R: usize = 1>(pub FieldOpEvent<F, R>);
pub struct MulEvent<F, const R: usize = 1>(pub FieldOpEvent<F>);
pub struct RomEvent<F>(pub usize, pub F);

impl<F: Field> RomEvent<F> {
    pub fn generate_trace<'a, I: Iterator<Item = &'a RomEvent<F>>>(
        events: I,
        events_len: usize,
    ) -> RowMajorMatrix<F> {
        let n_padded = events_len.next_power_of_two();
        let mut trace = RowMajorMatrix::new(
            F::zero_vec(n_padded * 1), // 1 column for witness values
            1,
        );

        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<[F; 1]>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), events_len);

        for (i, &RomEvent(col, val)) in events.enumerate() {
            rows[i][0] = F::from_usize(col);
            rows[i][0] = val; // Only one column
        }
        trace
    }
}

#[derive(Debug)]
/// Represents an event in the field operation trace.
pub struct FieldOpEvent<T, const R: usize = 1> {
    pub left_addr: [usize; R],
    pub left_val: [T; R],
    pub right_addr: [usize; R],
    pub right_val: [T; R],
    pub res_addr: [usize; R],
    pub res_val: [T; R],
}

#[repr(C)]
/// Represents the columns in the ALU trace.
/// R counts how many `a * b = c` operations to do per row in the AIR
pub struct AluCols<F, const R: usize = 1> {
    pub left_addr: [F; R],
    pub left_val: [F; R],
    pub right_addr: [F; R],
    pub right_val: [F; R],
    pub res_addr: [F; R],
    pub res_val: [F; R],
    _phantom_data: PhantomData<F>,
}

impl<F, const R: usize> AluCols<F, R> {
    pub const TRACE_WIDTH: usize = 6 * R;
}

impl<F, const R: usize> Borrow<AluCols<F, R>> for [F] {
    fn borrow(&self) -> &AluCols<F, R> {
        debug_assert_eq!(self.len(), AluCols::<F, R>::TRACE_WIDTH);
        let (prefix, shorts, _suffix) = unsafe { self.align_to::<AluCols<F, R>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<F: Field, const R: usize> BorrowMut<AluCols<F, R>> for [F] {
    fn borrow_mut(&mut self) -> &mut AluCols<F, R> {
        debug_assert_eq!(self.len(), AluCols::<F, R>::TRACE_WIDTH);
        let (prefix, shorts, _suffix) = unsafe { self.align_to_mut::<AluCols<F, R>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
