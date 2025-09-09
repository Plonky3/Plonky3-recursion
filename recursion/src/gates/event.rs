use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::air::{
    AddEvent, MulEvent, SubEvent,
    alu::cols::{ExtAddEvent, ExtMulEvent, ExtSubEvent},
};

#[derive(Default)]
pub struct AllEvents<F: Field, const D: usize> {
    pub add_events: Vec<AddEvent<F>>,
    pub sub_events: Vec<SubEvent<F>>,
    pub mul_events: Vec<MulEvent<F>>,

    pub ext_add_events: Vec<ExtAddEvent<F, D>>,
    pub ext_sub_events: Vec<ExtSubEvent<F, D>>,
    pub ext_mul_events: Vec<ExtMulEvent<F, D>>,
}

pub trait Table<F: Field, const D: usize> {
    fn generate_trace(&self, all_events: &AllEvents<F, D>) -> RowMajorMatrix<F>;
}
