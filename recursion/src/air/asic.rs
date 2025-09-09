use p3_field::Field;

use crate::gates::event::Table;

pub struct Asic<F, const D: usize> {
    pub asic: Vec<Box<dyn Table<F, D>>>,
}

impl<F: Field, const D: usize> Asic<F, D> {
    pub fn generate_trace(
        &self,
        all_events: &crate::gates::event::AllEvents<F, D>,
    ) -> Vec<p3_matrix::dense::RowMajorMatrix<F>> {
        self.asic
            .iter()
            .map(|table| table.generate_trace(all_events))
            .collect()
    }
}
