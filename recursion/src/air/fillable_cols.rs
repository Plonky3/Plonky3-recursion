use p3_field::Field;

use crate::gates::event::AllEvents;

pub trait FillableCollumns {
    type Event;
    /// Fills the columns with the provided events.
    fn fill<F: Field, const D: usize>(&mut self, events: AllEvents<F, D>);

    /// Returns the number of columns that this trait can fill.
    fn num_columns(&self) -> usize;
}
