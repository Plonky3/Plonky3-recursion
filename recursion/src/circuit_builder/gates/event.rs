use p3_field::Field;

use crate::air::alu::cols::RomEvent;
use crate::air::{AddEvent, MulEvent, SubEvent};

#[derive(Default)]
pub struct AllEvents<F: Field> {
    // TODO: Maybe leave event as iterators?
    pub add_events: Vec<AddEvent<F>>,
    pub sub_events: Vec<SubEvent<F>>,
    pub mul_events: Vec<MulEvent<F>>,
    pub witness_events: Vec<RomEvent<F>>,
}
