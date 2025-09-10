pub mod tables;

use p3_air::AirBuilder;
use p3_uni_stark::{Proof, StarkGenericConfig, Val};

use crate::air::asic::Asic;
use crate::circuit_builder::gates::event::AllEvents;
pub struct RecursiveProof<SC: StarkGenericConfig> {
    pub proofs: Vec<Proof<SC>>,
}

pub fn prove<SC, AB>(
    config: &SC,
    asic: &Asic<SC, AB>,
    all_events: AllEvents<Val<SC>>,
) -> RecursiveProof<SC>
where
    AB: AirBuilder,
    SC: StarkGenericConfig,
{
    let traces = asic.generate_trace(&all_events);

    asic.prove_chips(config, traces)
}
