use p3_air::AirBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{PcsError, StarkGenericConfig, Val, VerificationError};

use crate::prover::RecursiveProof;
use crate::prover::tables::AirWithTraceGenerationFromEvents;

pub struct Asic<SC: StarkGenericConfig, AB: AirBuilder> {
    pub chips: Vec<Box<dyn AirWithTraceGenerationFromEvents<SC, AB>>>,
}

impl<SC: StarkGenericConfig, AB: AirBuilder> Asic<SC, AB> {
    pub fn generate_trace(
        &self,
        all_events: &crate::circuit_builder::gates::event::AllEvents<Val<SC>>,
    ) -> Vec<RowMajorMatrix<Val<SC>>> {
        self.chips
            .iter()
            .map(|chip| chip.generate_trace(all_events))
            .collect()
    }
    pub fn prove_chips(
        &self,
        config: &SC,
        traces: Vec<RowMajorMatrix<Val<SC>>>,
    ) -> RecursiveProof<SC> {
        RecursiveProof {
            proofs: self
                .chips
                .iter()
                .zip(traces.into_iter())
                .map(|(chip, trace)| chip.prove_chip(config, trace))
                .collect(),
        }
    }

    pub fn verify_chips(
        &self,
        config: &SC,
        proof: RecursiveProof<SC>,
    ) -> Result<(), VerificationError<PcsError<SC>>> {
        self.chips
            .iter()
            .zip(proof.proofs.iter())
            .map(|(chip, proof)| chip.verify_chip(config, proof))
            .collect()
    }
}
