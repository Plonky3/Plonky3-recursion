use p3_air::{Air, AirBuilder};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(debug_assertions)]
use p3_uni_stark::{DebugConstraintBuilder, PcsError, Proof, VerificationError};
use p3_uni_stark::{ProverConstraintFolder, StarkGenericConfig, SymbolicAirBuilder, Val};

use crate::circuit_builder::gates::event::AllEvents;

#[cfg(not(debug_assertions))]
pub trait AirWithTraceGenerationFromEvents<SC: StarkGenericConfig, AB: AirBuilder, F: Field>:
    Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<ProverConstraintFolder<'a, SC>>
{
    fn generate_trace(&self, all_events: &AllEvents<F>) -> RowMajorMatrix<F>;
}
#[cfg(debug_assertions)]
pub trait AirWithTraceGenerationFromEvents<SC: StarkGenericConfig, AB: AirBuilder>:
    Air<SymbolicAirBuilder<Val<SC>>>
    + for<'a> Air<ProverConstraintFolder<'a, SC>>
    + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>>>
{
    fn generate_trace(&self, all_events: &AllEvents<Val<SC>>) -> RowMajorMatrix<Val<SC>>;
    fn prove_chip(&self, config: &SC, trace: RowMajorMatrix<Val<SC>>) -> Proof<SC>;
    fn verify_chip(
        &self,
        config: &SC,
        proof: &Proof<SC>,
    ) -> Result<(), VerificationError<PcsError<SC>>>;
}

#[macro_export]
macro_rules! impl_air_with_trace_from_events {
    // Arm 1: plain `.iter()` (no projection)
    ($Air:ty, $events_field:ident) => {
        impl<SC, AB> $crate::prover::tables::AirWithTraceGenerationFromEvents<SC, AB> for $Air
        where
            SC: p3_uni_stark::StarkGenericConfig,
            AB: p3_air::AirBuilder,
        {
            fn generate_trace(
                &self,
                all_events: &AllEvents<p3_uni_stark::Val<SC>>,
            ) -> p3_matrix::dense::RowMajorMatrix<p3_uni_stark::Val<SC>> {
                Self::build_trace(
                    all_events.$events_field.iter(),
                    all_events.$events_field.len(),
                )
            }
            fn prove_chip(
                &self,
                config: &SC,
                trace: p3_matrix::dense::RowMajorMatrix<p3_uni_stark::Val<SC>>,
            ) -> p3_uni_stark::Proof<SC> {
                p3_uni_stark::prove(config, self, trace, &vec![])
            }

            fn verify_chip(
                &self,
                config: &SC,
                proof: &p3_uni_stark::Proof<SC>,
            ) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<SC>>> {
                p3_uni_stark::verify(config, self, proof, &vec![])
            }
        }
    };
}
