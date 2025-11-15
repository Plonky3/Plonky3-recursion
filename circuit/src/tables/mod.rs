//! Execution trace tables for zkVM circuit operations.

mod add;
mod constant;
mod mmcs;
mod mul;
mod public;
mod runner;
mod witness;

pub use add::AddTrace;
pub use constant::ConstTrace;
pub use mmcs::{MmcsPathTrace, MmcsPrivateData, MmcsTrace};
pub use mul::MulTrace;
pub use public::PublicTrace;
pub use runner::CircuitRunner;
pub use witness::WitnessTrace;

/// Execution traces for all tables.
///
/// This structure holds the complete execution trace of a circuit,
/// containing all the data needed to generate proofs.
#[derive(Debug, Clone)]
pub struct Traces<F> {
    /// Central witness table (bus) storing all intermediate values.
    pub witness_trace: WitnessTrace<F>,
    /// Constant table for compile-time known values.
    pub const_trace: ConstTrace<F>,
    /// Public input table for externally provided values.
    pub public_trace: PublicTrace<F>,
    /// Addition operation table.
    pub add_trace: AddTrace<F>,
    /// Multiplication operation table.
    pub mul_trace: MulTrace<F>,
    /// MMCS (Merkle tree) verification table.
    pub mmcs_trace: MmcsTrace<F>,
}

#[cfg(debug_assertions)]
impl<F: alloc::fmt::Debug> Traces<F> {
    pub fn dump_traces_log(&self) {
        tracing::debug!("\n=== WITNESS TRACE ===");
        for (i, (idx, val)) in self
            .witness_trace
            .index
            .iter()
            .zip(self.witness_trace.values.iter())
            .enumerate()
        {
            tracing::debug!("Row {i}: WitnessId({idx}) = {val:?}");
        }

        tracing::debug!("\n=== CONST TRACE ===");
        for (i, (idx, val)) in self
            .const_trace
            .index
            .iter()
            .zip(self.const_trace.values.iter())
            .enumerate()
        {
            tracing::debug!("Row {i}: WitnessId({idx}) = {val:?}");
        }

        tracing::debug!("\n=== PUBLIC TRACE ===");
        for (i, (idx, val)) in self
            .public_trace
            .index
            .iter()
            .zip(self.public_trace.values.iter())
            .enumerate()
        {
            tracing::debug!("Row {i}: WitnessId({idx}) = {val:?}");
        }

        tracing::debug!("\n=== MUL TRACE ===");
        for i in 0..self.mul_trace.lhs_values.len() {
            tracing::debug!(
                "Row {}: WitnessId({}) * WitnessId({}) -> WitnessId({}) | {:?} * {:?} -> {:?}",
                i,
                self.mul_trace.lhs_index[i],
                self.mul_trace.rhs_index[i],
                self.mul_trace.result_index[i],
                self.mul_trace.lhs_values[i],
                self.mul_trace.rhs_values[i],
                self.mul_trace.result_values[i]
            );
        }

        tracing::debug!("\n=== ADD TRACE ===");
        for i in 0..self.add_trace.lhs_values.len() {
            tracing::debug!(
                "Row {}: WitnessId({}) + WitnessId({}) -> WitnessId({}) | {:?} + {:?} -> {:?}",
                i,
                self.add_trace.lhs_index[i],
                self.add_trace.rhs_index[i],
                self.add_trace.result_index[i],
                self.add_trace.lhs_values[i],
                self.add_trace.rhs_values[i],
                self.add_trace.result_values[i]
            );
        }
    }
}
