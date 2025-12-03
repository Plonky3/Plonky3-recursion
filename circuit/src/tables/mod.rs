//! Execution trace tables for zkVM circuit operations.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;

use hashbrown::HashMap;

use crate::CircuitError;
use crate::circuit::Circuit;
use crate::op::NonPrimitiveOpPrivateData;

mod add;
mod constant;
mod mmcs;
mod mul;
mod poseidon2;
mod public;
mod runner;
mod witness;

pub use add::AddTrace;
pub use constant::ConstTrace;
pub use mmcs::{MmcsPathTrace, MmcsPrivateData, MmcsTrace, generate_mmcs_trace};
pub use mul::MulTrace;
pub use poseidon2::{
    Poseidon2CircuitRow, Poseidon2CircuitTrace, Poseidon2Params, Poseidon2Trace,
    PoseidonPermPrivateData, generate_poseidon2_trace,
};
pub use public::PublicTrace;
pub use runner::CircuitRunner;
pub use witness::WitnessTrace;

/// Trait implemented by all non-primitive operation traces.
pub trait NonPrimitiveTrace<F>: Send + Sync {
    /// Identifier of the non-primitive table.
    fn id(&self) -> &'static str;
    /// Number of rows produced by this trace.
    fn rows(&self) -> usize;
    /// Type-erased access for downcasting.
    fn as_any(&self) -> &dyn Any;
    /// Clone the trace into a boxed trait object.
    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<F>>;
}

/// Function pointer for constructing a non-primitive trace from runner state.
pub type TraceGeneratorFn<F> = fn(
    circuit: &Circuit<F>,
    witness: &[Option<F>],
    non_primitive_data: &[Option<NonPrimitiveOpPrivateData<F>>],
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError>;

/// Execution traces for all tables.
///
/// This structure holds the complete execution trace of a circuit,
/// containing all the data needed to generate proofs.
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
    /// Dynamically registered non-primitive traces indexed by their table identifier.
    pub non_primitive_traces: HashMap<&'static str, Box<dyn NonPrimitiveTrace<F>>>,
}

impl<F> Traces<F> {
    /// Fetch a non-primitive trace by identifier and downcast to a concrete type.
    pub fn non_primitive_trace<T>(&self, id: &'static str) -> Option<&T>
    where
        T: NonPrimitiveTrace<F> + 'static,
    {
        self.non_primitive_traces
            .get(id)
            .and_then(|trace| trace.as_any().downcast_ref::<T>())
    }
}

impl<F: Clone> Clone for Traces<F> {
    fn clone(&self) -> Self {
        Self {
            witness_trace: self.witness_trace.clone(),
            const_trace: self.const_trace.clone(),
            public_trace: self.public_trace.clone(),
            add_trace: self.add_trace.clone(),
            mul_trace: self.mul_trace.clone(),
            non_primitive_traces: self
                .non_primitive_traces
                .iter()
                .map(|(&id, trace)| (id, trace.boxed_clone()))
                .collect(),
        }
    }
}

impl<F> fmt::Debug for Traces<F>
where
    WitnessTrace<F>: fmt::Debug,
    ConstTrace<F>: fmt::Debug,
    PublicTrace<F>: fmt::Debug,
    AddTrace<F>: fmt::Debug,
    MulTrace<F>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let extra_summary: Vec<_> = self
            .non_primitive_traces
            .iter()
            .map(|(&id, trace)| (id, trace.rows()))
            .collect();
        f.debug_struct("Traces")
            .field("witness_trace", &self.witness_trace)
            .field("const_trace", &self.const_trace)
            .field("public_trace", &self.public_trace)
            .field("add_trace", &self.add_trace)
            .field("mul_trace", &self.mul_trace)
            .field("non_primitive_traces", &extra_summary)
            .finish()
    }
}

impl<F: alloc::fmt::Debug> Traces<F> {
    #[allow(clippy::missing_const_for_fn)]
    pub fn dump_primitive_traces_log(&self) {
        #[cfg(debug_assertions)]
        {
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
}
