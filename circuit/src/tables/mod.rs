//! Execution trace tables for zkVM circuit operations.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;

use hashbrown::HashMap;

use crate::CircuitError;
use crate::op::{NonPrimitiveOpType, OpStateMap};
use crate::types::WitnessId;

mod add;
mod constant;
mod mul;
mod public;
mod runner;
mod witness;

pub use add::{AddTrace, AddTraceBuilder};
pub use constant::{ConstTrace, ConstTraceBuilder};
pub use mul::{MulTrace, MulTraceBuilder};
pub use public::{PublicTrace, PublicTraceBuilder};
pub use runner::CircuitRunner;
pub use witness::{WitnessTrace, WitnessTraceBuilder};

/// Trait implemented by all non-primitive operation traces.
pub trait NonPrimitiveTrace<F>: Send + Sync {
    /// Operation type for this non-primitive trace.
    fn op_type(&self) -> NonPrimitiveOpType;
    /// Number of rows produced by this trace.
    fn rows(&self) -> usize;
    /// Type-erased access for downcasting.
    fn as_any(&self) -> &dyn Any;
    /// Clone the trace into a boxed trait object.
    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<F>>;
}

/// Function pointer for constructing a non-primitive trace from runner state.
///
/// The trace generator receives operation execution state (recorded row data, chaining state, etc.).
pub type TraceGeneratorFn<F> =
    fn(op_states: &OpStateMap) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError>;

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
    /// Dynamically registered non-primitive traces indexed by operation type.
    pub non_primitive_traces: HashMap<NonPrimitiveOpType, Box<dyn NonPrimitiveTrace<F>>>,
    /// Tag to witness index mapping for probing values by name.
    pub tag_to_witness: HashMap<String, WitnessId>,
}

impl<F> Traces<F> {
    /// Fetch a non-primitive trace by identifier and downcast to a concrete type.
    pub fn non_primitive_trace<T>(&self, op_type: NonPrimitiveOpType) -> Option<&T>
    where
        T: NonPrimitiveTrace<F> + 'static,
    {
        self.non_primitive_traces
            .get(&op_type)
            .and_then(|trace| trace.as_any().downcast_ref::<T>())
    }

    /// Probes the value of a tagged wire.
    ///
    /// Returns `None` if the tag was not registered during circuit construction.
    ///
    /// # Example
    /// ```ignore
    /// let value = traces.probe("my-tag").expect("tag should exist");
    /// ```
    pub fn probe(&self, tag: &str) -> Option<&F> {
        let witness_id = self.tag_to_witness.get(tag)?;
        self.witness_trace.get_value(*witness_id)
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
                .map(|(&op_type, trace)| (op_type, trace.boxed_clone()))
                .collect(),
            tag_to_witness: self.tag_to_witness.clone(),
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
            .map(|(&op_type, trace)| (op_type, trace.rows()))
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
                .zip(self.witness_trace.values().iter())
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
