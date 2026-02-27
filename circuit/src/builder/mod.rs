//! Circuit builder module with specialized sub-components.

mod circuit_builder;
pub mod compiler;
mod config;
mod errors;
mod expression_builder;
mod public_input_tracker;

pub use circuit_builder::{
    CircuitBuilder, NonPrimitiveOpParams, NonPrimitiveOperationData, NpoCircuitPlugin,
    NpoLoweringContext,
};
pub use config::BuilderConfig;
pub use errors::CircuitBuilderError;
pub use expression_builder::ExpressionBuilder;
#[cfg(feature = "profiling")]
pub use expression_builder::OpCounts;
pub use public_input_tracker::PublicInputTracker;
