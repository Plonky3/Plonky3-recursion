//! Circuit compilation and lowering subsystem.

mod expression_lowerer;
mod non_primitive_lowerer;
mod optimizer;

pub use expression_lowerer::{ExpressionLowerer, HintsWithFiller};
use hashbrown::HashMap;
pub use non_primitive_lowerer::NonPrimitiveLowerer;
pub use optimizer::Optimizer;

use crate::{CircuitBuilderError, ExprId, WitnessId};

// Utility functions

/// Helper function to get WitnessId with descriptive error messages
fn get_witness_id(
    expr_to_widx: &HashMap<ExprId, WitnessId>,
    expr_id: ExprId,
    context: &str,
) -> Result<WitnessId, CircuitBuilderError> {
    expr_to_widx
        .get(&expr_id)
        .copied()
        .ok_or_else(|| CircuitBuilderError::MissingExprMapping {
            expr_id,
            context: context.into(),
        })
}
