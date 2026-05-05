//! Inherent `CircuitBuilder` methods for adding Blake3 round operations.

use alloc::vec::Vec;
use alloc::vec;

use p3_field::Field;

use crate::CircuitBuilderError;
use crate::builder::{CircuitBuilder, NonPrimitiveOpParams};
use crate::ops::NpoTypeId;
use crate::ops::blake3::call::Blake3Call;
use crate::types::{ExprId, NonPrimitiveOpId};

/// Number of output limbs for a Blake3 hash (8 u32 words x 2 16-bit limbs).
const CV_LIMBS: usize = 16;

impl<F: Field> CircuitBuilder<F> {
    /// Add a single Blake3 round operation to the circuit.
    ///
    /// Returns `(op_id, outputs)` where outputs has length `CV_LIMBS` (16):
    /// each entry is `Some(expr)` when `call.is_hash_output` is true
    /// (only valid on the last round of a compression), otherwise `None`.
    pub fn add_blake3_round(
        &mut self,
        call: &Blake3Call,
    ) -> Result<(NonPrimitiveOpId, Vec<Option<ExprId>>), CircuitBuilderError> {
        let op_type = NpoTypeId::blake3();
        self.ensure_op_enabled(&op_type)?;

        let mut input_exprs: Vec<Vec<ExprId>> = Vec::with_capacity(CV_LIMBS);
        for limb in &call.inputs {
            input_exprs.push(limb.map_or_else(Vec::new, |v| vec![v]));
        }
        // Pad to CV_LIMBS if fewer inputs provided.
        while input_exprs.len() < CV_LIMBS {
            input_exprs.push(Vec::new());
        }

        let output_labels: Vec<Option<&'static str>> = (0..CV_LIMBS)
            .map(|_| call.is_hash_output.then_some("blake3_out"))
            .collect();

        let (op_id, _call_expr_id, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            input_exprs,
            output_labels,
            Some(NonPrimitiveOpParams::Blake3 {
                new_start: call.new_start,
                is_new_blake: call.is_new_blake,
                is_hash_output: call.is_hash_output,
            }),
            "blake3",
        );
        Ok((op_id, outputs))
    }

    /// Enable Blake3 membership proof operations.
    ///
    /// Registers the Blake3 circuit plugin with the given trace generator.
    /// After calling this, `add_blake3_round` and `add_blake3_merkle_verify`
    /// can be used.
    pub fn enable_blake3(
        &mut self,
        trace_gen: crate::tables::TraceGeneratorFn<F>,
    ) {
        use crate::ops::blake3::plugin::Blake3CircuitPlugin;
        let plugin = Blake3CircuitPlugin::new(trace_gen);
        self.register_npo(plugin);
    }
}
