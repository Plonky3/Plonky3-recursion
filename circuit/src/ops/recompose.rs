//! Recompose non-primitive operation: packs D base-field witnesses into one extension-field witness.
//!
//! This table replaces the ALU-based `recompose_base_coeffs_to_ext` with a structural operation
//! that has zero local AIR constraints — correctness is enforced entirely by CTL bus consistency.
//!
//! Each row reads D base-field witness values and writes one extension-field witness whose
//! coefficients are exactly those D values.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;

use p3_field::{ExtensionField, Field, PrimeField64};

use crate::builder::{
    CircuitBuilderError, NonPrimitiveOpParams, NpoCircuitPlugin, NpoLoweringContext,
};
use crate::op::{ExecutionContext, NonPrimitiveExecutor, NpoTypeId, Op, OpExecutionState};
use crate::tables::{NonPrimitiveTrace, TraceGeneratorFn};
use crate::types::{ExprId, WitnessId};
use crate::{CircuitError, PreprocessedColumns};

// ============================================================================
// Configuration
// ============================================================================

/// Config payload stored in `NpoConfig` for recompose tables.
#[derive(Debug, Clone)]
pub struct RecomposeConfig {
    pub d: usize,
}

// ============================================================================
// Execution State
// ============================================================================

/// Per-row data captured during execution.
#[derive(Debug, Clone)]
pub struct RecomposeCircuitRow<F> {
    /// D input base-field witness IDs.
    pub input_wids: Vec<WitnessId>,
    /// Output extension-field witness ID.
    pub output_wid: WitnessId,
    /// The D base-field coefficient values.
    pub values: Vec<F>,
}

/// Execution state collecting rows across all recompose calls.
#[derive(Debug, Default)]
pub struct RecomposeExecutionState<F> {
    pub rows: Vec<RecomposeCircuitRow<F>>,
}

impl<F: Send + Sync + Debug + 'static> OpExecutionState for RecomposeExecutionState<F> {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ============================================================================
// Executor
// ============================================================================

/// Type-erased recompose function: takes D extension-field values (each embedding
/// a base-field coefficient) and returns the properly recomposed extension-field value.
pub type RecomposeFn<F> = Arc<dyn Fn(&[F]) -> F + Send + Sync>;

/// Executor for recompose operations.
///
/// Reads D base-field witnesses, packs them into an extension-field value,
/// writes the output witness, and records the row for trace generation.
pub struct RecomposeExecutor<F> {
    op_type: NpoTypeId,
    d: usize,
    recompose_fn: RecomposeFn<F>,
}

impl<F> Clone for RecomposeExecutor<F> {
    fn clone(&self) -> Self {
        Self {
            op_type: self.op_type.clone(),
            d: self.d,
            recompose_fn: Arc::clone(&self.recompose_fn),
        }
    }
}

impl<F> Debug for RecomposeExecutor<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecomposeExecutor")
            .field("op_type", &self.op_type)
            .field("d", &self.d)
            .finish()
    }
}

impl<F> RecomposeExecutor<F> {
    pub fn new(d: usize, recompose_fn: RecomposeFn<F>) -> Self {
        Self {
            op_type: NpoTypeId::recompose(),
            d,
            recompose_fn,
        }
    }
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for RecomposeExecutor<F> {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1 || inputs[0].len() != self.d {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: format!("1 input group with {} witnesses", self.d),
                got: inputs.len(),
            });
        }

        if outputs.len() != 1 || outputs[0].len() != 1 {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "1 output group with 1 witness".to_string(),
                got: outputs.len(),
            });
        }

        let input_wids = &inputs[0];
        let output_wid = outputs[0][0];

        let mut bf_values = Vec::with_capacity(self.d);
        for &wid in input_wids {
            bf_values.push(ctx.get_witness(wid)?);
        }

        // Use the type-aware recompose function that was created at `enable_recompose` time,
        // where the base field BF was known. This correctly uses `BasedVectorSpace<BF>`
        // (DIMENSION=D) rather than the trivial `BasedVectorSpace<F>` (DIMENSION=1).
        let ef_value = (self.recompose_fn)(&bf_values);

        ctx.set_witness(output_wid, ef_value)?;

        let state = ctx.get_op_state_mut::<RecomposeExecutionState<F>>(&self.op_type);
        state.rows.push(RecomposeCircuitRow {
            input_wids: input_wids.to_vec(),
            output_wid,
            values: bf_values,
        });

        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn preprocess(
        &self,
        _inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut PreprocessedColumns<F>,
    ) -> Result<(), CircuitError> {
        let output_wid = outputs[0][0];

        // Preprocessed layout: [output_idx, out_mult]
        // No input reads are registered — the output lookup alone constrains
        // correctness via `connect()` aliasing + the WitnessChecks bus.
        preprocessed.register_non_primitive_output_index(&self.op_type, &[output_wid]);
        preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ONE]);

        Ok(())
    }

    fn num_exposed_outputs(&self) -> Option<usize> {
        Some(1)
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Circuit Plugin
// ============================================================================

/// Circuit-layer plugin for recompose non-primitive operations.
pub struct RecomposeCircuitPlugin<F: Field> {
    d: usize,
    trace_gen: TraceGeneratorFn<F>,
    recompose_fn: RecomposeFn<F>,
}

impl<F: Field> RecomposeCircuitPlugin<F> {
    pub fn new(d: usize, trace_gen: TraceGeneratorFn<F>, recompose_fn: RecomposeFn<F>) -> Self {
        Self {
            d,
            trace_gen,
            recompose_fn,
        }
    }
}

impl<F: Field> Debug for RecomposeCircuitPlugin<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecomposeCircuitPlugin")
            .field("d", &self.d)
            .finish()
    }
}

impl<F> NpoCircuitPlugin<F> for RecomposeCircuitPlugin<F>
where
    F: Field,
{
    fn type_id(&self) -> NpoTypeId {
        NpoTypeId::recompose()
    }

    fn lower(
        &self,
        data: &crate::builder::NonPrimitiveOperationData<F>,
        output_exprs: &[(u32, ExprId)],
        ctx: &mut NpoLoweringContext<'_, F>,
    ) -> Result<Op<F>, CircuitBuilderError> {
        let expr_to_widx = &mut *ctx.expr_to_widx;

        // Ensure output ExprIds are mapped
        for (_output_idx, expr_id) in output_exprs {
            expr_to_widx
                .entry(*expr_id)
                .or_insert_with(|| (ctx.alloc_witness_id)(expr_id.0 as usize));
        }

        // Validate params
        match data.params.as_ref() {
            Some(NonPrimitiveOpParams::Recompose) => {}
            _ => {
                return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                    op: data.op_type.clone(),
                });
            }
        }

        // Expect 1 input group with D expressions
        if data.input_exprs.len() != 1 || data.input_exprs[0].len() != self.d {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Recompose",
                expected: format!("1 input group with {} base-field coefficients", self.d),
                got: data.input_exprs.len(),
            });
        }

        // Map input expressions to witness IDs
        let input_wids: Vec<WitnessId> = data.input_exprs[0]
            .iter()
            .enumerate()
            .map(|(i, &expr)| {
                expr_to_widx.get(&expr).copied().ok_or_else(|| {
                    CircuitBuilderError::MissingExprMapping {
                        expr_id: expr,
                        context: format!("Recompose input coefficient {i}"),
                    }
                })
            })
            .collect::<Result<_, _>>()?;

        // Map output expression to witness ID (should be exactly 1 output)
        if output_exprs.len() != 1 {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Recompose",
                expected: "1 output (extension field element)".to_string(),
                got: output_exprs.len(),
            });
        }
        let (_, out_expr) = output_exprs[0];
        let out_wid = *expr_to_widx.get(&out_expr).ok_or_else(|| {
            CircuitBuilderError::MissingExprMapping {
                expr_id: out_expr,
                context: "Recompose output".to_string(),
            }
        })?;

        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![input_wids],
            outputs: vec![vec![out_wid]],
            executor: Box::new(RecomposeExecutor::new(
                self.d,
                Arc::clone(&self.recompose_fn),
            )),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<F> {
        self.trace_gen
    }

    fn config(&self) -> crate::op::NpoConfig {
        crate::op::NpoConfig::new(RecomposeConfig { d: self.d })
    }
}

// Implement Send + Sync for the plugin (required by NpoCircuitPlugin)
unsafe impl<F: Field> Send for RecomposeCircuitPlugin<F> {}
unsafe impl<F: Field> Sync for RecomposeCircuitPlugin<F> {}

// ============================================================================
// Trace
// ============================================================================

/// Trace for recompose operations.
#[derive(Debug, Clone)]
pub struct RecomposeTrace<F> {
    pub operations: Vec<RecomposeCircuitRow<F>>,
}

impl<F> RecomposeTrace<F> {
    pub const fn total_rows(&self) -> usize {
        self.operations.len()
    }
}

impl<TraceF: Clone + Send + Sync + 'static, CF> NonPrimitiveTrace<CF> for RecomposeTrace<TraceF> {
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::recompose()
    }

    fn rows(&self) -> usize {
        self.total_rows()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Trace Generation
// ============================================================================

/// Generate the recompose trace from execution state.
///
/// The trace generator extracts BF coefficient values from the extension-field execution state.
/// Since the circuit operates on extension-field values, each BF coefficient is stored as
/// an extension element `(c_j, 0, 0, 0)`. We extract just the 0th basis coefficient.
pub fn generate_recompose_trace<BF, EF>(
    op_states: &crate::op::OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<EF>>>, CircuitError>
where
    BF: PrimeField64,
    EF: Field + ExtensionField<BF>,
{
    let op_type = NpoTypeId::recompose();
    let Some(state) = op_states
        .get(&op_type)
        .and_then(|s| s.as_any().downcast_ref::<RecomposeExecutionState<EF>>())
    else {
        return Ok(None);
    };

    if state.rows.is_empty() {
        return Ok(None);
    }

    // Convert extension-field rows to base-field rows.
    // Each value in state.rows[i].values is an EF element of the form (c_j, 0, 0, 0).
    // We extract c_j (the 0th basis coefficient) as a BF value, then re-embed as EF.
    let operations: Vec<RecomposeCircuitRow<BF>> = state
        .rows
        .iter()
        .map(|row| {
            let bf_values: Vec<BF> = row
                .values
                .iter()
                .map(|ef_val| {
                    let coeffs = ef_val.as_basis_coefficients_slice();
                    coeffs[0]
                })
                .collect();
            RecomposeCircuitRow {
                input_wids: row.input_wids.clone(),
                output_wid: row.output_wid,
                values: bf_values,
            }
        })
        .collect();

    Ok(Some(Box::new(RecomposeTrace { operations })))
}
