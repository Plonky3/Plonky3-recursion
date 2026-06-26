//! ExposeClaim non-primitive operation: reads N existing witness values off the
//! `WitnessChecks` bus and surfaces them as host-readable table public values.
//!
//! Unlike recompose/poseidon2 (which CREATE outputs on the bus), this op is a
//! pure READER: it allocates no new witnesses. Each input witness is received
//! off the bus with reader multiplicity `-1` (incrementing that witness's
//! ext-read count, so the bus stays balanced against the writer that sent it),
//! placed into a main column, and bound to the table's public value for that
//! lane by the AIR. The result is a non-primitive table whose `public_values`
//! carry exactly those N witness values, provably equal to the genuine
//! in-circuit witnesses.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;

use p3_field::{ExtensionField, Field, PrimeField64};

use crate::CircuitError;
use crate::builder::{CircuitBuilderError, NpoCircuitPlugin, NpoLoweringContext};
use crate::ops::{ExecutionContext, NonPrimitiveExecutor, NpoTypeId, Op, PreprocessedWriter};
use crate::tables::{NonPrimitiveTrace, TraceGeneratorFn};
use crate::types::{ExprId, WitnessId};

/// Config payload stored in `NpoConfig` for the expose-claim table.
#[derive(Debug, Clone)]
pub(crate) struct ExposeClaimConfig;

/// Per-row data captured during execution: which witness was read and its value.
///
/// `value` is the host-exposed scalar (coeff-0 of the read cell). `read_coeffs`
/// holds ALL `D` base-field coefficients of the read witness — the table's main
/// trace must reproduce the FULL witness value so the `WitnessChecks` receive
/// tuple `[idx, c_0, ..., c_{D-1}]` exactly matches the tuple the witness's
/// CREATOR sent (e.g. a W24 Poseidon2 output limb, whose higher coefficients are
/// genuinely nonzero). Binding only coeff-0 and zeroing the rest would read a
/// DIFFERENT tuple than the creator sent, unbalancing the global lookup bus.
///
/// On the execution-state rows `F` is the circuit extension field and `read_coeffs`
/// is left empty (the trace generator derives it); on the base-field trace rows it
/// is populated with the `D` coefficients.
#[derive(Debug, Clone)]
pub struct ExposeClaimCircuitRow<F> {
    pub witness_id: WitnessId,
    pub value: F,
    pub read_coeffs: alloc::vec::Vec<F>,
}

/// Execution state collecting the exposed claim rows (in lane order).
#[derive(Debug, Default)]
pub struct ExposeClaimExecutionState<F> {
    pub rows: Vec<ExposeClaimCircuitRow<F>>,
}

/// Executor for the expose-claim op. Reads the input witnesses and records them;
/// writes no new witnesses.
#[derive(Debug, Clone)]
pub struct ExposeClaimExecutor {
    op_type: NpoTypeId,
}

impl ExposeClaimExecutor {
    pub fn new(op_type: NpoTypeId) -> Self {
        Self { op_type }
    }
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for ExposeClaimExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1 {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "1 input group".to_string(),
                got: inputs.len(),
            });
        }
        if !outputs.is_empty() && !outputs.iter().all(Vec::is_empty) {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "no outputs (reader-only op)".to_string(),
                got: outputs.len(),
            });
        }

        let mut rows = Vec::with_capacity(inputs[0].len());
        for &wid in &inputs[0] {
            let value = ctx.get_witness(wid)?;
            rows.push(ExposeClaimCircuitRow {
                witness_id: wid,
                value,
                read_coeffs: alloc::vec::Vec::new(),
            });
        }

        let state = ctx.get_op_state_mut::<ExposeClaimExecutionState<F>>(&self.op_type);
        state.rows.extend(rows);

        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        preprocessed: &mut dyn PreprocessedWriter<F>,
    ) -> Result<(), CircuitError> {
        // Per-lane preprocessed layout (EF): [witness_idx, mult_placeholder].
        // The preprocessor overwrites the placeholder with the reader
        // multiplicity (-1). We also increment the witness's ext-read count so
        // the PublicAir send that created it carries one more copy — keeping the
        // WitnessChecks bus balanced.
        for &wid in &inputs[0] {
            preprocessed.register_non_primitive_output_index(&self.op_type, &[wid]);
            preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ONE]);
            preprocessed.increment_ext_reads(&[wid]);
        }
        Ok(())
    }

    fn num_exposed_outputs(&self) -> Option<usize> {
        // Reader-only: creates no outputs on the bus.
        Some(0)
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

/// Circuit-layer plugin for the expose-claim op.
pub(crate) struct ExposeClaimCircuitPlugin<F: Field> {
    trace_gen: TraceGeneratorFn<F>,
}

impl<F: Field> ExposeClaimCircuitPlugin<F> {
    pub fn new(trace_gen: TraceGeneratorFn<F>) -> Self {
        Self { trace_gen }
    }
}

impl<F: Field> Debug for ExposeClaimCircuitPlugin<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExposeClaimCircuitPlugin").finish()
    }
}

impl<F> NpoCircuitPlugin<F> for ExposeClaimCircuitPlugin<F>
where
    F: Field,
{
    fn type_id(&self) -> NpoTypeId {
        NpoTypeId::expose_claim()
    }

    fn lower(
        &self,
        data: &crate::builder::NonPrimitiveOperationData<F>,
        _output_exprs: &[(u32, ExprId)],
        ctx: &mut NpoLoweringContext<'_, F>,
    ) -> Result<Op<F>, CircuitBuilderError> {
        if data.input_exprs.len() != 1 {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "ExposeClaim",
                expected: "1 input group".to_string(),
                got: data.input_exprs.len(),
            });
        }

        let input_wids: Vec<WitnessId> = data.input_exprs[0]
            .iter()
            .enumerate()
            .map(|(i, &expr)| ctx.resolve_witness_id(expr, &format!("ExposeClaim input {i}")))
            .collect::<Result<_, _>>()?;

        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![input_wids],
            outputs: vec![],
            executor: Box::new(ExposeClaimExecutor::new(NpoTypeId::expose_claim())),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<F> {
        self.trace_gen
    }

    fn config(&self) -> crate::ops::NpoConfig {
        crate::ops::NpoConfig::new(ExposeClaimConfig)
    }
}

// SAFETY: the only field is a bare `fn` pointer (`TraceGeneratorFn<F>`), which
// is always `Send + Sync`. No `F` value is stored.
unsafe impl<F: Field> Send for ExposeClaimCircuitPlugin<F> {}
unsafe impl<F: Field> Sync for ExposeClaimCircuitPlugin<F> {}

/// Trace for the expose-claim op.
#[derive(Debug, Clone)]
pub struct ExposeClaimTrace<F> {
    pub operations: Vec<ExposeClaimCircuitRow<F>>,
}

impl<F> ExposeClaimTrace<F> {
    pub const fn total_rows(&self) -> usize {
        self.operations.len()
    }
}

impl<TraceF: Clone + Send + Sync + 'static, CF> NonPrimitiveTrace<CF> for ExposeClaimTrace<TraceF> {
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::expose_claim()
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

/// Generate the expose-claim trace from execution state.
///
/// Each recorded value is an EF element `(c, 0, ..., 0)`; we extract `c` (the
/// 0th basis coefficient) as a base-field value, then re-embed as EF.
pub fn generate_expose_claim_trace<BF, EF>(
    op_states: &crate::ops::OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<EF>>>, CircuitError>
where
    BF: PrimeField64,
    EF: Field + ExtensionField<BF>,
{
    let op_type = NpoTypeId::expose_claim();
    let Some(state) = op_states
        .get(&op_type)
        .and_then(|s| s.downcast_ref::<ExposeClaimExecutionState<EF>>())
    else {
        return Ok(None);
    };

    if state.rows.is_empty() {
        return Ok(None);
    }

    let operations: Vec<ExposeClaimCircuitRow<BF>> = state
        .rows
        .iter()
        .map(|row| {
            // Capture ALL `D` base-field coefficients of the read witness. The host
            // value exposed is coeff-0, but the table's `WitnessChecks` receive must
            // carry the FULL witness tuple so it matches the tuple the witness's
            // creator sent (a base-field witness has zero higher coeffs; a Poseidon2
            // output limb carries 4 genuinely-nonzero base lanes packed as one ext
            // element). See `ExposeClaimCircuitRow` for why.
            let coeffs = row.value.as_basis_coefficients_slice();
            ExposeClaimCircuitRow {
                witness_id: row.witness_id,
                value: coeffs[0],
                read_coeffs: coeffs.to_vec(),
            }
        })
        .collect();

    Ok(Some(Box::new(ExposeClaimTrace { operations })))
}
