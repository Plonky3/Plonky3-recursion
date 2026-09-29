use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::HashMap;
use p3_field::{Dup, Field};
use p3_maybe_rayon::prelude::*;
use tracing::instrument;

use super::alu::{AluOpRecord, AluTrace};
use super::constant::ConstTraceBuilder;
use super::public::PublicTraceBuilder;
use super::witness::WitnessTrace;
use super::{NonPrimitiveTrace, Traces};
use crate::circuit::Circuit;
#[cfg(feature = "debugging")]
use crate::diagnostics::{CircuitDiagnostic, DiagnosticPhase};
use crate::ops::{ExecutionContext, NpoPrivateData, NpoTypeId, Op, OpStateMap};
use crate::types::{NonPrimitiveOpId, WitnessId};
use crate::{AluOpKind, CircuitError};

type TraceGenerationResult<F> = Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError>;

/// Circuit execution engine.
pub struct CircuitRunner<'a, F> {
    /// Borrowed circuit specification.
    circuit: &'a Circuit<F>,
    /// Witness values (None = unset, Some = computed).
    witness: Vec<Option<F>>,
    /// ALU deduplication rewrite map.
    witness_rewrite: Option<HashMap<WitnessId, WitnessId>>,
    /// Private data for non-primitive operations (not on witness bus)
    non_primitive_op_private_data: Vec<Option<NpoPrivateData>>,
    /// Map from NonPrimitiveOpId -> index in `circuit.ops` for type checks.
    non_primitive_op_index_by_id: Vec<Option<usize>>,
    /// Operation-specific execution state (e.g., Poseidon chaining, row records).
    op_states: OpStateMap,
    /// Set only by diagnostic execution; ordinary runs do not track location.
    #[cfg(feature = "debugging")]
    diagnostic_phase: DiagnosticPhase,
}

impl<'a, F: Field> CircuitRunner<'a, F> {
    /// Creates circuit runner with empty witness storage.
    pub fn new(circuit: &'a Circuit<F>) -> Self {
        let witness = vec![None; circuit.witness_count as usize];

        // Single pass over `circuit.ops`: collect each non-primitive op's (index, id) and track
        // the max id, instead of scanning the full op list twice.
        let mut non_primitive_op_positions: Vec<(usize, u32)> = Vec::new();
        let mut max_op_id: Option<u32> = None;
        for (idx, op) in circuit.ops.iter().enumerate() {
            if let Op::NonPrimitiveOpWithExecutor { op_id, .. } = op {
                max_op_id = Some(max_op_id.map_or(op_id.0, |cur| cur.max(op_id.0)));
                non_primitive_op_positions.push((idx, op_id.0));
            }
        }
        let non_primitive_op_count = max_op_id.map_or(0, |m| m as usize + 1);

        let mut non_primitive_op_index_by_id = vec![None; non_primitive_op_count];
        for (idx, op_id) in non_primitive_op_positions {
            if let Some(slot) = non_primitive_op_index_by_id.get_mut(op_id as usize) {
                #[cfg(debug_assertions)]
                debug_assert!(
                    slot.is_none(),
                    "duplicate NonPrimitiveOpId({op_id}) in circuit.ops",
                );
                // Keep the first occurrence if duplicates exist (release builds).
                if slot.is_none() {
                    *slot = Some(idx);
                }
            }
        }

        let mut non_primitive_op_private_data: Vec<Option<NpoPrivateData>> =
            Vec::with_capacity(non_primitive_op_count);
        non_primitive_op_private_data.resize_with(non_primitive_op_count, || None);
        let witness_rewrite = circuit.witness_rewrite.clone();
        let op_states = BTreeMap::new();
        Self {
            circuit,
            witness,
            witness_rewrite,
            non_primitive_op_private_data,
            non_primitive_op_index_by_id,
            op_states,
            #[cfg(feature = "debugging")]
            diagnostic_phase: DiagnosticPhase::Caller,
        }
    }

    /// Sets public input values into witness table.
    pub fn set_public_inputs(&mut self, public_values: &[F]) -> Result<(), CircuitError> {
        if public_values.len() != self.circuit.public_flat_len {
            return Err(CircuitError::PublicInputLengthMismatch {
                expected: self.circuit.public_flat_len,
                got: public_values.len(),
            });
        }
        if self.circuit.public_rows.len() != self.circuit.public_flat_len {
            return Err(CircuitError::MissingPublicRowsMapping);
        }

        for (i, value) in public_values.iter().enumerate() {
            let widx = self.circuit.public_rows[i];
            self.set_witness(widx, *value)?;
        }

        Ok(())
    }

    /// Sets private input values into witness table.
    ///
    /// Private inputs do not create Public table rows, and should be constrained by downstream use.
    pub fn set_private_inputs(&mut self, private_values: &[F]) -> Result<(), CircuitError> {
        if private_values.len() != self.circuit.private_flat_len {
            return Err(CircuitError::PrivateInputLengthMismatch {
                expected: self.circuit.private_flat_len,
                got: private_values.len(),
            });
        }
        if self.circuit.private_input_rows.len() != self.circuit.private_flat_len {
            return Err(CircuitError::MissingPrivateRowsMapping);
        }

        for (i, value) in private_values.iter().enumerate() {
            let widx = self.circuit.private_input_rows[i];
            self.set_witness(widx, *value)?;
        }

        Ok(())
    }

    /// Sets private data for a non-primitive operation.
    pub fn set_private_data(
        &mut self,
        op_id: NonPrimitiveOpId,
        private_data: NpoPrivateData,
    ) -> Result<(), CircuitError> {
        // Validate that the op_id exists in the circuit.
        if op_id.0 as usize >= self.non_primitive_op_private_data.len()
            || self
                .non_primitive_op_index_by_id
                .get(op_id.0 as usize)
                .and_then(|x| *x)
                .is_none()
        {
            return Err(CircuitError::NonPrimitiveOpIdOutOfRange {
                op_id: op_id.0,
                max_ops: self.non_primitive_op_private_data.len(),
            });
        }

        // Validate that the private data matches the operation type
        let Some(op_idx) = self
            .non_primitive_op_index_by_id
            .get(op_id.0 as usize)
            .and_then(|x| *x)
        else {
            return Err(CircuitError::NonPrimitiveOpIdOutOfRange {
                op_id: op_id.0,
                max_ops: self.non_primitive_op_private_data.len(),
            });
        };
        let Op::NonPrimitiveOpWithExecutor { executor, .. } = &self.circuit.ops[op_idx] else {
            return Err(CircuitError::NonPrimitiveOpIdOutOfRange {
                op_id: op_id.0,
                max_ops: self.non_primitive_op_private_data.len(),
            });
        };
        // Disallow double-setting private data
        if self.non_primitive_op_private_data[op_id.0 as usize].is_some() {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: executor.op_type().clone(),
                operation_index: op_id,
                expected: "private data not previously set".to_string(),
                got: "already set".to_string(),
            });
        }

        // Store private data for this operation
        self.non_primitive_op_private_data[op_id.0 as usize] = Some(private_data);
        Ok(())
    }

    /// Sets private data for a non-primitive operation by its tag.
    ///
    /// The tag must have been registered during circuit construction via `builder.tag_op()`.
    ///
    /// # Errors
    /// Returns `CircuitError::UnknownTag` if the tag was not registered.
    pub fn set_private_data_by_tag(
        &mut self,
        tag: &str,
        private_data: NpoPrivateData,
    ) -> Result<(), CircuitError> {
        let op_id = self.circuit.tag_to_op_id.get(tag).copied().ok_or_else(|| {
            CircuitError::UnknownTag {
                tag: tag.to_string(),
            }
        })?;
        self.set_private_data(op_id, private_data)
    }

    /// Run the circuit and generate traces
    #[instrument(skip_all)]
    pub fn run(mut self) -> Result<Traces<F>, CircuitError> {
        self.run_inner::<false>()
    }

    /// Run the circuit, retaining owned source and compiled-operation context on failure.
    #[cfg(feature = "debugging")]
    #[instrument(skip_all)]
    pub fn run_with_diagnostics(mut self) -> Result<Traces<F>, CircuitDiagnostic> {
        // A preceding public `execute_all` may have failed. No earlier location is relevant.
        self.diagnostic_phase = DiagnosticPhase::Caller;
        match self.run_inner::<true>() {
            Ok(traces) => Ok(traces),
            Err(error) => Err(CircuitDiagnostic::from_error(
                self.circuit,
                error,
                self.diagnostic_phase.clone(),
            )),
        }
    }

    fn run_inner<const DIAGNOSTICS: bool>(&mut self) -> Result<Traces<F>, CircuitError> {
        let alu_trace = self.execute_all_inner::<DIAGNOSTICS>()?;

        #[cfg(feature = "debugging")]
        if DIAGNOSTICS {
            self.diagnostic_phase = DiagnosticPhase::WitnessAliases;
        }

        if let Some(rewrite) = self.witness_rewrite.take() {
            let mut resolved: HashMap<WitnessId, WitnessId> = HashMap::with_capacity(rewrite.len());
            let mut root = |canon: WitnessId| {
                *resolved.entry(canon).or_insert_with(|| {
                    let mut cur = canon;
                    while let Some(&next) = rewrite.get(&cur) {
                        cur = next;
                    }
                    cur
                })
            };
            let mut replay = |dup: WitnessId, canon: WitnessId| -> Result<(), CircuitError> {
                let r = root(canon);
                if let Some(ref val) = self.witness[r.0 as usize] {
                    self.set_witness(dup, *val)?;
                }
                Ok(())
            };
            if DIAGNOSTICS {
                let mut entries: Vec<_> = rewrite.iter().collect();
                entries.sort_unstable_by_key(|(dup, _)| **dup);
                for (dup, canon) in entries {
                    replay(*dup, *canon)?;
                }
            } else {
                for (dup, canon) in &rewrite {
                    replay(*dup, *canon)?;
                }
            }
        }

        #[cfg(feature = "debugging")]
        if DIAGNOSTICS {
            self.diagnostic_phase = DiagnosticPhase::WitnessTrace;
        }
        // Build witness trace directly from the populated witness table.
        let mut witness_values = Vec::with_capacity(self.witness.len());
        for (i, value) in self.witness.iter().enumerate() {
            let Some(value) = *value else {
                return Err(CircuitError::WitnessNotSetForIndex { index: i });
            };
            witness_values.push(value);
        }
        let witness_trace = WitnessTrace::new(witness_values);

        #[cfg(feature = "debugging")]
        if DIAGNOSTICS {
            self.diagnostic_phase = DiagnosticPhase::ConstTrace;
        }
        let const_trace = ConstTraceBuilder::new(&self.circuit.ops).build()?;
        #[cfg(feature = "debugging")]
        if DIAGNOSTICS {
            self.diagnostic_phase = DiagnosticPhase::PublicTrace;
        }
        let public_trace = PublicTraceBuilder::new(&self.circuit.ops, &self.witness).build()?;

        // Iterate over generators in deterministic order (sorted by key). Generators only read
        // the already-populated `op_states` and each writes an independent output, so they can
        // run concurrently; insertion into the result map happens after, since order doesn't
        // matter there.
        let _scope = tracing::debug_span!("generators").entered();
        let generators = &self.circuit.non_primitive_trace_generators;
        let generated: Vec<Option<Box<dyn NonPrimitiveTrace<F>>>> = if DIAGNOSTICS {
            let results: Vec<TraceGenerationResult<F>> = self
                .circuit
                .non_primitive_trace_generator_order
                .par_iter()
                .map(|op_type| generators[op_type](&self.op_states))
                .collect();
            let mut generated = Vec::with_capacity(results.len());
            for (op_type, result) in self
                .circuit
                .non_primitive_trace_generator_order
                .iter()
                .zip(results)
            {
                #[cfg(feature = "debugging")]
                if result.is_err() {
                    self.diagnostic_phase = DiagnosticPhase::NonPrimitiveTrace {
                        op_type: op_type.clone(),
                    };
                }
                #[cfg(not(feature = "debugging"))]
                let _ = op_type;
                generated.push(result?);
            }
            generated
        } else {
            self.circuit
                .non_primitive_trace_generator_order
                .par_iter()
                .map(|op_type| generators[op_type](&self.op_states))
                .collect::<Result<Vec<_>, _>>()?
        };
        _scope.exit();

        let mut non_primitive_traces: HashMap<NpoTypeId, Box<dyn NonPrimitiveTrace<F>>> =
            HashMap::with_capacity(generated.len());
        for trace in generated.into_iter().flatten() {
            non_primitive_traces.insert(trace.op_type(), trace);
        }

        Ok(Traces {
            witness_trace,
            const_trace,
            public_trace,
            alu_trace,
            tag_to_witness: self.circuit.tag_to_witness.clone(),
            non_primitive_traces,
        })
    }

    /// Executes the full circuit operation list to populate witness table.
    ///
    /// The circuit is already lowered into a valid execution order, so this function
    /// can blindly execute from index 0 to end.
    pub fn execute_all(&mut self) -> Result<AluTrace<F>, CircuitError> {
        self.execute_all_inner::<false>()
    }

    #[instrument(name = "execute_all", skip_all, level = "debug")]
    fn execute_all_inner<const DIAGNOSTICS: bool>(&mut self) -> Result<AluTrace<F>, CircuitError> {
        // Written directly from each AluOpRecord as it's produced, instead of collecting into
        // an intermediate Vec<AluOpRecord> and re-scattering it into these columns afterward.
        let mut op_kind = Vec::with_capacity(self.circuit.ops.len());
        let mut values = Vec::with_capacity(self.circuit.ops.len());
        let mut indices = Vec::with_capacity(self.circuit.ops.len());

        #[cfg(feature = "debugging")]
        let mut compiled_op_index = 0usize;
        for op in &self.circuit.ops {
            #[cfg(feature = "debugging")]
            if DIAGNOSTICS {
                self.diagnostic_phase = DiagnosticPhase::Execution { compiled_op_index };
                compiled_op_index += 1;
            }
            match op {
                Op::Const { out, val } => {
                    self.set_witness(*out, *val)?;
                }
                Op::Public { out, public_pos: _ } => {
                    if self.witness[out.0 as usize].is_none() {
                        return Err(CircuitError::PublicInputNotSet { witness_id: *out });
                    }
                }
                Op::Alu {
                    kind,
                    a,
                    b,
                    c,
                    out,
                    intermediate_out,
                } => {
                    let record = self.execute_alu_op(*kind, *a, *b, *c, *out, *intermediate_out)?;
                    op_kind.push(record.kind);
                    values.push([record.a_val, record.b_val, record.c_val, record.out_val]);
                    indices.push([
                        record.a_index,
                        record.b_index,
                        record.c_index,
                        record.out_index,
                    ]);
                }
                Op::Hint {
                    inputs,
                    outputs,
                    executor,
                } => {
                    executor.execute(inputs, outputs, &mut self.witness)?;
                }
                Op::NonPrimitiveOpWithExecutor {
                    inputs,
                    outputs,
                    executor,
                    op_id,
                } => {
                    let mut ctx = ExecutionContext::new(
                        &mut self.witness,
                        &self.non_primitive_op_private_data,
                        &self.circuit.enabled_ops,
                        *op_id,
                        &mut self.op_states,
                    );

                    executor.execute(inputs, outputs, &mut ctx)?;
                }
            }
        }

        #[cfg(feature = "debugging")]
        if DIAGNOSTICS {
            self.diagnostic_phase = DiagnosticPhase::Caller;
        }

        // If the trace is empty, add a dummy row: 0 + 0 = 0.
        if op_kind.is_empty() {
            op_kind.push(AluOpKind::Add);
            values.push([F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
            indices.push([WitnessId(0), WitnessId(0), WitnessId(0), WitnessId(0)]);
        }

        Ok(AluTrace {
            op_kind,
            values,
            indices,
        })
    }

    /// Execute a single ALU op against the current witness and return its trace record.
    ///
    /// Each [`AluOpKind`] produces exactly one [`AluOpRecord`]; the caller appends it in op order.
    fn execute_alu_op(
        &mut self,
        kind: AluOpKind,
        a: WitnessId,
        b: WitnessId,
        c: Option<WitnessId>,
        out: WitnessId,
        intermediate_out: Option<WitnessId>,
    ) -> Result<AluOpRecord<F>, CircuitError> {
        let c_index = c.unwrap_or(WitnessId(0));
        match kind {
            AluOpKind::Add => {
                let a_val = self.get_witness(a)?;
                if let Some(b_val) = self.witness_value(b) {
                    let result = a_val + b_val;
                    self.set_witness(out, result)?;
                    Ok(AluOpRecord {
                        kind,
                        a_index: a,
                        b_index: b,
                        c_index,
                        out_index: out,
                        a_val,
                        b_val,
                        c_val: F::ZERO,
                        out_val: result,
                    })
                } else {
                    let out_val = self.get_witness(out)?;
                    let b_val = out_val - a_val;
                    self.set_witness(b, b_val)?;
                    Ok(AluOpRecord {
                        kind,
                        a_index: a,
                        b_index: b,
                        c_index,
                        out_index: out,
                        a_val,
                        b_val,
                        c_val: F::ZERO,
                        out_val,
                    })
                }
            }
            AluOpKind::Mul => {
                let a_val = self.get_witness(a)?;
                if let Some(b_val) = self.witness_value(b) {
                    let result = a_val * b_val;
                    self.set_witness(out, result)?;
                    Ok(AluOpRecord {
                        kind,
                        a_index: a,
                        b_index: b,
                        c_index,
                        out_index: out,
                        a_val,
                        b_val,
                        c_val: F::ZERO,
                        out_val: result,
                    })
                } else {
                    let result_val = self.get_witness(out)?;
                    let Some(a_inv) = a_val.try_inverse() else {
                        return Err(CircuitError::DivisionByZero);
                    };
                    let b_val = result_val * a_inv;
                    self.set_witness(b, b_val)?;
                    Ok(AluOpRecord {
                        kind,
                        a_index: a,
                        b_index: b,
                        c_index,
                        out_index: out,
                        a_val,
                        b_val,
                        c_val: F::ZERO,
                        out_val: result_val,
                    })
                }
            }
            AluOpKind::BoolCheck => {
                let a_val = self.get_witness(a)?;
                self.set_witness(out, a_val)?;
                Ok(AluOpRecord {
                    kind,
                    a_index: a,
                    b_index: b,
                    c_index,
                    out_index: out,
                    a_val,
                    b_val: F::ZERO,
                    c_val: a_val,
                    out_val: a_val,
                })
            }
            AluOpKind::MulAdd => {
                let a_val = self.get_witness(a)?;
                let b_val = self.get_witness(b)?;
                let ab_product = a_val * b_val;

                if let Some(io) = intermediate_out {
                    self.set_witness(io, ab_product)?;
                }

                let c_val = if let Some(c_id) = c {
                    self.get_witness(c_id)?
                } else {
                    F::ZERO
                };
                let out_val = ab_product + c_val;
                self.set_witness(out, out_val)?;
                Ok(AluOpRecord {
                    kind,
                    a_index: a,
                    b_index: b,
                    c_index,
                    out_index: out,
                    a_val,
                    b_val,
                    c_val,
                    out_val,
                })
            }
            AluOpKind::HornerAcc => {
                let acc_id = intermediate_out.expect("HornerAcc requires acc in intermediate_out");
                let c_id = c.expect("HornerAcc requires c operand");
                let acc_val = self.get_witness(acc_id)?;
                let a_val = self.get_witness(a)?;
                let b_val = self.get_witness(b)?;
                let c_val = self.get_witness(c_id)?;
                let result = acc_val * b_val + c_val - a_val;
                self.set_witness(out, result)?;
                Ok(AluOpRecord {
                    kind,
                    a_index: a,
                    b_index: b,
                    c_index,
                    out_index: out,
                    a_val,
                    b_val,
                    c_val,
                    out_val: result,
                })
            }
        }
    }

    /// Witness value if the slot exists and is set (`None` = unset or out of range).
    #[inline(always)]
    fn witness_value(&self, widx: WitnessId) -> Option<F> {
        self.witness
            .get(widx.0 as usize)
            .and_then(|opt| opt.as_ref().map(Dup::dup))
    }

    /// Gets witness value by ID.
    #[inline(always)]
    fn get_witness(&self, widx: WitnessId) -> Result<F, CircuitError> {
        let Some(value) = self.witness_value(widx) else {
            return Err(CircuitError::WitnessNotSet { witness_id: widx });
        };
        Ok(value)
    }

    /// Sets witness value by ID.
    #[inline(always)]
    fn set_witness(&mut self, widx: WitnessId, value: F) -> Result<(), CircuitError> {
        if widx.0 as usize >= self.witness.len() {
            return Err(CircuitError::WitnessIdOutOfBounds { witness_id: widx });
        }

        let slot = &mut self.witness[widx.0 as usize];

        // Check for conflicting reassignment
        if let Some(existing_value) = slot.as_ref() {
            if *existing_value == value {
                return Ok(());
            }
            #[cfg(feature = "debugging")]
            let expr_ids = self
                .circuit
                .expr_to_widx
                .iter()
                .filter_map(|(expr_id, &witness_id)| {
                    if witness_id == widx {
                        Some(*expr_id)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            #[cfg(not(feature = "debugging"))]
            let expr_ids = vec![];

            return Err(CircuitError::WitnessConflict {
                witness_id: widx,
                existing: format!("{existing_value:?}"),
                new: format!("{value:?}"),
                expr_ids,
            });
        }

        *slot = Some(value);
        Ok(())
    }

    /// Reference to the witness slice (for benchmarking trace builders after `execute_all`).
    pub fn witness(&self) -> &[Option<F>] {
        &self.witness
    }

    /// Reference to the circuit ops (for benchmarking trace builders after `execute_all`).
    pub fn ops(&self) -> &[Op<F>] {
        &self.circuit.ops
    }
}

#[cfg(test)]
mod tests {
    use p3_test_utils::baby_bear_params::{
        BabyBear, BasedVectorSpace, BinomialExtensionField, Field, PrimeCharacteristicRing,
    };
    use tracing_forest::ForestLayer;
    use tracing_forest::util::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Registry};

    use super::*;
    use crate::builder::CircuitBuilder;
    #[cfg(feature = "debugging")]
    use crate::builder::{NonPrimitiveOperationData, NpoCircuitPlugin, NpoLoweringContext};
    use crate::ops::HintExecutor;
    #[cfg(feature = "debugging")]
    use crate::ops::NpoConfig;
    #[cfg(feature = "debugging")]
    use crate::tables::TraceGeneratorFn;
    use crate::tables::{ConstTrace, PublicTrace};
    use crate::types::WitnessId;
    #[cfg(feature = "debugging")]
    use crate::{AllocationType, CircuitBuilderError, ExprId, NpoPrivateData};

    #[cfg(feature = "debugging")]
    #[derive(Debug, Clone)]
    struct DiagnosticNpo {
        op_type: NpoTypeId,
        fail: bool,
    }

    #[cfg(feature = "debugging")]
    impl crate::ops::NonPrimitiveExecutor<BabyBear> for DiagnosticNpo {
        fn execute(
            &self,
            _inputs: &[Vec<WitnessId>],
            _outputs: &[Vec<WitnessId>],
            _ctx: &mut ExecutionContext<'_, BabyBear>,
        ) -> Result<(), CircuitError> {
            if self.fail {
                Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                    op: self.op_type.clone(),
                })
            } else {
                Ok(())
            }
        }

        fn op_type(&self) -> &NpoTypeId {
            &self.op_type
        }

        fn boxed(&self) -> Box<dyn crate::ops::NonPrimitiveExecutor<BabyBear>> {
            Box::new(self.clone())
        }
    }

    #[cfg(feature = "debugging")]
    struct DiagnosticNpoPlugin {
        op_type: NpoTypeId,
    }

    #[cfg(feature = "debugging")]
    impl NpoCircuitPlugin<BabyBear> for DiagnosticNpoPlugin {
        fn type_id(&self) -> NpoTypeId {
            self.op_type.clone()
        }

        fn lower(
            &self,
            data: &NonPrimitiveOperationData<BabyBear>,
            output_exprs: &[(u32, ExprId)],
            ctx: &mut NpoLoweringContext<'_, BabyBear>,
        ) -> Result<Op<BabyBear>, CircuitBuilderError> {
            assert!(output_exprs.is_empty());
            Ok(Op::NonPrimitiveOpWithExecutor {
                inputs: ctx.lower_expr_slots(&data.input_exprs, "DiagnosticNpo", "input")?,
                outputs: vec![],
                executor: Box::new(DiagnosticNpo {
                    op_type: self.op_type.clone(),
                    fail: data.op_id == NonPrimitiveOpId(1),
                }),
                op_id: data.op_id,
            })
        }

        fn trace_generator(&self) -> TraceGeneratorFn<BabyBear> {
            empty_diagnostic_generator
        }

        fn config(&self) -> NpoConfig {
            NpoConfig::new(())
        }
    }

    #[cfg(feature = "debugging")]
    fn empty_diagnostic_generator(
        _states: &OpStateMap,
    ) -> Result<Option<Box<dyn NonPrimitiveTrace<BabyBear>>>, CircuitError> {
        Ok(None)
    }

    #[cfg(feature = "debugging")]
    struct OutputlessFixture {
        circuit: Circuit<BabyBear>,
        first_call: ExprId,
        second_op_id: NonPrimitiveOpId,
        second_call: ExprId,
        second_inputs: [ExprId; 2],
        op_type: NpoTypeId,
    }

    #[cfg(feature = "debugging")]
    fn outputless_npo_fixture() -> OutputlessFixture {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let op_type = NpoTypeId::new("test/builder_outputless");
        builder.register_npo(DiagnosticNpoPlugin {
            op_type: op_type.clone(),
        });
        let left = builder.define_const(BabyBear::ONE);
        let right = builder.define_const(BabyBear::from_u64(2));
        builder.push_scope("outputless_scope");
        let (first_id, first_call, _) = builder.push_non_primitive_op_with_outputs(
            op_type.clone(),
            vec![vec![left], vec![right]],
            vec![],
            None,
            "first_call",
        );
        let (second_op_id, second_call, _) = builder.push_non_primitive_op_with_outputs(
            op_type.clone(),
            vec![vec![right], vec![left]],
            vec![],
            None,
            "second_call",
        );
        builder.pop_scope();
        builder.tag_op(first_id, "first_tag").unwrap();
        builder.tag_op(second_op_id, "z_second").unwrap();
        builder.tag_op(second_op_id, "a_second").unwrap();
        OutputlessFixture {
            circuit: builder.build().unwrap(),
            first_call,
            second_op_id,
            second_call,
            second_inputs: [right, left],
            op_type,
        }
    }

    #[cfg(feature = "debugging")]
    #[derive(Debug, Clone)]
    struct DiagnosticHint;

    #[cfg(feature = "debugging")]
    impl HintExecutor<BabyBear> for DiagnosticHint {
        fn execute(
            &self,
            _inputs: &[WitnessId],
            _outputs: &[WitnessId],
            _witness: &mut [Option<BabyBear>],
        ) -> Result<(), CircuitError> {
            Err(CircuitError::DivisionByZero)
        }

        fn boxed(&self) -> Box<dyn HintExecutor<BabyBear>> {
            Box::new(self.clone())
        }
    }

    #[cfg(feature = "debugging")]
    #[test]
    fn outputless_same_type_failure_identifies_exact_compiled_call() {
        let mut circuit = Circuit::<BabyBear>::new(0, HashMap::new());
        let op_type = NpoTypeId::new("test/outputless");
        for (id, fail) in [(0, false), (1, true)] {
            circuit.ops.push(Op::NonPrimitiveOpWithExecutor {
                inputs: vec![],
                outputs: vec![],
                executor: Box::new(DiagnosticNpo {
                    op_type: op_type.clone(),
                    fail,
                }),
                op_id: NonPrimitiveOpId(id),
            });
        }
        let report = circuit.runner().run_with_diagnostics().unwrap_err();
        assert_eq!(
            report.phase(),
            &DiagnosticPhase::Execution {
                compiled_op_index: 1
            }
        );
        assert_eq!(report.compiled_operation().unwrap().compiled_op_index, 1);
        assert_eq!(
            report.compiled_operation().unwrap().kind,
            crate::diagnostics::CompiledOpKind::NonPrimitive {
                op_id: NonPrimitiveOpId(1),
                op_type
            }
        );
        assert!(report.operation_origins().is_empty());
        assert!(report.to_string().contains("unavailable"));
    }

    #[cfg(feature = "debugging")]
    #[test]
    fn builder_outputless_npo_failure_retains_the_second_call_anchor() {
        let fixture = outputless_npo_fixture();
        let op_index = fixture
            .circuit
            .ops
            .iter()
            .position(|op| matches!(op, Op::NonPrimitiveOpWithExecutor { op_id, .. } if *op_id == fixture.second_op_id))
            .unwrap();
        let report = fixture.circuit.runner().run_with_diagnostics().unwrap_err();

        assert_eq!(
            report.phase(),
            &DiagnosticPhase::Execution {
                compiled_op_index: op_index
            }
        );
        assert_eq!(
            report.compiled_operation().unwrap().kind,
            crate::diagnostics::CompiledOpKind::NonPrimitive {
                op_id: fixture.second_op_id,
                op_type: fixture.op_type.clone(),
            }
        );
        let origins = report.operation_origins();
        assert_eq!(origins.len(), 1);
        assert_ne!(origins[0].expr_id, fixture.first_call);
        assert_eq!(origins[0].expr_id, fixture.second_call);
        let allocation = origins[0].allocation.as_ref().unwrap();
        assert!(
            matches!(&allocation.alloc_type, AllocationType::NonPrimitiveOp(op_type) if op_type == &fixture.op_type)
        );
        assert_eq!(allocation.label, "second_call");
        assert_eq!(allocation.scope.as_deref(), Some("outputless_scope"));
        assert_eq!(
            origins[0]
                .dependencies
                .iter()
                .map(|group| group
                    .iter()
                    .map(|source| source.expr_id)
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            vec![
                vec![fixture.second_inputs[0]],
                vec![fixture.second_inputs[1]]
            ]
        );
        assert_eq!(
            report.tags(),
            &["a_second".to_string(), "z_second".to_string()]
        );
    }

    #[cfg(feature = "debugging")]
    #[test]
    fn caller_id_error_resolves_the_second_outputless_call_and_its_tags() {
        let fixture = outputless_npo_fixture();
        let op_index = fixture
            .circuit
            .ops
            .iter()
            .position(|op| matches!(op, Op::NonPrimitiveOpWithExecutor { op_id, .. } if *op_id == fixture.second_op_id))
            .unwrap();
        let mut runner = fixture.circuit.runner();
        runner
            .set_private_data(fixture.second_op_id, NpoPrivateData::new(()))
            .unwrap();
        let error = runner
            .set_private_data(fixture.second_op_id, NpoPrivateData::new(()))
            .unwrap_err();
        let report = fixture.circuit.diagnose_error(error);

        assert_eq!(report.phase(), &DiagnosticPhase::Caller);
        assert!(
            matches!(report.error(), CircuitError::IncorrectNonPrimitiveOpPrivateData { operation_index, .. } if *operation_index == fixture.second_op_id)
        );
        assert_eq!(
            report.compiled_operation().unwrap().compiled_op_index,
            op_index
        );
        assert_eq!(
            report.compiled_operation().unwrap().kind,
            crate::diagnostics::CompiledOpKind::NonPrimitive {
                op_id: fixture.second_op_id,
                op_type: fixture.op_type,
            }
        );
        assert_eq!(report.operation_origins().len(), 1);
        assert_eq!(report.operation_origins()[0].expr_id, fixture.second_call);
        assert_eq!(
            report.tags(),
            &["a_second".to_string(), "z_second".to_string()]
        );
    }

    #[cfg(feature = "debugging")]
    #[test]
    fn builder_outputless_hint_failure_retains_its_call_anchor() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let left = builder.define_const(BabyBear::ONE);
        let right = builder.define_const(BabyBear::from_u64(2));
        builder.push_scope("hint_scope");
        let (_, call, outputs) = builder.push_unconstrained_op(
            vec![vec![right, left]],
            0,
            DiagnosticHint,
            "failing_hint",
        );
        builder.pop_scope();
        assert!(outputs.is_empty());
        let circuit = builder.build().unwrap();
        let op_index = circuit
            .ops
            .iter()
            .position(|op| matches!(op, Op::Hint { .. }))
            .unwrap();
        let report = circuit.runner().run_with_diagnostics().unwrap_err();

        assert_eq!(
            report.phase(),
            &DiagnosticPhase::Execution {
                compiled_op_index: op_index
            }
        );
        assert_eq!(
            report.compiled_operation().unwrap().kind,
            crate::diagnostics::CompiledOpKind::Hint
        );
        assert_eq!(report.operation_origins().len(), 1);
        let origin = &report.operation_origins()[0];
        assert_eq!(origin.expr_id, call);
        let allocation = origin.allocation.as_ref().unwrap();
        assert!(
            matches!(&allocation.alloc_type, AllocationType::NonPrimitiveOp(op_type) if op_type == &NpoTypeId::unconstrained())
        );
        assert_eq!(allocation.label, "failing_hint");
        assert_eq!(allocation.scope.as_deref(), Some("hint_scope"));
        assert_eq!(
            origin
                .dependencies
                .iter()
                .map(|group| group
                    .iter()
                    .map(|source| source.expr_id)
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            vec![vec![right], vec![left]]
        );
    }

    #[cfg(feature = "debugging")]
    #[test]
    fn hint_type_only_failure_has_compiled_position_without_npo_id() {
        let mut circuit = Circuit::<BabyBear>::new(0, HashMap::new());
        circuit.ops.push(Op::Hint {
            inputs: vec![],
            outputs: vec![],
            executor: Box::new(DiagnosticHint),
        });
        let report = circuit.runner().run_with_diagnostics().unwrap_err();
        assert_eq!(
            report.phase(),
            &DiagnosticPhase::Execution {
                compiled_op_index: 0
            }
        );
        assert_eq!(
            report.compiled_operation().unwrap().kind,
            crate::diagnostics::CompiledOpKind::Hint
        );
    }

    #[cfg(feature = "debugging")]
    fn failing_diagnostic_generator(
        _states: &OpStateMap,
    ) -> Result<Option<Box<dyn NonPrimitiveTrace<BabyBear>>>, CircuitError> {
        Err(CircuitError::DivisionByZero)
    }

    #[cfg(feature = "debugging")]
    fn row_index_generator_error(
        _states: &OpStateMap,
    ) -> Result<Option<Box<dyn NonPrimitiveTrace<BabyBear>>>, CircuitError> {
        Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
            op: NpoTypeId::new("test/beta"),
            operation_index: NonPrimitiveOpId(0), // Generator-local row index, not a global op ID.
            expected: "valid row".to_string(),
            got: "invalid row".to_string(),
        })
    }

    #[cfg(feature = "debugging")]
    #[test]
    fn generator_local_row_index_does_not_identify_an_unrelated_compiled_call() {
        let mut circuit = Circuit::<BabyBear>::new(0, HashMap::new());
        let alpha = NpoTypeId::new("test/alpha");
        let beta = NpoTypeId::new("test/beta");
        circuit.ops.push(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![],
            outputs: vec![],
            executor: Box::new(DiagnosticNpo {
                op_type: alpha,
                fail: false,
            }),
            op_id: NonPrimitiveOpId(0),
        });
        circuit
            .tag_to_op_id
            .insert("alpha".to_string(), NonPrimitiveOpId(0));
        circuit
            .non_primitive_trace_generator_order
            .push(beta.clone());
        circuit
            .non_primitive_trace_generators
            .insert(beta.clone(), row_index_generator_error);

        let report = circuit.runner().run_with_diagnostics().unwrap_err();
        assert_eq!(
            report.phase(),
            &DiagnosticPhase::NonPrimitiveTrace { op_type: beta }
        );
        assert!(report.compiled_operation().is_none());
        assert!(report.operation_origins().is_empty());
        assert!(report.tags().is_empty());
        assert!(matches!(
            report.error(),
            CircuitError::IncorrectNonPrimitiveOpPrivateData { .. }
        ));
    }

    #[cfg(feature = "debugging")]
    #[test]
    fn prior_execute_failure_does_not_stale_attribute_generator_failure() {
        let mut circuit = Circuit::<BabyBear>::new(1, HashMap::new());
        circuit.ops.push(Op::Public {
            out: WitnessId(0),
            public_pos: 0,
        });
        circuit.public_rows.push(WitnessId(0));
        circuit.public_flat_len = 1;
        let op_type = NpoTypeId::new("test/generator");
        circuit
            .non_primitive_trace_generator_order
            .push(op_type.clone());
        circuit
            .non_primitive_trace_generators
            .insert(op_type.clone(), failing_diagnostic_generator);

        let mut runner = circuit.runner();
        assert!(matches!(
            runner.execute_all(),
            Err(CircuitError::PublicInputNotSet { .. })
        ));
        runner.set_public_inputs(&[BabyBear::ONE]).unwrap();
        let report = runner.run_with_diagnostics().unwrap_err();
        assert_eq!(
            report.phase(),
            &DiagnosticPhase::NonPrimitiveTrace { op_type }
        );
        assert!(report.compiled_operation().is_none());
    }

    /// Initializes a global logger with default parameters.
    fn init_logger() {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();
    }

    #[test]
    fn test_table_generation_basic() {
        let mut builder = CircuitBuilder::new();

        // Simple test: x + 5 = result
        let x = builder.public_input();
        let c5 = builder.define_const(BabyBear::from_u64(5));
        let _result = builder.add(x, c5);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Set public input: x = 3
        runner.set_public_inputs(&[BabyBear::from_u64(3)]).unwrap();

        let traces = runner.run().unwrap();

        let f = BabyBear::from_u64;
        assert_eq!(
            traces,
            Traces {
                witness_trace: WitnessTrace::new(vec![f(0), f(5), f(3), f(8)]),
                const_trace: ConstTrace {
                    index: vec![WitnessId(0), WitnessId(1)],
                    values: vec![f(0), f(5)],
                },
                public_trace: PublicTrace {
                    index: vec![WitnessId(2)],
                    values: vec![f(3)],
                },
                alu_trace: AluTrace {
                    op_kind: vec![AluOpKind::Add],
                    values: vec![[f(3), f(5), f(0), f(8)]],
                    indices: vec![[WitnessId(2), WitnessId(1), WitnessId(0), WitnessId(3)]],
                },
                non_primitive_traces: HashMap::new(),
                tag_to_witness: HashMap::new(),
            }
        );
    }

    #[derive(Debug, Clone)]
    /// The hint defined by x in an equation a*x - b = 0
    struct XHint;

    impl XHint {
        pub fn new() -> Self {
            Self
        }
    }

    impl<F: Field> HintExecutor<F> for XHint {
        fn execute(
            &self,
            inputs: &[WitnessId],
            outputs: &[WitnessId],
            witness: &mut [Option<F>],
        ) -> Result<(), CircuitError> {
            if inputs.len() != 2 || outputs.len() != 1 {
                return Err(CircuitError::UnconstrainedOpInputLengthMismatch {
                    op: "XHint".to_string(),
                    expected: 2,
                    got: inputs.len(),
                });
            }

            let a_idx = inputs[0].0 as usize;
            let b_idx = inputs[1].0 as usize;

            let a = witness
                .get(a_idx)
                .and_then(|opt| opt.as_ref())
                .copied()
                .ok_or(CircuitError::WitnessNotSet {
                    witness_id: inputs[0],
                })?;
            let b = witness
                .get(b_idx)
                .and_then(|opt| opt.as_ref())
                .copied()
                .ok_or(CircuitError::WitnessNotSet {
                    witness_id: inputs[1],
                })?;

            let inv_a = a.try_inverse().ok_or(CircuitError::DivisionByZero)?;
            let x = b * inv_a;

            let out_wid = outputs[0];
            let out_idx = out_wid.0 as usize;
            if out_idx >= witness.len() {
                return Err(CircuitError::WitnessIdOutOfBounds {
                    witness_id: out_wid,
                });
            }
            let slot = &mut witness[out_idx];
            if let Some(existing) = slot.as_ref() {
                if *existing != x {
                    return Err(CircuitError::WitnessConflict {
                        witness_id: out_wid,
                        existing: format!("{existing:?}"),
                        new: format!("{x:?}"),
                        expr_ids: vec![],
                    });
                }
            } else {
                *slot = Some(x);
            }

            Ok(())
        }

        fn boxed(&self) -> Box<dyn HintExecutor<F>> {
            Box::new(self.clone())
        }
    }

    #[test]
    // Proves that we know x such that 37 * x - 111 = 0
    fn test_toy_example_37_times_x_minus_111() {
        init_logger();

        let mut builder = CircuitBuilder::new();

        let c37 = builder.define_const(BabyBear::from_u64(37));
        let c111 = builder.define_const(BabyBear::from_u64(111));
        let x_hint = XHint::new();
        let x = builder
            .push_unconstrained_op(vec![vec![c37, c111]], 1, x_hint, "x")
            .2[0]
            .unwrap();

        let mul_result = builder.mul(c37, x);
        let sub_result = builder.sub(mul_result, c111);
        builder.assert_zero(sub_result);

        let circuit = builder.build().unwrap();

        let runner = circuit.runner();

        let traces = runner.run().unwrap();

        let f = BabyBear::from_u64;
        let neg_111 = -f(111);
        assert_eq!(
            traces,
            Traces {
                witness_trace: WitnessTrace::new(vec![f(0), f(37), f(111), f(3), f(111), neg_111]),
                const_trace: ConstTrace {
                    index: vec![WitnessId(0), WitnessId(1), WitnessId(2), WitnessId(5)],
                    values: vec![f(0), f(37), f(111), neg_111],
                },
                public_trace: PublicTrace {
                    index: vec![],
                    values: vec![],
                },
                alu_trace: AluTrace {
                    op_kind: vec![AluOpKind::Mul, AluOpKind::Add],
                    values: vec![[f(37), f(3), f(0), f(111)], [f(111), neg_111, f(0), f(0)]],
                    indices: vec![
                        [WitnessId(1), WitnessId(3), WitnessId(0), WitnessId(4)],
                        [WitnessId(4), WitnessId(5), WitnessId(0), WitnessId(0)],
                    ],
                },
                non_primitive_traces: HashMap::new(),
                tag_to_witness: HashMap::new(),
            }
        );
    }

    #[test]
    fn test_extension_field_support() {
        type ExtField = BinomialExtensionField<BabyBear, 4>;

        let mut builder = CircuitBuilder::new();

        // Test extension field operations: y * z + x (fused multiply-add)
        let x = builder.public_input();
        let y = builder.public_input();
        let z = builder.public_input();

        let _result = builder.mul_add(y, z, x);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Set public inputs to genuine extension field values with ALL non-zero coefficients
        let x_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(1), // a0
            BabyBear::from_u64(2), // a1
            BabyBear::from_u64(3), // a2
            BabyBear::from_u64(4), // a3
        ])
        .unwrap();
        let y_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(5), // b0
            BabyBear::from_u64(6), // b1
            BabyBear::from_u64(7), // b2
            BabyBear::from_u64(8), // b3
        ])
        .unwrap();
        let z_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(9),  // c0
            BabyBear::from_u64(10), // c1
            BabyBear::from_u64(11), // c2
            BabyBear::from_u64(12), // c3
        ])
        .unwrap();

        runner.set_public_inputs(&[x_val, y_val, z_val]).unwrap();
        let traces = runner.run().unwrap();

        let result = y_val * z_val + x_val;
        assert_eq!(
            traces,
            Traces {
                witness_trace: WitnessTrace::new(
                    vec![ExtField::ZERO, x_val, y_val, z_val, result,]
                ),
                const_trace: ConstTrace {
                    index: vec![WitnessId(0)],
                    values: vec![ExtField::ZERO],
                },
                public_trace: PublicTrace {
                    index: vec![WitnessId(1), WitnessId(2), WitnessId(3)],
                    values: vec![x_val, y_val, z_val],
                },
                alu_trace: AluTrace {
                    op_kind: vec![AluOpKind::MulAdd],
                    values: vec![[y_val, z_val, x_val, result]],
                    indices: vec![[WitnessId(2), WitnessId(3), WitnessId(1), WitnessId(4)]],
                },
                non_primitive_traces: HashMap::new(),
                tag_to_witness: HashMap::new(),
            }
        );
    }

    #[test]
    fn test_set_private_data_by_unknown_tag_error() {
        use crate::ops::poseidon2_perm::Poseidon2PermPrivateData;

        let builder = CircuitBuilder::<BabyBear>::new();
        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        let private_data = Poseidon2PermPrivateData {
            sibling: vec![BabyBear::ZERO, BabyBear::ZERO],
        };

        let result = runner.set_private_data_by_tag(
            "nonexistent-tag",
            crate::ops::NpoPrivateData::new(private_data),
        );

        assert!(matches!(
            result,
            Err(CircuitError::UnknownTag { tag }) if tag == "nonexistent-tag"
        ));
    }
}
