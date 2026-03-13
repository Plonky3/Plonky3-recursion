//! Poseidon2 permutation executor.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_field::Field;

use crate::ops::poseidon2_perm::config::{
    Poseidon2Config, Poseidon2PermBaseConfigData, Poseidon2PermConfigData, Poseidon2PermExecBase,
};
use crate::ops::poseidon2_perm::input_resolver::resolve_all_inputs;
use crate::ops::poseidon2_perm::state::{Poseidon2ExecutionState, Poseidon2PermPrivateData};
use crate::ops::poseidon2_perm::trace::Poseidon2CircuitRow;
use crate::ops::{ExecutionContext, NonPrimitiveExecutor, NpoTypeId};
use crate::types::WitnessId;
use crate::{CircuitError, PreprocessedColumns};

/// Executor for Poseidon2 perm operations.
#[derive(Debug, Clone)]
pub(crate) struct Poseidon2PermExecutor {
    op_type: NpoTypeId,
    config: Poseidon2Config,
    pub(crate) new_start: bool,
    pub(crate) merkle_path: bool,
}

impl Poseidon2PermExecutor {
    pub const fn new(
        op_type: NpoTypeId,
        config: Poseidon2Config,
        new_start: bool,
        merkle_path: bool,
    ) -> Self {
        Self {
            op_type,
            config,
            new_start,
            merkle_path,
        }
    }

    /// Validate input layout for extension field mode.
    fn validate_ext_inputs(
        &self,
        inputs: &[Vec<WitnessId>],
        width_ext: usize,
    ) -> Result<(), CircuitError> {
        let min_inputs = width_ext + 1;
        let max_inputs = width_ext + 1 + 2;
        if inputs.len() < min_inputs || inputs.len() > max_inputs {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: format!("{min_inputs}..={max_inputs} input vectors"),
                got: inputs.len(),
            });
        }
        for limb_inputs in inputs[..width_ext].iter() {
            if limb_inputs.len() > 1 {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type.clone(),
                    expected: "0 or 1 witness per input limb (extension-only)".to_string(),
                    got: limb_inputs.len(),
                });
            }
        }
        if inputs[width_ext].len() > 1 {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "0 or 1 element for mmcs_index_sum".to_string(),
                got: inputs[width_ext].len(),
            });
        }
        let num_mmcs_bits = inputs.len().saturating_sub(width_ext + 1);
        if num_mmcs_bits > 2 {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "1 or 2 elements for mmcs_bits".to_string(),
                got: num_mmcs_bits,
            });
        }
        for slot in &inputs[width_ext + 1..] {
            if slot.len() > 1 {
                return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                    op: self.op_type.clone(),
                    expected: "0 or 1 element per mmcs_bit slot".to_string(),
                    got: slot.len(),
                });
            }
        }
        Ok(())
    }

    /// Validate output layout for extension field mode.
    fn validate_ext_outputs(
        &self,
        outputs: &[Vec<WitnessId>],
        rate_ext: usize,
        width_ext: usize,
    ) -> Result<(), CircuitError> {
        if outputs.len() != rate_ext && outputs.len() != width_ext {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: format!("{rate_ext} or {width_ext} output vectors"),
                got: outputs.len(),
            });
        }
        Ok(())
    }

    /// Write output values to witness slots.
    fn write_outputs<F: Field>(
        &self,
        outputs: &[Vec<WitnessId>],
        output_values: &[F],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        for (out_idx, out_slot) in outputs.iter().enumerate() {
            if out_slot.len() == 1 {
                let wid = out_slot[0];
                ctx.set_witness(wid, output_values[out_idx])?;
            } else if !out_slot.is_empty() {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type.clone(),
                    expected: "0 or 1 witness per output limb".to_string(),
                    got: out_slot.len(),
                });
            }
        }
        Ok(())
    }

    /// Execute D=1 (base field) permutation with 16 input/output elements.
    #[unroll::unroll_for_loops]
    fn execute_base<F: Field + Send + Sync + 'static>(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
        exec: &Poseidon2PermExecBase<F>,
    ) -> Result<(), CircuitError> {
        // D=1 mode: Input layout: [in0, in1, ..., in15]
        // Output layout: [out0, ..., out7] (rate) or [out0, ..., out15] (with capacity)
        if inputs.len() != 16 {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "16 input vectors for D=1 mode".to_string(),
                got: inputs.len(),
            });
        }
        for (i, inp) in inputs.iter().enumerate() {
            if inp.len() > 1 {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type.clone(),
                    expected: format!("0 or 1 witness per input element {}", i),
                    got: inp.len(),
                });
            }
        }
        // Support 8 outputs (rate only) or 16 outputs (with capacity)
        if outputs.len() != 8 && outputs.len() != 16 {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "8 or 16 output vectors for D=1 mode".to_string(),
                got: outputs.len(),
            });
        }

        // Resolve input values: use witness value if available, otherwise zero
        let mut resolved_inputs = [F::ZERO; 16];
        for (i, inp) in inputs.iter().enumerate() {
            if inp.len() == 1 {
                resolved_inputs[i] = ctx.get_witness(inp[0])?;
            }
            // If inp is empty, leave as zero (capacity or unused input)
        }

        // Execute the permutation
        let output = exec(&resolved_inputs);

        let mut in_ctl = [false; 4];
        let mut input_indices = [0u32; 4];
        for limb in 0..4 {
            for d in 0..4 {
                let idx = limb * 4 + d;
                if !inputs[idx].is_empty() {
                    in_ctl[limb] = true;
                    if input_indices[limb] == 0 {
                        input_indices[limb] = inputs[idx][0].0;
                    }
                }
            }
        }

        let mut out_ctl = [false; 2];
        let mut output_indices = [0u32; 2];
        for limb in 0..2 {
            for d in 0..4 {
                let idx = limb * 4 + d;
                if idx < outputs.len() && !outputs[idx].is_empty() {
                    out_ctl[limb] = true;
                    if output_indices[limb] == 0 {
                        output_indices[limb] = outputs[idx][0].0;
                    }
                }
            }
        }

        // Convert resolved inputs to Vec for the row record
        let input_values = resolved_inputs.to_vec();

        let row = Poseidon2CircuitRow {
            new_start: self.new_start,
            merkle_path: false, // No merkle path for D=1
            mmcs_bit: false,
            mmcs_index_sum: F::ZERO,
            input_values,
            in_ctl: in_ctl.to_vec(),
            input_indices: input_indices.to_vec(),
            out_ctl: out_ctl.to_vec(),
            output_indices: output_indices.to_vec(),
            mmcs_index_sum_idx: 0,
            mmcs_ctl_enabled: false,
        };

        // Update state: store rows for trace generation
        let state = ctx.get_op_state_mut::<Poseidon2ExecutionState<F>>(&self.op_type);
        state.rows.push(row);

        // Write outputs to witness
        self.write_outputs(outputs, &output, ctx)?;

        Ok(())
    }
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for Poseidon2PermExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        let config = ctx.get_config(&self.op_type)?;

        if let Some(base_cfg) = config.downcast_ref::<Poseidon2PermBaseConfigData<F>>() {
            return self.execute_base(inputs, outputs, ctx, &Arc::clone(&base_cfg.exec));
        }

        let ext_cfg = config
            .downcast_ref::<Poseidon2PermConfigData<F>>()
            .ok_or_else(|| CircuitError::InvalidNonPrimitiveOpConfiguration {
                op: self.op_type.clone(),
            })?;
        let poseidon2_config = ext_cfg.config;
        let merkle_arity = ext_cfg.merkle_arity;
        // Merkle arity is a per-table constant; only small powers of two are
        // currently supported to keep the table aligned with MerkleTree/MMCS.
        if !(merkle_arity == 2 || merkle_arity == 4) {
            return Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                op: self.op_type.clone(),
            });
        }
        let exec = Arc::clone(&ext_cfg.exec);

        let width_ext = poseidon2_config.width_ext();
        let rate_ext = poseidon2_config.rate_ext();

        self.validate_ext_inputs(inputs, width_ext)?;
        self.validate_ext_outputs(outputs, rate_ext, width_ext)?;

        let private_inputs: Option<&[F]> = match ctx.get_private_data() {
            Ok(private_data) => {
                if !self.merkle_path {
                    if private_data
                        .downcast_ref::<Poseidon2PermPrivateData<F, 2>>()
                        .is_some()
                        || private_data
                            .downcast_ref::<Poseidon2PermPrivateData<F, 6>>()
                            .is_some()
                    {
                        return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                            op: self.op_type.clone(),
                            operation_index: ctx.operation_id(),
                            expected: "no private data (only Merkle mode accepts private data)"
                                .to_string(),
                            got: "private data provided for non-Merkle operation".to_string(),
                        });
                    }
                    None
                } else if merkle_arity == 4 {
                    private_data
                        .downcast_ref::<Poseidon2PermPrivateData<F, 6>>()
                        .map_or_else(
                            || {
                                private_data
                                    .downcast_ref::<Poseidon2PermPrivateData<F, 2>>()
                                    .map(|data| &data.sibling[..])
                            },
                            |data| Some(&data.sibling[..]),
                        )
                } else if let Some(data) =
                    private_data.downcast_ref::<Poseidon2PermPrivateData<F, 2>>()
                {
                    Some(&data.sibling[..])
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        let log_arity = (merkle_arity as usize).trailing_zeros() as usize;
        let num_bits = if self.merkle_path {
            log_arity.max(1)
        } else {
            0
        };
        let mut pos_in_group = 0usize;
        if self.merkle_path {
            for (i, slot) in inputs[width_ext + 1..].iter().take(num_bits).enumerate() {
                let val = if let Some(&wid) = slot.first() {
                    let v = ctx.get_witness(wid)?;
                    match (v == F::ZERO, v == F::ONE) {
                        (true, _) => false,
                        (_, true) => true,
                        _ => {
                            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                                op: self.op_type.clone(),
                                operation_index: ctx.operation_id(),
                                expected: "boolean mmcs_bit (0 or 1)".into(),
                                got: format!("{v:?}"),
                            });
                        }
                    }
                } else {
                    return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                        op: self.op_type.clone(),
                        operation_index: ctx.operation_id(),
                        expected: "mmcs_bits must be provided when merkle_path=true".into(),
                        got: "missing mmcs_bit".into(),
                    });
                };
                if val {
                    pos_in_group |= 1 << i;
                }
            }
        }

        let last_output: Option<&Vec<F>> = ctx
            .get_op_state::<Poseidon2ExecutionState<F>>(&self.op_type)
            .and_then(|s| {
                if self.merkle_path {
                    s.last_output_merkle.as_ref()
                } else {
                    s.last_output_normal.as_ref()
                }
            });

        let resolved_inputs = resolve_all_inputs(
            self.new_start,
            self.merkle_path,
            pos_in_group,
            inputs,
            private_inputs,
            ctx,
            last_output.map(|v| v.as_slice()),
            width_ext,
            rate_ext,
            merkle_arity,
        )?;

        let output = exec(&resolved_inputs);

        let (in_ctl, input_indices) = inputs[..width_ext].iter().enumerate().fold(
            (vec![false; width_ext], vec![0u32; width_ext]),
            |(mut in_ctl, mut input_indices), (i, inp)| {
                if let Some(&wid) = inp.first() {
                    in_ctl[i] = true;
                    input_indices[i] = wid.0;
                }
                (in_ctl, input_indices)
            },
        );

        let (out_ctl, output_indices) = outputs.iter().take(rate_ext).enumerate().fold(
            (vec![false; rate_ext], vec![0u32; rate_ext]),
            |(mut out_ctl, mut output_indices), (i, out_slot)| {
                if let Some(&wid) = out_slot.first() {
                    out_ctl[i] = true;
                    output_indices[i] = wid.0;
                }
                (out_ctl, output_indices)
            },
        );

        let (mmcs_index_sum, mmcs_index_sum_idx, mmcs_ctl_enabled) = if inputs[width_ext].len() == 1
        {
            let wid = inputs[width_ext][0];
            let val = ctx.get_witness(wid)?;
            (val, wid.0, true)
        } else {
            (F::ZERO, 0, false)
        };

        let input_values = resolved_inputs;
        debug_assert_eq!(
            input_values.len(),
            width_ext,
            "Execution row must have width_ext input limbs"
        );

        let row = Poseidon2CircuitRow {
            new_start: self.new_start,
            merkle_path: self.merkle_path,
            mmcs_bit: (pos_in_group & 1) != 0,
            mmcs_index_sum,
            input_values,
            in_ctl,
            input_indices,
            out_ctl,
            output_indices,
            mmcs_index_sum_idx,
            mmcs_ctl_enabled,
        };

        self.write_outputs(outputs, &output, ctx)?;

        let op_id = ctx.operation_id();
        let state = ctx.get_op_state_mut::<Poseidon2ExecutionState<F>>(&self.op_type);
        if self.merkle_path {
            tracing::trace!(
                "Poseidon2 op {:?}: updating last_output_merkle from {:?} to {:?}",
                op_id,
                state
                    .last_output_merkle
                    .as_ref()
                    .map(|o| format!("{:?}", o)),
                format!("{:?}", output)
            );
            state.last_output_merkle = Some(output);
        } else {
            tracing::trace!(
                "Poseidon2 op {:?}: updating last_output_normal from {:?} to {:?}",
                op_id,
                state
                    .last_output_normal
                    .as_ref()
                    .map(|o| format!("{:?}", o)),
                format!("{:?}", output)
            );
            state.last_output_normal = Some(output);
        }
        state.rows.push(row);

        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn num_exposed_outputs(&self) -> Option<usize> {
        Some(self.config.rate_ext())
    }

    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut PreprocessedColumns<F>,
    ) -> Result<(), CircuitError> {
        let config = self.config;
        let width_ext = config.width_ext();
        let rate_ext = config.rate_ext();

        self.preprocess_inputs(inputs, preprocessed, width_ext)?;
        self.preprocess_outputs(outputs, preprocessed, rate_ext)?;
        self.preprocess_flags(inputs, preprocessed, width_ext)?;

        Ok(())
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

impl Poseidon2PermExecutor {
    /// Preprocess input columns.
    fn preprocess_inputs<F: Field>(
        &self,
        inputs: &[Vec<WitnessId>],
        preprocessed: &mut PreprocessedColumns<F>,
        width_ext: usize,
    ) -> Result<(), CircuitError> {
        for (limb_idx, inp) in inputs[0..width_ext].iter().enumerate() {
            if inp.is_empty() {
                // Private input
                preprocessed.register_non_primitive_preprocessed_no_read(
                    &self.op_type,
                    &[F::ZERO, F::ZERO], // in_idx, in_ctl
                );
            } else {
                // Exposed input
                // In merkle_path mode, input CTL lookups are disabled in the AIR
                if self.merkle_path {
                    preprocessed.register_non_primitive_preprocessed_no_read(
                        &self.op_type,
                        &[preprocessed.witness_index_as_field(inp[0])],
                    );
                } else {
                    preprocessed.register_non_primitive_witness_reads(&self.op_type, inp)?;
                }
                preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ONE]);
            }
            let normal_chain_sel =
                if !self.new_start && !self.merkle_path && inputs[limb_idx].is_empty() {
                    F::ONE
                } else {
                    F::ZERO
                };

            preprocessed
                .register_non_primitive_preprocessed_no_read(&self.op_type, &[normal_chain_sel]);

            let merkle_chain_sel =
                if !self.new_start && self.merkle_path && inputs[limb_idx].is_empty() {
                    F::ONE
                } else {
                    F::ZERO
                };
            preprocessed
                .register_non_primitive_preprocessed_no_read(&self.op_type, &[merkle_chain_sel]);
        }
        Ok(())
    }

    /// Preprocess output columns.
    fn preprocess_outputs<F: Field>(
        &self,
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut PreprocessedColumns<F>,
        rate_ext: usize,
    ) -> Result<(), CircuitError> {
        for out in outputs.iter().take(rate_ext) {
            if out.is_empty() {
                preprocessed.register_non_primitive_preprocessed_no_read(
                    &self.op_type,
                    &[F::ZERO, F::ZERO], // out_idx, out_ctl
                );
            } else {
                preprocessed.register_non_primitive_output_index(&self.op_type, out);
                preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ONE]);
            }
        }
        Ok(())
    }

    /// Preprocess flag columns (mmcs_index_sum, merkle flags, new_start, merkle_path).
    fn preprocess_flags<F: Field>(
        &self,
        inputs: &[Vec<WitnessId>],
        preprocessed: &mut PreprocessedColumns<F>,
        width_ext: usize,
    ) -> Result<(), CircuitError> {
        if inputs[width_ext].is_empty() {
            preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ZERO]);
        } else {
            preprocessed.register_non_primitive_preprocessed_no_read(
                &self.op_type,
                &[preprocessed.witness_index_as_field(inputs[width_ext][0])],
            );
        }

        let mmcs_ctl_enabled = !inputs[width_ext].is_empty();
        let mmcs_merkle_flag = if mmcs_ctl_enabled && self.merkle_path {
            F::ONE
        } else {
            F::ZERO
        };
        preprocessed
            .register_non_primitive_preprocessed_no_read(&self.op_type, &[mmcs_merkle_flag]);

        let new_start_val = if self.new_start { F::ONE } else { F::ZERO };
        let merkle_path_val = if self.merkle_path { F::ONE } else { F::ZERO };
        preprocessed.register_non_primitive_preprocessed_no_read(
            &self.op_type,
            &[new_start_val, merkle_path_val],
        );

        Ok(())
    }
}
