//! BLAKE3 compression over raw native binary coordinates.
//!
//! One call consumes 56 raw 16-bit limbs (sixteen block words, eight chaining
//! value words, the two counter words, the block length and the flags, each as
//! a low/high limb pair) and produces the 16 limbs of the output chaining
//! value. The native hash AIR supplied by the native binary circuit backend
//! range-constrains every input and output limb.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use crate::builder::{NonPrimitiveOperationData, NpoLoweringContext};
use crate::ops::binary_native::BinaryCoordinateField;
use crate::ops::blake3_compress::{
    BLAKE3_INPUT_LIMBS, BLAKE3_INPUT_WORDS, blake3_compress, limbs_to_words, words_to_limbs,
};
use crate::ops::native_keccak::check_field;
use crate::ops::{ExecutionContext, NonPrimitiveExecutor, NpoConfig, NpoTypeId, Op};
use crate::tables::TraceGeneratorFn;
use crate::{
    CircuitBuilder, CircuitBuilderError, CircuitError, ExprId, NpoCircuitPlugin, WitnessId,
};

/// Output limbs of one native compression: the eight-word chaining value.
pub const NATIVE_BLAKE3_OUTPUT_LIMBS: usize = 16;

impl<F: BinaryCoordinateField> CircuitBuilder<F> {
    /// Enables native BLAKE3 compression calls over raw 16-bit limbs.
    /// Requires at least 16 independent coordinates in the carrier field.
    pub fn enable_native_blake3_compress(&mut self) -> Result<(), CircuitBuilderError> {
        check_field::<F>()?;
        self.check_construction_limits()?;
        self.register_npo(NativeBlake3Plugin);
        Ok(())
    }

    /// Compresses one block. The input is the 56 limbs of the block words,
    /// chaining value, counter, block length and flags, in that order; the
    /// output is the 16 limbs of the new chaining value. Inputs and outputs
    /// are range-constrained by the native hash AIR.
    pub fn add_native_blake3_compress(
        &mut self,
        input: &[ExprId],
    ) -> Result<[ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS], CircuitBuilderError> {
        check_field::<F>()?;
        self.check_construction_limits()?;
        let op = NpoTypeId::native_blake3_compress();
        self.ensure_op_enabled(&op)?;
        if input.len() != BLAKE3_INPUT_LIMBS {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "NativeBlake3Compress",
                expected: format!("{BLAKE3_INPUT_LIMBS} raw limbs"),
                got: input.len(),
            });
        }
        let outputs = self
            .push_non_primitive_op_with_outputs(
                op,
                input.iter().map(|&limb| vec![limb]).collect(),
                vec![Some("native_blake3_out"); NATIVE_BLAKE3_OUTPUT_LIMBS],
                None,
                "native_blake3_compress",
            )
            .2
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(CircuitBuilderError::MissingOutput)?;
        self.check_construction_limits()?;
        Ok(outputs
            .try_into()
            .expect("requested 16 native BLAKE3 outputs"))
    }
}

#[derive(Debug)]
struct NativeBlake3Plugin;

impl<F: BinaryCoordinateField> NpoCircuitPlugin<F> for NativeBlake3Plugin {
    fn type_id(&self) -> NpoTypeId {
        NpoTypeId::native_blake3_compress()
    }

    fn lower(
        &self,
        data: &NonPrimitiveOperationData<F>,
        output_exprs: &[(u32, ExprId)],
        ctx: &mut NpoLoweringContext<'_, F>,
    ) -> Result<Op<F>, CircuitBuilderError> {
        if data.params.is_some() {
            return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                op: data.op_type.clone(),
            });
        }
        if data.input_exprs.len() != BLAKE3_INPUT_LIMBS
            || data.input_exprs.iter().any(|slot| slot.len() != 1)
        {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "NativeBlake3Compress",
                expected: format!("{BLAKE3_INPUT_LIMBS} single-limb inputs"),
                got: data.input_exprs.len(),
            });
        }
        let mut ordered = output_exprs.to_vec();
        ordered.sort_unstable_by_key(|&(index, _)| index);
        if ordered.len() != NATIVE_BLAKE3_OUTPUT_LIMBS
            || ordered
                .iter()
                .enumerate()
                .any(|(i, &(index, _))| i != index as usize)
        {
            return Err(CircuitBuilderError::MalformedNonPrimitiveOutputs {
                op_id: data.op_id,
                details: "native BLAKE3 outputs must be indexed 0..16 without gaps".into(),
            });
        }
        let inputs = data
            .input_exprs
            .iter()
            .enumerate()
            .map(|(i, slot)| ctx.resolve_witness_id(slot[0], || format!("native BLAKE3 input {i}")))
            .collect::<Result<Vec<_>, _>>()?;
        for &(_, expr) in &ordered {
            ctx.ensure_witness_id(expr);
        }
        let outputs = ordered
            .iter()
            .map(|&(i, expr)| ctx.resolve_witness_id(expr, || format!("native BLAKE3 output {i}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![inputs],
            outputs: vec![outputs],
            executor: Box::new(NativeBlake3Executor {
                op: NpoTypeId::native_blake3_compress(),
            }),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<F> {
        // The native backend regenerates the hash trace from its frozen call
        // input IDs and the canonical witness assignment. No runner record is
        // trusted to specify wiring or call order.
        |_| Ok(None)
    }
    fn config(&self) -> NpoConfig {
        NpoConfig::new(())
    }
}

#[derive(Clone, Debug)]
struct NativeBlake3Executor {
    op: NpoTypeId,
}

impl<F: BinaryCoordinateField> NonPrimitiveExecutor<F> for NativeBlake3Executor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1
            || inputs[0].len() != BLAKE3_INPUT_LIMBS
            || outputs.len() != 1
            || outputs[0].len() != NATIVE_BLAKE3_OUTPUT_LIMBS
        {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op.clone(),
                expected: "one input group of 56 and one output group of 16 raw limbs".into(),
                got: inputs.first().map_or(0, Vec::len),
            });
        }
        let mut limbs = [0u16; BLAKE3_INPUT_LIMBS];
        for (limb, &id) in limbs.iter_mut().zip(&inputs[0]) {
            let value = ctx.get_witness(id)?;
            *limb = u16::try_from(value.to_raw_coordinates()).map_err(|_| {
                CircuitError::InvalidNonPrimitiveOpInput {
                    op: self.op.clone(),
                    witness_id: id,
                    expected: "at most 16 raw binary coordinates",
                    got: value.to_string(),
                }
            })?;
        }
        let words: [u32; BLAKE3_INPUT_WORDS] = limbs_to_words(&limbs)
            .try_into()
            .expect("56 limbs form 28 words");
        let output = blake3_compress(&words);
        for (raw, &id) in words_to_limbs(&output[..8]).into_iter().zip(&outputs[0]) {
            ctx.set_witness(
                id,
                F::from_raw_coordinates(raw.into()).expect("checked native limb width"),
            )?;
        }
        Ok(())
    }
    fn op_type(&self) -> &NpoTypeId {
        &self.op
    }
    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}
