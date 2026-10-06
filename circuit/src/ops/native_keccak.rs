//! Keccak over raw native binary coordinates.
//!
//! The dedicated operation has a distinct identity from prime integer-limb
//! Keccak. Its native AIR and fixed indexed wiring are supplied by the native
//! binary circuit backend; the legacy count-based preprocessor is not used.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

use crate::builder::{NonPrimitiveOperationData, NpoLoweringContext};
use crate::ops::binary_native::BinaryCoordinateField;
use crate::ops::keccak_perm::{
    KECCAK_STATE_LIMBS, KECCAK256_RATE_BYTES, keccak_limbs_to_state, keccak_state_to_limbs,
};
use crate::ops::{ExecutionContext, NonPrimitiveExecutor, NpoConfig, NpoTypeId, Op};
use crate::tables::TraceGeneratorFn;
use crate::{
    CircuitBuilder, CircuitBuilderError, CircuitError, ExprId, NpoCircuitPlugin, WitnessId,
};

impl<F: BinaryCoordinateField> CircuitBuilder<F> {
    /// Enables native Keccak-f calls with 100 low-first raw 16-bit limbs.
    /// Requires at least 16 independent coordinates in the carrier field.
    pub fn enable_native_keccak_f1600(&mut self) -> Result<(), CircuitBuilderError> {
        check_field::<F>()?;
        self.check_construction_limits()?;
        self.register_npo(NativeKeccakPlugin);
        Ok(())
    }

    /// Applies Keccak-f to raw 16-coordinate limbs. Inputs and outputs are
    /// range-constrained by the native hash AIR, rather than integer codecs.
    /// All IDs must belong to this builder's graph.
    pub fn add_native_keccak_f1600(
        &mut self,
        state: &[ExprId],
    ) -> Result<[ExprId; KECCAK_STATE_LIMBS], CircuitBuilderError> {
        check_field::<F>()?;
        self.check_construction_limits()?;
        let op = NpoTypeId::native_keccak_f1600();
        self.ensure_op_enabled(&op)?;
        if state.len() != KECCAK_STATE_LIMBS {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "NativeKeccakF1600",
                expected: format!("{KECCAK_STATE_LIMBS} raw limbs"),
                got: state.len(),
            });
        }
        let outputs = self
            .push_non_primitive_op_with_outputs(
                op,
                state.iter().map(|&limb| vec![limb]).collect(),
                vec![Some("native_keccak_out"); KECCAK_STATE_LIMBS],
                None,
                "native_keccak_f1600",
            )
            .2
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(CircuitBuilderError::MissingOutput)?;
        self.check_construction_limits()?;
        Ok(outputs
            .try_into()
            .expect("requested 100 native Keccak outputs"))
    }

    /// Keccak-256 of low-first raw sixteen-coordinate words.
    ///
    /// Each word is serialized as two little-endian bytes. The native Keccak
    /// AIR and its complete wiring argument constrain every absorbed word and
    /// output limb to sixteen coordinates, without a byte-codec round trip.
    /// Enable the native permutation before calling this.
    pub fn native_keccak256_words(
        &mut self,
        words: &[ExprId],
    ) -> Result<[ExprId; 16], CircuitBuilderError> {
        check_field::<F>()?;
        self.check_construction_limits()?;
        self.ensure_op_enabled(&NpoTypeId::native_keccak_f1600())?;
        const RATE_WORDS: usize = KECCAK256_RATE_BYTES / 2;
        let padded_len = (words.len() / RATE_WORDS)
            .checked_add(1)
            .and_then(|blocks| blocks.checked_mul(RATE_WORDS))
            .ok_or_else(|| CircuitBuilderError::NonPrimitiveOpArity {
                op: "NativeKeccak256Words",
                expected: "a representable padded word length".into(),
                got: words.len(),
            })?;
        let mut padded = words.to_vec();
        padded.push(self.define_const(F::from_raw_coordinates(1).expect("native one")));
        padded.resize(padded_len, ExprId::ZERO);
        let high = self.define_const(F::from_raw_coordinates(0x8000).expect("checked limb width"));
        let last = padded.last_mut().expect("at least one padding block");
        *last = self.add(*last, high);
        let mut state = [ExprId::ZERO; KECCAK_STATE_LIMBS];
        for block in padded.as_chunks::<RATE_WORDS>().0 {
            for (limb, &word) in state.iter_mut().zip(block) {
                *limb = self.add(*limb, word);
            }
            state = self.add_native_keccak_f1600(&state)?;
        }
        Ok(state[..16].try_into().expect("sixteen digest limbs"))
    }

    /// Keccak-256 of any fixed byte length, including odd lengths.
    ///
    /// Bytes are checked raw eight-coordinate values. Absorption uses native
    /// field addition (bitwise XOR), with Keccak's 0x01/0x80 padding and natural
    /// digest byte order. Enable the native permutation before calling this.
    pub fn native_keccak256_bytes(
        &mut self,
        message: &[ExprId],
    ) -> Result<[ExprId; 32], CircuitBuilderError> {
        check_field::<F>()?;
        self.check_construction_limits()?;
        self.ensure_op_enabled(&NpoTypeId::native_keccak_f1600())?;
        let blocks = message.len() / KECCAK256_RATE_BYTES + 1;
        let padded_len = blocks.checked_mul(KECCAK256_RATE_BYTES).ok_or_else(|| {
            CircuitBuilderError::NonPrimitiveOpArity {
                op: "NativeKeccak256",
                expected: "a representable padded message length".into(),
                got: message.len(),
            }
        })?;
        let mut padded = message.to_vec();
        padded.push(self.define_const(F::from_raw_coordinates(1).expect("native one")));
        padded.resize(padded_len, ExprId::ZERO);
        let high = self.define_const(F::from_raw_coordinates(0x80).expect("checked byte width"));
        let last = padded.last_mut().expect("at least one padding block");
        *last = self.add(*last, high);
        let mut state = [ExprId::ZERO; KECCAK_STATE_LIMBS];
        for block in padded.as_chunks::<KECCAK256_RATE_BYTES>().0 {
            for (i, bytes) in block.as_chunks::<2>().0.iter().enumerate() {
                let mut bits = self.binary_decompose_coordinates(bytes[0], 8)?;
                bits.extend(self.binary_decompose_coordinates(bytes[1], 8)?);
                let limb = self.binary_recompose_coordinates(&bits)?;
                state[i] = self.add(state[i], limb);
                self.check_construction_limits()?;
            }
            state = self.add_native_keccak_f1600(&state)?;
        }
        let mut digest = Vec::with_capacity(32);
        for limb in &state[..16] {
            let bits = self.binary_decompose_coordinates(*limb, 16)?;
            digest.push(self.binary_recompose_coordinates(&bits[..8])?);
            digest.push(self.binary_recompose_coordinates(&bits[8..])?);
        }
        Ok(digest
            .try_into()
            .expect("sixteen low-first limbs produce 32 bytes"))
    }
}

const fn check_field<F: BinaryCoordinateField>() -> Result<(), CircuitBuilderError> {
    if F::COORDINATE_BITS < 16 {
        Err(CircuitBuilderError::InvalidDimension {
            expected: 16,
            actual: F::COORDINATE_BITS,
        })
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct NativeKeccakPlugin;

impl<F: BinaryCoordinateField> NpoCircuitPlugin<F> for NativeKeccakPlugin {
    fn type_id(&self) -> NpoTypeId {
        NpoTypeId::native_keccak_f1600()
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
        if data.input_exprs.len() != KECCAK_STATE_LIMBS
            || data.input_exprs.iter().any(|slot| slot.len() != 1)
        {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "NativeKeccakF1600",
                expected: format!("{KECCAK_STATE_LIMBS} single-limb inputs"),
                got: data.input_exprs.len(),
            });
        }
        let mut ordered = output_exprs.to_vec();
        ordered.sort_unstable_by_key(|&(index, _)| index);
        if ordered.len() != KECCAK_STATE_LIMBS
            || ordered
                .iter()
                .enumerate()
                .any(|(i, &(index, _))| i != index as usize)
        {
            return Err(CircuitBuilderError::MalformedNonPrimitiveOutputs {
                op_id: data.op_id,
                details: "native Keccak outputs must be indexed 0..100 without gaps".into(),
            });
        }
        let inputs = data
            .input_exprs
            .iter()
            .enumerate()
            .map(|(i, slot)| ctx.resolve_witness_id(slot[0], || format!("native Keccak input {i}")))
            .collect::<Result<Vec<_>, _>>()?;
        for &(_, expr) in &ordered {
            ctx.ensure_witness_id(expr);
        }
        let outputs = ordered
            .iter()
            .map(|&(i, expr)| ctx.resolve_witness_id(expr, || format!("native Keccak output {i}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![inputs],
            outputs: vec![outputs],
            executor: Box::new(NativeKeccakExecutor {
                op: NpoTypeId::native_keccak_f1600(),
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
struct NativeKeccakExecutor {
    op: NpoTypeId,
}

impl<F: BinaryCoordinateField> NonPrimitiveExecutor<F> for NativeKeccakExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1
            || inputs[0].len() != KECCAK_STATE_LIMBS
            || outputs.len() != 1
            || outputs[0].len() != KECCAK_STATE_LIMBS
        {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op.clone(),
                expected: "one input and output group of 100 raw limbs".into(),
                got: inputs.first().map_or(0, Vec::len),
            });
        }
        let mut limbs = [0u16; KECCAK_STATE_LIMBS];
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
        let mut state = keccak_limbs_to_state(&limbs);
        KeccakF.permute_mut(&mut state);
        for (raw, &id) in keccak_state_to_limbs(&state).into_iter().zip(&outputs[0]) {
            ctx.set_witness(
                id,
                F::from_raw_coordinates(raw as u128).expect("checked native limb width"),
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
