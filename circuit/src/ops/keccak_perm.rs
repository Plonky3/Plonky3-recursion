//! Keccak-f\[1600\] non-primitive operation over a prime field.
//!
//! Keccak works on 64-bit lanes, which do not fit in a 31-bit field element, so the operation
//! exchanges the state with the witness table as 16-bit limbs, the representation
//! `p3-keccak-air`'s `KeccakAir` constrains:
//!
//! ```text
//!     limb 4·i + k  =  bits [16k, 16k + 16) of lane i,   i = x + 5·y,   k ∈ 0..4
//! ```
//!
//! Each call reads [`KECCAK_STATE_LIMBS`] input limbs and writes as many output limbs. Every
//! limb is a base-field element; a value that is not a base-field integer below `2^16` is an
//! execution error, and the AIR rejects it independently through its bit decompositions.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;

use p3_field::{ExtensionField, Field, PrimeField64};
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

use crate::CircuitError;
use crate::builder::{CircuitBuilderError, NpoCircuitPlugin, NpoLoweringContext};
use crate::ops::{ExecutionContext, NonPrimitiveExecutor, NpoTypeId, Op, PreprocessedWriter};
use crate::tables::{NonPrimitiveTrace, TraceGeneratorFn};
use crate::types::{ExprId, WitnessId};

/// Lanes in the Keccak-f\[1600\] state.
pub const KECCAK_LANES: usize = 25;
/// 16-bit limbs per 64-bit lane.
pub const KECCAK_LIMBS_PER_LANE: usize = 4;
/// Bits per limb.
pub const KECCAK_LIMB_BITS: usize = 16;
/// Limbs in the whole state, which is both the input and the output width of one call.
pub const KECCAK_STATE_LIMBS: usize = KECCAK_LANES * KECCAK_LIMBS_PER_LANE;

/// 16-bit limbs in a 32-byte Keccak-256 digest.
pub const KECCAK256_DIGEST_LIMBS: usize = 16;
/// Bytes absorbed per Keccak-256 block (the sponge rate).
pub const KECCAK256_RATE_BYTES: usize = 136;

/// The little-endian 16-bit limbs of a byte string of even length.
pub fn bytes_to_limbs(bytes: &[u8]) -> Vec<u16> {
    assert!(bytes.len().is_multiple_of(2), "limbs hold two bytes each");
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect()
}

/// Split a state into its little-endian 16-bit limbs, lane by lane.
pub fn keccak_state_to_limbs(state: &[u64; KECCAK_LANES]) -> [u16; KECCAK_STATE_LIMBS] {
    let mut limbs = [0u16; KECCAK_STATE_LIMBS];
    for (lane, chunk) in state
        .iter()
        .zip(limbs.chunks_exact_mut(KECCAK_LIMBS_PER_LANE))
    {
        for (k, limb) in chunk.iter_mut().enumerate() {
            *limb = (lane >> (KECCAK_LIMB_BITS * k)) as u16;
        }
    }
    limbs
}

/// Reassemble a state from its little-endian 16-bit limbs, lane by lane.
pub fn keccak_limbs_to_state(limbs: &[u16; KECCAK_STATE_LIMBS]) -> [u64; KECCAK_LANES] {
    core::array::from_fn(|lane| {
        limbs[lane * KECCAK_LIMBS_PER_LANE..(lane + 1) * KECCAK_LIMBS_PER_LANE]
            .iter()
            .enumerate()
            .fold(0u64, |acc, (k, &limb)| {
                acc | (u64::from(limb) << (KECCAK_LIMB_BITS * k))
            })
    })
}

// ============================================================================
// Configuration
// ============================================================================

/// Config payload stored in `NpoConfig` for the Keccak-f table.
#[derive(Debug, Clone)]
pub(crate) struct KeccakF1600Config;

// ============================================================================
// Execution State
// ============================================================================

/// One permutation call captured during execution.
#[derive(Debug, Clone)]
pub struct KeccakF1600CircuitRow {
    /// Witness IDs of the [`KECCAK_STATE_LIMBS`] input limbs.
    pub input_wids: Vec<WitnessId>,
    /// Witness IDs of the [`KECCAK_STATE_LIMBS`] output limbs.
    pub output_wids: Vec<WitnessId>,
    /// The input state.
    pub input: [u64; KECCAK_LANES],
    /// The permuted state.
    pub output: [u64; KECCAK_LANES],
}

/// Execution state collecting every Keccak-f call.
#[derive(Debug, Default)]
pub struct KeccakF1600ExecutionState {
    pub rows: Vec<KeccakF1600CircuitRow>,
}

// ============================================================================
// Executor
// ============================================================================

/// Reads a witness as a limb: `Some` only for a base-field integer below `2^16`.
pub(crate) type LimbFn<F> = Arc<dyn Fn(&F) -> Option<u16> + Send + Sync>;

/// Executor for Keccak-f\[1600\] calls.
pub struct KeccakF1600Executor<F> {
    op_type: NpoTypeId,
    limb_fn: LimbFn<F>,
}

impl<F> Clone for KeccakF1600Executor<F> {
    fn clone(&self) -> Self {
        Self {
            op_type: self.op_type.clone(),
            limb_fn: Arc::clone(&self.limb_fn),
        }
    }
}

impl<F> Debug for KeccakF1600Executor<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeccakF1600Executor")
            .field("op_type", &self.op_type)
            .finish()
    }
}

impl<F> KeccakF1600Executor<F> {
    pub(crate) fn new(limb_fn: LimbFn<F>) -> Self {
        Self {
            op_type: NpoTypeId::keccak_f1600(),
            limb_fn,
        }
    }
}

fn check_layout(
    op_type: &NpoTypeId,
    inputs: &[Vec<WitnessId>],
    outputs: &[Vec<WitnessId>],
) -> Result<(), CircuitError> {
    if inputs.len() != 1 || inputs[0].len() != KECCAK_STATE_LIMBS {
        return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
            op: op_type.clone(),
            expected: format!("1 input group with {KECCAK_STATE_LIMBS} limbs"),
            got: inputs.first().map_or(0, Vec::len),
        });
    }
    if outputs.len() != 1 || outputs[0].len() != KECCAK_STATE_LIMBS {
        return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
            op: op_type.clone(),
            expected: format!("1 output group with {KECCAK_STATE_LIMBS} limbs"),
            got: outputs.first().map_or(0, Vec::len),
        });
    }
    Ok(())
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for KeccakF1600Executor<F> {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        check_layout(&self.op_type, inputs, outputs)?;

        let mut limbs = [0u16; KECCAK_STATE_LIMBS];
        for (limb, &wid) in limbs.iter_mut().zip(&inputs[0]) {
            let value = ctx.get_witness(wid)?;
            *limb =
                (self.limb_fn)(&value).ok_or_else(|| CircuitError::InvalidNonPrimitiveOpInput {
                    op: self.op_type.clone(),
                    witness_id: wid,
                    expected: "a base-field integer below 2^16",
                    got: value.to_string(),
                })?;
        }

        let input = keccak_limbs_to_state(&limbs);
        let mut output = input;
        KeccakF.permute_mut(&mut output);

        for (&limb, &wid) in keccak_state_to_limbs(&output).iter().zip(&outputs[0]) {
            ctx.set_witness(wid, F::from_u16(limb))?;
        }

        let state = ctx.get_op_state_mut::<KeccakF1600ExecutionState>(&self.op_type);
        state.rows.push(KeccakF1600CircuitRow {
            input_wids: inputs[0].clone(),
            output_wids: outputs[0].clone(),
            input,
            output,
        });
        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    /// Per call: `[active, in_idx × 100, (out_idx, out_mult) × 100]`.
    ///
    /// The input indices count as bus reads; every output is a bus creator whose multiplicity
    /// placeholder the prover-side preprocessor replaces with its read count.
    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut dyn PreprocessedWriter<F>,
    ) -> Result<(), CircuitError> {
        check_layout(&self.op_type, inputs, outputs)?;
        preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ONE]);
        preprocessed.register_non_primitive_witness_reads(&self.op_type, &inputs[0])?;
        for &wid in &outputs[0] {
            preprocessed.register_non_primitive_output_index(&self.op_type, &[wid]);
            preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ONE]);
        }
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

/// Circuit-layer plugin for Keccak-f\[1600\] calls.
pub(crate) struct KeccakF1600CircuitPlugin<F: Field> {
    trace_gen: TraceGeneratorFn<F>,
    limb_fn: LimbFn<F>,
}

impl<F: Field> KeccakF1600CircuitPlugin<F> {
    pub(crate) fn new(trace_gen: TraceGeneratorFn<F>, limb_fn: LimbFn<F>) -> Self {
        Self { trace_gen, limb_fn }
    }
}

impl<F: Field> Debug for KeccakF1600CircuitPlugin<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeccakF1600CircuitPlugin").finish()
    }
}

impl<F: Field> NpoCircuitPlugin<F> for KeccakF1600CircuitPlugin<F> {
    fn type_id(&self) -> NpoTypeId {
        NpoTypeId::keccak_f1600()
    }

    fn lower(
        &self,
        data: &crate::builder::NonPrimitiveOperationData<F>,
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
                op: "KeccakF1600",
                expected: format!("{KECCAK_STATE_LIMBS} single-limb input slots"),
                got: data.input_exprs.len(),
            });
        }
        if output_exprs.len() != KECCAK_STATE_LIMBS {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "KeccakF1600",
                expected: format!("{KECCAK_STATE_LIMBS} output limbs"),
                got: output_exprs.len(),
            });
        }

        for (_, expr) in output_exprs {
            ctx.ensure_witness_id(*expr);
        }
        let input_wids = data
            .input_exprs
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                ctx.resolve_witness_id(slot[0], || format!("KeccakF1600 input limb {i}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut ordered: Vec<(u32, ExprId)> = output_exprs.to_vec();
        ordered.sort_unstable_by_key(|&(index, _)| index);
        if ordered
            .iter()
            .enumerate()
            .any(|(position, &(index, _))| index as usize != position)
        {
            return Err(CircuitBuilderError::MalformedNonPrimitiveOutputs {
                op_id: data.op_id,
                details: "Keccak-f output limbs must be indexed 0..100 without gaps".into(),
            });
        }
        let output_wids = ordered
            .iter()
            .map(|&(index, expr)| {
                ctx.resolve_witness_id(expr, || format!("KeccakF1600 output limb {index}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![input_wids],
            outputs: vec![output_wids],
            executor: Box::new(KeccakF1600Executor::new(Arc::clone(&self.limb_fn))),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<F> {
        self.trace_gen
    }

    fn config(&self) -> crate::ops::NpoConfig {
        crate::ops::NpoConfig::new(KeccakF1600Config)
    }
}

// SAFETY: `trace_gen` is a bare `fn` pointer and `limb_fn` is an
// `Arc<dyn Fn(..) + Send + Sync>`; no `F` value is stored, so both markers hold for every `F`.
// They are explicit because `NpoCircuitPlugin: Send + Sync` and the generic `F` would otherwise
// make the auto-derived bounds conditional on `F`.
unsafe impl<F: Field> Send for KeccakF1600CircuitPlugin<F> {}
unsafe impl<F: Field> Sync for KeccakF1600CircuitPlugin<F> {}

/// Builds the limb reader for a circuit over `F ⊇ BF`.
pub(crate) fn limb_fn<BF, F>() -> LimbFn<F>
where
    BF: PrimeField64,
    F: ExtensionField<BF>,
{
    Arc::new(|value: &F| {
        let coeffs = value.as_basis_coefficients_slice();
        if coeffs[1..].iter().any(|c| !c.is_zero()) {
            return None;
        }
        u16::try_from(coeffs[0].as_canonical_u64()).ok()
    })
}

// ============================================================================
// Builder API
// ============================================================================

impl<F> crate::CircuitBuilder<F>
where
    F: Field + Eq + core::hash::Hash,
{
    /// Enables Keccak-f\[1600\] calls in a circuit over `F ⊇ BF`.
    ///
    /// # Panics
    ///
    /// If `BF` has at most `2^16` elements: a limb must be a distinct base-field integer.
    pub fn enable_keccak_f1600<BF>(&mut self)
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        assert!(
            BF::ORDER_U64 > 1 << KECCAK_LIMB_BITS,
            "Keccak-f limbs need a base field with more than 2^16 elements"
        );
        self.register_npo(KeccakF1600CircuitPlugin::new(
            generate_keccak_f1600_trace::<F>,
            limb_fn::<BF, F>(),
        ));
    }

    /// Applies Keccak-f\[1600\] to a state given as [`KECCAK_STATE_LIMBS`] 16-bit limbs.
    ///
    /// Limb `4·i + k` is bits `[16k, 16k + 16)` of lane `i = x + 5·y`. Returns the permuted
    /// state in the same layout. The limbs must be base-field integers below `2^16`; the
    /// Keccak-f table's bit decompositions enforce that when the circuit is proved.
    ///
    /// # Errors
    ///
    /// - [`CircuitBuilderError::OpNotAllowed`] unless [`Self::enable_keccak_f1600`] ran first.
    /// - [`CircuitBuilderError::NonPrimitiveOpArity`] for a state of the wrong width.
    pub fn add_keccak_f1600(
        &mut self,
        state: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        let op_type = NpoTypeId::keccak_f1600();
        self.ensure_op_enabled(&op_type)?;
        if state.len() != KECCAK_STATE_LIMBS {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "KeccakF1600",
                expected: format!("{KECCAK_STATE_LIMBS} input limbs"),
                got: state.len(),
            });
        }
        let (_, _, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            state.iter().map(|&limb| vec![limb]).collect(),
            vec![Some("keccak_f1600_out"); KECCAK_STATE_LIMBS],
            None,
            "keccak_f1600",
        );
        Ok(outputs
            .into_iter()
            .map(|out| out.expect("every Keccak-f output limb is requested"))
            .collect())
    }
}

impl<F> crate::CircuitBuilder<F>
where
    F: Field + Eq + core::hash::Hash,
{
    /// Keccak-256 of the 64-byte concatenation of two 32-byte digests, each given as
    /// [`KECCAK256_DIGEST_LIMBS`] little-endian 16-bit limbs; returns the digest in the same
    /// form.
    ///
    /// This is `CompressionFunctionFromHasher<Keccak256Hash, 2, 32>`, the node compression of a
    /// Keccak Merkle tree. The message fits in one 136-byte block, so the sponge is a single
    /// Keccak-f call on `left ‖ right ‖ pad`: no state is carried between blocks and nothing
    /// needs XOR-absorbing. Keccak-256 pads with `0x01` after the message and sets the top bit
    /// of the block's last byte.
    ///
    /// # Errors
    ///
    /// As [`Self::add_keccak_f1600`], or [`CircuitBuilderError::NonPrimitiveOpArity`] for a
    /// digest of the wrong width.
    pub fn keccak256_compress(
        &mut self,
        left: &[ExprId],
        right: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        for digest in [left, right] {
            if digest.len() != KECCAK256_DIGEST_LIMBS {
                return Err(CircuitBuilderError::NonPrimitiveOpArity {
                    op: "Keccak256Compress",
                    expected: format!("{KECCAK256_DIGEST_LIMBS} limbs per digest"),
                    got: digest.len(),
                });
            }
        }

        let mut block = [0u8; KECCAK256_RATE_BYTES];
        block[2 * 32] = 0x01;
        block[KECCAK256_RATE_BYTES - 1] |= 0x80;
        let padding = bytes_to_limbs(&block);

        let mut state = Vec::with_capacity(KECCAK_STATE_LIMBS);
        state.extend_from_slice(left);
        state.extend_from_slice(right);
        for &limb in &padding[state.len()..] {
            state.push(self.define_const(F::from_u16(limb)));
        }
        let zero = self.define_const(F::ZERO);
        state.resize(KECCAK_STATE_LIMBS, zero);

        let mut out = self.add_keccak_f1600(&state)?;
        out.truncate(KECCAK256_DIGEST_LIMBS);
        Ok(out)
    }
}

impl<F> crate::CircuitBuilder<F>
where
    F: Field + Eq + core::hash::Hash,
{
    /// The XOR of two 16-bit limbs, bit by bit: `a ⊕ b = a + b − 2ab`.
    ///
    /// Decomposing each operand into 16 bits also constrains it below `2^16`.
    fn xor_limb16<BF>(&mut self, a: ExprId, b: ExprId) -> Result<ExprId, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        let a_bits = self.decompose_to_bits::<BF>(a, KECCAK_LIMB_BITS)?;
        let b_bits = self.decompose_to_bits::<BF>(b, KECCAK_LIMB_BITS)?;
        let minus_two = self.define_const(-F::TWO);
        let mut limb = self.define_const(F::ZERO);
        for (i, (&x, &y)) in a_bits.iter().zip(&b_bits).enumerate() {
            let sum = self.add(x, y);
            let product = self.mul(x, y);
            let bit = self.mul_add(product, minus_two, sum);
            let weight = self.define_const(F::from_u32(1 << i));
            limb = self.mul_add(bit, weight, limb);
        }
        Ok(limb)
    }

    /// Keccak-256 of a message given as little-endian 16-bit limbs (an even number of bytes);
    /// returns the digest as [`KECCAK256_DIGEST_LIMBS`] limbs.
    ///
    /// The sponge absorbs one 136-byte block per Keccak-f call. The first block fills the zero
    /// state directly; every later block is XORed into the permuted state with a bitwise gadget.
    /// Padding is constant: `0x01` after the message and `0x80` in the last block's final byte.
    ///
    /// # Errors
    ///
    /// As [`Self::add_keccak_f1600`] and [`Self::decompose_to_bits`].
    pub fn keccak256_limbs<BF>(
        &mut self,
        message: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        const RATE_LIMBS: usize = KECCAK256_RATE_BYTES / 2;

        // The padded tail: `0x01` right after the message, `0x80` in the last byte of its block.
        let message_bytes = 2 * message.len();
        let padded_bytes = (message_bytes / KECCAK256_RATE_BYTES + 1) * KECCAK256_RATE_BYTES;
        let mut tail = vec![0u8; padded_bytes - message_bytes];
        tail[0] = 0x01;
        *tail.last_mut().expect("a padded message has a tail") |= 0x80;

        let mut padded: Vec<Option<ExprId>> = message.iter().copied().map(Some).collect();
        let mut constants: Vec<u16> = vec![0; message.len()];
        for limb in bytes_to_limbs(&tail) {
            padded.push(None);
            constants.push(limb);
        }

        let zero = self.define_const(F::ZERO);
        let mut state: Vec<ExprId> = Vec::new();
        for (block, (limbs, consts)) in padded
            .chunks_exact(RATE_LIMBS)
            .zip(constants.chunks_exact(RATE_LIMBS))
            .enumerate()
        {
            let mut next = Vec::with_capacity(KECCAK_STATE_LIMBS);
            for (j, (&limb, &constant)) in limbs.iter().zip(consts).enumerate() {
                let absorbed = match (limb, block) {
                    // A zero padding limb leaves the permuted state unchanged.
                    (None, _) if constant == 0 && block > 0 => state[j],
                    (None, _) => {
                        let value = self.define_const(F::from_u16(constant));
                        if block == 0 {
                            value
                        } else {
                            self.xor_limb16::<BF>(state[j], value)?
                        }
                    }
                    // The first block fills the all-zero initial state, so XOR is a copy.
                    (Some(expr), 0) => expr,
                    (Some(expr), _) => self.xor_limb16::<BF>(state[j], expr)?,
                };
                next.push(absorbed);
            }
            if block == 0 {
                next.resize(KECCAK_STATE_LIMBS, zero);
            } else {
                next.extend_from_slice(&state[RATE_LIMBS..]);
            }
            state = self.add_keccak_f1600(&next)?;
        }
        state.truncate(KECCAK256_DIGEST_LIMBS);
        Ok(state)
    }

    /// `SerializingHasher<Keccak256Hash>` of base-field elements: Keccak-256 of their
    /// canonical little-endian bytes, the leaf hash of a Keccak Merkle tree.
    ///
    /// # Errors
    ///
    /// As [`Self::serialize_field_elements_to_limbs`] and [`Self::keccak256_limbs`].
    pub fn keccak256_field_elements<BF>(
        &mut self,
        elements: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        let limbs = self.serialize_field_elements_to_limbs::<BF>(elements)?;
        self.keccak256_limbs::<BF>(&limbs)
    }
}

// ============================================================================
// Trace
// ============================================================================

/// Every Keccak-f call a circuit run made, in execution order.
#[derive(Debug, Clone)]
pub struct KeccakF1600Trace {
    pub operations: Vec<KeccakF1600CircuitRow>,
}

impl<CF> NonPrimitiveTrace<CF> for KeccakF1600Trace {
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::keccak_f1600()
    }

    fn rows(&self) -> usize {
        self.operations.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}

/// Collects the Keccak-f calls of a run into a [`KeccakF1600Trace`].
pub fn generate_keccak_f1600_trace<F>(
    op_states: &crate::ops::OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    let Some(state) = op_states
        .get(&NpoTypeId::keccak_f1600())
        .and_then(|s| s.downcast_ref::<KeccakF1600ExecutionState>())
    else {
        return Ok(None);
    };
    if state.rows.is_empty() {
        return Ok(None);
    }
    Ok(Some(Box::new(KeccakF1600Trace {
        operations: state.rows.clone(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limb_split_roundtrips_and_is_little_endian() {
        let state: [u64; KECCAK_LANES] =
            core::array::from_fn(|i| 0x0123_4567_89ab_cdef_u64.rotate_left(i as u32 * 7));
        let limbs = keccak_state_to_limbs(&state);
        assert_eq!(limbs[0], 0xcdef);
        assert_eq!(limbs[3], 0x0123);
        assert_eq!(keccak_limbs_to_state(&limbs), state);
    }
}
