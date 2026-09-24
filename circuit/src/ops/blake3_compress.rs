//! BLAKE3 compression non-primitive operation over a prime field.
//!
//! One call is one BLAKE3 compression. Its 32-bit words travel through the witness table as
//! little-endian 16-bit limb pairs (`lo`, `hi`), the packing `p3-blake3-air`'s `Blake3Air`
//! uses:
//!
//! ```text
//!     inputs  (56 limbs): block[0..16] ‖ chaining_value[0..8] ‖ counter_lo ‖ counter_hi
//!                         ‖ block_len ‖ flags
//!     outputs (32 limbs): the 16-word compression output
//! ```
//!
//! The first 8 output words are the next chaining value; all 16 form the extended output.
//! Every limb is a base-field element; a value that is not a base-field integer below `2^16` is
//! an execution error, and the AIR rejects it through its bit decompositions.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;

use p3_field::{ExtensionField, Field, PrimeField64};

use crate::CircuitError;
use crate::builder::{CircuitBuilderError, NpoCircuitPlugin, NpoLoweringContext};
use crate::ops::keccak_perm::{LimbFn, limb_fn};
use crate::ops::{ExecutionContext, NonPrimitiveExecutor, NpoTypeId, Op, PreprocessedWriter};
use crate::tables::{NonPrimitiveTrace, TraceGeneratorFn};
use crate::types::{ExprId, WitnessId};

/// 32-bit words read by one compression: 16 block words, 8 chaining-value words, then the
/// counter's low and high words, the block length and the flags.
pub const BLAKE3_INPUT_WORDS: usize = 28;
/// 32-bit words one compression outputs.
pub const BLAKE3_OUTPUT_WORDS: usize = 16;
/// Input limbs of one compression.
pub const BLAKE3_INPUT_LIMBS: usize = 2 * BLAKE3_INPUT_WORDS;
/// Output limbs of one compression.
pub const BLAKE3_OUTPUT_LIMBS: usize = 2 * BLAKE3_OUTPUT_WORDS;

/// BLAKE3's initialization vector, which is also the key of the unkeyed hash.
pub const BLAKE3_IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// Domain flags of a BLAKE3 compression.
pub mod blake3_flags {
    /// First block of a chunk.
    pub const CHUNK_START: u32 = 1;
    /// Last block of a chunk.
    pub const CHUNK_END: u32 = 2;
    /// A parent node of the chunk tree.
    pub const PARENT: u32 = 4;
    /// The root of the tree, whose output is the hash.
    pub const ROOT: u32 = 8;
}

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// The BLAKE3 compression function: 7 rounds over `chaining_value`, `block` and the counter,
/// length and flags words, returning the 16-word extended output.
pub fn blake3_compress(input: &[u32; BLAKE3_INPUT_WORDS]) -> [u32; BLAKE3_OUTPUT_WORDS] {
    let mut block: [u32; 16] = core::array::from_fn(|i| input[i]);
    let cv: [u32; 8] = core::array::from_fn(|i| input[16 + i]);
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        BLAKE3_IV[0],
        BLAKE3_IV[1],
        BLAKE3_IV[2],
        BLAKE3_IV[3],
        input[24],
        input[25],
        input[26],
        input[27],
    ];
    for round in 0..7 {
        g(&mut state, 0, 4, 8, 12, block[0], block[1]);
        g(&mut state, 1, 5, 9, 13, block[2], block[3]);
        g(&mut state, 2, 6, 10, 14, block[4], block[5]);
        g(&mut state, 3, 7, 11, 15, block[6], block[7]);
        g(&mut state, 0, 5, 10, 15, block[8], block[9]);
        g(&mut state, 1, 6, 11, 12, block[10], block[11]);
        g(&mut state, 2, 7, 8, 13, block[12], block[13]);
        g(&mut state, 3, 4, 9, 14, block[14], block[15]);
        if round < 6 {
            block = core::array::from_fn(|i| block[MSG_PERMUTATION[i]]);
        }
    }
    core::array::from_fn(|i| {
        if i < 8 {
            state[i] ^ state[i + 8]
        } else {
            state[i] ^ cv[i - 8]
        }
    })
}

/// Split words into their little-endian 16-bit limb pairs.
pub fn words_to_limbs(words: &[u32]) -> Vec<u16> {
    words
        .iter()
        .flat_map(|&w| [w as u16, (w >> 16) as u16])
        .collect()
}

/// Reassemble words from their little-endian 16-bit limb pairs.
pub fn limbs_to_words(limbs: &[u16]) -> Vec<u32> {
    limbs
        .chunks_exact(2)
        .map(|pair| u32::from(pair[0]) | (u32::from(pair[1]) << 16))
        .collect()
}

// ============================================================================
// Execution State
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct Blake3CompressConfig;

/// One compression captured during execution.
#[derive(Debug, Clone)]
pub struct Blake3CompressCircuitRow {
    /// Witness IDs of the [`BLAKE3_INPUT_LIMBS`] input limbs.
    pub input_wids: Vec<WitnessId>,
    /// Witness IDs of the [`BLAKE3_OUTPUT_LIMBS`] output limbs.
    pub output_wids: Vec<WitnessId>,
    /// The input words.
    pub input: [u32; BLAKE3_INPUT_WORDS],
}

/// Execution state collecting every BLAKE3 compression.
#[derive(Debug, Default)]
pub struct Blake3CompressExecutionState {
    pub rows: Vec<Blake3CompressCircuitRow>,
}

// ============================================================================
// Executor
// ============================================================================

/// Executor for BLAKE3 compressions.
pub struct Blake3CompressExecutor<F> {
    op_type: NpoTypeId,
    limb_fn: LimbFn<F>,
}

impl<F> Clone for Blake3CompressExecutor<F> {
    fn clone(&self) -> Self {
        Self {
            op_type: self.op_type.clone(),
            limb_fn: Arc::clone(&self.limb_fn),
        }
    }
}

impl<F> Debug for Blake3CompressExecutor<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blake3CompressExecutor")
            .field("op_type", &self.op_type)
            .finish()
    }
}

fn check_layout(
    op_type: &NpoTypeId,
    inputs: &[Vec<WitnessId>],
    outputs: &[Vec<WitnessId>],
) -> Result<(), CircuitError> {
    if inputs.len() != 1 || inputs[0].len() != BLAKE3_INPUT_LIMBS {
        return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
            op: op_type.clone(),
            expected: format!("1 input group with {BLAKE3_INPUT_LIMBS} limbs"),
            got: inputs.first().map_or(0, Vec::len),
        });
    }
    if outputs.len() != 1 || outputs[0].len() != BLAKE3_OUTPUT_LIMBS {
        return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
            op: op_type.clone(),
            expected: format!("1 output group with {BLAKE3_OUTPUT_LIMBS} limbs"),
            got: outputs.first().map_or(0, Vec::len),
        });
    }
    Ok(())
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for Blake3CompressExecutor<F> {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        check_layout(&self.op_type, inputs, outputs)?;

        let mut limbs = [0u16; BLAKE3_INPUT_LIMBS];
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
        let input: [u32; BLAKE3_INPUT_WORDS] = limbs_to_words(&limbs)
            .try_into()
            .expect("56 limbs are 28 words");
        let output = blake3_compress(&input);
        for (&limb, &wid) in words_to_limbs(&output).iter().zip(&outputs[0]) {
            ctx.set_witness(wid, F::from_u16(limb))?;
        }

        let state = ctx.get_op_state_mut::<Blake3CompressExecutionState>(&self.op_type);
        state.rows.push(Blake3CompressCircuitRow {
            input_wids: inputs[0].clone(),
            output_wids: outputs[0].clone(),
            input,
        });
        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    /// Per call: `[active, in_idx × 56, (out_idx, out_mult) × 32]`.
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

pub(crate) struct Blake3CompressCircuitPlugin<F: Field> {
    trace_gen: TraceGeneratorFn<F>,
    limb_fn: LimbFn<F>,
}

impl<F: Field> Debug for Blake3CompressCircuitPlugin<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blake3CompressCircuitPlugin").finish()
    }
}

impl<F: Field> NpoCircuitPlugin<F> for Blake3CompressCircuitPlugin<F> {
    fn type_id(&self) -> NpoTypeId {
        NpoTypeId::blake3_compress()
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
        if data.input_exprs.len() != BLAKE3_INPUT_LIMBS
            || data.input_exprs.iter().any(|slot| slot.len() != 1)
        {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Blake3Compress",
                expected: format!("{BLAKE3_INPUT_LIMBS} single-limb input slots"),
                got: data.input_exprs.len(),
            });
        }
        if output_exprs.len() != BLAKE3_OUTPUT_LIMBS {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Blake3Compress",
                expected: format!("{BLAKE3_OUTPUT_LIMBS} output limbs"),
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
                ctx.resolve_witness_id(slot[0], || format!("Blake3Compress input limb {i}"))
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
                details: "BLAKE3 output limbs must be indexed 0..32 without gaps".into(),
            });
        }
        let output_wids = ordered
            .iter()
            .map(|&(index, expr)| {
                ctx.resolve_witness_id(expr, || format!("Blake3Compress output limb {index}"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![input_wids],
            outputs: vec![output_wids],
            executor: Box::new(Blake3CompressExecutor {
                op_type: NpoTypeId::blake3_compress(),
                limb_fn: Arc::clone(&self.limb_fn),
            }),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<F> {
        self.trace_gen
    }

    fn config(&self) -> crate::ops::NpoConfig {
        crate::ops::NpoConfig::new(Blake3CompressConfig)
    }
}

// SAFETY: as for the Keccak-f plugin: a bare `fn` pointer and an `Arc<dyn Fn + Send + Sync>`,
// with no `F` value stored.
unsafe impl<F: Field> Send for Blake3CompressCircuitPlugin<F> {}
unsafe impl<F: Field> Sync for Blake3CompressCircuitPlugin<F> {}

// ============================================================================
// Builder API
// ============================================================================

impl<F> crate::CircuitBuilder<F>
where
    F: Field + Eq + core::hash::Hash,
{
    /// Enables BLAKE3 compressions in a circuit over `F ⊇ BF`.
    ///
    /// # Panics
    ///
    /// If `BF` has at most `2^16` elements: a limb must be a distinct base-field integer.
    pub fn enable_blake3_compress<BF>(&mut self)
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        assert!(
            BF::ORDER_U64 > 1 << 16,
            "BLAKE3 limbs need a base field with more than 2^16 elements"
        );
        self.register_npo(Blake3CompressCircuitPlugin {
            trace_gen: generate_blake3_compress_trace::<F>,
            limb_fn: limb_fn::<BF, F>(),
        });
    }

    /// One BLAKE3 compression of [`BLAKE3_INPUT_LIMBS`] input limbs (block, chaining value,
    /// counter words, block length and flags, each word as a little-endian limb pair);
    /// returns the [`BLAKE3_OUTPUT_LIMBS`] output limbs.
    ///
    /// # Errors
    ///
    /// - [`CircuitBuilderError::OpNotAllowed`] unless [`Self::enable_blake3_compress`] ran
    ///   first.
    /// - [`CircuitBuilderError::NonPrimitiveOpArity`] for an input of the wrong width.
    pub fn add_blake3_compress(
        &mut self,
        input: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        let op_type = NpoTypeId::blake3_compress();
        self.ensure_op_enabled(&op_type)?;
        if input.len() != BLAKE3_INPUT_LIMBS {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Blake3Compress",
                expected: format!("{BLAKE3_INPUT_LIMBS} input limbs"),
                got: input.len(),
            });
        }
        let (_, _, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            input.iter().map(|&limb| vec![limb]).collect(),
            vec![Some("blake3_compress_out"); BLAKE3_OUTPUT_LIMBS],
            None,
            "blake3_compress",
        );
        Ok(outputs
            .into_iter()
            .map(|out| out.expect("every BLAKE3 output limb is requested"))
            .collect())
    }
}

/// Bytes BLAKE3 compresses per call.
pub const BLAKE3_BLOCK_BYTES: usize = 64;
/// Bytes in one BLAKE3 chunk, the most [`crate::CircuitBuilder::blake3_limbs`] hashes.
pub const BLAKE3_CHUNK_BYTES: usize = 1024;

impl<F> crate::CircuitBuilder<F>
where
    F: Field + Eq + core::hash::Hash,
{
    /// BLAKE3 of a message given as little-endian 16-bit limbs (an even number of bytes, at
    /// most one 1024-byte chunk); returns the digest as 16 limbs.
    ///
    /// The chunk's 64-byte blocks are compressed in order, each chaining value being the first
    /// eight output words of the previous block. The first block carries `CHUNK_START`, the last
    /// `CHUNK_END | ROOT` and its true length; the counter is zero; a partial final block is
    /// zero-padded. The empty message is one empty block.
    ///
    /// # Errors
    ///
    /// - [`CircuitBuilderError::NonPrimitiveOpArity`] for a message longer than one chunk, which
    ///   needs BLAKE3's chunk tree.
    /// - As [`Self::add_blake3_compress`].
    pub fn blake3_limbs<BF>(
        &mut self,
        message: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        const BLOCK_LIMBS: usize = BLAKE3_BLOCK_BYTES / 2;
        if 2 * message.len() > BLAKE3_CHUNK_BYTES {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Blake3Hash",
                expected: format!("at most {BLAKE3_CHUNK_BYTES} message bytes (one chunk)"),
                got: 2 * message.len(),
            });
        }

        let constant_words = |builder: &mut Self, words: &[u32]| -> Vec<ExprId> {
            words_to_limbs(words)
                .into_iter()
                .map(|limb| builder.define_const(F::from_u16(limb)))
                .collect::<Vec<_>>()
        };

        let blocks: Vec<&[ExprId]> = if message.is_empty() {
            vec![&[]]
        } else {
            message.chunks(BLOCK_LIMBS).collect()
        };
        let zero = self.define_const(F::ZERO);
        let mut cv = constant_words(self, &BLAKE3_IV);
        for (i, block) in blocks.iter().enumerate() {
            let last = i + 1 == blocks.len();
            let mut flags = 0;
            if i == 0 {
                flags |= blake3_flags::CHUNK_START;
            }
            if last {
                flags |= blake3_flags::CHUNK_END | blake3_flags::ROOT;
            }
            let block_len = 2 * block.len() as u32;

            let mut input = block.to_vec();
            input.resize(BLOCK_LIMBS, zero);
            input.extend_from_slice(&cv);
            input.extend(constant_words(self, &[0, 0, block_len, flags]));
            let out = self.add_blake3_compress(&input)?;
            cv = out[..16].to_vec();
        }
        Ok(cv)
    }

    /// `CompressionFunctionFromHasher<Blake3, 2, 32>`: BLAKE3 of the 64-byte concatenation of two
    /// 16-limb digests, one compression.
    ///
    /// # Errors
    ///
    /// [`CircuitBuilderError::NonPrimitiveOpArity`] for a digest of the wrong width, or as
    /// [`Self::blake3_limbs`].
    pub fn blake3_compress_digests<BF>(
        &mut self,
        left: &[ExprId],
        right: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        for digest in [left, right] {
            if digest.len() != 16 {
                return Err(CircuitBuilderError::NonPrimitiveOpArity {
                    op: "Blake3Compress",
                    expected: "16 limbs per digest".into(),
                    got: digest.len(),
                });
            }
        }
        let mut message = left.to_vec();
        message.extend_from_slice(right);
        self.blake3_limbs::<BF>(&message)
    }

    /// `SerializingHasher<Blake3>` of base-field elements, the leaf hash of a BLAKE3 Merkle tree.
    ///
    /// # Errors
    ///
    /// As [`Self::serialize_field_elements_to_limbs`] and [`Self::blake3_limbs`].
    pub fn blake3_field_elements<BF>(
        &mut self,
        elements: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        let limbs = self.serialize_field_elements_to_limbs::<BF>(elements)?;
        self.blake3_limbs::<BF>(&limbs)
    }
}

// ============================================================================
// Trace
// ============================================================================

/// Every BLAKE3 compression a circuit run made, in execution order.
#[derive(Debug, Clone)]
pub struct Blake3CompressTrace {
    pub operations: Vec<Blake3CompressCircuitRow>,
}

impl<CF> NonPrimitiveTrace<CF> for Blake3CompressTrace {
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::blake3_compress()
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

/// Collects the BLAKE3 compressions of a run into a [`Blake3CompressTrace`].
pub fn generate_blake3_compress_trace<F>(
    op_states: &crate::ops::OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    let Some(state) = op_states
        .get(&NpoTypeId::blake3_compress())
        .and_then(|s| s.downcast_ref::<Blake3CompressExecutionState>())
    else {
        return Ok(None);
    };
    if state.rows.is_empty() {
        return Ok(None);
    }
    Ok(Some(Box::new(Blake3CompressTrace {
        operations: state.rows.clone(),
    })))
}
