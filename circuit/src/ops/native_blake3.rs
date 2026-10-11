//! BLAKE3 compression over raw native binary coordinates.
//!
//! One call consumes 56 raw 16-bit limbs (sixteen block words, eight chaining
//! value words, the two counter words, the block length and the flags, each as
//! a low/high limb pair) and produces the 16 limbs of the output chaining
//! value, optionally followed by the same 16 limbs with their two bytes
//! swapped. The native hash AIR supplied by the native binary circuit backend
//! range-constrains every input and output limb.
//!
//! The BLAKE3 hash of words or bytes runs the standard chunk and tree
//! schedule over these calls. A compression whose chaining value and block
//! are known while building is computed natively instead of becoming a call.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use crate::builder::{NonPrimitiveOperationData, NpoLoweringContext};
use crate::ops::binary_native::BinaryCoordinateField;
use crate::ops::blake3_compress::{
    BLAKE3_BLOCK_BYTES, BLAKE3_CHUNK_BYTES, BLAKE3_INPUT_LIMBS, BLAKE3_INPUT_WORDS, BLAKE3_IV,
    blake3_compress, blake3_flags, limbs_to_words, words_to_limbs,
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
        let outputs = self.push_native_blake3_compress(input, false)?;
        Ok(outputs
            .try_into()
            .expect("requested 16 native BLAKE3 outputs"))
    }

    /// Compresses one block like [`Self::add_native_blake3_compress`], and
    /// also returns the output limbs with their two bytes swapped: swapped
    /// limb `m` has the raw coordinates of output limb `m` with coordinates
    /// `0..8` and `8..16` exchanged. Both are outputs of the same call. The
    /// native bus backend derives them from the same output bits of its hash
    /// AIR, so they are range-constrained like every other output limb.
    pub fn add_native_blake3_compress_with_swapped_digest(
        &mut self,
        input: &[ExprId],
    ) -> Result<
        (
            [ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS],
            [ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS],
        ),
        CircuitBuilderError,
    > {
        let outputs = self.push_native_blake3_compress(input, true)?;
        let (limbs, swapped) = outputs.split_at(NATIVE_BLAKE3_OUTPUT_LIMBS);
        Ok((
            limbs
                .try_into()
                .expect("requested 16 native BLAKE3 outputs"),
            swapped
                .try_into()
                .expect("requested 16 swapped digest limbs"),
        ))
    }

    fn push_native_blake3_compress(
        &mut self,
        input: &[ExprId],
        swapped_digest: bool,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
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
        let mut names = vec![Some("native_blake3_out"); NATIVE_BLAKE3_OUTPUT_LIMBS];
        if swapped_digest {
            names.extend([Some("native_blake3_swapped_digest"); NATIVE_BLAKE3_OUTPUT_LIMBS]);
        }
        let outputs = self
            .push_non_primitive_op_with_outputs(
                op,
                input.iter().map(|&limb| vec![limb]).collect(),
                names,
                None,
                "native_blake3_compress",
            )
            .2
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(CircuitBuilderError::MissingOutput)?;
        self.check_construction_limits()?;
        Ok(outputs)
    }

    /// BLAKE3 of low-first raw sixteen-coordinate words.
    ///
    /// Each word is serialized as two little-endian bytes, so the message has
    /// `2 * words.len()` bytes; the digest is returned as 16 low-first limbs.
    /// A word read by a native compression is a block input, which its AIR
    /// constrains to sixteen coordinates. A block whose chaining value is
    /// known while building and whose words are all circuit constants below
    /// `2^16` is compressed while building, as is a parent of two known
    /// chaining values; a wider constant word stays in a native compression,
    /// which rejects it. A constant message has a constant digest. Enable the
    /// native compression before calling this.
    pub fn native_blake3_words(
        &mut self,
        words: &[ExprId],
    ) -> Result<[ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS], CircuitBuilderError> {
        let root = self.native_blake3_words_root(words, false)?;
        Ok(self
            .native_blake3_wire(&cv_limbs(root))?
            .try_into()
            .expect("a chaining value has 16 limbs"))
    }

    /// [`Self::native_blake3_words`] with each digest limb also returned
    /// with its two bytes swapped, as in
    /// [`Self::add_native_blake3_compress_with_swapped_digest`]. The swapped
    /// limbs are outputs of the root compression call, or circuit constants
    /// when the root is compressed while building.
    pub fn native_blake3_words_with_swapped_digest(
        &mut self,
        words: &[ExprId],
    ) -> Result<
        (
            [ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS],
            [ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS],
        ),
        CircuitBuilderError,
    > {
        let root = self.native_blake3_words_root(words, true)?;
        self.native_blake3_swapped_digest(root)
    }

    /// The root chaining value of [`Self::native_blake3_words`]. With
    /// `swapped_digest`, a root compression call also outputs its swapped
    /// digest limbs.
    fn native_blake3_words_root(
        &mut self,
        words: &[ExprId],
        swapped_digest: bool,
    ) -> Result<Cv, CircuitBuilderError> {
        check_field::<F>()?;
        self.check_construction_limits()?;
        self.ensure_op_enabled(&NpoTypeId::native_blake3_compress())?;
        let limbs: Vec<_> = words
            .iter()
            .map(|&word| {
                self.constant_raw(word, 16)
                    .map_or(Limb::Wired(word), Limb::Raw)
            })
            .collect();
        self.native_blake3_message(&limbs, 2 * words.len(), swapped_digest)
    }

    /// BLAKE3 of any byte length, including odd lengths.
    ///
    /// Bytes are checked raw eight-coordinate values, packed low-first in
    /// pairs into sixteen-coordinate block limbs. An odd last byte is paired
    /// with a zero byte, and block lengths count only message bytes. A pair of
    /// circuit constants below `2^8` is a constant limb; any other pair is
    /// range-checked by bit decomposition. Constant blocks are compressed
    /// while building as in [`Self::native_blake3_words`], and a constant
    /// message has a constant digest. The digest is returned as 32 bytes in
    /// natural order. Enable the native compression before calling this.
    pub fn native_blake3_bytes(
        &mut self,
        message: &[ExprId],
    ) -> Result<[ExprId; 32], CircuitBuilderError> {
        let root = self.native_blake3_bytes_root(message, false)?;
        let mut digest = Vec::with_capacity(32);
        for limb in cv_limbs(root) {
            match limb {
                Limb::Raw(raw) => {
                    for byte in raw.to_le_bytes() {
                        digest.push(self.define_const(
                            F::from_raw_coordinates(byte.into()).expect("checked byte width"),
                        ));
                    }
                }
                Limb::Wired(limb) => {
                    let bits = self.binary_decompose_coordinates(limb, 16)?;
                    digest.push(self.binary_recompose_coordinates(&bits[..8])?);
                    digest.push(self.binary_recompose_coordinates(&bits[8..])?);
                }
            }
        }
        self.check_construction_limits()?;
        Ok(digest
            .try_into()
            .expect("sixteen low-first limbs produce 32 bytes"))
    }

    /// The BLAKE3 digest of [`Self::native_blake3_bytes`] as sixteen
    /// low-first limbs, each also returned with its two bytes swapped, as in
    /// [`Self::native_blake3_words_with_swapped_digest`]. The digest is not
    /// split into bytes.
    pub fn native_blake3_bytes_with_swapped_digest(
        &mut self,
        message: &[ExprId],
    ) -> Result<
        (
            [ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS],
            [ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS],
        ),
        CircuitBuilderError,
    > {
        let root = self.native_blake3_bytes_root(message, true)?;
        self.native_blake3_swapped_digest(root)
    }

    /// The root chaining value of [`Self::native_blake3_bytes`]. With
    /// `swapped_digest`, a root compression call also outputs its swapped
    /// digest limbs.
    fn native_blake3_bytes_root(
        &mut self,
        message: &[ExprId],
        swapped_digest: bool,
    ) -> Result<Cv, CircuitBuilderError> {
        check_field::<F>()?;
        self.check_construction_limits()?;
        self.ensure_op_enabled(&NpoTypeId::native_blake3_compress())?;
        let mut limbs = Vec::with_capacity(message.len().div_ceil(2));
        for pair in message.chunks(2) {
            let low = pair[0];
            let high = pair.get(1).copied().unwrap_or(ExprId::ZERO);
            let limb = match (self.constant_raw(low, 8), self.constant_raw(high, 8)) {
                (Some(low), Some(high)) => Limb::Raw(low | high << 8),
                _ => {
                    let mut bits = self.binary_decompose_coordinates(low, 8)?;
                    bits.extend(self.binary_decompose_coordinates(high, 8)?);
                    Limb::Wired(self.binary_recompose_coordinates(&bits)?)
                }
            };
            limbs.push(limb);
            self.check_construction_limits()?;
        }
        self.native_blake3_message(&limbs, message.len(), swapped_digest)
    }

    /// The digest limbs of a root chaining value and their byte-swapped
    /// copies: the outputs of a root compression call that outputs them, or
    /// constants for a root compressed while building.
    fn native_blake3_swapped_digest(
        &mut self,
        root: Cv,
    ) -> Result<
        (
            [ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS],
            [ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS],
        ),
        CircuitBuilderError,
    > {
        let digest = self
            .native_blake3_wire(&cv_limbs(root))?
            .try_into()
            .expect("a chaining value has 16 limbs");
        let swapped = match root {
            Cv::Known(words) => {
                let swapped: Vec<_> = words_to_limbs(&words)
                    .into_iter()
                    .map(|raw| Limb::Raw(raw.swap_bytes()))
                    .collect();
                self.native_blake3_wire(&swapped)?
                    .try_into()
                    .expect("a chaining value has 16 limbs")
            }
            Cv::Wired(_, swapped) => {
                swapped.expect("a root call asked for its swapped digest outputs them")
            }
        };
        Ok((digest, swapped))
    }

    /// The root chaining value of BLAKE3 over `message` limbs that hold
    /// `message_bytes` bytes. The message is split into 1024-byte chunks, and
    /// the empty message is one empty chunk. With `swapped_digest`, a root
    /// compression call also outputs its swapped digest limbs.
    fn native_blake3_message(
        &mut self,
        message: &[Limb],
        message_bytes: usize,
        swapped_digest: bool,
    ) -> Result<Cv, CircuitBuilderError> {
        let chunks: Vec<&[Limb]> = if message.is_empty() {
            vec![&[]]
        } else {
            message.chunks(CHUNK_LIMBS).collect()
        };
        let last_chunk_bytes = message_bytes - (chunks.len() - 1) * BLAKE3_CHUNK_BYTES;
        self.native_blake3_subtree(&chunks, last_chunk_bytes, 0, true, swapped_digest)
    }

    /// The chaining value of the subtree over `chunks`, whose first chunk has
    /// index `first`: a single chunk's own value, or the `PARENT` compression,
    /// keyed by the IV, of the left subtree (the largest power of two of
    /// chunks strictly fewer than all) and the right subtree. The node at the
    /// top also carries `ROOT`; `swapped_digest` is passed to every block.
    fn native_blake3_subtree(
        &mut self,
        chunks: &[&[Limb]],
        last_chunk_bytes: usize,
        first: u64,
        root: bool,
        swapped_digest: bool,
    ) -> Result<Cv, CircuitBuilderError> {
        if let [chunk] = chunks {
            return self.native_blake3_chunk(chunk, last_chunk_bytes, first, root, swapped_digest);
        }
        let left_len = 1 << (chunks.len() - 1).ilog2();
        let left = self.native_blake3_subtree(
            &chunks[..left_len],
            BLAKE3_CHUNK_BYTES,
            first,
            false,
            swapped_digest,
        )?;
        let right = self.native_blake3_subtree(
            &chunks[left_len..],
            last_chunk_bytes,
            first + left_len as u64,
            false,
            swapped_digest,
        )?;
        let mut block = cv_limbs(left).to_vec();
        block.extend(cv_limbs(right));
        let flags = if root {
            blake3_flags::PARENT | blake3_flags::ROOT
        } else {
            blake3_flags::PARENT
        };
        self.native_blake3_block(
            &block,
            Cv::Known(BLAKE3_IV),
            0,
            BLAKE3_BLOCK_BYTES as u32,
            flags,
            swapped_digest,
        )
    }

    /// The chaining value of chunk `index`: its 64-byte blocks compressed in
    /// order from the IV, with the chunk index as counter, the first with
    /// `CHUNK_START` and the last with `CHUNK_END` (and `ROOT` if `root`) and
    /// its true length. An empty chunk is one empty block. `swapped_digest`
    /// is passed to every block.
    fn native_blake3_chunk(
        &mut self,
        chunk: &[Limb],
        chunk_bytes: usize,
        index: u64,
        root: bool,
        swapped_digest: bool,
    ) -> Result<Cv, CircuitBuilderError> {
        let blocks: Vec<&[Limb]> = if chunk.is_empty() {
            vec![&[]]
        } else {
            chunk.chunks(BLOCK_LIMBS).collect()
        };
        let mut cv = Cv::Known(BLAKE3_IV);
        for (i, block) in blocks.iter().enumerate() {
            let last = i + 1 == blocks.len();
            let mut flags = 0;
            if i == 0 {
                flags |= blake3_flags::CHUNK_START;
            }
            if last {
                flags |= blake3_flags::CHUNK_END;
                if root {
                    flags |= blake3_flags::ROOT;
                }
            }
            let block_len = if last {
                chunk_bytes - i * BLAKE3_BLOCK_BYTES
            } else {
                BLAKE3_BLOCK_BYTES
            };
            cv = self.native_blake3_block(
                block,
                cv,
                index,
                block_len as u32,
                flags,
                swapped_digest,
            )?;
        }
        Ok(cv)
    }

    /// Compresses one block of at most 32 limbs, zero-padded. A known chaining
    /// value with raw block limbs is compressed while building; otherwise the
    /// block is a native compression call, with the raw limbs, a known
    /// chaining value, the counter, the block length and the flags as
    /// constants. With `swapped_digest`, a call with the `ROOT` flag also
    /// outputs its swapped digest limbs.
    fn native_blake3_block(
        &mut self,
        block: &[Limb],
        cv: Cv,
        counter: u64,
        block_len: u32,
        flags: u32,
        swapped_digest: bool,
    ) -> Result<Cv, CircuitBuilderError> {
        if let Cv::Known(cv) = cv {
            let raw = block
                .iter()
                .map(|&limb| match limb {
                    Limb::Raw(raw) => Some(raw),
                    Limb::Wired(_) => None,
                })
                .collect::<Option<Vec<_>>>();
            if let Some(mut raw) = raw {
                raw.resize(BLOCK_LIMBS, 0);
                let block = limbs_to_words(&raw)
                    .try_into()
                    .expect("32 limbs form 16 words");
                return Ok(Cv::Known(known_compression(
                    &block, &cv, counter, block_len, flags,
                )));
            }
        }
        let mut input = block.to_vec();
        input.resize(BLOCK_LIMBS, Limb::Raw(0));
        input.extend(cv_limbs(cv));
        input.extend(
            words_to_limbs(&tail_words(counter, block_len, flags))
                .into_iter()
                .map(Limb::Raw),
        );
        let input = self.native_blake3_wire(&input)?;
        if swapped_digest && flags & blake3_flags::ROOT != 0 {
            let (limbs, swapped) = self.add_native_blake3_compress_with_swapped_digest(&input)?;
            Ok(Cv::Wired(limbs, Some(swapped)))
        } else {
            Ok(Cv::Wired(self.add_native_blake3_compress(&input)?, None))
        }
    }

    /// Circuit values of `limbs`, with raw limbs as constants.
    fn native_blake3_wire(&mut self, limbs: &[Limb]) -> Result<Vec<ExprId>, CircuitBuilderError> {
        let wired = limbs
            .iter()
            .map(|&limb| match limb {
                Limb::Raw(raw) => self
                    .define_const(F::from_raw_coordinates(raw.into()).expect("checked limb width")),
                Limb::Wired(expr) => expr,
            })
            .collect();
        self.check_construction_limits()?;
        Ok(wired)
    }
}

const BLOCK_LIMBS: usize = BLAKE3_BLOCK_BYTES / 2;
const CHUNK_LIMBS: usize = BLAKE3_CHUNK_BYTES / 2;

/// A call outputs the chaining value, optionally followed by its swapped digest limbs.
const fn output_count_is_valid(count: usize) -> bool {
    count == NATIVE_BLAKE3_OUTPUT_LIMBS || count == 2 * NATIVE_BLAKE3_OUTPUT_LIMBS
}

/// A sixteen-coordinate limb: raw coordinates known while building, or a
/// circuit value. Raw limbs become circuit constants only where a native
/// compression call reads them.
#[derive(Clone, Copy)]
enum Limb {
    Raw(u16),
    Wired(ExprId),
}

/// A BLAKE3 chaining value: words known while building, or the output limbs
/// of a native compression call, with its swapped digest limbs when the call
/// outputs them.
#[derive(Clone, Copy)]
enum Cv {
    Known([u32; 8]),
    Wired(
        [ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS],
        Option<[ExprId; NATIVE_BLAKE3_OUTPUT_LIMBS]>,
    ),
}

/// The 16 low-first limbs of a chaining value.
fn cv_limbs(cv: Cv) -> [Limb; NATIVE_BLAKE3_OUTPUT_LIMBS] {
    match cv {
        Cv::Known(words) => {
            let raw = words_to_limbs(&words);
            core::array::from_fn(|i| Limb::Raw(raw[i]))
        }
        Cv::Wired(limbs, _) => limbs.map(Limb::Wired),
    }
}

/// The counter's low and high words, the block length and the flags.
const fn tail_words(counter: u64, block_len: u32, flags: u32) -> [u32; 4] {
    [counter as u32, (counter >> 32) as u32, block_len, flags]
}

/// The chaining value of one compression computed while building.
fn known_compression(
    block: &[u32; 16],
    cv: &[u32; 8],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 8] {
    let mut input = [0; BLAKE3_INPUT_WORDS];
    input[..16].copy_from_slice(block);
    input[16..24].copy_from_slice(cv);
    input[24..].copy_from_slice(&tail_words(counter, block_len, flags));
    let output = blake3_compress(&input);
    core::array::from_fn(|i| output[i])
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
        if !output_count_is_valid(ordered.len())
            || ordered
                .iter()
                .enumerate()
                .any(|(i, &(index, _))| i != index as usize)
        {
            return Err(CircuitBuilderError::MalformedNonPrimitiveOutputs {
                op_id: data.op_id,
                details: "native BLAKE3 outputs must be indexed 0..16 or 0..32 without gaps".into(),
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
            || !output_count_is_valid(outputs[0].len())
        {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op.clone(),
                expected: "one input group of 56 raw limbs and an output group of 16 or 32".into(),
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
        let output = words_to_limbs(&blake3_compress(&words)[..8]);
        let swapped: Vec<_> = output.iter().map(|raw| raw.swap_bytes()).collect();
        for (raw, &id) in output.into_iter().chain(swapped).zip(&outputs[0]) {
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
