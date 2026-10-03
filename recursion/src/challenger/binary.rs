//! Byte-hash challenger for the 128-bit Wiedemann binary tower.
//!
//! This matches `BinaryChallenger<BinaryField128, HashChallenger<u8, H, 32>>`
//! with `H = p3_keccak::Keccak256Hash` or `H = p3_blake3::Blake3`.
//! Transcript buffers hold individual bytes, supporting observations and
//! samples of any byte length. All methods must use
//! one [`CircuitBuilder`] expression graph: [`ExprId`] has no graph owner to
//! let this type detect targets copied from another builder.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, PrimeField64};

/// A circuit transcript for raw binary-tower observations and byte-hash samples.
///
/// Both private buffers hold natural-order bytes, constrained to eight bits.
/// The fixed [`ByteHash`] choice is part of the circuit relation, and its
/// corresponding Keccak-f or BLAKE3 non-primitive operation must be enabled
/// before a sample needs a refill. A failed fallible method preserves this
/// challenger's state for retry; expressions or constraints already emitted by
/// the builder before that error may remain in the builder.
#[derive(Clone, Debug)]
pub struct BinaryTower128Challenger {
    hash: ByteHash,
    input_buffer: Vec<ExprId>,
    output_buffer: Vec<ExprId>,
}

/// The exact retained hash input at native rejection-sampling completion.
/// The varying number of unsampled output bytes is inaccessible: a nonempty next
/// observation discards them in both native and circuit transcripts.
#[derive(Debug)]
pub struct BinaryQueryContinuation {
    hash: ByteHash,
    digest: [ExprId; 32],
}

impl BinaryQueryContinuation {
    pub(crate) const fn from_digest(hash: ByteHash, digest: [ExprId; 32]) -> Self {
        Self { hash, digest }
    }

    /// Resumes by absorbing the next protocol observation exactly once. Empty
    /// observations are rejected because they would retain a proof-dependent
    /// native output buffer. All targets must belong to this builder.
    pub fn resume_with_observation<BF, EF>(
        self,
        circuit: &mut CircuitBuilder<EF>,
        bytes: &[ExprId],
    ) -> Result<BinaryTower128Challenger, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        if bytes.is_empty() {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryQueryContinuation",
                expected: "a nonempty next observation".into(),
                got: 0,
            });
        }
        let mut challenger = BinaryTower128Challenger {
            hash: self.hash,
            input_buffer: self.digest.to_vec(),
            output_buffer: Vec::new(),
        };
        challenger.observe_bytes::<BF, EF>(circuit, bytes)?;
        Ok(challenger)
    }
}

impl BinaryTower128Challenger {
    /// A positive-width field draw or uniform-bit draw leaves the full forward
    /// digest as the retained input, including when no output remains.
    pub(crate) fn retained_query_digest(
        &self,
    ) -> Result<(ByteHash, [ExprId; 32]), CircuitBuilderError> {
        let digest = self.input_buffer.as_slice().try_into().map_err(|_| {
            CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryQueryDigest",
                expected: "32 retained bytes after a query draw".into(),
                got: self.input_buffer.len(),
            }
        })?;
        Ok((self.hash, digest))
    }

    /// Selects one equal-shape continuation under constrained one-hot selectors.
    /// Every branch must use the same builder and hash.
    pub(crate) fn select_same_shape<EF: p3_field::Field + Eq + Hash>(
        circuit: &mut CircuitBuilder<EF>,
        branches: &[(ExprId, Self)],
    ) -> Result<Self, CircuitBuilderError> {
        let Some((_, first)) = branches.first() else {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryChallengerSelect",
                expected: "at least one branch".into(),
                got: 0,
            });
        };
        if branches.iter().any(|(_, branch)| {
            branch.hash != first.hash
                || branch.input_buffer.len() != first.input_buffer.len()
                || branch.output_buffer.len() != first.output_buffer.len()
        }) {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryChallengerSelect",
                expected: "matching hashes and buffer lengths".into(),
                got: branches.len(),
            });
        }
        let mut total = ExprId::ZERO;
        for (selector, _) in branches {
            circuit.assert_bool(*selector);
            total = circuit.add(total, *selector);
        }
        let one = circuit.define_const(EF::ONE);
        let difference = circuit.sub(one, total);
        circuit.assert_zero(difference);
        let mut select = |output: bool, len: usize| {
            (0..len)
                .map(|i| {
                    branches
                        .iter()
                        .fold(ExprId::ZERO, |sum, (selector, branch)| {
                            let byte = if output {
                                branch.output_buffer[i]
                            } else {
                                branch.input_buffer[i]
                            };
                            circuit.mul_add(*selector, byte, sum)
                        })
                })
                .collect()
        };
        let input_buffer = select(false, first.input_buffer.len());
        let output_buffer = select(true, first.output_buffer.len());
        Ok(Self {
            hash: first.hash,
            input_buffer,
            output_buffer,
        })
    }

    /// Starts an empty byte transcript with the fixed hash choice.
    ///
    /// `Keccak256` matches `p3_keccak::Keccak256Hash`; `Blake3` matches
    /// `p3_blake3::Blake3`. A builder is needed only for later operations.
    pub const fn new(hash: ByteHash) -> Self {
        Self {
            hash,
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
        }
    }

    /// Starts with the exact bytes of `initial`: each natural-order limb
    /// contributes its low byte followed by its high byte, with no length tag
    /// or padding. This represents only empty or even-byte initial transcripts.
    /// Every supplied limb is constrained to a base-field integer in `0..=65535`.
    /// All IDs must belong to `circuit`'s expression graph.
    ///
    /// # Errors
    /// Rejects characteristic two or a base field of order at most 65535
    /// before adding constraints, then propagates limb decomposition errors.
    pub fn with_initial_limbs<BF, EF>(
        circuit: &mut CircuitBuilder<EF>,
        hash: ByteHash,
        initial: &[ExprId],
    ) -> Result<Self, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Self::check_limb_field::<BF, EF>("binary128_challenger_with_initial_limbs")?;
        let bytes = Self::bytes_from_limbs::<BF, EF>(circuit, initial)?;
        Ok(Self {
            hash,
            input_buffer: bytes,
            output_buffer: Vec::new(),
        })
    }

    /// Starts with an exact byte string, without a length tag or padding.
    /// Every input is constrained to a base-field integer in `0..=255`.
    /// IDs must belong to `circuit`'s expression graph.
    ///
    /// # Errors
    /// Rejects an unsupported host field before adding constraints, then
    /// propagates byte decomposition errors.
    pub fn with_initial_bytes<BF, EF>(
        circuit: &mut CircuitBuilder<EF>,
        hash: ByteHash,
        initial: &[ExprId],
    ) -> Result<Self, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Self::check_limb_field::<BF, EF>("binary_challenger_with_initial_bytes")?;
        for &byte in initial {
            circuit.decompose_to_bits::<BF>(byte, 8)?;
        }
        Ok(Self {
            hash,
            input_buffer: initial.to_vec(),
            output_buffer: Vec::new(),
        })
    }

    /// Observes an exact byte string. Every byte is constrained to `0..=255`.
    /// A nonempty observation discards unsampled output and appends to the
    /// next hash input. An empty observation leaves the transcript unchanged.
    /// IDs must belong to `circuit`'s expression graph.
    ///
    /// # Errors
    /// Rejects an unsupported host field before adding constraints, then
    /// propagates decomposition errors. On error, challenger state is unchanged.
    pub fn observe_bytes<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        bytes: &[ExprId],
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Self::check_limb_field::<BF, EF>("binary_challenger_observe_bytes")?;
        for &byte in bytes {
            circuit.decompose_to_bits::<BF>(byte, 8)?;
        }
        if !bytes.is_empty() {
            self.output_buffer.clear();
            self.input_buffer.extend_from_slice(bytes);
        }
        Ok(())
    }

    /// Draws `count` bytes from the back of the digest, spanning chained
    /// refills when necessary. This matches native sampling of binary elements
    /// whose serialized widths total `count`. A zero count consumes nothing.
    /// Returned expressions are constrained to `0..=255`.
    ///
    /// # Errors
    /// Rejects an unsupported host field before adding constraints, then
    /// propagates hash and decomposition errors. On error, challenger state
    /// is unchanged; expressions already emitted by the builder may remain.
    pub fn sample_bytes<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        count: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Self::check_limb_field::<BF, EF>("binary_challenger_sample_bytes")?;
        let mut staged = self.clone();
        let result = staged.sample_stream_bytes::<BF, EF>(circuit, count)?;
        *self = staged;
        Ok(result)
    }

    /// Observes a checked tower target as its 16 raw little-endian bytes.
    /// This appends sixteen low-first bytes to the next hash input and discards
    /// any unsampled output. The target must belong to `circuit`'s graph.
    ///
    /// # Errors
    /// Rejects an unsupported field before adding constraints, then propagates
    /// checked tower export errors. On error, challenger state is unchanged.
    pub fn observe<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        value: &BinaryTower128Target,
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Self::check_limb_field::<BF, EF>("binary128_challenger_observe")?;
        let mut staged = self.clone();
        staged.observe_inner::<BF, EF>(circuit, value)?;
        *self = staged;
        Ok(())
    }

    /// Observes checked tower targets in slice order. An empty slice leaves
    /// the transcript unchanged on a supported host field. All targets must
    /// belong to `circuit`'s expression graph.
    ///
    /// # Errors
    /// Rejects an unsupported field before adding constraints, then propagates
    /// checked tower export errors. On error, challenger state is unchanged.
    pub fn observe_slice<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        values: &[BinaryTower128Target],
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Self::check_limb_field::<BF, EF>("binary128_challenger_observe_slice")?;
        let mut staged = self.clone();
        for value in values {
            staged.observe_inner::<BF, EF>(circuit, value)?;
        }
        *self = staged;
        Ok(())
    }

    /// Observes exactly 32 digest bytes as sixteen natural-order little-endian
    /// limbs. Every supplied limb is constrained to a base-field integer in
    /// `0..=65535`. Observation discards unsampled output but preserves the
    /// full previous digest in the next hash input. IDs must belong to
    /// `circuit`'s expression graph.
    ///
    /// # Errors
    /// Rejects an unsupported field before adding constraints, then propagates
    /// limb decomposition errors. On error, challenger state is unchanged.
    pub fn observe_digest<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        digest: &[ExprId; 16],
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Self::check_limb_field::<BF, EF>("binary128_challenger_observe_digest")?;
        let mut staged = self.clone();
        let bytes = Self::bytes_from_limbs::<BF, EF>(circuit, digest)?;
        staged.output_buffer.clear();
        staged.input_buffer.extend(bytes);
        *self = staged;
        Ok(())
    }

    /// Draws 16 bytes as one checked raw `BinaryField128` tower element.
    /// Bytes are popped from the back of the current digest and may span a
    /// chained refill. A refill hashes the entire forward input with the
    /// selected byte hash, requiring its NPO to be enabled on `circuit`.
    ///
    /// # Errors
    /// Rejects an unsupported field before adding constraints, then propagates
    /// hash and checked tower ingress errors. On error, challenger state is
    /// unchanged, although the builder may retain expressions or constraints.
    pub fn sample<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryTower128Target, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Self::check_limb_field::<BF, EF>("binary128_challenger_sample")?;
        let mut staged = self.clone();
        let stream = staged.sample_stream_bytes::<BF, EF>(circuit, 16)?;
        let mut bits = Vec::with_capacity(128);
        for byte in stream {
            bits.extend(circuit.decompose_to_bits::<BF>(byte, 8)?);
        }
        let result = circuit.binary128_from_bits(
            bits.try_into()
                .expect("sixteen sampled bytes form one binary tower element"),
        )?;
        *self = staged;
        Ok(result)
    }

    /// Draws eight bytes as a little-endian `u64` and returns its lowest
    /// `bits` Boolean targets. Even `bits == 0` consumes all eight bytes.
    /// The draw may cross a chained digest refill.
    ///
    /// # Errors
    /// Rejects `bits >= usize::BITS` or an unsupported field before adding
    /// constraints, then propagates hash and limb decomposition errors. On
    /// error, challenger state is unchanged; the builder may retain work.
    pub fn sample_bits<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        bits: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Self::check_bit_count(bits)?;
        Self::check_limb_field::<BF, EF>("binary128_challenger_sample_bits")?;
        let mut staged = self.clone();
        let result = staged.sample_bits_inner::<BF, EF>(circuit, bits)?;
        *self = staged;
        Ok(result)
    }

    /// Checks a canonical binary tower PoW witness by observing its raw 16
    /// bytes, drawing eight bytes, and constraining the lowest `bits` to zero.
    /// At zero difficulty this is a complete no-op, including no field guard.
    /// Native grinding search and its separate search-margin bound are outside
    /// this verifier operation. The witness must belong to `circuit`'s graph.
    ///
    /// # Errors
    /// For nonzero difficulty, rejects `bits >= usize::BITS` or an unsupported
    /// field before adding constraints, then propagates hash/decomposition
    /// errors. On error, challenger state is unchanged; builder work may remain.
    pub fn check_witness<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        bits: usize,
        witness: &BinaryTower128Target,
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        if bits == 0 {
            return Ok(());
        }
        Self::check_bit_count(bits)?;
        Self::check_limb_field::<BF, EF>("binary128_challenger_check_witness")?;
        let mut staged = self.clone();
        staged.observe_inner::<BF, EF>(circuit, witness)?;
        for bit in staged.sample_bits_inner::<BF, EF>(circuit, bits)? {
            circuit.assert_zero(bit);
        }
        *self = staged;
        Ok(())
    }

    fn observe_inner<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        value: &BinaryTower128Target,
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let bytes: Vec<_> = value
            .bits()
            .chunks(8)
            .map(|bits| circuit.reconstruct_index_from_bits::<BF>(bits))
            .collect::<Result<_, _>>()?;
        self.output_buffer.clear();
        self.input_buffer.extend(bytes);
        Ok(())
    }

    fn sample_bits_inner<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        bits: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let stream = self.sample_stream_bytes::<BF, EF>(circuit, 8)?;
        let mut result = Vec::with_capacity(bits);
        for byte in stream {
            result.extend(circuit.decompose_to_bits::<BF>(byte, 8)?);
        }
        result.truncate(bits);
        Ok(result)
    }

    fn sample_stream_bytes<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        count: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut stream = Vec::with_capacity(count);
        while stream.len() < count {
            if self.output_buffer.is_empty() {
                // Native HashChallenger hashes the whole forward message and
                // retains that complete digest for the next chained refill.
                let digest = circuit.byte_hash_bytes::<BF>(self.hash, &self.input_buffer)?;
                let bytes = Self::bytes_from_limbs::<BF, EF>(circuit, &digest)?;
                self.input_buffer.clone_from(&bytes);
                self.output_buffer = bytes;
            }
            stream.push(
                self.output_buffer
                    .pop()
                    .expect("a byte hash refill yields thirty-two digest bytes"),
            );
        }
        Ok(stream)
    }

    fn bytes_from_limbs<BF, EF>(
        circuit: &mut CircuitBuilder<EF>,
        limbs: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut bytes = Vec::with_capacity(2 * limbs.len());
        for &limb in limbs {
            let bits = circuit.decompose_to_bits::<BF>(limb, 16)?;
            for byte in bits.chunks(8) {
                bytes.push(circuit.reconstruct_index_from_bits::<BF>(byte)?);
            }
        }
        Ok(bytes)
    }

    const fn check_bit_count(bits: usize) -> Result<(), CircuitBuilderError> {
        if bits >= usize::BITS as usize {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: usize::BITS as usize - 1,
                n_bits: bits,
            });
        }
        Ok(())
    }

    fn check_limb_field<BF, EF>(operation: &'static str) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF>,
    {
        if EF::TWO == EF::ZERO {
            return Err(CircuitBuilderError::CharacteristicTwoUnsupported { operation });
        }
        if BF::ORDER_U64 <= u64::from(u16::MAX) {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: BF::ORDER_U64.ilog2() as usize,
                n_bits: 16,
            });
        }
        Ok(())
    }
}
