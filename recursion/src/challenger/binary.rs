//! Byte-hash challenger for binary protocols with an explicit circuit carrier.
//!
//! This matches `BinaryChallenger<BinaryField128, HashChallenger<u8, H, 32>>`
//! with `H = p3_keccak::Keccak256Hash` or `H = p3_blake3::Blake3`.
//! Transcript buffers hold individual bytes, and the pending input may also
//! hold sixteen-bit words standing for their two little-endian bytes. This
//! supports observations and samples of any byte length. All methods must use
//! one [`CircuitBuilder`] expression graph: [`ExprId`] has no graph owner to
//! let this type detect targets copied from another builder.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_circuit::ops::binary_encoding::PrimeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryPoly64Target, BinaryPoly192Target, BinaryTower128Target, ByteHash};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};

/// A circuit transcript for raw binary-tower observations and byte-hash samples.
///
/// Both private buffers hold natural-order bytes, constrained to eight bits;
/// the input buffer may also hold sixteen-bit words, each standing for its two
/// little-endian bytes and range-checked when hashed.
/// The fixed [`ByteHash`] choice is part of the circuit relation, and its
/// corresponding Keccak-f or BLAKE3 non-primitive operation must be enabled
/// before a sample needs a refill. A failed fallible method preserves this
/// challenger's state for retry; expressions or constraints already emitted by
/// the builder before that error may remain in the builder.
#[derive(Clone, Debug)]
pub struct BinaryTower128Challenger {
    hash: ByteHash,
    input_buffer: Vec<Absorbed>,
    output_buffer: Vec<ExprId>,
}

/// One entry of the next hash input.
#[derive(Clone, Copy, Debug)]
enum Absorbed {
    Byte(ExprId),
    /// A low-first sixteen-bit word, absorbed as its two little-endian bytes.
    Word(ExprId),
}

impl Absorbed {
    const fn len(self) -> usize {
        match self {
            Self::Byte(_) => 1,
            Self::Word(_) => 2,
        }
    }

    const fn byte(self) -> Option<ExprId> {
        match self {
            Self::Byte(byte) => Some(byte),
            Self::Word(_) => None,
        }
    }
}

fn absorbed_bytes(bytes: &[ExprId]) -> impl Iterator<Item = Absorbed> + '_ {
    bytes.iter().map(|&byte| Absorbed::Byte(byte))
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
        self.resume_with_observation_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, bytes)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn resume_with_observation_with_host<H, EF>(
        self,
        circuit: &mut CircuitBuilder<EF>,
        bytes: &[ExprId],
    ) -> Result<BinaryTower128Challenger, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        if bytes.is_empty() {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryQueryContinuation",
                expected: "a nonempty next observation".into(),
                got: 0,
            });
        }
        let mut challenger = BinaryTower128Challenger {
            hash: self.hash,
            input_buffer: absorbed_bytes(&self.digest).collect(),
            output_buffer: Vec::new(),
        };
        challenger.observe_bytes_with_host::<H, EF>(circuit, bytes)?;
        Ok(challenger)
    }
}

impl BinaryTower128Challenger {
    /// A positive-width field draw or uniform-bit draw leaves the full forward
    /// digest as the retained input, including when no output remains.
    pub(crate) fn retained_query_digest(
        &self,
    ) -> Result<(ByteHash, [ExprId; 32]), CircuitBuilderError> {
        let bytes: Option<Vec<_>> = self.input_buffer.iter().map(|unit| unit.byte()).collect();
        let digest = bytes
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryQueryDigest",
                expected: "32 retained bytes after a query draw".into(),
                got: self.input_buffer.iter().map(|unit| unit.len()).sum(),
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
                || branch
                    .input_buffer
                    .iter()
                    .zip(&first.input_buffer)
                    .any(|(unit, other)| unit.len() != other.len())
        }) {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryChallengerSelect",
                expected: "matching hashes and buffer lengths".into(),
                got: branches.len(),
            });
        }
        let selectors: Vec<_> = branches.iter().map(|(selector, _)| *selector).collect();
        circuit.assert_exactly_one(&selectors)?;
        let mut select = |output: bool, len: usize| {
            (0..len)
                .map(|i| {
                    branches
                        .iter()
                        .fold(ExprId::ZERO, |sum, (selector, branch)| {
                            let byte = if output {
                                branch.output_buffer[i]
                            } else {
                                match branch.input_buffer[i] {
                                    Absorbed::Byte(entry) | Absorbed::Word(entry) => entry,
                                }
                            };
                            circuit.mul_add(*selector, byte, sum)
                        })
                })
                .collect::<Vec<_>>()
        };
        let input_buffer = select(false, first.input_buffer.len())
            .into_iter()
            .zip(&first.input_buffer)
            .map(|(entry, unit)| match unit {
                Absorbed::Byte(_) => Absorbed::Byte(entry),
                Absorbed::Word(_) => Absorbed::Word(entry),
            })
            .collect();
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
        Self::with_initial_limbs_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, hash, initial)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn with_initial_limbs_with_host<H, EF>(
        circuit: &mut CircuitBuilder<EF>,
        hash: ByteHash,
        initial: &[ExprId],
    ) -> Result<Self, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(hash)?;
        let bytes = Self::bytes_from_limbs::<H, EF>(circuit, initial)?;
        Ok(Self {
            hash,
            input_buffer: absorbed_bytes(&bytes).collect(),
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
        Self::with_initial_bytes_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, hash, initial)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn with_initial_bytes_with_host<H, EF>(
        circuit: &mut CircuitBuilder<EF>,
        hash: ByteHash,
        initial: &[ExprId],
    ) -> Result<Self, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(hash)?;
        for &byte in initial {
            H::decompose_word(circuit, byte, 8)?;
        }
        Ok(Self {
            hash,
            input_buffer: absorbed_bytes(initial).collect(),
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
        self.observe_bytes_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, bytes)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn observe_bytes_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        bytes: &[ExprId],
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        for &byte in bytes {
            H::decompose_word(circuit, byte, 8)?;
        }
        if !bytes.is_empty() {
            self.output_buffer.clear();
            self.input_buffer.extend(absorbed_bytes(bytes));
        }
        Ok(())
    }

    /// Observes the natural-order bytes of low-first sixteen-bit words: each
    /// word contributes its low byte, then its high byte. A nonempty
    /// observation discards unsampled output; an empty one changes nothing.
    ///
    /// Words are range-checked when a refill hashes them: a word at an even
    /// byte offset of an even-length input goes to the host's word hash, which
    /// a native host absorbs as a raw Keccak limb; any other word is split into
    /// checked bytes. The caller binds each word to the value it encodes. IDs
    /// must belong to `circuit`'s expression graph.
    ///
    /// # Errors
    /// Rejects an unsupported host field before adding constraints.
    pub fn observe_words_with_host<H, EF>(
        &mut self,
        _circuit: &mut CircuitBuilder<EF>,
        words: &[ExprId],
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        if !words.is_empty() {
            self.output_buffer.clear();
            self.input_buffer
                .extend(words.iter().map(|&word| Absorbed::Word(word)));
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
        self.sample_bytes_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, count)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn sample_bytes_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        count: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        let mut staged = self.clone();
        let result = staged.sample_stream_bytes::<H, EF>(circuit, count)?;
        *self = staged;
        Ok(result)
    }

    /// Observes the eight raw little-endian bytes of a checked Poly64 target.
    /// This uses its polynomial basis without converting to tower coordinates.
    pub fn observe_poly64<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        value: &BinaryPoly64Target,
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.observe_poly64_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, value)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn observe_poly64_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        value: &BinaryPoly64Target,
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        let bytes = value
            .bits()
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bits| H::recompose_word(circuit, bits))
            .collect::<Result<Vec<_>, _>>()?;
        self.observe_bytes_with_host::<H, EF>(circuit, &bytes)
    }

    /// Observes all three Poly64 coefficients in ascending degree of `y`.
    /// Each coefficient contributes eight raw little-endian bytes.
    pub fn observe_poly192<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        value: &BinaryPoly192Target,
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.observe_poly192_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, value)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn observe_poly192_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        value: &BinaryPoly192Target,
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        let mut staged = self.clone();
        for coefficient in value.coefficients() {
            staged.observe_poly64_with_host::<H, EF>(circuit, coefficient)?;
        }
        *self = staged;
        Ok(())
    }

    /// Draws 24 bytes as the three checked polynomial coefficients of Poly192.
    /// This matches `BinaryChallenger<Poly64, _>::sample_algebra_element`,
    /// including a partial or empty digest refill between coefficients.
    pub fn sample_poly192<BF, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryPoly192Target, CircuitBuilderError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.sample_poly192_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn sample_poly192_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryPoly192Target, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        let mut staged = self.clone();
        let bytes = staged.sample_bytes_with_host::<H, EF>(circuit, 24)?;
        let coefficients = bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bytes| {
                let mut bits = Vec::with_capacity(64);
                for &byte in bytes {
                    bits.extend(H::decompose_word(circuit, byte, 8)?);
                }
                circuit.binary_poly64_from_bits(bits.try_into().expect("eight bytes have 64 bits"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let result = circuit.binary_poly192_from_coefficients(
            coefficients
                .try_into()
                .expect("Poly192 has three coefficients"),
        );
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
        self.observe_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, value)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn observe_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        value: &BinaryTower128Target,
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        let mut staged = self.clone();
        staged.observe_inner::<H, EF>(circuit, value)?;
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
        self.observe_slice_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, values)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn observe_slice_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        values: &[BinaryTower128Target],
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        let mut staged = self.clone();
        for value in values {
            staged.observe_inner::<H, EF>(circuit, value)?;
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
        self.observe_digest_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, digest)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn observe_digest_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        digest: &[ExprId; 16],
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        let mut staged = self.clone();
        let bytes = Self::bytes_from_limbs::<H, EF>(circuit, digest)?;
        staged.output_buffer.clear();
        staged.input_buffer.extend(absorbed_bytes(&bytes));
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
        self.sample_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn sample_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryTower128Target, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        let mut staged = self.clone();
        let stream = staged.sample_stream_bytes::<H, EF>(circuit, 16)?;
        let mut bits = Vec::with_capacity(128);
        for byte in stream {
            bits.extend(H::decompose_word(circuit, byte, 8)?);
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
        self.sample_bits_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, bits)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn sample_bits_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        bits: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        Self::check_bit_count(bits)?;
        H::check_hash(self.hash)?;
        let mut staged = self.clone();
        let result = staged.sample_bits_inner::<H, EF>(circuit, bits)?;
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
        self.check_witness_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, bits, witness)
    }

    /// Uses the explicit carrier encoding and byte-hash implementation.
    pub fn check_witness_with_host<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        bits: usize,
        witness: &BinaryTower128Target,
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        if bits == 0 {
            return Ok(());
        }
        Self::check_bit_count(bits)?;
        H::check_hash(self.hash)?;
        let mut staged = self.clone();
        staged.observe_inner::<H, EF>(circuit, witness)?;
        for bit in staged.sample_bits_inner::<H, EF>(circuit, bits)? {
            circuit.assert_zero(bit);
        }
        *self = staged;
        Ok(())
    }

    fn observe_inner<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        value: &BinaryTower128Target,
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        let bytes: Vec<_> = value
            .bits()
            .chunks(8)
            .map(|bits| H::recompose_word(circuit, bits))
            .collect::<Result<Vec<_>, _>>()?;
        self.output_buffer.clear();
        self.input_buffer.extend(absorbed_bytes(&bytes));
        Ok(())
    }

    fn sample_bits_inner<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        bits: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        let stream = self.sample_stream_bytes::<H, EF>(circuit, 8)?;
        let mut result = Vec::with_capacity(bits);
        for byte in stream {
            result.extend(H::decompose_word(circuit, byte, 8)?);
        }
        result.truncate(bits);
        Ok(result)
    }

    fn sample_stream_bytes<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        count: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        let mut stream = Vec::with_capacity(count);
        while stream.len() < count {
            if self.output_buffer.is_empty() {
                // Native HashChallenger hashes the whole forward message and
                // retains that complete digest for the next chained refill.
                let bytes = Self::hash_input::<H, EF>(circuit, self.hash, &self.input_buffer)?;
                self.input_buffer = absorbed_bytes(&bytes).collect();
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

    /// The digest bytes of the input's natural-order byte string. An input
    /// of only bytes hashes them directly. Otherwise an even-length input is
    /// packed into low-first words, absorbing each word entry whole at an
    /// even offset; an odd-length input splits every word into checked bytes.
    fn hash_input<H, EF>(
        circuit: &mut CircuitBuilder<EF>,
        hash: ByteHash,
        input: &[Absorbed],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        let bytes: Option<Vec<_>> = input.iter().map(|unit| unit.byte()).collect();
        if let Some(bytes) = bytes {
            return Ok(H::hash_bytes(circuit, hash, &bytes)?.to_vec());
        }
        if !input
            .iter()
            .map(|unit| unit.len())
            .sum::<usize>()
            .is_multiple_of(2)
        {
            let mut bytes = Vec::new();
            for &unit in input {
                match unit {
                    Absorbed::Byte(byte) => bytes.push(byte),
                    Absorbed::Word(word) => bytes.extend(H::bytes_from_words(circuit, &[word])?),
                }
            }
            return Ok(H::hash_bytes(circuit, hash, &bytes)?.to_vec());
        }
        let mut words = Vec::new();
        let mut low = None;
        for &unit in input {
            match (unit, low.take()) {
                (Absorbed::Byte(byte), None) => low = Some(byte),
                (Absorbed::Word(word), None) => words.push(word),
                (Absorbed::Byte(byte), Some(first)) => {
                    words.extend(H::words_from_bytes(circuit, &[first, byte])?);
                }
                (Absorbed::Word(word), Some(first)) => {
                    let split = H::bytes_from_words(circuit, &[word])?;
                    words.extend(H::words_from_bytes(circuit, &[first, split[0]])?);
                    low = Some(split[1]);
                }
            }
        }
        let digest = H::hash_words(circuit, hash, &words)?;
        H::bytes_from_words(circuit, &digest)
    }

    fn bytes_from_limbs<H, EF>(
        circuit: &mut CircuitBuilder<EF>,
        limbs: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::bytes_from_words(circuit, limbs)
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
}
