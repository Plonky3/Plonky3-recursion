//! Byte-hash challenger for binary protocols with an explicit circuit carrier.
//!
//! This matches `BinaryChallenger<BinaryField128, HashChallenger<u8, H, 32>>`
//! with `H = p3_keccak::Keccak256Hash` or `H = p3_blake3::Blake3`.
//! Transcript buffers hold individual bytes. The pending input may also hold
//! sixteen-bit words standing for their two little-endian bytes, and the
//! unsampled digest may hold sixteen-bit words standing for the next two bytes
//! drawn from its back. This supports observations and samples of any byte
//! length. All methods must use one [`CircuitBuilder`] expression graph:
//! [`ExprId`] has no graph owner to let this type detect targets copied from
//! another builder.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_circuit::ops::binary_encoding::PrimeBinaryEncoding;
use p3_circuit::ops::binary_host::{BinaryCircuitHost, DigestLimbs};
use p3_circuit::ops::{BinaryPoly64Target, BinaryPoly192Target, BinaryTower128Target, ByteHash};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};

/// A circuit transcript for raw binary-tower observations and byte-hash samples.
///
/// The input buffer holds natural-order bytes, constrained to eight bits, and
/// sixteen-bit words, each standing for its two little-endian bytes and
/// range-checked when hashed. The output buffer holds the unsampled digest,
/// drawn from its back: checked bytes or, on a host whose hash returns
/// [`DigestLimbs`], swapped digest limbs, each standing for the next two bytes
/// drawn.
/// The fixed [`ByteHash`] choice is part of the circuit relation, and its
/// corresponding Keccak-f or BLAKE3 non-primitive operation must be enabled
/// before a sample needs a refill. A failed fallible method preserves this
/// challenger's state for retry; expressions or constraints already emitted by
/// the builder before that error may remain in the builder.
#[derive(Clone, Debug)]
pub struct BinaryTower128Challenger {
    hash: ByteHash,
    input_buffer: Vec<Absorbed>,
    output_buffer: Vec<Unsampled>,
    /// The input is the digest of the last refill, with nothing observed since.
    retains_digest: bool,
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

    const fn word(self) -> Option<ExprId> {
        match self {
            Self::Byte(_) => None,
            Self::Word(word) => Some(word),
        }
    }
}

fn absorbed_bytes(bytes: &[ExprId]) -> impl Iterator<Item = Absorbed> + '_ {
    bytes.iter().map(|&byte| Absorbed::Byte(byte))
}

/// A refill's digest: limbs from a host whose hash returns [`DigestLimbs`],
/// and otherwise bytes.
enum Digest {
    Limbs(DigestLimbs),
    Bytes(Vec<ExprId>),
}

/// One entry of the unsampled digest, which draws pop from the back.
#[derive(Clone, Copy, Debug)]
enum Unsampled {
    Byte(ExprId),
    /// The low-first sixteen-bit value of the next two drawn bytes: a digest
    /// limb with its two bytes swapped, since bytes are drawn from the back.
    Word(ExprId),
}

impl Unsampled {
    const fn len(self) -> usize {
        match self {
            Self::Byte(_) => 1,
            Self::Word(_) => 2,
        }
    }

    const fn expr(self) -> ExprId {
        match self {
            Self::Byte(entry) | Self::Word(entry) => entry,
        }
    }
}

/// The complete digest that a draw leaves as the next hash input: 32 bytes,
/// or the sixteen low-first limbs of a host whose hash returns [`DigestLimbs`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum RetainedDigest {
    Bytes([ExprId; 32]),
    Words([ExprId; 16]),
}

impl RetainedDigest {
    /// The same form with every entry `zero`.
    pub(crate) const fn zeroed(&self, zero: ExprId) -> Self {
        match self {
            Self::Bytes(_) => Self::Bytes([zero; 32]),
            Self::Words(_) => Self::Words([zero; 16]),
        }
    }

    /// Entrywise `selector * self + sum`. Both digests must have the same form.
    pub(crate) fn mul_add<EF: Field + Eq + Hash>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        selector: ExprId,
        sum: &Self,
    ) -> Result<Self, CircuitBuilderError> {
        let mut select = |entries: &[ExprId], sums: &[ExprId]| -> Vec<ExprId> {
            entries
                .iter()
                .zip(sums)
                .map(|(&entry, &sum)| circuit.mul_add(selector, entry, sum))
                .collect()
        };
        match (self, sum) {
            (Self::Bytes(entries), Self::Bytes(sums)) => Ok(Self::Bytes(
                select(entries, sums)
                    .try_into()
                    .expect("thirty-two digest bytes"),
            )),
            (Self::Words(entries), Self::Words(sums)) => Ok(Self::Words(
                select(entries, sums)
                    .try_into()
                    .expect("sixteen digest limbs"),
            )),
            _ => Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryRetainedDigest",
                expected: "digests of the same form".into(),
                got: 2,
            }),
        }
    }

    fn absorbed(&self) -> Vec<Absorbed> {
        match self {
            Self::Bytes(bytes) => absorbed_bytes(bytes).collect(),
            Self::Words(words) => words.iter().map(|&word| Absorbed::Word(word)).collect(),
        }
    }
}

/// The exact retained hash input at native rejection-sampling completion.
/// The varying number of unsampled output bytes is inaccessible: a nonempty next
/// observation discards them in both native and circuit transcripts.
#[derive(Debug)]
pub struct BinaryQueryContinuation {
    hash: ByteHash,
    digest: RetainedDigest,
}

impl BinaryQueryContinuation {
    pub(crate) const fn from_digest(hash: ByteHash, digest: RetainedDigest) -> Self {
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
        let mut challenger = self.resume::<H, EF>(bytes.len())?;
        challenger.observe_bytes_with_host::<H, EF>(circuit, bytes)?;
        Ok(challenger)
    }

    /// Resumes by absorbing the next protocol observation exactly once, given
    /// as low-first sixteen-bit words observed as by
    /// [`BinaryTower128Challenger::observe_words_with_host`]: only a later
    /// refill range-checks each word. Empty observations are rejected as in
    /// [`Self::resume_with_observation_with_host`]. All targets must belong to
    /// this builder.
    pub fn resume_with_words_with_host<H, EF>(
        self,
        circuit: &mut CircuitBuilder<EF>,
        words: &[ExprId],
    ) -> Result<BinaryTower128Challenger, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        let mut challenger = self.resume::<H, EF>(words.len())?;
        challenger.observe_words_with_host::<H, EF>(circuit, words)?;
        Ok(challenger)
    }

    /// The challenger whose next input is the retained digest, for a next
    /// observation of `len` entries, which must be nonempty.
    fn resume<H, EF>(self, len: usize) -> Result<BinaryTower128Challenger, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        H::check_hash(self.hash)?;
        if len == 0 {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryQueryContinuation",
                expected: "a nonempty next observation".into(),
                got: 0,
            });
        }
        Ok(BinaryTower128Challenger {
            hash: self.hash,
            input_buffer: self.digest.absorbed(),
            output_buffer: Vec::new(),
            retains_digest: false,
        })
    }
}

impl BinaryTower128Challenger {
    /// The fixed byte hash of this transcript.
    pub(crate) const fn hash(&self) -> ByteHash {
        self.hash
    }

    /// A positive-width field draw or uniform-bit draw leaves the full forward
    /// digest as the retained input, including when no output remains.
    pub(crate) fn retained_query_digest(
        &self,
    ) -> Result<(ByteHash, RetainedDigest), CircuitBuilderError> {
        let bytes: Option<Vec<_>> = self.input_buffer.iter().map(|unit| unit.byte()).collect();
        let words: Option<Vec<_>> = self.input_buffer.iter().map(|unit| unit.word()).collect();
        let digest = match (bytes, words) {
            (Some(bytes), _) => bytes.try_into().ok().map(RetainedDigest::Bytes),
            (_, Some(words)) => words.try_into().ok().map(RetainedDigest::Words),
            _ => None,
        };
        let digest = digest.filter(|_| self.retains_digest).ok_or_else(|| {
            CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryQueryDigest",
                expected: "the digest retained by a query draw".into(),
                got: self.input_buffer.iter().map(|unit| unit.len()).sum(),
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
                || branch.retains_digest != first.retains_digest
                || branch.input_buffer.len() != first.input_buffer.len()
                || branch.output_buffer.len() != first.output_buffer.len()
                || branch
                    .input_buffer
                    .iter()
                    .zip(&first.input_buffer)
                    .any(|(unit, other)| unit.len() != other.len())
                || branch
                    .output_buffer
                    .iter()
                    .zip(&first.output_buffer)
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
                                branch.output_buffer[i].expr()
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
        let output_buffer = select(true, first.output_buffer.len())
            .into_iter()
            .zip(&first.output_buffer)
            .map(|(entry, unit)| match unit {
                Unsampled::Byte(_) => Unsampled::Byte(entry),
                Unsampled::Word(_) => Unsampled::Word(entry),
            })
            .collect();
        Ok(Self {
            hash: first.hash,
            input_buffer,
            output_buffer,
            retains_digest: first.retains_digest,
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
            retains_digest: false,
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
            retains_digest: false,
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
            retains_digest: false,
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
            self.retains_digest = false;
        }
        Ok(())
    }

    /// Observes the natural-order bytes of low-first sixteen-bit words: each
    /// word contributes its low byte, then its high byte. A nonempty
    /// observation discards unsampled output; an empty one changes nothing.
    ///
    /// Words are range-checked when a refill hashes them: a word at an even
    /// byte offset of an even-length input goes to the host's word hash, which
    /// a native host absorbs as a hash block input (a Keccak lane limb or a
    /// BLAKE3 block word); any other word is split into checked bytes. Words
    /// that no later refill hashes are never range-checked, so callers must
    /// not rely on them as a canonical split outside the transcript. The
    /// caller binds each word to the value it encodes. IDs must belong to
    /// `circuit`'s expression graph.
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
            self.retains_digest = false;
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

    /// Draws `2 * count` bytes as `count` low-first sixteen-bit words, each
    /// the little-endian value of the next two drawn bytes, spanning chained
    /// refills when necessary. Every word encodes sixteen bits: a swapped
    /// digest limb drawn whole is a native Keccak-f output, which the native
    /// hash AIR derives from Boolean bits, and any other word is packed from
    /// checked bytes.
    ///
    /// # Errors
    /// As [`Self::sample_bytes_with_host`]. On error, challenger state is
    /// unchanged; expressions already emitted by the builder may remain.
    pub fn sample_words_with_host<H, EF>(
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
        let mut words = Vec::with_capacity(count);
        let mut low = None;
        for unit in staged.pop_units::<H, EF>(circuit, 2 * count)? {
            match (unit, low.take()) {
                (Unsampled::Word(word), None) => words.push(word),
                (Unsampled::Byte(byte), None) => low = Some(byte),
                (Unsampled::Byte(byte), Some(first)) => {
                    words.extend(H::words_from_bytes(circuit, &[first, byte])?);
                }
                (Unsampled::Word(word), Some(first)) => {
                    let [second, next] = Self::split_word::<H, EF>(circuit, word)?;
                    words.extend(H::words_from_bytes(circuit, &[first, second])?);
                    low = Some(next);
                }
            }
        }
        debug_assert!(low.is_none(), "an even byte count forms whole words");
        *self = staged;
        Ok(words)
    }

    /// Draws `count` bytes and returns their `8 * count` low-first bits, the
    /// bits of each drawn byte in draw order. A swapped digest limb drawn
    /// whole is decomposed once, rather than split into checked bytes.
    ///
    /// # Errors
    /// As [`Self::sample_bytes_with_host`]. On error, challenger state is
    /// unchanged; expressions already emitted by the builder may remain.
    pub fn sample_byte_bits_with_host<H, EF>(
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
        let mut bits = Vec::with_capacity(8 * count);
        for unit in staged.pop_units::<H, EF>(circuit, count)? {
            bits.extend(H::decompose_word(circuit, unit.expr(), 8 * unit.len())?);
        }
        *self = staged;
        Ok(bits)
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
        let bits = staged.sample_byte_bits_with_host::<H, EF>(circuit, 24)?;
        let coefficients = bits
            .as_chunks::<64>()
            .0
            .iter()
            .map(|&bits| circuit.binary_poly64_from_bits(bits))
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
        staged.retains_digest = false;
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
        let bits = staged.sample_byte_bits_with_host::<H, EF>(circuit, 16)?;
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
        self.retains_digest = false;
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
        let mut result = Vec::with_capacity(64);
        for unit in self.pop_units::<H, EF>(circuit, 8)? {
            // A word drawn after the requested bits is not decomposed: the
            // truncation drops all of its bits, and a hash output word needs no
            // range check here.
            if let Unsampled::Word(_) = unit
                && result.len() >= bits
            {
                continue;
            }
            result.extend(H::decompose_word(circuit, unit.expr(), 8 * unit.len())?);
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
        for unit in self.pop_units::<H, EF>(circuit, count)? {
            match unit {
                Unsampled::Byte(byte) => stream.push(byte),
                Unsampled::Word(word) => stream.extend(Self::split_word::<H, EF>(circuit, word)?),
            }
        }
        Ok(stream)
    }

    /// Pops unsampled entries covering exactly `count` bytes, refilling
    /// whenever the output is empty. A word that would end past `count` is
    /// split into its two drawn bytes, and the second stays unsampled.
    fn pop_units<H, EF>(
        &mut self,
        circuit: &mut CircuitBuilder<EF>,
        count: usize,
    ) -> Result<Vec<Unsampled>, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        let mut units = Vec::new();
        let mut len = 0;
        while len < count {
            if self.output_buffer.is_empty() {
                self.refill::<H, EF>(circuit)?;
            }
            let unit = self
                .output_buffer
                .pop()
                .expect("a byte hash refill yields a thirty-two byte digest");
            if let Unsampled::Word(word) = unit
                && len + 1 == count
            {
                let [first, second] = Self::split_word::<H, EF>(circuit, word)?;
                self.output_buffer.push(Unsampled::Byte(second));
                units.push(Unsampled::Byte(first));
                len += 1;
            } else {
                len += unit.len();
                units.push(unit);
            }
        }
        Ok(units)
    }

    /// Native HashChallenger hashes the whole forward message and retains
    /// that complete digest as the next input. Draws read the digest from its
    /// back, as swapped limbs when the host returns [`DigestLimbs`].
    fn refill<H, EF>(&mut self, circuit: &mut CircuitBuilder<EF>) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        match Self::hash_input::<H, EF>(circuit, self.hash, &self.input_buffer)? {
            Digest::Limbs(DigestLimbs { limbs, swapped }) => {
                self.input_buffer = limbs.map(Absorbed::Word).to_vec();
                self.output_buffer = swapped.map(Unsampled::Word).to_vec();
            }
            Digest::Bytes(bytes) => {
                self.input_buffer = absorbed_bytes(&bytes).collect();
                self.output_buffer = bytes.into_iter().map(Unsampled::Byte).collect();
            }
        }
        self.retains_digest = true;
        Ok(())
    }

    /// The two bytes of a drawn word, in draw order.
    fn split_word<H, EF>(
        circuit: &mut CircuitBuilder<EF>,
        word: ExprId,
    ) -> Result<[ExprId; 2], CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        Ok(H::bytes_from_words(circuit, &[word])?
            .try_into()
            .expect("a word has two bytes"))
    }

    /// The digest of the input's natural-order byte string: its limbs when
    /// the host returns [`DigestLimbs`], and otherwise its bytes. An input of
    /// only bytes hashes them directly. Otherwise an even-length input is
    /// packed into low-first words, absorbing each word entry whole at an
    /// even offset; an odd-length input splits every word into checked bytes.
    fn hash_input<H, EF>(
        circuit: &mut CircuitBuilder<EF>,
        hash: ByteHash,
        input: &[Absorbed],
    ) -> Result<Digest, CircuitBuilderError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        let hash_bytes = |circuit: &mut CircuitBuilder<EF>, bytes: &[ExprId]| {
            Ok(match H::hash_bytes_to_limbs(circuit, hash, bytes)? {
                Some(limbs) => Digest::Limbs(limbs),
                None => Digest::Bytes(H::hash_bytes(circuit, hash, bytes)?.to_vec()),
            })
        };
        let bytes: Option<Vec<_>> = input.iter().map(|unit| unit.byte()).collect();
        if let Some(bytes) = bytes {
            return hash_bytes(circuit, &bytes);
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
            return hash_bytes(circuit, &bytes);
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
        if let Some(limbs) = H::hash_words_to_limbs(circuit, hash, &words)? {
            return Ok(Digest::Limbs(limbs));
        }
        let digest = H::hash_words(circuit, hash, &words)?;
        Ok(Digest::Bytes(H::bytes_from_words(circuit, &digest)?))
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

#[cfg(test)]
mod tests {
    use p3_binary_field::{BinaryChallenger, BinaryField8, BinaryField128, TowerLevel};
    use p3_challenger::{CanObserve, CanSample};
    use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
    use p3_field::PrimeCharacteristicRing;
    use p3_keccak::Keccak256Hash;

    use super::*;

    type E = NativeBinaryEncoding;
    type F = BinaryField128;

    /// Pending words and bytes of each branch: a word at an even offset, a
    /// byte, a word at an odd offset and a byte.
    const BRANCHES: [([u16; 2], [u8; 2]); 2] =
        [([0xb7e5, 0x1c03], [7, 251]), ([0x4d21, 0xe8f0], [129, 3])];

    fn observe_branch(
        b: &mut CircuitBuilder<F>,
        words: [ExprId; 2],
        bytes: [u8; 2],
    ) -> BinaryTower128Challenger {
        let mut ch = BinaryTower128Challenger::new(ByteHash::Keccak256);
        for (word, byte) in words.into_iter().zip(bytes) {
            ch.observe_words_with_host::<E, F>(b, &[word]).unwrap();
            let byte = b.define_const(E::encode_u16(byte.into()).unwrap());
            ch.observe_bytes_with_host::<E, F>(b, &[byte]).unwrap();
        }
        ch
    }

    /// The branch picked by a private selector samples exactly like the native
    /// transcript of its own observations, so its pending words keep their
    /// sixteen-bit kind and the other branch's values do not leak in.
    #[test]
    fn selected_word_branches_hash_like_the_native_transcript() {
        for (chosen, &(words, bytes)) in BRANCHES.iter().enumerate() {
            let mut native =
                BinaryChallenger::<BinaryField8, _>::from_hasher(Vec::new(), Keccak256Hash);
            for (word, byte) in words.into_iter().zip(bytes) {
                for byte in word.to_le_bytes().into_iter().chain([byte]) {
                    native.observe(BinaryField8::from_repr(byte));
                }
            }
            let expected: BinaryField128 = native.sample();

            let mut b = CircuitBuilder::<F>::new();
            b.enable_native_keccak_f1600().unwrap();
            let pick = b.alloc_private_input("branch");
            let one = b.define_const(F::ONE);
            let keep = b.sub(one, pick);
            let branches: Vec<_> = BRANCHES
                .iter()
                .zip([keep, pick])
                .map(|(&(_, bytes), selector)| {
                    let words = [b.public_input(), b.public_input()];
                    (selector, observe_branch(&mut b, words, bytes))
                })
                .collect();
            let mut selected =
                BinaryTower128Challenger::select_same_shape(&mut b, &branches).unwrap();
            let actual = selected.sample_with_host::<E, F>(&mut b).unwrap();
            for (i, &bit) in actual.bits().iter().enumerate() {
                let bit_value = b.define_const(F::from_bool(expected.to_repr() >> i & 1 != 0));
                b.connect(bit, bit_value);
            }
            let circuit = b.build().unwrap();
            let public: Vec<F> = BRANCHES
                .iter()
                .flat_map(|(words, _)| words.map(|word| E::encode_u16(word).unwrap()))
                .collect();
            let runs = |pick: usize| {
                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&public)
                    .and_then(|()| runner.set_private_inputs(&[F::from_bool(pick == 1)]))
                    .and_then(|()| runner.run())
                    .is_ok()
            };
            assert!(runs(chosen), "branch {chosen} selected");
            assert!(!runs(1 - chosen), "the other branch hashes differently");
        }
    }

    #[test]
    fn branches_must_agree_on_every_pending_entry_width() {
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let [pick, word] = [b.alloc_private_input("branch"), b.public_input()];
        let byte = b.define_const(F::ONE);
        let mut word_first = BinaryTower128Challenger::new(ByteHash::Keccak256);
        word_first
            .observe_words_with_host::<E, F>(&mut b, &[word])
            .unwrap();
        word_first
            .observe_bytes_with_host::<E, F>(&mut b, &[byte])
            .unwrap();
        let mut byte_first = BinaryTower128Challenger::new(ByteHash::Keccak256);
        byte_first
            .observe_bytes_with_host::<E, F>(&mut b, &[byte])
            .unwrap();
        byte_first
            .observe_words_with_host::<E, F>(&mut b, &[word])
            .unwrap();
        let one = b.define_const(F::ONE);
        let keep = b.sub(one, pick);
        let branches = [(keep, word_first), (pick, byte_first)];
        assert!(BinaryTower128Challenger::select_same_shape(&mut b, &branches).is_err());

        // Sixteen pending words are 32 bytes, but not a retained digest.
        let mut pending = BinaryTower128Challenger::new(ByteHash::Keccak256);
        pending
            .observe_words_with_host::<E, F>(&mut b, &[word; 16])
            .unwrap();
        assert!(matches!(
            pending.retained_query_digest(),
            Err(CircuitBuilderError::NonPrimitiveOpArity { got: 32, .. })
        ));
    }
}
