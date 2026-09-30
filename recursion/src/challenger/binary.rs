//! Byte-hash challenger for the 128-bit Wiedemann binary tower.
//!
//! This matches `BinaryChallenger<BinaryField128, HashChallenger<u8, H, 32>>`
//! with `H = p3_keccak::Keccak256Hash` or `H = p3_blake3::Blake3`.
//! Transcript bytes are represented by little-endian 16-bit limbs, so an
//! initial transcript must have an even number of bytes. All methods must use
//! one [`CircuitBuilder`] expression graph: [`ExprId`] has no graph owner to
//! let this type detect targets copied from another builder.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, PrimeField64};

/// A circuit transcript for raw binary-tower observations and byte-hash samples.
///
/// Both private buffers hold natural-order, little-endian 16-bit byte limbs.
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

impl BinaryTower128Challenger {
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
        for &limb in initial {
            circuit.decompose_to_bits::<BF>(limb, 16)?;
        }
        Ok(Self {
            hash,
            input_buffer: initial.to_vec(),
            output_buffer: Vec::new(),
        })
    }

    /// Observes a checked tower target as its 16 raw little-endian bytes.
    /// This appends eight low-first limbs to the next hash input and discards
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
        for &limb in digest {
            circuit.decompose_to_bits::<BF>(limb, 16)?;
        }
        staged.output_buffer.clear();
        staged.input_buffer.extend_from_slice(digest);
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
        let stream = staged.sample_stream_limbs::<BF, EF>(circuit, 8)?;
        let limbs: [ExprId; 8] = stream
            .try_into()
            .expect("eight sampled limbs form one binary tower element");
        let result = circuit.binary128_from_limbs::<BF>(limbs)?;
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
        let limbs = circuit.binary128_to_limbs::<BF>(value)?;
        self.output_buffer.clear();
        self.input_buffer.extend_from_slice(&limbs);
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
        let stream = self.sample_stream_limbs::<BF, EF>(circuit, 4)?;
        let mut result = Vec::with_capacity(bits);
        for limb in stream {
            result.extend(circuit.decompose_to_bits::<BF>(limb, 16)?);
        }
        result.truncate(bits);
        Ok(result)
    }

    fn sample_stream_limbs<BF, EF>(
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
                let digest = circuit.byte_hash_limbs::<BF>(self.hash, &self.input_buffer)?;
                self.input_buffer.clone_from(&digest);
                self.output_buffer = digest;
            }
            let natural = self
                .output_buffer
                .pop()
                .expect("a byte hash refill yields sixteen digest limbs");
            let natural_bits = circuit.decompose_to_bits::<BF>(natural, 16)?;
            // Popping a two-byte limb from the back samples its high byte
            // first, then its low byte, exactly like a native byte stack.
            let swapped: Vec<_> = natural_bits[8..]
                .iter()
                .chain(&natural_bits[..8])
                .copied()
                .collect();
            stream.push(circuit.reconstruct_index_from_bits::<BF>(&swapped)?);
        }
        Ok(stream)
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
