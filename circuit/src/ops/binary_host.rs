//! Byte hashing and word packing for binary protocols with an explicit carrier.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_field::{ExtensionField, Field, PrimeField64};

use super::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding, PrimeBinaryEncoding};
use super::binary_native::BinaryCoordinateField;
use super::{ByteHash, KECCAK256_RATE_BYTES};
use crate::{CircuitBuilder, CircuitBuilderError, ExprId};

/// A byte-hash digest as sixteen low-first limbs, each also with its two bytes
/// swapped. Drawing a digest's bytes from its back yields, two at a time, the
/// little-endian words `swapped[15]`, `swapped[14]`, and so on.
#[derive(Clone, Copy, Debug)]
pub struct DigestLimbs {
    pub limbs: [ExprId; 16],
    pub swapped: [ExprId; 16],
}

/// The byte-hash boundary of a binary verifier circuit.
///
/// Words use the selected encoding; hashes always consume and return natural
/// byte order. These methods do not change the native protocol's serialization.
pub trait BinaryCircuitHost<F: Field + Eq + Hash>: BinaryCircuitEncoding<F> + Sized {
    /// Reject unavailable hashes and invalid carriers before emitting constraints.
    fn check_hash(hash: ByteHash) -> Result<(), CircuitBuilderError>;

    fn hash_bytes(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        bytes: &[ExprId],
    ) -> Result<[ExprId; 32], CircuitBuilderError>;

    /// Splits checked low-first sixteen-bit words into natural-order bytes.
    fn bytes_from_words(
        builder: &mut CircuitBuilder<F>,
        words: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        Self::check_carrier()?;
        let mut bytes = Vec::new();
        for &word in words {
            let bits = Self::decompose_word(builder, word, 16)?;
            for byte in bits.as_chunks::<8>().0 {
                bytes.push(Self::recompose_word(builder, byte)?);
            }
        }
        Ok(bytes)
    }

    /// Packs bytes into low-first words. An odd final byte has a zero high byte.
    fn words_from_bytes(
        builder: &mut CircuitBuilder<F>,
        bytes: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        Self::check_carrier()?;
        let mut words = Vec::new();
        for pair in bytes.chunks(2) {
            let mut bits = Vec::new();
            for &byte in pair {
                bits.extend(Self::decompose_word(builder, byte, 8)?);
            }
            words.push(Self::recompose_word(builder, &bits)?);
        }
        Ok(words)
    }

    fn hash_words(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        words: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        Self::check_hash(hash)?;
        let bytes = Self::bytes_from_words(builder, words)?;
        let digest = Self::hash_bytes(builder, hash, &bytes)?;
        Self::words_from_bytes(builder, &digest)
    }

    /// The digest of [`Self::hash_bytes`] as [`DigestLimbs`], when the hash
    /// returns them without splitting the digest. `None` means callers split
    /// the digest into bytes instead.
    fn hash_bytes_to_limbs(
        _builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        _bytes: &[ExprId],
    ) -> Result<Option<DigestLimbs>, CircuitBuilderError> {
        Self::check_hash(hash)?;
        Ok(None)
    }

    /// The digest of [`Self::hash_words`] as [`DigestLimbs`], as in
    /// [`Self::hash_bytes_to_limbs`].
    fn hash_words_to_limbs(
        _builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        _words: &[ExprId],
    ) -> Result<Option<DigestLimbs>, CircuitBuilderError> {
        Self::check_hash(hash)?;
        Ok(None)
    }

    /// Whether [`Self::hash_words`] and [`Self::hash_words_to_limbs`] absorb
    /// each word whole, as a hash input lane that the hash itself constrains
    /// to sixteen bits. Words such a hash absorbs need no other range check
    /// and cost no more than their checked bytes; any other host splits every
    /// word into checked bytes before hashing.
    fn hashes_words_whole(hash: ByteHash) -> bool {
        let _ = hash;
        false
    }

    /// Range-checks the words of a proof-supplied Merkle sibling digest, which
    /// an MMCS opening places with the current digest and the level's other
    /// siblings under Boolean index bits to form the inputs of
    /// [`Self::compress`] or [`Self::compress_n`].
    ///
    /// Callers must pass the same sibling to
    /// [`CircuitBuilder::verify_byte_hash_mmcs_opening_words_with_host`],
    /// [`CircuitBuilder::verify_byte_hash_mmcs_opening_bytes_with_host`],
    /// [`CircuitBuilder::verify_byte_hash_mmcs_opening_words_with_host_arity`],
    /// [`CircuitBuilder::verify_byte_hash_mmcs_opening_bytes_with_host_arity`],
    /// [`CircuitBuilder::verify_byte_hash_mmcs_subtree_words_with_host`] or
    /// [`CircuitBuilder::verify_byte_hash_mmcs_subtree_bytes_with_host`] and
    /// read it nowhere else: a host whose compressions range-check their
    /// inputs relies on that opening and adds no constraint here.
    fn constrain_sibling(
        builder: &mut CircuitBuilder<F>,
        sibling: &[ExprId],
    ) -> Result<(), CircuitBuilderError> {
        for &word in sibling {
            Self::decompose_word(builder, word, 16)?;
        }
        Ok(())
    }

    /// Native `CompressionFunctionFromHasher`: hash the two complete digests.
    fn compress(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        left: &[ExprId],
        right: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        Self::check_hash(hash)?;
        if left.len() != 16 || right.len() != 16 {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryDigestCompression",
                expected: "two sixteen-word digests".into(),
                got: left.len().saturating_add(right.len()),
            });
        }
        let mut words = left.to_vec();
        words.extend_from_slice(right);
        Self::hash_words(builder, hash, &words)
    }

    /// Native `CompressionFunctionFromHasher<_, N, 32>` for `N = inputs.len()`:
    /// hash the concatenated sixteen-word digests.
    ///
    /// `N` is two to four: under Keccak-256 the at most 128 message bytes and
    /// their padding fill one rate block, so a node costs a single Keccak-f
    /// call that absorbs every input word as a first-block lane. Under
    /// Blake3, `32 * N` bytes are `ceil(N / 2)` compressions, each digest word
    /// a direct block input.
    fn compress_n(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        inputs: &[&[ExprId]],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        Self::check_hash(hash)?;
        if !(2..=MAX_COMPRESSION_ARITY).contains(&inputs.len())
            || inputs.iter().any(|digest| digest.len() != 16)
        {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "BinaryDigestCompression",
                expected: "two to four sixteen-word digests".into(),
                got: inputs.iter().map(|digest| digest.len()).sum(),
            });
        }
        Self::hash_words(builder, hash, &inputs.concat())
    }
}

/// The most 32-byte digests one node compression hashes under any hash: their
/// concatenation leaves at least the one padding byte Keccak-256 needs in its
/// rate block.
const MAX_COMPRESSION_ARITY: usize = (KECCAK256_RATE_BYTES - 1) / 32;

impl<F: BinaryCoordinateField> BinaryCircuitHost<F> for NativeBinaryEncoding {
    fn check_hash(hash: ByteHash) -> Result<(), CircuitBuilderError> {
        <Self as BinaryCircuitEncoding<F>>::check_carrier()?;
        match hash {
            ByteHash::Keccak256 | ByteHash::Blake3 => Ok(()),
        }
    }

    fn hash_bytes(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        bytes: &[ExprId],
    ) -> Result<[ExprId; 32], CircuitBuilderError> {
        <Self as BinaryCircuitHost<F>>::check_hash(hash)?;
        match hash {
            ByteHash::Keccak256 => builder.native_keccak256_bytes(bytes),
            ByteHash::Blake3 => builder.native_blake3_bytes(bytes),
        }
    }

    fn hash_words(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        words: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        <Self as BinaryCircuitHost<F>>::check_hash(hash)?;
        Ok(match hash {
            ByteHash::Keccak256 => builder.native_keccak256_words(words)?.to_vec(),
            ByteHash::Blake3 => builder.native_blake3_words(words)?.to_vec(),
        })
    }

    /// Returns swapped limbs that are outputs of the final native compression
    /// call (Keccak-f or Blake3), which the native hash AIR derives from that
    /// call's output bits, or constants for a message absorbed while building.
    fn hash_bytes_to_limbs(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        bytes: &[ExprId],
    ) -> Result<Option<DigestLimbs>, CircuitBuilderError> {
        <Self as BinaryCircuitHost<F>>::check_hash(hash)?;
        match hash {
            ByteHash::Keccak256 => {
                let (limbs, swapped) = builder.native_keccak256_bytes_with_swapped_digest(bytes)?;
                Ok(Some(DigestLimbs { limbs, swapped }))
            }
            ByteHash::Blake3 => {
                let (limbs, swapped) = builder.native_blake3_bytes_with_swapped_digest(bytes)?;
                Ok(Some(DigestLimbs { limbs, swapped }))
            }
        }
    }

    /// As [`Self::hash_bytes_to_limbs`].
    fn hash_words_to_limbs(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        words: &[ExprId],
    ) -> Result<Option<DigestLimbs>, CircuitBuilderError> {
        <Self as BinaryCircuitHost<F>>::check_hash(hash)?;
        match hash {
            ByteHash::Keccak256 => {
                let (limbs, swapped) = builder.native_keccak256_words_with_swapped_digest(words)?;
                Ok(Some(DigestLimbs { limbs, swapped }))
            }
            ByteHash::Blake3 => {
                let (limbs, swapped) = builder.native_blake3_words_with_swapped_digest(words)?;
                Ok(Some(DigestLimbs { limbs, swapped }))
            }
        }
    }

    /// Keccak-256 absorbs each word as a native Keccak lane, which the native
    /// Keccak AIR constrains to sixteen coordinates, or, in a leading block of
    /// constants, checks it while building.
    fn hashes_words_whole(hash: ByteHash) -> bool {
        matches!(hash, ByteHash::Keccak256)
    }

    /// Adds no constraint. Under Boolean index bits the selected digests are
    /// the current digest and the level's siblings, each in exactly one input,
    /// so each sibling word equals a word that [`Self::compress`] or
    /// [`Self::compress_n`] absorbs: under Keccak-256 a first-block native
    /// Keccak lane, under Blake3 a direct block input of a native compression,
    /// which the respective native AIR constrains to sixteen coordinates.
    fn constrain_sibling(
        _builder: &mut CircuitBuilder<F>,
        _sibling: &[ExprId],
    ) -> Result<(), CircuitBuilderError> {
        <Self as BinaryCircuitEncoding<F>>::check_carrier()
    }
}

impl<BF, F> BinaryCircuitHost<F> for PrimeBinaryEncoding<BF>
where
    BF: PrimeField64,
    F: ExtensionField<BF> + Eq + Hash,
{
    fn check_hash(_hash: ByteHash) -> Result<(), CircuitBuilderError> {
        <Self as BinaryCircuitEncoding<F>>::check_carrier()
    }

    fn hash_bytes(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        bytes: &[ExprId],
    ) -> Result<[ExprId; 32], CircuitBuilderError> {
        <Self as BinaryCircuitHost<F>>::check_hash(hash)?;
        let words = builder.byte_hash_bytes::<BF>(hash, bytes)?;
        Ok(Self::bytes_from_words(builder, &words)?
            .try_into()
            .expect("a byte hash returns thirty-two bytes"))
    }
}
