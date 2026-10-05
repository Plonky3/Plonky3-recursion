//! Byte hashing and word packing for binary protocols with an explicit carrier.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_field::{ExtensionField, Field, PrimeField64};

use super::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding, PrimeBinaryEncoding};
use super::binary_native::BinaryCoordinateField;
use super::{ByteHash, NpoTypeId};
use crate::{CircuitBuilder, CircuitBuilderError, ExprId};

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
            for byte in bits.chunks_exact(8) {
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
}

impl<F: BinaryCoordinateField> BinaryCircuitHost<F> for NativeBinaryEncoding {
    fn check_hash(hash: ByteHash) -> Result<(), CircuitBuilderError> {
        <Self as BinaryCircuitEncoding<F>>::check_carrier()?;
        match hash {
            ByteHash::Keccak256 => Ok(()),
            ByteHash::Blake3 => Err(CircuitBuilderError::UnsupportedNonPrimitiveOp {
                op: NpoTypeId::blake3_compress(),
            }),
        }
    }

    fn hash_bytes(
        builder: &mut CircuitBuilder<F>,
        hash: ByteHash,
        bytes: &[ExprId],
    ) -> Result<[ExprId; 32], CircuitBuilderError> {
        <Self as BinaryCircuitHost<F>>::check_hash(hash)?;
        builder.native_keccak256_bytes(bytes)
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
