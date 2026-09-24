//! Gadgets shared by the byte-oriented hashes (Keccak-256 and BLAKE3): canonical field-element
//! serialization and Merkle path verification.
//!
//! Byte strings travel as little-endian 16-bit limbs, two bytes per limb; a 32-byte digest is
//! [`DIGEST_LIMBS`] limbs.

use alloc::format;
use alloc::vec::Vec;

use p3_field::{ExtensionField, Field, PrimeField64};

use crate::builder::CircuitBuilderError;
use crate::types::ExprId;

/// Bits per limb.
const LIMB_BITS: usize = 16;
/// 16-bit limbs in a 32-byte digest.
pub const DIGEST_LIMBS: usize = 16;

/// A 32-byte hash available as a circuit gadget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteHash {
    /// Keccak-256 (`p3_keccak::Keccak256Hash`), over the Keccak-f\[1600\] operation.
    Keccak256,
    /// BLAKE3 (`p3_blake3::Blake3`), over the BLAKE3 compression operation.
    Blake3,
}

impl<F> crate::CircuitBuilder<F>
where
    F: Field + Eq + core::hash::Hash,
{
    /// Each element's serialized little-endian bytes, as 16-bit limbs: the byte stream a
    /// `SerializingHasher` feeds its byte hash.
    ///
    /// Plonky3 serializes an element as a unique integer below `p`, which is not always its
    /// canonical value: Montgomery fields (BabyBear, KoalaBear) serialize `x·2^32 mod p`. Both
    /// forms are `x·u(1)` for the serialization `u(1)` of one, so each element is scaled by that
    /// constant and then decomposed into canonical bits (`value < p`), which stops a prover from
    /// substituting the encoding of `y + p` for `y`.
    ///
    /// # Errors
    ///
    /// As [`Self::decompose_to_bits`].
    ///
    /// # Panics
    ///
    /// If `BF`'s serialization is not linear in the element, which no Plonky3 prime field is.
    pub fn serialize_field_elements_to_limbs<BF>(
        &mut self,
        elements: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        let limbs_per_element = BF::NUM_BYTES / 2;
        let serialized = |x: BF| -> u64 {
            BF::into_byte_stream([x])
                .into_iter()
                .enumerate()
                .fold(0, |acc, (i, byte)| acc | (u64::from(byte) << (8 * i)))
        };
        let scale = BF::from_u64(serialized(BF::ONE));
        assert_eq!(
            serialized(BF::GENERATOR),
            (BF::GENERATOR * scale).as_canonical_u64(),
            "field serialization must be x -> x * u(1)"
        );
        let scale = self.define_const(F::from(scale));

        let mut limbs = Vec::with_capacity(elements.len() * limbs_per_element);
        for &element in elements {
            let serialized_value = self.mul(element, scale);
            let bits = self.decompose_to_bits::<BF>(serialized_value, BF::bits())?;
            for chunk in 0..limbs_per_element {
                let mut limb = self.define_const(F::ZERO);
                for (i, &bit) in bits
                    .iter()
                    .skip(chunk * LIMB_BITS)
                    .take(LIMB_BITS)
                    .enumerate()
                {
                    let weight = self.define_const(F::from_u32(1 << i));
                    limb = self.mul_add(bit, weight, limb);
                }
                limbs.push(limb);
            }
        }
        Ok(limbs)
    }

    /// `hash` of a message given as little-endian 16-bit limbs; returns the 32-byte digest as
    /// [`DIGEST_LIMBS`] limbs.
    ///
    /// # Errors
    ///
    /// As [`Self::keccak256_limbs`] or [`Self::blake3_limbs`].
    pub fn byte_hash_limbs<BF>(
        &mut self,
        hash: ByteHash,
        message: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        match hash {
            ByteHash::Keccak256 => self.keccak256_limbs::<BF>(message),
            ByteHash::Blake3 => self.blake3_limbs::<BF>(message),
        }
    }

    /// `SerializingHasher<hash>` of base-field elements, the leaf hash of a `hash` Merkle tree.
    ///
    /// # Errors
    ///
    /// As [`Self::serialize_field_elements_to_limbs`] and [`Self::byte_hash_limbs`].
    pub fn byte_hash_field_elements<BF>(
        &mut self,
        hash: ByteHash,
        elements: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        let limbs = self.serialize_field_elements_to_limbs::<BF>(elements)?;
        self.byte_hash_limbs::<BF>(hash, &limbs)
    }

    /// `CompressionFunctionFromHasher<hash, 2, 32>`: `hash` of the 64-byte concatenation of two
    /// digests, the node compression of a `hash` Merkle tree.
    ///
    /// # Errors
    ///
    /// [`CircuitBuilderError::NonPrimitiveOpArity`] for a digest of the wrong width, or as the
    /// hash's own gadget.
    pub fn byte_hash_compress<BF>(
        &mut self,
        hash: ByteHash,
        left: &[ExprId],
        right: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        match hash {
            ByteHash::Keccak256 => self.keccak256_compress(left, right),
            ByteHash::Blake3 => self.blake3_compress_digests::<BF>(left, right),
        }
    }

    /// Constrains a single-matrix Merkle opening under `hash`: `leaf` (a row of base-field
    /// elements) sits at the position whose little-endian bits are `index_bits`, under `root`.
    ///
    /// This is `MerkleTreeMmcs` with a `SerializingHasher<hash>` leaf hash, a
    /// `CompressionFunctionFromHasher<hash, 2, 32>` node compression and a one-root cap.
    /// `siblings[i]` is the sibling digest at level `i` (bottom-up), `root` the cap digest, each
    /// as [`DIGEST_LIMBS`] limbs. At level `i`, a set `index_bits[i]` means the current node is
    /// the right child. Every index bit is constrained to be boolean.
    ///
    /// # Errors
    ///
    /// - [`CircuitBuilderError::NonPrimitiveOpArity`] if the path length differs from the index
    ///   width, or a digest has the wrong width.
    /// - As [`Self::byte_hash_field_elements`] and [`Self::byte_hash_compress`].
    pub fn verify_byte_hash_merkle_path<BF>(
        &mut self,
        hash: ByteHash,
        leaf: &[ExprId],
        index_bits: &[ExprId],
        siblings: &[Vec<ExprId>],
        root: &[ExprId],
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        if siblings.len() != index_bits.len() {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "MerklePath",
                expected: format!("one sibling per index bit ({})", index_bits.len()),
                got: siblings.len(),
            });
        }
        for digest in siblings.iter().map(Vec::as_slice).chain([root]) {
            if digest.len() != DIGEST_LIMBS {
                return Err(CircuitBuilderError::NonPrimitiveOpArity {
                    op: "MerklePath",
                    expected: format!("{DIGEST_LIMBS} limbs per digest"),
                    got: digest.len(),
                });
            }
        }

        let mut node = self.byte_hash_field_elements::<BF>(hash, leaf)?;
        for (&bit, sibling) in index_bits.iter().zip(siblings) {
            self.assert_bool(bit);
            let (left, right): (Vec<ExprId>, Vec<ExprId>) = node
                .iter()
                .zip(sibling)
                .map(|(&current, &other)| {
                    (
                        self.select(bit, other, current),
                        self.select(bit, current, other),
                    )
                })
                .unzip();
            node = self.byte_hash_compress::<BF>(hash, &left, &right)?;
        }
        for (&computed, &expected) in node.iter().zip(root) {
            self.connect(computed, expected);
        }
        Ok(())
    }

    /// [`Self::verify_byte_hash_merkle_path`] under Keccak-256.
    ///
    /// # Errors
    ///
    /// As [`Self::verify_byte_hash_merkle_path`].
    pub fn verify_keccak_merkle_path<BF>(
        &mut self,
        leaf: &[ExprId],
        index_bits: &[ExprId],
        siblings: &[Vec<ExprId>],
        root: &[ExprId],
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        self.verify_byte_hash_merkle_path::<BF>(
            ByteHash::Keccak256,
            leaf,
            index_bits,
            siblings,
            root,
        )
    }

    /// [`Self::verify_byte_hash_merkle_path`] under BLAKE3.
    ///
    /// # Errors
    ///
    /// As [`Self::verify_byte_hash_merkle_path`].
    pub fn verify_blake3_merkle_path<BF>(
        &mut self,
        leaf: &[ExprId],
        index_bits: &[ExprId],
        siblings: &[Vec<ExprId>],
        root: &[ExprId],
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        self.verify_byte_hash_merkle_path::<BF>(ByteHash::Blake3, leaf, index_bits, siblings, root)
    }
}
