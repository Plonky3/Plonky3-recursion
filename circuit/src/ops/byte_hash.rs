//! Gadgets shared by the byte-oriented hashes (Keccak-256 and BLAKE3): canonical field-element
//! serialization and Merkle path verification.
//!
//! Byte strings travel as little-endian 16-bit limbs, two bytes per limb; a 32-byte digest is
//! [`DIGEST_LIMBS`] limbs.

use alloc::format;
use alloc::vec::Vec;

use p3_field::{ExtensionField, Field, PrimeField64};
use p3_util::log2_ceil_usize;

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

    /// Constrains an opening of a `hash` `MerkleTreeMmcs` batch commitment at one index.
    ///
    /// This mirrors the native binary-arity `verify_batch`:
    ///
    /// - `rows[m]` is matrix `m`'s opened row (base-field elements), in commitment order, and
    ///   `heights[m]` its height. Heights need not be powers of two, but as natively, each must be
    ///   `ceil(max_height / 2^k)` for some `k`; the tree has `index_bits.len() =
    ///   ceil(log2(max_height))` levels, and a matrix of height `h` sits `ceil(log2(h))` levels
    ///   above the root.
    /// - The index, whose little-endian bits are `index_bits`, is constrained below `max_height`.
    /// - The leaf digest hashes the concatenated rows of every tallest matrix
    ///   (`SerializingHasher<hash>`).
    /// - Level `i` compresses the pair ordered by `index_bits[i]` (set: the current node is the
    ///   right child) with `siblings[i]`; then, if some matrices sit at the level just reached,
    ///   the digest becomes `compress(digest, hash(their rows))`.
    /// - After `index_bits.len() - log2(cap.len())` levels, the remaining index bits select the
    ///   cap root the digest must equal.
    ///
    /// Digests are [`DIGEST_LIMBS`] limbs. Every index bit is constrained to be boolean.
    ///
    /// # Errors
    ///
    /// - [`CircuitBuilderError::NonPrimitiveOpArity`] if the rows and heights, the path and the
    ///   index, or a digest's width disagree; if a height is not reachable from the tallest; if
    ///   the cap is not a power-of-two root count at most `2^index_bits.len()`; or if some matrix
    ///   sits below the cap layer.
    /// - As [`Self::byte_hash_field_elements`] and [`Self::byte_hash_compress`].
    #[allow(clippy::too_many_arguments)]
    pub fn verify_byte_hash_mmcs_opening<BF>(
        &mut self,
        hash: ByteHash,
        rows: &[Vec<ExprId>],
        heights: &[usize],
        index_bits: &[ExprId],
        siblings: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        let shape_error = |expected: alloc::string::String, got: usize| {
            CircuitBuilderError::NonPrimitiveOpArity {
                op: "MmcsOpening",
                expected,
                got,
            }
        };
        let log_max = index_bits.len();
        if rows.is_empty() || rows.len() != heights.len() {
            return Err(shape_error(
                format!("one height per opened row ({})", rows.len()),
                heights.len(),
            ));
        }
        let max_height = heights.iter().copied().max().unwrap_or(0);
        if max_height == 0 || log2_ceil_usize(max_height) != log_max {
            return Err(shape_error(
                format!("a tallest matrix of height needing {log_max} index bits"),
                max_height,
            ));
        }
        // As natively: a height `h` sits `k = log_max - ceil(log2(h))` levels up and must be
        // `ceil(max_height / 2^k)`, so each level holds at most one height.
        for &height in heights {
            let reduced = log_max - log2_ceil_usize(height.max(1));
            if height != ((max_height - 1) >> reduced) + 1 {
                return Err(shape_error(
                    format!("a height of ceil({max_height} / 2^k)"),
                    height,
                ));
            }
        }
        let log_heights: Vec<usize> = heights.iter().map(|&h| log2_ceil_usize(h)).collect();
        if !cap.len().is_power_of_two() || cap.len() > 1 << log_max {
            return Err(shape_error(
                format!("a power-of-two cap of at most 2^{log_max} roots"),
                cap.len(),
            ));
        }
        let cap_height = cap.len().trailing_zeros() as usize;
        let levels = log_max - cap_height;
        if siblings.len() != levels {
            return Err(shape_error(format!("{levels} siblings"), siblings.len()));
        }
        if let Some(&short) = log_heights.iter().find(|&&h| h < cap_height) {
            return Err(shape_error(
                format!("matrices at least as tall as the cap layer (log-height {cap_height})"),
                short,
            ));
        }
        for digest in siblings.iter().chain(cap) {
            if digest.len() != DIGEST_LIMBS {
                return Err(shape_error(
                    format!("{DIGEST_LIMBS} limbs per digest"),
                    digest.len(),
                ));
            }
        }

        // The concatenated rows of every matrix of one log-height, in commitment order.
        let rows_at = |log_height: usize| -> Vec<ExprId> {
            rows.iter()
                .zip(&log_heights)
                .filter(|&(_, &h)| h == log_height)
                .flat_map(|(row, _)| row.iter().copied())
                .collect()
        };

        for &bit in index_bits {
            self.assert_bool(bit);
        }
        if !max_height.is_power_of_two() {
            self.assert_bits_at_most(index_bits, max_height - 1);
        }

        let leaf = rows_at(log_max);
        let mut node = self.byte_hash_field_elements::<BF>(hash, &leaf)?;
        for (level, (&bit, sibling)) in index_bits.iter().zip(siblings).enumerate() {
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

            let reached = log_max - level - 1;
            if log_heights.contains(&reached) {
                let injected = rows_at(reached);
                let digest = self.byte_hash_field_elements::<BF>(hash, &injected)?;
                node = self.byte_hash_compress::<BF>(hash, &node, &digest)?;
            }
        }

        // The remaining index bits pick the cap root, one multiplexer layer per bit.
        let mut candidates: Vec<Vec<ExprId>> = cap.to_vec();
        for &bit in &index_bits[levels..] {
            candidates = candidates
                .chunks_exact(2)
                .map(|pair| {
                    pair[0]
                        .iter()
                        .zip(&pair[1])
                        .map(|(&even, &odd)| self.select(bit, odd, even))
                        .collect()
                })
                .collect();
        }
        for (&computed, &expected) in node.iter().zip(&candidates[0]) {
            self.connect(computed, expected);
        }
        Ok(())
    }

    /// Constrains the number whose little-endian (boolean) bits are `bits` to be at most `bound`.
    fn assert_bits_at_most(&mut self, bits: &[ExprId], bound: usize) {
        // `above` is whether the bits read so far, from the least significant, exceed `bound`'s
        // bits of the same positions: a set bit over a clear one exceeds it, a clear bit over a
        // set one does not, and equal bits leave the lower positions to decide.
        let mut above = self.define_const(F::ZERO);
        for (i, &bit) in bits.iter().enumerate() {
            let both = self.mul(bit, above);
            above = if bound >> i & 1 == 1 {
                both
            } else {
                let either = self.add(bit, above);
                self.sub(either, both)
            };
        }
        let zero = self.define_const(F::ZERO);
        self.connect(above, zero);
    }

    /// Constrains a single-matrix Merkle opening under `hash`: `leaf` sits at the position
    /// whose little-endian bits are `index_bits`, under a one-root cap `root`.
    ///
    /// [`Self::verify_byte_hash_mmcs_opening`] for one matrix and a one-root cap.
    ///
    /// # Errors
    ///
    /// As [`Self::verify_byte_hash_mmcs_opening`].
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
        self.verify_byte_hash_mmcs_opening::<BF>(
            hash,
            &[leaf.to_vec()],
            &[1 << index_bits.len()],
            index_bits,
            siblings,
            &[root.to_vec()],
        )
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

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::CircuitBuilder;

    #[test]
    fn the_index_bound_admits_exactly_the_indices_up_to_it() {
        for bound in 0..8usize {
            let mut builder = CircuitBuilder::<BabyBear>::new();
            let bits: Vec<ExprId> = (0..3).map(|_| builder.public_input()).collect();
            builder.assert_bits_at_most(&bits, bound);
            let circuit = builder.build().unwrap();
            for index in 0..8usize {
                let public: Vec<BabyBear> = (0..3)
                    .map(|i| BabyBear::from_bool(index >> i & 1 == 1))
                    .collect();
                let mut runner = circuit.runner();
                let runs = runner.set_public_inputs(&public).is_ok() && runner.run().is_ok();
                assert_eq!(runs, index <= bound, "index {index}, bound {bound}");
            }
        }
    }
}
