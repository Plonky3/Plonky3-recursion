//! Native cubic challenge arithmetic over `Poly64` circuit cells.

use alloc::vec;
use alloc::vec::Vec;

use p3_binary_field::Poly64;
use p3_field::PrimeCharacteristicRing;

use super::binary_native::WordSplitHint;
use crate::{CircuitBuilder, CircuitBuilderError, ExprId};

/// `a0 + a1*y + a2*y²`, with native Poly64 coefficients and `y³ = y + 1`.
///
/// Every cell is already in Poly64, so no coefficient membership hint is needed.
/// IDs and targets must belong to the builder graph that uses them.
#[derive(Clone, Debug)]
pub struct NativePoly192Target {
    coefficients: [ExprId; 3],
}

impl NativePoly192Target {
    pub const fn coefficients(&self) -> &[ExprId; 3] {
        &self.coefficients
    }
}

impl CircuitBuilder<Poly64> {
    /// Low-first raw coordinates of coefficient 0, then 1, then 2. Each
    /// coordinate is Boolean and reconstructed in the coefficient's own basis.
    pub fn native_poly192_from_bits(
        &mut self,
        bits: [ExprId; 192],
    ) -> Result<NativePoly192Target, CircuitBuilderError> {
        let mut coefficients = [ExprId::ZERO; 3];
        for (coefficient, bits) in coefficients.iter_mut().zip(bits.as_chunks::<64>().0) {
            *coefficient = self.binary_recompose_coordinates(bits)?;
        }
        Ok(self.native_poly192_from_coefficients(coefficients))
    }

    /// Materializes checked raw bits only at a serialization boundary.
    pub fn native_poly192_to_bits(
        &mut self,
        value: &NativePoly192Target,
    ) -> Result<[ExprId; 192], CircuitBuilderError> {
        let mut bits = [ExprId::ZERO; 192];
        for (&coefficient, output) in value.coefficients.iter().zip(bits.as_chunks_mut::<64>().0) {
            output.copy_from_slice(&self.binary_decompose_coordinates(coefficient, 64)?);
        }
        Ok(bits)
    }

    /// Splits a Poly64 cell into `count` low-first sixteen-coefficient words
    /// without range-checking them.
    ///
    /// The hinted words satisfy `value = sum_j words[j] * x^(16j)`. A word of
    /// degree below sixteen times `x^(16j)` has degree below `16 * (j + 1)`,
    /// at most 63 for `j < 4`, so the product needs no reduction modulo the
    /// field polynomial and only shifts the word's coefficients up by
    /// `16 * j`. Once every word is constrained to sixteen coordinates, the
    /// words are therefore the unique split of `value`'s coefficients, and
    /// `value` has no coefficient at or above `16 * count`. The caller must
    /// establish that range, for example by absorbing every word through
    /// [`Self::native_keccak256_words`], whose AIR range-checks absorbed
    /// words. A zero count constrains `value` to zero. IDs must belong to this
    /// builder's graph.
    pub fn native_poly64_unchecked_words(
        &mut self,
        value: ExprId,
        count: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        if count > 4 {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: 64,
                n_bits: count.saturating_mul(16),
            });
        }
        self.check_construction_limits()?;
        let words = if count == 0 {
            Vec::new()
        } else {
            self.push_unconstrained_op(
                vec![vec![value]],
                count,
                WordSplitHint,
                "native_poly64_unchecked_words",
            )
            .2
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(CircuitBuilderError::MissingOutput)?
        };
        let mut sum = words.first().copied().unwrap_or(ExprId::ZERO);
        for (j, &word) in words.iter().enumerate().skip(1) {
            let shift = self.define_const(Poly64::new(1 << (16 * j)));
            sum = self.mul_add(word, shift, sum);
        }
        self.connect(value, sum);
        self.check_construction_limits()?;
        Ok(words)
    }

    /// Packs four low-first words into the cell `sum_j words[j] * x^(16j)`,
    /// which is `Poly64::from_le_bytes` of their little-endian bytes, with
    /// three fused multiply-adds and no decomposition.
    ///
    /// A word of degree below sixteen times `x^(16j)` has degree below 64, so
    /// the product only shifts its coefficients up by `16 * j` once every word
    /// has at most sixteen coefficients. The caller must establish that range,
    /// for example by reading the words from native Keccak-f or Blake3
    /// outputs, which the native hash AIR derives from Boolean bits. No
    /// coordinates are recorded. IDs must belong to this builder's graph.
    pub fn native_poly64_from_unchecked_words(
        &mut self,
        words: [ExprId; 4],
    ) -> Result<ExprId, CircuitBuilderError> {
        let mut sum = words[0];
        for (j, &word) in words.iter().enumerate().skip(1) {
            let shift = self.define_const(Poly64::new(1 << (16 * j)));
            sum = self.mul_add(word, shift, sum);
        }
        self.check_construction_limits()?;
        Ok(sum)
    }

    /// Packs eight low-first bytes into the cell `sum_k bytes[k] * x^(8k)`,
    /// which is `Poly64::from_le_bytes` of the bytes.
    ///
    /// Every byte is constrained to eight coordinates, which costs nothing
    /// when its coordinates are already known. A byte of degree below eight
    /// times `x^(8k)` has degree below 64, so the product only shifts its
    /// coefficients up by `8 * k`, and the packed cell's coordinates are the
    /// bytes' bits in order; they are recorded for later decompositions. IDs
    /// must belong to this builder's graph.
    pub fn native_poly64_from_bytes(
        &mut self,
        bytes: [ExprId; 8],
    ) -> Result<ExprId, CircuitBuilderError> {
        let mut bits = Vec::with_capacity(64);
        for &byte in &bytes {
            bits.extend(self.binary_decompose_coordinates(byte, 8)?);
        }
        let mut sum = bytes[0];
        for (k, &byte) in bytes.iter().enumerate().skip(1) {
            let shift = self.define_const(Poly64::new(1 << (8 * k)));
            sum = self.mul_add(byte, shift, sum);
        }
        self.check_construction_limits()?;
        self.record_native_coordinates(sum, &bits);
        Ok(sum)
    }

    pub const fn native_poly192_from_coefficients(
        &self,
        coefficients: [ExprId; 3],
    ) -> NativePoly192Target {
        NativePoly192Target { coefficients }
    }

    /// Raw polynomial coefficients, rather than integer ring embeddings.
    pub fn native_poly192_constant(&mut self, raw: [u64; 3]) -> NativePoly192Target {
        NativePoly192Target {
            coefficients: raw.map(|x| self.define_const(Poly64::new(x))),
        }
    }

    pub fn native_poly192_add(
        &mut self,
        a: &NativePoly192Target,
        b: &NativePoly192Target,
    ) -> NativePoly192Target {
        NativePoly192Target {
            coefficients: core::array::from_fn(|i| self.add(a.coefficients[i], b.coefficients[i])),
        }
    }

    pub fn native_poly192_mul(
        &mut self,
        a: &NativePoly192Target,
        b: &NativePoly192Target,
    ) -> NativePoly192Target {
        let [a0, a1, a2] = a.coefficients;
        let [b0, b1, b2] = b.coefficients;
        let cross = self.mul(a1, b2);
        let cross = self.mul_add(a2, b1, cross);
        let high = self.mul(a2, b2);
        // y³ = y + 1 and y⁴ = y² + y. Share their contributions and
        // accumulate the remaining products with one ALU operation each.
        let out0 = self.mul_add(a0, b0, cross);
        let out1 = self.add(cross, high);
        let out1 = self.mul_add(a0, b1, out1);
        let out1 = self.mul_add(a1, b0, out1);
        let out2 = self.mul_add(a0, b2, high);
        let out2 = self.mul_add(a1, b1, out2);
        let out2 = self.mul_add(a2, b0, out2);
        NativePoly192Target {
            coefficients: [out0, out1, out2],
        }
    }

    pub fn native_poly192_square(&mut self, value: &NativePoly192Target) -> NativePoly192Target {
        let [a0, a1, a2] = value.coefficients.map(|a| self.mul(a, a));
        let high = self.add(a1, a2);
        NativePoly192Target {
            coefficients: [a0, a2, high],
        }
    }

    /// Checks a caller-supplied inverse; zero has no satisfying candidate.
    pub fn assert_native_poly192_inverse(
        &mut self,
        value: &NativePoly192Target,
        candidate: &NativePoly192Target,
    ) {
        let product = self.native_poly192_mul(value, candidate);
        let one = self.define_const(Poly64::ONE);
        self.connect(product.coefficients[0], one);
        self.assert_zero(product.coefficients[1]);
        self.assert_zero(product.coefficients[2]);
    }
}
