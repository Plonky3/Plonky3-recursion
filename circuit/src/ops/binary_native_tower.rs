//! Scalar arithmetic in the exact native 128-bit Wiedemann tower carrier.
//!
//! A scalar remains one circuit expression through arithmetic. Bits are
//! materialized, constrained and reconstructed only at serialization boundaries.
//! GHASH and polynomial carriers must not use this field's multiplication.

use alloc::vec;
use alloc::vec::Vec;

use p3_binary_field::{BinaryField128, TowerLevel};

use super::binary_native::WordSplitHint;
use crate::{CircuitBuilder, CircuitBuilderError, ExprId};

/// A native Tower128 scalar belonging to one builder's expression graph.
///
/// Every native carrier value is a valid scalar. Unlike `BinaryTower128Target`,
/// this type does not store bits; extracting them needs a checked builder call.
/// Expression IDs themselves do not carry a graph identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NativeTower128Target {
    value: ExprId,
}

impl NativeTower128Target {
    pub const fn as_expr(&self) -> ExprId {
        self.value
    }
}

impl CircuitBuilder<BinaryField128> {
    pub const fn native_tower128_from_expr(&self, value: ExprId) -> NativeTower128Target {
        NativeTower128Target { value }
    }

    /// Uses raw Wiedemann coordinates, not the ring's integer embedding.
    pub fn native_tower128_constant(&mut self, raw: u128) -> NativeTower128Target {
        let value = self.define_const(BinaryField128::from_repr(raw));
        NativeTower128Target { value }
    }

    pub fn native_tower128_add(
        &mut self,
        a: &NativeTower128Target,
        b: &NativeTower128Target,
    ) -> NativeTower128Target {
        let value = self.add(a.value, b.value);
        NativeTower128Target { value }
    }

    pub fn native_tower128_mul(
        &mut self,
        a: &NativeTower128Target,
        b: &NativeTower128Target,
    ) -> NativeTower128Target {
        let value = self.mul(a.value, b.value);
        NativeTower128Target { value }
    }

    pub fn native_tower128_square(&mut self, a: &NativeTower128Target) -> NativeTower128Target {
        self.native_tower128_mul(a, a)
    }

    pub fn assert_native_tower128_inverse(
        &mut self,
        value: &NativeTower128Target,
        candidate: &NativeTower128Target,
    ) {
        let product = self.mul(value.value, candidate.value);
        let one = self.define_const(BinaryField128::from_repr(1));
        self.connect(product, one);
    }

    pub fn native_tower128_from_bits(
        &mut self,
        bits: [ExprId; 128],
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        let value = self.binary_recompose_coordinates(&bits)?;
        Ok(NativeTower128Target { value })
    }

    pub fn native_tower128_to_bits(
        &mut self,
        value: &NativeTower128Target,
    ) -> Result<[ExprId; 128], CircuitBuilderError> {
        Ok(self
            .binary_decompose_coordinates(value.value, 128)?
            .try_into()
            .expect("full native tower decomposition has 128 bits"))
    }

    /// Each word is a checked low-first raw sixteen-coordinate span.
    pub fn native_tower128_from_words(
        &mut self,
        words: [ExprId; 8],
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        let mut bits = Vec::with_capacity(128);
        for word in words {
            bits.extend(self.binary_decompose_coordinates(word, 16)?);
        }
        self.native_tower128_from_bits(bits.try_into().expect("eight words have 128 bits"))
    }

    /// Packs sixteen low-first bytes into the scalar `sum_k bytes[k] * x_k`,
    /// where `x_k` has the single raw coordinate `8 * k`.
    ///
    /// Every byte is constrained to eight raw coordinates, which costs nothing
    /// when its coordinates are already known. In the tower basis, multiplying
    /// a scalar of at most eight coordinates by `x_k` shifts its coordinates
    /// up by `8 * k`, so the packed scalar's coordinates are the bytes' bits in
    /// order; they are recorded for later decompositions. IDs must belong to
    /// this builder's graph.
    pub fn native_tower128_from_bytes(
        &mut self,
        bytes: [ExprId; 16],
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        let mut bits = Vec::with_capacity(128);
        for &byte in &bytes {
            bits.extend(self.binary_decompose_coordinates(byte, 8)?);
        }
        let mut sum = bytes[0];
        for (k, &byte) in bytes.iter().enumerate().skip(1) {
            let shift = self.define_const(BinaryField128::from_repr(1 << (8 * k)));
            sum = self.mul_add(byte, shift, sum);
        }
        self.check_construction_limits()?;
        self.record_native_coordinates(sum, &bits);
        Ok(NativeTower128Target { value: sum })
    }

    pub fn native_tower128_to_words(
        &mut self,
        value: &NativeTower128Target,
    ) -> Result<[ExprId; 8], CircuitBuilderError> {
        let bits = self.native_tower128_to_bits(value)?;
        let words = bits
            .as_chunks::<16>()
            .0
            .iter()
            .map(|word| self.binary_recompose_coordinates(word))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(words.try_into().expect("128 bits have eight words"))
    }

    /// Splits a scalar into `count` low-first raw sixteen-coordinate words
    /// without range-checking them.
    ///
    /// The hinted words satisfy `value = sum_j words[j] * x_j`, where `x_j`
    /// has the single raw coordinate `16 * j`. In the tower basis, multiplying
    /// a scalar of at most sixteen coordinates by `x_j` shifts its coordinates
    /// up by `16 * j`. Once every word is constrained to sixteen coordinates,
    /// the words are therefore the unique raw split of `value`, and `value`
    /// has no coordinate at or above `16 * count`. The caller must establish
    /// that range, for example by absorbing every word through
    /// [`Self::native_keccak256_words`], whose AIR range-checks absorbed words.
    /// A zero count constrains `value` to zero. IDs must belong to this
    /// builder's graph.
    pub fn native_tower128_unchecked_words(
        &mut self,
        value: &NativeTower128Target,
        count: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        if count > 8 {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: 128,
                n_bits: count.saturating_mul(16),
            });
        }
        self.check_construction_limits()?;
        let words = if count == 0 {
            Vec::new()
        } else {
            self.push_unconstrained_op(
                vec![vec![value.value]],
                count,
                WordSplitHint,
                "native_tower128_unchecked_words",
            )
            .2
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(CircuitBuilderError::MissingOutput)?
        };
        let mut sum = words.first().copied().unwrap_or(ExprId::ZERO);
        for (j, &word) in words.iter().enumerate().skip(1) {
            let shift = self.define_const(BinaryField128::from_repr(1 << (16 * j)));
            sum = self.mul_add(word, shift, sum);
        }
        self.connect(value.value, sum);
        self.check_construction_limits()?;
        Ok(words)
    }
}
