//! Coordinate arithmetic for Plonky3's 128-bit Wiedemann binary tower.
//!
//! The coordinate at bit zero is one. At each quadratic level the low half
//! precedes the high half: `a = a0 + a1 * X`, where `X² = alpha * X + 1` and
//! `alpha` is the generator of the preceding level. This is the raw
//! `p3_binary_field::BinaryField128` tower representation, not GHASH's
//! polynomial basis. Every 128-bit string is a valid tower element.
//!
//! Bits can live in prime or binary circuit fields. Ingress constrains them
//! to zero or one; XOR is `(a - b)²` in odd characteristic and `a + b` in
//! characteristic two. AND is `a * b`. Integer-limb codecs remain prime-only.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_field::{ExtensionField, Field, PrimeField64};

use crate::builder::CircuitBuilderError;
use crate::{CircuitBuilder, ExprId};

/// Number of raw tower coordinates in a binary-128 element.
pub const BINARY_TOWER128_BITS: usize = 128;
/// Number of little-endian 16-bit limbs in a binary-128 element.
pub const BINARY_TOWER128_LIMBS: usize = 8;

const LIMB_BITS: usize = 16;

/// A constrained element of Plonky3's 128-bit Wiedemann binary tower.
///
/// Coordinates are little-endian: `bits()[0]` is the coefficient of one,
/// and each consecutive 16 coordinates form a little-endian limb. The
/// private representation ensures that only the checked builder constructors
/// can create a target. As with all [`ExprId`] targets, every target passed to
/// a builder method must originate in that same builder's expression graph;
/// `ExprId` itself does not encode graph identity.
#[derive(Clone, Debug)]
pub struct BinaryTower128Target {
    bits: [ExprId; BINARY_TOWER128_BITS],
}

impl BinaryTower128Target {
    /// Read-only access to the 128 constrained tower coordinates.
    pub const fn bits(&self) -> &[ExprId; BINARY_TOWER128_BITS] {
        &self.bits
    }
}

impl<F> CircuitBuilder<F>
where
    F: Field + Eq + Hash,
{
    /// Imports 128 little-endian raw tower bits, constraining every bit to
    /// the prime subfield values zero or one.
    ///
    /// The input IDs must belong to this builder's expression graph.
    ///
    /// Supports both prime and binary carrier fields.
    pub fn binary128_from_bits(
        &mut self,
        bits: [ExprId; BINARY_TOWER128_BITS],
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        for bit in bits {
            self.assert_bool(bit);
        }
        Ok(BinaryTower128Target { bits })
    }

    /// Imports eight little-endian 16-bit limbs as one raw tower element.
    /// Each limb is decomposed into Boolean bits and constrained to the base
    /// field range `0..=65535`, including when the circuit uses an extension
    /// field. The limb IDs must belong to this builder's expression graph.
    ///
    /// # Errors
    ///
    /// Rejects characteristic two, then base-field order at most 65535,
    /// before changing the builder. Propagates decomposition errors.
    pub fn binary128_from_limbs<BF>(
        &mut self,
        limbs: [ExprId; BINARY_TOWER128_LIMBS],
    ) -> Result<BinaryTower128Target, CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        Self::check_limb_field::<BF>("binary128_from_limbs")?;
        let mut bits = Vec::with_capacity(BINARY_TOWER128_BITS);
        for limb in limbs {
            bits.extend(self.decompose_to_bits::<BF>(limb, LIMB_BITS)?);
        }
        Ok(BinaryTower128Target {
            bits: bits
                .try_into()
                .expect("eight 16-bit limbs produce 128 bits"),
        })
    }

    /// Makes the tower element whose raw coordinates are the bits of `raw`,
    /// least significant first. This is a coordinate constructor, not a
    /// prime-subfield integer embedding.
    ///
    /// Supports both prime and binary carrier fields.
    pub fn binary128_constant(
        &mut self,
        raw: u128,
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        let zero = self.define_const(F::ZERO);
        let one = self.define_const(F::ONE);
        Ok(BinaryTower128Target {
            bits: core::array::from_fn(|i| if raw & (1u128 << i) == 0 { zero } else { one }),
        })
    }

    /// Exports a constrained tower element as eight little-endian 16-bit
    /// limbs embedded in the base field. The target must belong to this
    /// builder's expression graph.
    ///
    /// # Errors
    ///
    /// Rejects characteristic two, then base-field order at most 65535,
    /// before changing the builder.
    pub fn binary128_to_limbs<BF>(
        &mut self,
        value: &BinaryTower128Target,
    ) -> Result<[ExprId; BINARY_TOWER128_LIMBS], CircuitBuilderError>
    where
        BF: PrimeField64,
        F: ExtensionField<BF>,
    {
        Self::check_limb_field::<BF>("binary128_to_limbs")?;
        let zero = self.define_const(F::ZERO);
        let weights =
            core::array::from_fn::<_, LIMB_BITS, _>(|i| self.define_const(F::from_u32(1u32 << i)));
        Ok(core::array::from_fn(|j| {
            (0..LIMB_BITS).fold(zero, |acc, i| {
                self.mul_add(value.bits[j * LIMB_BITS + i], weights[i], acc)
            })
        }))
    }

    /// Adds two tower elements (coordinate-wise XOR).
    /// Both targets must belong to this builder's expression graph.
    pub fn binary128_add(
        &mut self,
        a: &BinaryTower128Target,
        b: &BinaryTower128Target,
    ) -> BinaryTower128Target {
        BinaryTower128Target {
            bits: core::array::from_fn(|i| self.binary_xor(a.bits[i], b.bits[i])),
        }
    }

    /// Multiplies two tower elements with recursive Karatsuba reduction by
    /// `X² = alpha * X + 1`. Both targets must belong to this builder's graph.
    pub fn binary128_mul(
        &mut self,
        a: &BinaryTower128Target,
        b: &BinaryTower128Target,
    ) -> BinaryTower128Target {
        BinaryTower128Target {
            bits: self
                .binary_mul_recursive(&a.bits, &b.bits)
                .try_into()
                .expect("binary-128 multiplication returns 128 bits"),
        }
    }

    /// Squares a tower element using the characteristic-two tower identity
    /// `(a0 + a1*X)² = (a0² + a1²) + alpha*a1²*X`.
    /// The target must belong to this builder's expression graph.
    pub fn binary128_square(&mut self, a: &BinaryTower128Target) -> BinaryTower128Target {
        BinaryTower128Target {
            bits: self
                .binary_square_recursive(&a.bits)
                .try_into()
                .expect("binary-128 square returns 128 bits"),
        }
    }

    /// Constrains `value * candidate == 1` in the binary tower. This proves
    /// that `candidate` is the unique inverse of a nonzero `value`; zero has
    /// no satisfying candidate. Both targets must belong to this builder's
    /// expression graph. The supplied values remain independent witness
    /// expressions: equality is imposed on derived differences.
    pub fn assert_binary128_inverse(
        &mut self,
        value: &BinaryTower128Target,
        candidate: &BinaryTower128Target,
    ) {
        let product = self.binary128_mul(value, candidate);
        let zero = self.define_const(F::ZERO);
        let one = self.define_const(F::ONE);
        for (i, &bit) in product.bits.iter().enumerate() {
            let expected = if i == 0 { one } else { zero };
            let difference = self.sub(bit, expected);
            self.assert_zero(difference);
        }
    }

    fn check_limb_field<BF: PrimeField64>(
        operation: &'static str,
    ) -> Result<(), CircuitBuilderError> {
        if F::TWO == F::ZERO {
            return Err(CircuitBuilderError::CharacteristicTwoUnsupported { operation });
        }
        if BF::ORDER_U64 <= u64::from(u16::MAX) {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: BF::ORDER_U64.ilog2() as usize,
                n_bits: LIMB_BITS,
            });
        }
        Ok(())
    }

    /// XOR of constrained bits, in either characteristic.
    fn binary_xor(&mut self, a: ExprId, b: ExprId) -> ExprId {
        if F::TWO == F::ZERO {
            return self.add(a, b);
        }
        let difference = self.sub(a, b);
        self.mul(difference, difference)
    }

    fn binary_xor_slices(&mut self, a: &[ExprId], b: &[ExprId]) -> Vec<ExprId> {
        a.iter()
            .zip(b)
            .map(|(&a_bit, &b_bit)| self.binary_xor(a_bit, b_bit))
            .collect()
    }

    /// Multiplication by this level's generator in the preceding tower.
    /// At one bit the generator is one; at larger levels,
    /// `alpha(c0,c1) = (c1, c0 XOR alpha(c1))`.
    fn binary_mul_alpha(&mut self, value: &[ExprId]) -> Vec<ExprId> {
        if value.len() == 1 {
            return value.to_vec();
        }
        let (lo, hi) = value.split_at(value.len() / 2);
        let alpha_hi = self.binary_mul_alpha(hi);
        let mut result = hi.to_vec();
        result.extend(self.binary_xor_slices(lo, &alpha_hi));
        result
    }

    fn binary_mul_recursive(&mut self, a: &[ExprId], b: &[ExprId]) -> Vec<ExprId> {
        if a.len() == 1 {
            return alloc::vec![self.mul(a[0], b[0])];
        }
        let half = a.len() / 2;
        let (a0, a1) = a.split_at(half);
        let (b0, b1) = b.split_at(half);
        let z0 = self.binary_mul_recursive(a0, b0);
        let z2 = self.binary_mul_recursive(a1, b1);
        let a_sum = self.binary_xor_slices(a0, a1);
        let b_sum = self.binary_xor_slices(b0, b1);
        let middle = self.binary_mul_recursive(&a_sum, &b_sum);
        let mut result = self.binary_xor_slices(&z0, &z2);
        if half == 1 {
            // Here alpha(z2) = z2, so middle XOR (z0 XOR z2) XOR z2
            // simplifies to middle XOR z0.
            result.push(self.binary_xor(middle[0], z0[0]));
        } else {
            let alpha_z2 = self.binary_mul_alpha(&z2);
            let high_without_alpha = self.binary_xor_slices(&middle, &result);
            result.extend(self.binary_xor_slices(&high_without_alpha, &alpha_z2));
        }
        result
    }

    fn binary_square_recursive(&mut self, a: &[ExprId]) -> Vec<ExprId> {
        if a.len() == 1 {
            return a.to_vec();
        }
        let (a0, a1) = a.split_at(a.len() / 2);
        let lo_square = self.binary_square_recursive(a0);
        let hi_square = self.binary_square_recursive(a1);
        let mut result = self.binary_xor_slices(&lo_square, &hi_square);
        result.extend(self.binary_mul_alpha(&hi_square));
        result
    }
}
