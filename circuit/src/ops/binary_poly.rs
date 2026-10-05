//! Coordinate Poly64 and Poly192 arithmetic in their released polynomial bases.
//!
//! Poly64 reduces modulo `x^64 + x^4 + x^3 + x + 1`. Poly192 has three
//! Poly64 coefficients in ascending degree of `y`, with `y^3 = y + 1`.
//! Coordinates stay in these bases throughout arithmetic and serialization.
//! Checked Boolean coordinates and ordinary ALU operations suffice.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_field::{ExtensionField, Field, PrimeField64};

use crate::{CircuitBuilder, CircuitBuilderError, ExprId};

pub const BINARY_POLY64_BITS: usize = 64;
pub const BINARY_POLY64_LIMBS: usize = 4;
pub const BINARY_POLY192_LIMBS: usize = 12;

/// Checked polynomial coordinates: bit `i` is the coefficient of `x^i`.
/// Every target supplied to an operation must belong to that builder's graph.
#[derive(Clone, Debug)]
pub struct BinaryPoly64Target {
    bits: [ExprId; BINARY_POLY64_BITS],
}

impl BinaryPoly64Target {
    pub const fn bits(&self) -> &[ExprId; BINARY_POLY64_BITS] {
        &self.bits
    }
}

/// Checked coefficients `[a0, a1, a2]` of `a0 + a1*y + a2*y^2`.
/// Each coefficient uses Poly64's polynomial coordinates.
#[derive(Clone, Debug)]
pub struct BinaryPoly192Target {
    coefficients: [BinaryPoly64Target; 3],
}

impl BinaryPoly192Target {
    pub const fn coefficients(&self) -> &[BinaryPoly64Target; 3] {
        &self.coefficients
    }
}

impl<F: Field + Eq + Hash> CircuitBuilder<F> {
    /// Constrains every input coordinate to zero or one in either a prime or
    /// binary carrier field. Input IDs must belong to this graph.
    pub fn binary_poly64_from_bits(
        &mut self,
        bits: [ExprId; BINARY_POLY64_BITS],
    ) -> Result<BinaryPoly64Target, CircuitBuilderError> {
        for bit in bits {
            self.assert_bool(bit);
        }
        Ok(BinaryPoly64Target { bits })
    }

    /// Imports four little-endian u16 limbs with Boolean and base-field range
    /// constraints, including when this circuit uses an extension field.
    pub fn binary_poly64_from_limbs<BF: PrimeField64>(
        &mut self,
        limbs: [ExprId; BINARY_POLY64_LIMBS],
    ) -> Result<BinaryPoly64Target, CircuitBuilderError>
    where
        F: ExtensionField<BF>,
    {
        Self::check_poly_limb_field::<BF>("binary_poly64_from_limbs")?;
        let mut bits = [ExprId::ZERO; BINARY_POLY64_BITS];
        for (i, limb) in limbs.into_iter().enumerate() {
            bits[16 * i..16 * i + 16].copy_from_slice(&self.decompose_to_bits::<BF>(limb, 16)?);
        }
        Ok(BinaryPoly64Target { bits })
    }

    /// Constructs raw polynomial coordinates; this is not an integer embedding.
    pub fn binary_poly64_constant(
        &mut self,
        raw: u64,
    ) -> Result<BinaryPoly64Target, CircuitBuilderError> {
        let zero = self.define_const(F::ZERO);
        let one = self.define_const(F::ONE);
        Ok(BinaryPoly64Target {
            bits: core::array::from_fn(|i| if raw >> i & 1 == 0 { zero } else { one }),
        })
    }

    /// Exports the checked coordinates as four little-endian base-field limbs.
    pub fn binary_poly64_to_limbs<BF: PrimeField64>(
        &mut self,
        value: &BinaryPoly64Target,
    ) -> Result<[ExprId; BINARY_POLY64_LIMBS], CircuitBuilderError>
    where
        F: ExtensionField<BF>,
    {
        Self::check_poly_limb_field::<BF>("binary_poly64_to_limbs")?;
        let zero = self.define_const(F::ZERO);
        let weights = core::array::from_fn::<_, 16, _>(|i| self.define_const(F::from_u16(1 << i)));
        Ok(core::array::from_fn(|limb| {
            (0..16).fold(zero, |sum, i| {
                self.mul_add(value.bits[16 * limb + i], weights[i], sum)
            })
        }))
    }

    pub fn binary_poly64_add(
        &mut self,
        a: &BinaryPoly64Target,
        b: &BinaryPoly64Target,
    ) -> BinaryPoly64Target {
        BinaryPoly64Target {
            bits: core::array::from_fn(|i| self.poly_xor(a.bits[i], b.bits[i])),
        }
    }

    /// Carryless Karatsuba product followed by complete polynomial reduction.
    pub fn binary_poly64_mul(
        &mut self,
        a: &BinaryPoly64Target,
        b: &BinaryPoly64Target,
    ) -> BinaryPoly64Target {
        let product = self.poly_carryless_product(&a.bits, &b.bits);
        self.poly_reduce(product)
    }

    /// Frobenius squaring: insert zero odd coefficients, then reduce.
    pub fn binary_poly64_square(&mut self, a: &BinaryPoly64Target) -> BinaryPoly64Target {
        let mut coefficients = vec![ExprId::ZERO; 127];
        for (i, &bit) in a.bits.iter().enumerate() {
            coefficients[2 * i] = bit;
        }
        self.poly_reduce(coefficients)
    }

    /// Constrains `value*candidate == 1`; zero has no satisfying candidate.
    pub fn assert_binary_poly64_inverse(
        &mut self,
        value: &BinaryPoly64Target,
        candidate: &BinaryPoly64Target,
    ) {
        let product = self.binary_poly64_mul(value, candidate);
        self.assert_poly_one(&product);
    }

    /// Assembles three already checked coefficient targets from this graph.
    pub const fn binary_poly192_from_coefficients(
        &mut self,
        coefficients: [BinaryPoly64Target; 3],
    ) -> BinaryPoly192Target {
        BinaryPoly192Target { coefficients }
    }

    /// Imports twelve little-endian u16 limbs in coefficient order.
    pub fn binary_poly192_from_limbs<BF: PrimeField64>(
        &mut self,
        limbs: [ExprId; BINARY_POLY192_LIMBS],
    ) -> Result<BinaryPoly192Target, CircuitBuilderError>
    where
        F: ExtensionField<BF>,
    {
        Self::check_poly_limb_field::<BF>("binary_poly192_from_limbs")?;
        let a0 =
            self.binary_poly64_from_limbs::<BF>(limbs[..4].try_into().expect("fixed coefficient"))?;
        let a1 = self
            .binary_poly64_from_limbs::<BF>(limbs[4..8].try_into().expect("fixed coefficient"))?;
        let a2 =
            self.binary_poly64_from_limbs::<BF>(limbs[8..].try_into().expect("fixed coefficient"))?;
        Ok(BinaryPoly192Target {
            coefficients: [a0, a1, a2],
        })
    }

    pub fn binary_poly192_constant(
        &mut self,
        raw: [u64; 3],
    ) -> Result<BinaryPoly192Target, CircuitBuilderError> {
        Ok(BinaryPoly192Target {
            coefficients: [
                self.binary_poly64_constant(raw[0])?,
                self.binary_poly64_constant(raw[1])?,
                self.binary_poly64_constant(raw[2])?,
            ],
        })
    }

    pub fn binary_poly192_to_limbs<BF: PrimeField64>(
        &mut self,
        value: &BinaryPoly192Target,
    ) -> Result<[ExprId; BINARY_POLY192_LIMBS], CircuitBuilderError>
    where
        F: ExtensionField<BF>,
    {
        Self::check_poly_limb_field::<BF>("binary_poly192_to_limbs")?;
        let mut result = [ExprId::ZERO; BINARY_POLY192_LIMBS];
        for (i, coefficient) in value.coefficients.iter().enumerate() {
            result[4 * i..4 * i + 4]
                .copy_from_slice(&self.binary_poly64_to_limbs::<BF>(coefficient)?);
        }
        Ok(result)
    }

    pub fn binary_poly192_add(
        &mut self,
        a: &BinaryPoly192Target,
        b: &BinaryPoly192Target,
    ) -> BinaryPoly192Target {
        BinaryPoly192Target {
            coefficients: core::array::from_fn(|i| {
                self.binary_poly64_add(&a.coefficients[i], &b.coefficients[i])
            }),
        }
    }

    /// Six Poly64 products, reduced by `y^3=y+1`.
    pub fn binary_poly192_mul(
        &mut self,
        a: &BinaryPoly192Target,
        b: &BinaryPoly192Target,
    ) -> BinaryPoly192Target {
        let c0 = self.binary_poly64_mul(&a.coefficients[0], &b.coefficients[0]);
        let c1 = self.binary_poly64_mul(&a.coefficients[1], &b.coefficients[1]);
        let c2 = self.binary_poly64_mul(&a.coefficients[2], &b.coefficients[2]);
        let mut cross = |i, j| {
            let a = self.binary_poly64_add(&a.coefficients[i], &a.coefficients[j]);
            let b = self.binary_poly64_add(&b.coefficients[i], &b.coefficients[j]);
            self.binary_poly64_mul(&a, &b)
        };
        let d01 = cross(0, 1);
        let d02 = cross(0, 2);
        let d12 = cross(1, 2);
        let s = self.binary_poly64_add(&c0, &c1);
        let a0 = self.binary_poly64_add(&s, &c2);
        let a0 = self.binary_poly64_add(&a0, &d12);
        let a1 = self.binary_poly64_add(&c0, &d01);
        let a1 = self.binary_poly64_add(&a1, &d12);
        let a2 = self.binary_poly64_add(&s, &d02);
        BinaryPoly192Target {
            coefficients: [a0, a1, a2],
        }
    }

    pub fn binary_poly192_square(&mut self, a: &BinaryPoly192Target) -> BinaryPoly192Target {
        let a0 = self.binary_poly64_square(&a.coefficients[0]);
        let a1 = self.binary_poly64_square(&a.coefficients[1]);
        let a2 = self.binary_poly64_square(&a.coefficients[2]);
        let last = self.binary_poly64_add(&a1, &a2);
        BinaryPoly192Target {
            coefficients: [a0, a2, last],
        }
    }

    pub fn binary_poly192_scale(
        &mut self,
        a: &BinaryPoly192Target,
        scalar: &BinaryPoly64Target,
    ) -> BinaryPoly192Target {
        BinaryPoly192Target {
            coefficients: core::array::from_fn(|i| {
                self.binary_poly64_mul(&a.coefficients[i], scalar)
            }),
        }
    }

    pub fn binary_poly192_mul_y(&mut self, a: &BinaryPoly192Target) -> BinaryPoly192Target {
        let middle = self.binary_poly64_add(&a.coefficients[0], &a.coefficients[2]);
        BinaryPoly192Target {
            coefficients: [a.coefficients[2].clone(), middle, a.coefficients[1].clone()],
        }
    }

    pub fn assert_binary_poly192_inverse(
        &mut self,
        value: &BinaryPoly192Target,
        candidate: &BinaryPoly192Target,
    ) {
        let product = self.binary_poly192_mul(value, candidate);
        self.assert_poly_one(&product.coefficients[0]);
        for coefficient in &product.coefficients[1..] {
            for &bit in &coefficient.bits {
                self.assert_zero(bit);
            }
        }
    }

    fn check_poly_characteristic(operation: &'static str) -> Result<(), CircuitBuilderError> {
        if F::TWO == F::ZERO {
            Err(CircuitBuilderError::CharacteristicTwoUnsupported { operation })
        } else {
            Ok(())
        }
    }
    fn check_poly_limb_field<BF: PrimeField64>(
        operation: &'static str,
    ) -> Result<(), CircuitBuilderError> {
        Self::check_poly_characteristic(operation)?;
        if BF::ORDER_U64 <= u64::from(u16::MAX) {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: BF::ORDER_U64.ilog2() as usize,
                n_bits: 16,
            });
        }
        Ok(())
    }
    fn poly_xor(&mut self, a: ExprId, b: ExprId) -> ExprId {
        if a == ExprId::ZERO {
            return b;
        }
        if b == ExprId::ZERO {
            return a;
        }
        if F::TWO == F::ZERO {
            return self.add(a, b);
        }
        let difference = self.sub(a, b);
        self.mul(difference, difference)
    }
    fn poly_carryless_product(&mut self, a: &[ExprId], b: &[ExprId]) -> Vec<ExprId> {
        if a.len() == 1 {
            return vec![self.mul(a[0], b[0])];
        }
        let half = a.len() / 2;
        let z0 = self.poly_carryless_product(&a[..half], &b[..half]);
        let z2 = self.poly_carryless_product(&a[half..], &b[half..]);
        let a_sum: Vec<_> = (0..half)
            .map(|i| self.poly_xor(a[i], a[half + i]))
            .collect();
        let b_sum: Vec<_> = (0..half)
            .map(|i| self.poly_xor(b[i], b[half + i]))
            .collect();
        let middle = self.poly_carryless_product(&a_sum, &b_sum);
        let mut result = vec![ExprId::ZERO; 2 * a.len() - 1];
        result[..z0.len()].copy_from_slice(&z0);
        result[a.len()..a.len() + z2.len()].copy_from_slice(&z2);
        for i in 0..middle.len() {
            let cross = self.poly_xor(middle[i], z0[i]);
            let cross = self.poly_xor(cross, z2[i]);
            result[half + i] = self.poly_xor(result[half + i], cross);
        }
        result
    }
    fn poly_reduce(&mut self, mut product: Vec<ExprId>) -> BinaryPoly64Target {
        // Descending reduction also processes the spill created by the four
        // taps at degrees 64..66. One truncated fold would lose those terms.
        for degree in (64..product.len()).rev() {
            let high = product[degree];
            for tap in [0, 1, 3, 4] {
                let position = degree - 64 + tap;
                product[position] = self.poly_xor(product[position], high);
            }
        }
        BinaryPoly64Target {
            bits: product[..64]
                .try_into()
                .expect("reduced Poly64 coordinates"),
        }
    }
    fn assert_poly_one(&mut self, value: &BinaryPoly64Target) {
        let one = self.define_const(F::ONE);
        let difference = self.sub(value.bits[0], one);
        self.assert_zero(difference);
        for &bit in &value.bits[1..] {
            self.assert_zero(bit);
        }
    }
}
