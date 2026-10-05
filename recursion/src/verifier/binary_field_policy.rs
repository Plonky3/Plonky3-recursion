//! Closed arithmetic choices for native binary AIR relations.

use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::{BinaryField128, Poly64, Poly192};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{
    BinaryPoly64Target, BinaryPoly192Target, BinaryTower128Target, NativeTower128Target,
};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, Field};

use crate::BinaryTower128Challenger;
use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::verifier::VerificationError;

mod whir;
pub(crate) use whir::{BinaryOracleWord, BinaryWhirPolicy};

mod native_poly;
pub(crate) use native_poly::{
    BinaryPolyPolicy, NativePoly64Relation, poly_native_values, poly_observe_seed_with_host,
    poly_seed_bytes_with_host,
};

mod sealed {
    pub trait Relation {}
}

pub(crate) trait BinaryRelationPolicy<EF: Field + Eq + Hash>: sealed::Relation {
    type Base: Field;
    type Challenge: ExtensionField<Self::Base>;
    type BaseTarget: Clone;
    type ChallengeTarget: Clone;
    fn constant(
        b: &mut CircuitBuilder<EF>,
        raw: u128,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
    fn lift(
        b: &mut CircuitBuilder<EF>,
        value: &Self::BaseTarget,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
    fn constrain_base(
        b: &mut CircuitBuilder<EF>,
        value: &Self::BaseTarget,
    ) -> Result<(), CircuitBuilderError>;
    fn constrain_challenge(b: &mut CircuitBuilder<EF>, value: &Self::ChallengeTarget);
    fn add(
        b: &mut CircuitBuilder<EF>,
        a: &Self::ChallengeTarget,
        c: &Self::ChallengeTarget,
    ) -> Self::ChallengeTarget;
    fn mul(
        b: &mut CircuitBuilder<EF>,
        a: &Self::ChallengeTarget,
        c: &Self::ChallengeTarget,
    ) -> Self::ChallengeTarget;
}

pub(crate) struct TowerRelation<F, E>(PhantomData<(F, E)>);
impl<F, E> sealed::Relation for TowerRelation<F, E> {}
impl<EF, F, E> BinaryRelationPolicy<EF> for TowerRelation<F, E>
where
    EF: Field + Eq + Hash,
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    type Base = F;
    type Challenge = E;
    type BaseTarget = BinaryTower128Target;
    type ChallengeTarget = BinaryTower128Target;
    fn constant(
        b: &mut CircuitBuilder<EF>,
        raw: u128,
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        b.binary128_constant(raw)
    }
    fn lift(
        _b: &mut CircuitBuilder<EF>,
        value: &BinaryTower128Target,
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        Ok(value.clone())
    }
    fn constrain_base(
        b: &mut CircuitBuilder<EF>,
        value: &BinaryTower128Target,
    ) -> Result<(), CircuitBuilderError> {
        constrain_tower_width(b, value, F::RAW_BITS);
        Ok(())
    }
    fn constrain_challenge(b: &mut CircuitBuilder<EF>, value: &BinaryTower128Target) {
        constrain_tower_width(b, value, E::RAW_BITS);
    }
    fn add(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryTower128Target,
        c: &BinaryTower128Target,
    ) -> BinaryTower128Target {
        b.binary128_add(a, c)
    }
    fn mul(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryTower128Target,
        c: &BinaryTower128Target,
    ) -> BinaryTower128Target {
        b.binary128_mul(a, c)
    }
}

pub(crate) struct Poly64Relation;
impl sealed::Relation for Poly64Relation {}
impl<EF: Field + Eq + Hash> BinaryRelationPolicy<EF> for Poly64Relation {
    type Base = Poly64;
    type Challenge = Poly192;
    type BaseTarget = BinaryPoly64Target;
    type ChallengeTarget = BinaryPoly192Target;
    fn constant(
        b: &mut CircuitBuilder<EF>,
        raw: u128,
    ) -> Result<BinaryPoly192Target, CircuitBuilderError> {
        // The private program compiler obtains constants only from Poly64.
        debug_assert!(raw <= u64::MAX as u128);
        b.binary_poly192_constant([raw as u64, 0, 0])
    }
    fn lift(
        b: &mut CircuitBuilder<EF>,
        value: &BinaryPoly64Target,
    ) -> Result<BinaryPoly192Target, CircuitBuilderError> {
        let zero = b.binary_poly64_constant(0)?;
        Ok(b.binary_poly192_from_coefficients([value.clone(), zero.clone(), zero]))
    }
    fn constrain_base(
        _b: &mut CircuitBuilder<EF>,
        _value: &BinaryPoly64Target,
    ) -> Result<(), CircuitBuilderError> {
        Ok(())
    }
    fn constrain_challenge(_b: &mut CircuitBuilder<EF>, _value: &BinaryPoly192Target) {}
    fn add(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryPoly192Target,
        c: &BinaryPoly192Target,
    ) -> BinaryPoly192Target {
        b.binary_poly192_add(a, c)
    }
    fn mul(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryPoly192Target,
        c: &BinaryPoly192Target,
    ) -> BinaryPoly192Target {
        b.binary_poly192_mul(a, c)
    }
}

fn constrain_tower_width<EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    value: &BinaryTower128Target,
    bits: usize,
) {
    for &bit in &value.bits()[bits..] {
        let difference = b.sub(ExprId::ZERO, bit);
        b.assert_zero(difference);
    }
}

/// Closed transcript and equality operations used by binary GKR kernels.
pub(crate) trait BinaryProtocolPolicy<EF: Field + Eq + Hash>:
    BinaryRelationPolicy<EF>
{
    fn observe<H: BinaryCircuitHost<EF>>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        values: &[Self::ChallengeTarget],
    ) -> Result<(), VerificationError>;
    fn observe_after_queries<H: BinaryCircuitHost<EF>>(
        b: &mut CircuitBuilder<EF>,
        token: crate::BinaryQueryContinuation,
        values: &[Self::ChallengeTarget],
    ) -> Result<BinaryTower128Challenger, VerificationError>;
    fn sample<H: BinaryCircuitHost<EF>>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<Self::ChallengeTarget, VerificationError>;
    fn assert_equal(
        b: &mut CircuitBuilder<EF>,
        a: &Self::ChallengeTarget,
        c: &Self::ChallengeTarget,
    );
    fn eq_eval(
        b: &mut CircuitBuilder<EF>,
        a: &[Self::ChallengeTarget],
        c: &[Self::ChallengeTarget],
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
}

impl<EF, F, E> BinaryProtocolPolicy<EF> for TowerRelation<F, E>
where
    EF: Field + Eq + Hash,
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    fn observe<H: BinaryCircuitHost<EF>>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        values: &[BinaryTower128Target],
    ) -> Result<(), VerificationError> {
        crate::pcs::binary::observe_values_with_host::<H, EF>(b, ch, values, E::RAW_BITS)
    }
    fn observe_after_queries<H: BinaryCircuitHost<EF>>(
        b: &mut CircuitBuilder<EF>,
        token: crate::BinaryQueryContinuation,
        values: &[BinaryTower128Target],
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        let bytes = values
            .iter()
            .flat_map(|value| value.bits()[..E::RAW_BITS].as_chunks::<8>().0.iter())
            .map(|bits| H::recompose_word(b, bits))
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;
        Ok(token.resume_with_observation_with_host::<H, EF>(b, &bytes)?)
    }
    fn sample<H: BinaryCircuitHost<EF>>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<BinaryTower128Target, VerificationError> {
        super::binary_product::sample_with_host::<E, H, EF>(b, ch)
    }
    fn assert_equal(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryTower128Target,
        c: &BinaryTower128Target,
    ) {
        crate::pcs::binary::assert_equal(b, a, c);
    }
    fn eq_eval(
        b: &mut CircuitBuilder<EF>,
        a: &[BinaryTower128Target],
        c: &[BinaryTower128Target],
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        crate::pcs::binary::binary128_eq_eval(b, a, c)
    }
}

impl<EF: Field + Eq + Hash> BinaryProtocolPolicy<EF> for Poly64Relation {
    fn observe<H: BinaryCircuitHost<EF>>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        values: &[BinaryPoly192Target],
    ) -> Result<(), VerificationError> {
        for value in values {
            ch.observe_poly192_with_host::<H, EF>(b, value)?;
        }
        Ok(())
    }
    fn observe_after_queries<H: BinaryCircuitHost<EF>>(
        b: &mut CircuitBuilder<EF>,
        token: crate::BinaryQueryContinuation,
        values: &[BinaryPoly192Target],
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        let bytes = values
            .iter()
            .flat_map(|value| {
                value
                    .coefficients()
                    .iter()
                    .flat_map(|coefficient| coefficient.bits().as_chunks::<8>().0.iter())
            })
            .map(|bits| H::recompose_word(b, bits))
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;
        Ok(token.resume_with_observation_with_host::<H, EF>(b, &bytes)?)
    }
    fn sample<H: BinaryCircuitHost<EF>>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<BinaryPoly192Target, VerificationError> {
        Ok(ch.sample_poly192_with_host::<H, EF>(b)?)
    }
    fn assert_equal(b: &mut CircuitBuilder<EF>, a: &BinaryPoly192Target, c: &BinaryPoly192Target) {
        crate::pcs::binary::poly_assert_equal(b, a, c);
    }
    fn eq_eval(
        b: &mut CircuitBuilder<EF>,
        a: &[BinaryPoly192Target],
        c: &[BinaryPoly192Target],
    ) -> Result<BinaryPoly192Target, CircuitBuilderError> {
        crate::pcs::binary::poly192_eq_eval(b, a, c)
    }
}

/// Arithmetic in the exact native Wiedemann carrier; no basis reinterpretation.
pub(crate) struct NativeTower128Relation<F = BinaryField128>(PhantomData<F>);
impl<F> sealed::Relation for NativeTower128Relation<F> {}
impl<F: RecursiveBinaryTowerField> BinaryRelationPolicy<BinaryField128>
    for NativeTower128Relation<F>
where
    BinaryField128: ExtensionField<F>,
{
    type Base = F;
    type Challenge = BinaryField128;
    type BaseTarget = NativeTower128Target;
    type ChallengeTarget = NativeTower128Target;
    fn constant(
        b: &mut CircuitBuilder<BinaryField128>,
        raw: u128,
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        Ok(b.native_tower128_constant(raw))
    }
    fn lift(
        _b: &mut CircuitBuilder<BinaryField128>,
        value: &NativeTower128Target,
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        Ok(*value)
    }
    fn constrain_base(
        b: &mut CircuitBuilder<BinaryField128>,
        value: &NativeTower128Target,
    ) -> Result<(), CircuitBuilderError> {
        if F::RAW_BITS < 128 {
            b.binary_decompose_coordinates(value.as_expr(), F::RAW_BITS)?;
        }
        Ok(())
    }
    fn constrain_challenge(_b: &mut CircuitBuilder<BinaryField128>, _value: &NativeTower128Target) {
    }
    fn add(
        b: &mut CircuitBuilder<BinaryField128>,
        a: &NativeTower128Target,
        c: &NativeTower128Target,
    ) -> NativeTower128Target {
        b.native_tower128_add(a, c)
    }
    fn mul(
        b: &mut CircuitBuilder<BinaryField128>,
        a: &NativeTower128Target,
        c: &NativeTower128Target,
    ) -> NativeTower128Target {
        b.native_tower128_mul(a, c)
    }
}
impl<F: RecursiveBinaryTowerField> BinaryProtocolPolicy<BinaryField128>
    for NativeTower128Relation<F>
where
    BinaryField128: ExtensionField<F>,
{
    fn observe<H: BinaryCircuitHost<BinaryField128>>(
        b: &mut CircuitBuilder<BinaryField128>,
        ch: &mut BinaryTower128Challenger,
        values: &[NativeTower128Target],
    ) -> Result<(), VerificationError> {
        let bytes = native_tower_bytes::<H>(b, values)?;
        Ok(ch.observe_bytes_with_host::<H, BinaryField128>(b, &bytes)?)
    }
    fn observe_after_queries<H: BinaryCircuitHost<BinaryField128>>(
        b: &mut CircuitBuilder<BinaryField128>,
        token: crate::BinaryQueryContinuation,
        values: &[NativeTower128Target],
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        let bytes = native_tower_bytes::<H>(b, values)?;
        Ok(token.resume_with_observation_with_host::<H, BinaryField128>(b, &bytes)?)
    }
    fn sample<H: BinaryCircuitHost<BinaryField128>>(
        b: &mut CircuitBuilder<BinaryField128>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<NativeTower128Target, VerificationError> {
        let value = ch.sample_with_host::<H, BinaryField128>(b)?;
        Ok(b.native_tower128_from_bits(*value.bits())?)
    }
    fn assert_equal(
        b: &mut CircuitBuilder<BinaryField128>,
        a: &NativeTower128Target,
        c: &NativeTower128Target,
    ) {
        let difference = if c.as_expr() == ExprId::ZERO {
            b.sub(c.as_expr(), a.as_expr())
        } else {
            b.sub(a.as_expr(), c.as_expr())
        };
        b.assert_zero(difference);
    }
    fn eq_eval(
        b: &mut CircuitBuilder<BinaryField128>,
        a: &[NativeTower128Target],
        c: &[NativeTower128Target],
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        assert_eq!(a.len(), c.len(), "binary equality point lengths differ");
        let one = b.native_tower128_constant(1);
        let mut weight = one;
        for (a, c) in a.iter().zip(c) {
            let sum = b.native_tower128_add(a, c);
            let equal = b.native_tower128_add(&one, &sum);
            weight = b.native_tower128_mul(&weight, &equal);
        }
        Ok(weight)
    }
}
fn native_tower_bytes<H: BinaryCircuitHost<BinaryField128>>(
    b: &mut CircuitBuilder<BinaryField128>,
    values: &[NativeTower128Target],
) -> Result<alloc::vec::Vec<ExprId>, CircuitBuilderError> {
    let mut bytes = alloc::vec::Vec::new();
    for value in values {
        let bits = b.native_tower128_to_bits(value)?;
        for byte in bits.as_chunks::<8>().0 {
            bytes.push(H::recompose_word(b, byte)?);
        }
    }
    Ok(bytes)
}

/// Raw tower-word boundaries shared by grinding and additive WHIR.
pub(crate) trait BinaryTowerPolicy<CF: Field + Eq + Hash>: BinaryProtocolPolicy<CF> {
    fn word_bytes<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        value: &Self::ChallengeTarget,
        width: usize,
    ) -> Result<alloc::vec::Vec<ExprId>, VerificationError>;
    fn constant_times_bit(
        b: &mut CircuitBuilder<CF>,
        bit: ExprId,
        raw: u128,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
    fn query_point(
        b: &mut CircuitBuilder<CF>,
        index_bits: &[ExprId],
        num_variables: usize,
    ) -> Result<alloc::vec::Vec<Self::ChallengeTarget>, CircuitBuilderError>;
    fn from_checked_bits(
        b: &mut CircuitBuilder<CF>,
        value: &BinaryTower128Target,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
}
fn check_word_width(width: usize) -> Result<(), VerificationError> {
    if width > 128 || !width.is_multiple_of(8) {
        return Err(VerificationError::InvalidProofShape(
            "invalid tower transcript word width".into(),
        ));
    }
    Ok(())
}
impl<CF, F, E> BinaryTowerPolicy<CF> for TowerRelation<F, E>
where
    CF: Field + Eq + Hash,
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    fn word_bytes<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        value: &BinaryTower128Target,
        width: usize,
    ) -> Result<alloc::vec::Vec<ExprId>, VerificationError> {
        check_word_width(width)?;
        H::check_carrier()?;
        constrain_tower_width(b, value, width);
        Ok(value.bits()[..width]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bits| H::recompose_word(b, bits))
            .collect::<Result<_, _>>()?)
    }
    fn constant_times_bit(
        b: &mut CircuitBuilder<CF>,
        bit: ExprId,
        raw: u128,
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        b.assert_bool(bit);
        let bits = core::array::from_fn(|i| if raw >> i & 1 != 0 { bit } else { ExprId::ZERO });
        b.binary128_from_bits(bits)
    }
    fn query_point(
        b: &mut CircuitBuilder<CF>,
        index_bits: &[ExprId],
        num_variables: usize,
    ) -> Result<alloc::vec::Vec<BinaryTower128Target>, CircuitBuilderError> {
        crate::pcs::binary::binary_whir_query_point::<F, CF>(b, index_bits, num_variables)
    }
    fn from_checked_bits(
        b: &mut CircuitBuilder<CF>,
        value: &BinaryTower128Target,
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        Self::constrain_challenge(b, value);
        Ok(value.clone())
    }
}
impl<F: RecursiveBinaryTowerField> BinaryTowerPolicy<BinaryField128> for NativeTower128Relation<F>
where
    BinaryField128: ExtensionField<F>,
{
    fn word_bytes<H: BinaryCircuitHost<BinaryField128>>(
        b: &mut CircuitBuilder<BinaryField128>,
        value: &NativeTower128Target,
        width: usize,
    ) -> Result<alloc::vec::Vec<ExprId>, VerificationError> {
        check_word_width(width)?;
        H::check_carrier()?;
        // Decomposition reconstructs the entire scalar from exactly this width.
        let bits = b.binary_decompose_coordinates(value.as_expr(), width)?;
        Ok(bits
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bits| H::recompose_word(b, bits))
            .collect::<Result<_, _>>()?)
    }
    fn constant_times_bit(
        b: &mut CircuitBuilder<BinaryField128>,
        bit: ExprId,
        raw: u128,
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        b.assert_bool(bit);
        let constant = b.native_tower128_constant(raw);
        let bit = b.native_tower128_from_expr(bit);
        Ok(b.native_tower128_mul(&constant, &bit))
    }
    fn query_point(
        b: &mut CircuitBuilder<BinaryField128>,
        index_bits: &[ExprId],
        num_variables: usize,
    ) -> Result<alloc::vec::Vec<NativeTower128Target>, CircuitBuilderError> {
        if index_bits.len() > F::RAW_BITS || num_variables > F::RAW_BITS {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: F::RAW_BITS,
                n_bits: index_bits.len().max(num_variables),
            });
        }
        for &bit in index_bits {
            b.assert_bool(bit);
        }
        b.check_construction_limits()?;
        (0..num_variables)
            .rev()
            .map(|shift| {
                let mut value = b.native_tower128_constant(0);
                for (j, &bit) in index_bits.iter().skip(shift).enumerate() {
                    let term =
                        Self::constant_times_bit(b, bit, F::cantor_basis(j).raw_coordinates())?;
                    value = b.native_tower128_add(&value, &term);
                }
                b.check_construction_limits()?;
                Ok(value)
            })
            .collect()
    }
    fn from_checked_bits(
        b: &mut CircuitBuilder<BinaryField128>,
        value: &BinaryTower128Target,
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        b.native_tower128_from_bits(*value.bits())
    }
}
