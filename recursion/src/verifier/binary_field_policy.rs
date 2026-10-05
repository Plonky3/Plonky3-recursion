//! Closed arithmetic choices for native binary AIR relations.

use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::{BinaryField128, Poly64, Poly192};
use p3_circuit::ops::{
    BinaryPoly64Target, BinaryPoly192Target, BinaryTower128Target, NativeTower128Target,
    binary_host::BinaryCircuitHost,
};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, Field};

use crate::BinaryTower128Challenger;
use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::verifier::VerificationError;

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
    fn constrain_base(b: &mut CircuitBuilder<EF>, value: &Self::BaseTarget);
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
    fn constrain_base(b: &mut CircuitBuilder<EF>, value: &BinaryTower128Target) {
        constrain_tower_width(b, value, F::RAW_BITS);
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
    fn constrain_base(_b: &mut CircuitBuilder<EF>, _value: &BinaryPoly64Target) {}
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
            .flat_map(|value| value.bits()[..E::RAW_BITS].chunks_exact(8))
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
                    .flat_map(|coefficient| coefficient.bits().chunks_exact(8))
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
pub(crate) struct NativeTower128Relation;
impl sealed::Relation for NativeTower128Relation {}
impl BinaryRelationPolicy<BinaryField128> for NativeTower128Relation {
    type Base = BinaryField128;
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
    fn constrain_base(_b: &mut CircuitBuilder<BinaryField128>, _value: &NativeTower128Target) {}
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
impl BinaryProtocolPolicy<BinaryField128> for NativeTower128Relation {
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
        for byte in bits.chunks_exact(8) {
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
}
fn check_word_width(width: usize) -> Result<(), VerificationError> {
    if width > 128 || width % 8 != 0 {
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
            .chunks_exact(8)
            .map(|bits| H::recompose_word(b, bits))
            .collect::<Result<_, _>>()?)
    }
}
impl BinaryTowerPolicy<BinaryField128> for NativeTower128Relation {
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
            .chunks_exact(8)
            .map(|bits| H::recompose_word(b, bits))
            .collect::<Result<_, _>>()?)
    }
}
