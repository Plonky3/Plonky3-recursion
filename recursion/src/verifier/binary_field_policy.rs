//! Closed arithmetic choices for native binary AIR relations.

use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::ops::{BinaryPoly64Target, BinaryPoly192Target, BinaryTower128Target};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};

use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::{BinaryTower128Challenger, verifier::VerificationError};

mod sealed {
    pub trait Relation {}
}

pub(crate) trait BinaryRelationPolicy: sealed::Relation {
    type Base: Field;
    type Challenge: ExtensionField<Self::Base>;
    type BaseTarget: Clone;
    type ChallengeTarget: Clone;
    const BASE_BITS: usize;

    fn base_raw(value: Self::Base) -> u128;
    fn constant<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        raw: u128,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
    fn lift<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        value: &Self::BaseTarget,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
    fn constrain_base<EF: Field + Eq + Hash>(b: &mut CircuitBuilder<EF>, value: &Self::BaseTarget);
    fn constrain_challenge<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        value: &Self::ChallengeTarget,
    );
    fn add<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &Self::ChallengeTarget,
        c: &Self::ChallengeTarget,
    ) -> Self::ChallengeTarget;
    fn mul<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &Self::ChallengeTarget,
        c: &Self::ChallengeTarget,
    ) -> Self::ChallengeTarget;
}

pub(crate) struct TowerRelation<F, E>(PhantomData<(F, E)>);
impl<F, E> sealed::Relation for TowerRelation<F, E> {}
impl<F, E> BinaryRelationPolicy for TowerRelation<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    type Base = F;
    type Challenge = E;
    type BaseTarget = BinaryTower128Target;
    type ChallengeTarget = BinaryTower128Target;
    const BASE_BITS: usize = F::RAW_BITS;
    fn base_raw(value: F) -> u128 {
        value.raw_coordinates()
    }
    fn constant<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        raw: u128,
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        b.binary128_constant(raw)
    }
    fn lift<EF: Field + Eq + Hash>(
        _b: &mut CircuitBuilder<EF>,
        value: &BinaryTower128Target,
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        Ok(value.clone())
    }
    fn constrain_base<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        value: &BinaryTower128Target,
    ) {
        constrain_tower_width(b, value, F::RAW_BITS);
    }
    fn constrain_challenge<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        value: &BinaryTower128Target,
    ) {
        constrain_tower_width(b, value, E::RAW_BITS);
    }
    fn add<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryTower128Target,
        c: &BinaryTower128Target,
    ) -> BinaryTower128Target {
        b.binary128_add(a, c)
    }
    fn mul<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryTower128Target,
        c: &BinaryTower128Target,
    ) -> BinaryTower128Target {
        b.binary128_mul(a, c)
    }
}

pub(crate) struct Poly64Relation;
impl sealed::Relation for Poly64Relation {}
impl BinaryRelationPolicy for Poly64Relation {
    type Base = Poly64;
    type Challenge = Poly192;
    type BaseTarget = BinaryPoly64Target;
    type ChallengeTarget = BinaryPoly192Target;
    const BASE_BITS: usize = 64;
    fn base_raw(value: Poly64) -> u128 {
        value.to_bits() as u128
    }
    fn constant<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        raw: u128,
    ) -> Result<BinaryPoly192Target, CircuitBuilderError> {
        // The private program compiler obtains constants only from Poly64.
        debug_assert!(raw <= u64::MAX as u128);
        b.binary_poly192_constant([raw as u64, 0, 0])
    }
    fn lift<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        value: &BinaryPoly64Target,
    ) -> Result<BinaryPoly192Target, CircuitBuilderError> {
        let zero = b.binary_poly64_constant(0)?;
        Ok(b.binary_poly192_from_coefficients([value.clone(), zero.clone(), zero]))
    }
    fn constrain_base<EF: Field + Eq + Hash>(
        _b: &mut CircuitBuilder<EF>,
        _value: &BinaryPoly64Target,
    ) {
    }
    fn constrain_challenge<EF: Field + Eq + Hash>(
        _b: &mut CircuitBuilder<EF>,
        _value: &BinaryPoly192Target,
    ) {
    }
    fn add<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryPoly192Target,
        c: &BinaryPoly192Target,
    ) -> BinaryPoly192Target {
        b.binary_poly192_add(a, c)
    }
    fn mul<EF: Field + Eq + Hash>(
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
pub(crate) trait BinaryProtocolPolicy: BinaryRelationPolicy {
    fn observe<BF, EF>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        values: &[Self::ChallengeTarget],
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash;
    fn observe_after_queries<BF, EF>(
        b: &mut CircuitBuilder<EF>,
        token: crate::BinaryQueryContinuation,
        values: &[Self::ChallengeTarget],
    ) -> Result<BinaryTower128Challenger, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash;
    fn sample<BF, EF>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<Self::ChallengeTarget, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash;
    fn assert_equal<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &Self::ChallengeTarget,
        c: &Self::ChallengeTarget,
    );
    fn eq_eval<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &[Self::ChallengeTarget],
        c: &[Self::ChallengeTarget],
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
}

impl<F, E> BinaryProtocolPolicy for TowerRelation<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    fn observe<BF, EF>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        values: &[BinaryTower128Target],
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        crate::pcs::binary::observe_values::<BF, EF>(b, ch, values, E::RAW_BITS)
    }
    fn observe_after_queries<BF, EF>(
        b: &mut CircuitBuilder<EF>,
        token: crate::BinaryQueryContinuation,
        values: &[BinaryTower128Target],
    ) -> Result<BinaryTower128Challenger, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let bytes = values
            .iter()
            .flat_map(|value| value.bits()[..E::RAW_BITS].chunks_exact(8))
            .map(|bits| b.reconstruct_index_from_bits::<BF>(bits))
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;
        Ok(token.resume_with_observation::<BF, EF>(b, &bytes)?)
    }
    fn sample<BF, EF>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<BinaryTower128Target, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        super::binary_product::sample::<E, BF, EF>(b, ch)
    }
    fn assert_equal<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryTower128Target,
        c: &BinaryTower128Target,
    ) {
        crate::pcs::binary::assert_equal(b, a, c);
    }
    fn eq_eval<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &[BinaryTower128Target],
        c: &[BinaryTower128Target],
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        crate::pcs::binary::binary128_eq_eval(b, a, c)
    }
}

impl BinaryProtocolPolicy for Poly64Relation {
    fn observe<BF, EF>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        values: &[BinaryPoly192Target],
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        for value in values {
            ch.observe_poly192::<BF, EF>(b, value)?;
        }
        Ok(())
    }
    fn observe_after_queries<BF, EF>(
        b: &mut CircuitBuilder<EF>,
        token: crate::BinaryQueryContinuation,
        values: &[BinaryPoly192Target],
    ) -> Result<BinaryTower128Challenger, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let bytes = values
            .iter()
            .flat_map(|value| {
                value
                    .coefficients()
                    .iter()
                    .flat_map(|coefficient| coefficient.bits().chunks_exact(8))
            })
            .map(|bits| b.reconstruct_index_from_bits::<BF>(bits))
            .collect::<Result<alloc::vec::Vec<_>, _>>()?;
        Ok(token.resume_with_observation::<BF, EF>(b, &bytes)?)
    }
    fn sample<BF, EF>(
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<BinaryPoly192Target, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        Ok(ch.sample_poly192::<BF, EF>(b)?)
    }
    fn assert_equal<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &BinaryPoly192Target,
        c: &BinaryPoly192Target,
    ) {
        crate::pcs::binary::poly_assert_equal(b, a, c);
    }
    fn eq_eval<EF: Field + Eq + Hash>(
        b: &mut CircuitBuilder<EF>,
        a: &[BinaryPoly192Target],
        c: &[BinaryPoly192Target],
    ) -> Result<BinaryPoly192Target, CircuitBuilderError> {
        crate::pcs::binary::poly192_eq_eval(b, a, c)
    }
}
