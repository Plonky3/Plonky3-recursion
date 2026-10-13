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
use crate::pcs::binary::{
    BinaryNonzeroChallengeOutput, BinaryNonzeroChallengePlan, RecursiveBinaryChallengeField,
    RecursiveBinaryTowerField,
};
use crate::verifier::VerificationError;

mod whir;
pub(crate) use whir::{BinaryOracleWord, BinaryWhirPolicy};

mod fold;
pub(crate) use fold::BinaryFoldPolicy;

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
    /// Whether a binary AIR program evaluates a sum with a product that nothing
    /// else reads as one [`Self::mul_add`], and folds a constraint that is a sum
    /// nothing else reads with [`Self::mul_add_add`]. Otherwise it evaluates every
    /// node as it stands.
    const FUSES_AIR_SUMS: bool = false;
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
    /// `a * c + d`.
    fn mul_add(
        b: &mut CircuitBuilder<EF>,
        a: &Self::ChallengeTarget,
        c: &Self::ChallengeTarget,
        d: &Self::ChallengeTarget,
    ) -> Self::ChallengeTarget {
        let product = Self::mul(b, a, c);
        Self::add(b, &product, d)
    }
    /// `a * c + d + e`.
    fn mul_add_add(
        b: &mut CircuitBuilder<EF>,
        a: &Self::ChallengeTarget,
        c: &Self::ChallengeTarget,
        d: &Self::ChallengeTarget,
        e: &Self::ChallengeTarget,
    ) -> Self::ChallengeTarget {
        let addend = Self::add(b, d, e);
        Self::mul_add(b, a, c, &addend)
    }
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
    const FUSES_AIR_SUMS: bool = true;
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
    /// One multiply-add gate, with no separately constrained product.
    fn mul_add(
        b: &mut CircuitBuilder<BinaryField128>,
        a: &NativeTower128Target,
        c: &NativeTower128Target,
        d: &NativeTower128Target,
    ) -> NativeTower128Target {
        let value = b.mul_add(a.as_expr(), c.as_expr(), d.as_expr());
        b.native_tower128_from_expr(value)
    }
    /// One Horner gate, or the single operation its zero operands leave.
    fn mul_add_add(
        b: &mut CircuitBuilder<BinaryField128>,
        a: &NativeTower128Target,
        c: &NativeTower128Target,
        d: &NativeTower128Target,
        e: &NativeTower128Target,
    ) -> NativeTower128Target {
        let value = char2_mul_add_add(b, a.as_expr(), c.as_expr(), d.as_expr(), e.as_expr());
        b.native_tower128_from_expr(value)
    }
}

/// A circuit field of characteristic two, in which the native Horner gate's
/// subtracted operand is an addend.
trait CharacteristicTwo: Field + Eq + Hash {}
impl CharacteristicTwo for BinaryField128 {}
impl CharacteristicTwo for Poly64 {}

/// `x * y + p + q` in one gate, or in the single operation its zero terms
/// leave.
fn char2_mul_add_add<F: CharacteristicTwo>(
    b: &mut CircuitBuilder<F>,
    x: ExprId,
    y: ExprId,
    p: ExprId,
    q: ExprId,
) -> ExprId {
    if p == ExprId::ZERO {
        b.mul_add(x, y, q)
    } else if q == ExprId::ZERO {
        b.mul_add(x, y, p)
    } else if x == ExprId::ZERO || y == ExprId::ZERO {
        b.add(p, q)
    } else {
        // In characteristic two, `x * y + p - q` is `x * y + p + q`. The native
        // Horner gate binds its accumulator `x` as an operand of its own, so `x`
        // need not be a previous Horner output.
        b.horner_acc_step(x, y, p, q)
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
        // The refill that hashes these words range-checks each one.
        let words = native_tower_words(b, values)?;
        Ok(ch.observe_words_with_host::<H, BinaryField128>(b, &words)?)
    }
    fn observe_after_queries<H: BinaryCircuitHost<BinaryField128>>(
        b: &mut CircuitBuilder<BinaryField128>,
        token: crate::BinaryQueryContinuation,
        values: &[NativeTower128Target],
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        // The refill of the draw that follows range-checks each word.
        let words = native_tower_words(b, values)?;
        Ok(token.resume_with_words_with_host::<H, BinaryField128>(b, &words)?)
    }
    fn sample<H: BinaryCircuitHost<BinaryField128>>(
        b: &mut CircuitBuilder<BinaryField128>,
        ch: &mut BinaryTower128Challenger,
    ) -> Result<NativeTower128Target, VerificationError> {
        // A native draw reads sixteen digest bytes as one low-first scalar,
        // packed from eight drawn words without decomposing them.
        let words = ch.sample_words_with_host::<H, BinaryField128>(b, 8)?;
        Ok(b.native_tower128_from_unchecked_words(words.try_into().expect("eight drawn words"))?)
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
/// The eight low-first sixteen-bit words of each value's sixteen
/// little-endian bytes, which only a refill that hashes them range-checks.
fn native_tower_words(
    b: &mut CircuitBuilder<BinaryField128>,
    values: &[NativeTower128Target],
) -> Result<alloc::vec::Vec<ExprId>, CircuitBuilderError> {
    let mut words = alloc::vec::Vec::with_capacity(8 * values.len());
    for value in values {
        words.extend(b.native_tower128_unchecked_words(value, 8)?);
    }
    Ok(words)
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
    /// Draws the plan's nonzero challenges and the continuation after them.
    ///
    /// The caller constrains each challenge with `constrain_challenge`.
    fn sample_nonzero<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        plan: &BinaryNonzeroChallengePlan<Self::Challenge>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryNonzeroChallengeOutput<Self::ChallengeTarget>, VerificationError>;
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
    fn sample_nonzero<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        plan: &BinaryNonzeroChallengePlan<E>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryNonzeroChallengeOutput, VerificationError> {
        plan.sample_with_host::<H, CF>(b, ch)
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
        crate::pcs::binary::native_tower128_whir_query_point::<F>(b, index_bits, num_variables)
    }
    fn sample_nonzero<H: BinaryCircuitHost<BinaryField128>>(
        b: &mut CircuitBuilder<BinaryField128>,
        plan: &BinaryNonzeroChallengePlan,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryNonzeroChallengeOutput<NativeTower128Target>, VerificationError> {
        plan.sample_scalars_using::<Self, H>(b, ch)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_binary_field::{BinaryChallenger, BinaryField8, TowerLevel};
    use p3_challenger::{CanObserve, CanSample, CanSampleBits, HashChallenger};
    use p3_circuit::ops::ByteHash;
    use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
    use p3_field::PrimeCharacteristicRing;
    use p3_keccak::Keccak256Hash;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    type F = BinaryField128;
    type H = NativeBinaryEncoding;
    type P = NativeTower128Relation;
    type Native = BinaryChallenger<BinaryField8, HashChallenger<u8, Keccak256Hash, 32>>;

    /// Binds `P::mul_add(a, c, d)` when `fused`, else `P::mul(a, c) + d`, to a
    /// public expected value. An operand flagged in `zero` is the constant zero;
    /// the others are public inputs, in order, before the expected value.
    fn mul_add_circuit(zero: [bool; 3], fused: bool) -> p3_circuit::Circuit<F> {
        let mut b = CircuitBuilder::<F>::new();
        let [a, c, d] = zero.map(|zero| {
            if zero {
                b.native_tower128_constant(0)
            } else {
                let value = b.public_input();
                b.native_tower128_from_expr(value)
            }
        });
        let expected = b.public_input();
        let expected = b.native_tower128_from_expr(expected);
        let value = if fused {
            P::mul_add(&mut b, &a, &c, &d)
        } else {
            let product = P::mul(&mut b, &a, &c);
            P::add(&mut b, &product, &d)
        };
        P::assert_equal(&mut b, &value, &expected);
        b.build().unwrap()
    }

    /// The native multiply-add computes `a * c + d`, as the in-circuit product
    /// and sum do, for random and zero values and for constant zero operands.
    /// Its gate keeps the addend out of the product: neither `d * c + a` nor
    /// `a * d + c` is accepted.
    #[test]
    fn native_tower_mul_add_is_the_product_plus_the_addend() {
        let mut rng = SmallRng::seed_from_u64(11);
        let random: [F; 3] = core::array::from_fn(|_| F::from_repr(rng.random()));
        let runs = |circuit: &p3_circuit::Circuit<F>, zero: [bool; 3], values: [F; 3], expected| {
            let mut public: Vec<F> = (0..3).filter(|&i| !zero[i]).map(|i| values[i]).collect();
            public.push(expected);
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(&public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        for mask in 0..8 {
            let zero: [bool; 3] = core::array::from_fn(|i| mask >> i & 1 != 0);
            let circuit = mul_add_circuit(zero, true);
            let reference = mul_add_circuit(zero, false);
            let values = core::array::from_fn(|i| if zero[i] { F::ZERO } else { random[i] });
            let [a, c, d] = values;
            for circuit in [&circuit, &reference] {
                assert!(
                    runs(circuit, zero, values, a * c + d),
                    "zero operands {zero:?}"
                );
            }
            assert!(!runs(&circuit, zero, values, a * c + d + F::ONE));
            if mask == 0 {
                assert!(!runs(&circuit, zero, values, d * c + a));
                assert!(!runs(&circuit, zero, values, a * d + c));
                for i in 0..3 {
                    let mut values = values;
                    values[i] = F::ZERO;
                    let [a, c, d] = values;
                    for circuit in [&circuit, &reference] {
                        assert!(runs(circuit, zero, values, a * c + d), "zero value {i}");
                    }
                }
            }
        }
    }

    /// The native multiply-add is one fused gate where a product and a sum
    /// would be two.
    #[test]
    fn native_tower_mul_add_is_one_node() {
        let added = |fused: bool| {
            let mut b = CircuitBuilder::<F>::new();
            let [a, c, d] = [(); 3].map(|()| {
                let value = b.public_input();
                b.native_tower128_from_expr(value)
            });
            let before = b.construction_usage().unwrap().expression_nodes;
            if fused {
                P::mul_add(&mut b, &a, &c, &d);
            } else {
                let product = P::mul(&mut b, &a, &c);
                P::add(&mut b, &product, &d);
            }
            b.construction_usage().unwrap().expression_nodes - before
        };
        assert_eq!(added(true), 1);
        assert_eq!(added(false), 2);
    }

    /// Binds `P::mul_add_add(a, c, d, e)` when `fused`, else `P::mul(a, c) + d + e`, to a
    /// public expected value. An operand flagged in `zero` is the constant zero; the others are
    /// public inputs, in order, before the expected value.
    fn mul_add_add_circuit(zero: [bool; 4], fused: bool) -> p3_circuit::Circuit<F> {
        let mut b = CircuitBuilder::<F>::new();
        let [a, c, d, e] = zero.map(|zero| {
            if zero {
                b.native_tower128_constant(0)
            } else {
                let value = b.public_input();
                b.native_tower128_from_expr(value)
            }
        });
        let expected = b.public_input();
        let expected = b.native_tower128_from_expr(expected);
        let value = if fused {
            P::mul_add_add(&mut b, &a, &c, &d, &e)
        } else {
            let product = P::mul(&mut b, &a, &c);
            let partial = P::add(&mut b, &product, &d);
            P::add(&mut b, &partial, &e)
        };
        P::assert_equal(&mut b, &value, &expected);
        b.build().unwrap()
    }

    /// The native multiply-add with two addends computes `a * c + d + e`, as the in-circuit
    /// product and sums do, for random and zero values and for constant zero operands. Its gate
    /// keeps both addends out of the product: neither `d * c + a + e`, `a * d + c + e` nor
    /// `a * e + d + c` is accepted, nor the value without `e`.
    #[test]
    fn native_tower_mul_add_add_is_the_product_plus_both_addends() {
        let mut rng = SmallRng::seed_from_u64(19);
        let random: [F; 4] = core::array::from_fn(|_| F::from_repr(rng.random()));
        let runs = |circuit: &p3_circuit::Circuit<F>, zero: [bool; 4], values: [F; 4], expected| {
            let mut public: Vec<F> = (0..4).filter(|&i| !zero[i]).map(|i| values[i]).collect();
            public.push(expected);
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(&public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        for mask in 0..16 {
            let zero: [bool; 4] = core::array::from_fn(|i| mask >> i & 1 != 0);
            let circuit = mul_add_add_circuit(zero, true);
            let reference = mul_add_add_circuit(zero, false);
            let values = core::array::from_fn(|i| if zero[i] { F::ZERO } else { random[i] });
            let [a, c, d, e] = values;
            for circuit in [&circuit, &reference] {
                assert!(
                    runs(circuit, zero, values, a * c + d + e),
                    "zero operands {zero:?}"
                );
            }
            assert!(!runs(&circuit, zero, values, a * c + d + e + F::ONE));
        }
        let zero = [false; 4];
        let circuit = mul_add_add_circuit(zero, true);
        let [a, c, d, e] = random;
        for wrong in [d * c + a + e, a * d + c + e, a * e + d + c, a * c + d] {
            assert_ne!(wrong, a * c + d + e);
            assert!(!runs(&circuit, zero, random, wrong));
        }
        for i in 0..4 {
            let mut values = random;
            values[i] = F::ZERO;
            let [a, c, d, e] = values;
            assert!(
                runs(&circuit, zero, values, a * c + d + e),
                "zero value {i}"
            );
        }
    }

    /// With every operand a public input, the native multiply-add with two addends is one Horner
    /// gate where a product and two sums would be three nodes.
    #[test]
    fn native_tower_mul_add_add_is_one_node() {
        let added = |fused: bool| {
            let mut b = CircuitBuilder::<F>::new();
            let [a, c, d, e] = [(); 4].map(|()| {
                let value = b.public_input();
                b.native_tower128_from_expr(value)
            });
            let before = b.construction_usage().unwrap().expression_nodes;
            if fused {
                P::mul_add_add(&mut b, &a, &c, &d, &e);
            } else {
                let product = P::mul(&mut b, &a, &c);
                let partial = P::add(&mut b, &product, &d);
                P::add(&mut b, &partial, &e);
            }
            b.construction_usage().unwrap().expression_nodes - before
        };
        assert_eq!(added(true), 1);
        assert_eq!(added(false), 3);
    }

    /// The default multiply-add, of tower targets in a prime circuit field,
    /// computes `a * c + d` for random and zero values, not `d * c + a`.
    #[test]
    fn prime_tower_mul_add_is_the_product_plus_the_addend() {
        type B = p3_baby_bear::BabyBear;
        type T = TowerRelation<F, F>;
        let mut b = CircuitBuilder::<B>::new();
        let [a, c, d] = [(); 3].map(|()| {
            let bits = b.alloc_public_input_array::<128>("operand bits");
            b.binary128_from_bits(bits).unwrap()
        });
        let fused = T::mul_add(&mut b, &a, &c, &d);
        let expected = b.alloc_public_input_array::<128>("expected bits");
        for (&bit, &expected) in fused.bits().iter().zip(&expected) {
            b.connect(bit, expected);
        }
        let circuit = b.build().unwrap();
        let runs = |values: [F; 4]| {
            let public: Vec<B> = values
                .iter()
                .flat_map(|value| (0..128).map(|i| B::from_bool(value.to_repr() >> i & 1 != 0)))
                .collect();
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(&public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        let mut rng = SmallRng::seed_from_u64(13);
        let [a, c, d]: [F; 3] = core::array::from_fn(|_| F::from_repr(rng.random()));
        assert!(runs([a, c, d, a * c + d]));
        assert!(!runs([a, c, d, d * c + a]));
        assert!(runs([F::ZERO, c, d, d]));
        assert!(runs([a, c, F::ZERO, a * c]));
    }

    /// Binds a native policy draw to the native transcript's next field sample.
    fn draw(
        b: &mut CircuitBuilder<F>,
        ch: &mut BinaryTower128Challenger,
        native: &mut Native,
    ) -> (NativeTower128Target, u128) {
        let expected: F = native.sample();
        let actual = P::sample::<H>(b, ch).unwrap();
        let constant = b.native_tower128_constant(expected.to_repr());
        P::assert_equal(b, &actual, &constant);
        (actual, expected.to_repr())
    }

    /// Native field draws equal the native transcript's samples wherever they
    /// start in the digest: at a fresh refill, on its aligned second half,
    /// at an odd offset after bit and byte draws, across a refill, and after
    /// word observations at even and odd offsets and a post-query observation.
    #[test]
    fn native_tower_draws_match_the_native_transcript() {
        let initial = [3u8, 251, 7];
        let values: [u128; 3] = [
            0x8123_4567_89ab_cdef_0fed_cba9_8765_4321,
            0x0102_0304_0506_0708_f9fa_fbfc_fdfe_ff00,
            0xdead_beef_0bad_f00d_1357_9bdf_2468_ace0,
        ];
        let mut native = Native::from_hasher(initial.to_vec(), Keccak256Hash);
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let initial = initial.map(|byte| b.define_const(H::encode_u16(byte.into()).unwrap()));
        let observed = b.alloc_public_input_array::<3>("observed values");
        let observed = observed.map(|value| b.native_tower128_from_expr(value));
        let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
            &mut b,
            ByteHash::Keccak256,
            &initial,
        )
        .unwrap();
        draw(&mut b, &mut ch, &mut native);
        draw(&mut b, &mut ch, &mut native);
        let expected = native.sample_bits(13);
        let bits = ch.sample_bits_with_host::<H, F>(&mut b, 13).unwrap();
        for (i, bit) in bits.into_iter().enumerate() {
            let value = b.define_const(F::from_bool(expected >> i & 1 != 0));
            b.connect(bit, value);
        }
        for byte in ch.sample_bytes_with_host::<H, F>(&mut b, 3).unwrap() {
            let expected: BinaryField8 = native.sample();
            let value = b.define_const(H::encode_u16(expected.to_repr().into()).unwrap());
            b.connect(byte, value);
        }
        draw(&mut b, &mut ch, &mut native);
        draw(&mut b, &mut ch, &mut native);
        for value in &values[..2] {
            native.observe_slice(&value.to_le_bytes().map(BinaryField8::from_repr));
        }
        P::observe::<H>(&mut b, &mut ch, &observed[..2]).unwrap();
        draw(&mut b, &mut ch, &mut native);
        native.observe(BinaryField8::from_repr(201));
        native.observe_slice(&values[2].to_le_bytes().map(BinaryField8::from_repr));
        let byte = b.define_const(H::encode_u16(201).unwrap());
        ch.observe_bytes_with_host::<H, F>(&mut b, &[byte]).unwrap();
        P::observe::<H>(&mut b, &mut ch, &observed[2..]).unwrap();
        let (last, raw) = draw(&mut b, &mut ch, &mut native);
        let (hash, digest) = ch.retained_query_digest().unwrap();
        native.observe_slice(&raw.to_le_bytes().map(BinaryField8::from_repr));
        let mut ch = P::observe_after_queries::<H>(
            &mut b,
            crate::BinaryQueryContinuation::from_digest(hash, digest),
            &[last],
        )
        .unwrap();
        draw(&mut b, &mut ch, &mut native);
        let circuit = b.build().unwrap();
        let runs = |public: &[F]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        let public = values.map(F::from_repr);
        assert!(runs(&public));
        for changed in 0..3 {
            let mut wrong = public;
            wrong[changed] += F::from_repr(1 << 77);
            assert!(!runs(&wrong), "changed observed value {changed}");
        }
    }

    /// A value observed after a query draw costs exactly a live observation:
    /// its unchecked word split, which the next refill range-checks as Keccak
    /// lanes.
    #[test]
    fn native_tower_after_query_observations_cost_a_live_observation() {
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let values = b.alloc_public_input_array::<3>("observed values");
        let values = values.map(|value| b.native_tower128_from_expr(value));
        let mut ch = BinaryTower128Challenger::new(ByteHash::Keccak256);
        P::observe::<H>(&mut b, &mut ch, &values[..1]).unwrap();
        P::sample::<H>(&mut b, &mut ch).unwrap();
        let (hash, digest) = ch.retained_query_digest().unwrap();
        let start = b.construction_usage().unwrap();
        P::observe::<H>(&mut b, &mut ch, &values[1..2]).unwrap();
        let live = b.construction_usage().unwrap();
        P::observe_after_queries::<H>(
            &mut b,
            crate::BinaryQueryContinuation::from_digest(hash, digest),
            &values[2..],
        )
        .unwrap();
        let resumed = b.construction_usage().unwrap();
        let added = |from: p3_circuit::CircuitConstructionUsage,
                     to: p3_circuit::CircuitConstructionUsage| {
            (
                to.expression_nodes - from.expression_nodes,
                to.pending_connects - from.pending_connects,
                to.non_primitive_calls - from.non_primitive_calls,
            )
        };
        assert_eq!(added(live, resumed), added(start, live));
    }

    /// A native field draw packs eight whole swapped digest limbs with seven
    /// fused multiply-adds: a second draw from one refill adds exactly seven
    /// expression nodes and no hint, decomposition, connection or hash call.
    /// Both draws equal the native transcript's samples.
    #[test]
    fn native_tower_draws_pack_swapped_digest_limbs() {
        let raw = 0x0f1e_2d3c_4b5a_6978_8796_a5b4_c3d2_e1f0u128;
        let mut native = Native::from_hasher(alloc::vec::Vec::new(), Keccak256Hash);
        native.observe_slice(&raw.to_le_bytes().map(BinaryField8::from_repr));
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let observed = b.public_input();
        let observed = b.native_tower128_from_expr(observed);
        let mut ch = BinaryTower128Challenger::new(ByteHash::Keccak256);
        P::observe::<H>(&mut b, &mut ch, &[observed]).unwrap();
        draw(&mut b, &mut ch, &mut native);
        let expected: F = native.sample();
        let before = b.construction_usage().unwrap();
        let actual = P::sample::<H>(&mut b, &mut ch).unwrap();
        let after = b.construction_usage().unwrap();
        assert_eq!(after.expression_nodes, before.expression_nodes + 7);
        assert_eq!(after.pending_connects, before.pending_connects);
        assert_eq!(after.non_primitive_calls, before.non_primitive_calls);
        let constant = b.native_tower128_constant(expected.to_repr());
        P::assert_equal(&mut b, &actual, &constant);
        let circuit = b.build().unwrap();
        let runs = |value: u128| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(&[F::from_repr(value)])
                .and_then(|()| runner.run())
                .is_ok()
        };
        assert!(runs(raw));
        assert!(!runs(raw ^ 1 << 100));
    }

    /// Native field draws from a challenger merged under a private one-hot
    /// selector read merged output words and a merged odd byte, and equal the
    /// chosen branch's native transcript: entirely from merged output, across
    /// the refill, and after observing both draws. The other branch's
    /// transcript is rejected.
    #[test]
    fn native_tower_draws_from_merged_branches_match_the_native_transcript() {
        let values: [u128; 2] = [
            0x8123_4567_89ab_cdef_0fed_cba9_8765_4321,
            0xdead_beef_0bad_f00d_1357_9bdf_2468_ace0,
        ];
        for (chosen, value) in values.into_iter().enumerate() {
            let mut native = Native::from_hasher(alloc::vec::Vec::new(), Keccak256Hash);
            native.observe_slice(&value.to_le_bytes().map(BinaryField8::from_repr));
            for _ in 0..3 {
                let _: BinaryField8 = native.sample();
            }
            let mut b = CircuitBuilder::<F>::new();
            b.enable_native_keccak_f1600().unwrap();
            let observed = b.alloc_public_input_array::<2>("branch values");
            let pick = b.alloc_private_input("branch");
            let one = b.define_const(F::ONE);
            let keep = b.sub(one, pick);
            let branches = [(keep, observed[0]), (pick, observed[1])].map(|(selector, value)| {
                let value = b.native_tower128_from_expr(value);
                let mut ch = BinaryTower128Challenger::new(ByteHash::Keccak256);
                P::observe::<H>(&mut b, &mut ch, &[value]).unwrap();
                ch.sample_bytes_with_host::<H, F>(&mut b, 3).unwrap();
                (selector, ch)
            });
            let mut ch = BinaryTower128Challenger::select_same_shape(&mut b, &branches).unwrap();
            let (merged, merged_raw) = draw(&mut b, &mut ch, &mut native);
            let (crossing, crossing_raw) = draw(&mut b, &mut ch, &mut native);
            let (hash, digest) = ch.retained_query_digest().unwrap();
            for raw in [merged_raw, crossing_raw] {
                native.observe_slice(&raw.to_le_bytes().map(BinaryField8::from_repr));
            }
            let mut ch = P::observe_after_queries::<H>(
                &mut b,
                crate::BinaryQueryContinuation::from_digest(hash, digest),
                &[merged, crossing],
            )
            .unwrap();
            draw(&mut b, &mut ch, &mut native);
            let circuit = b.build().unwrap();
            let runs = |pick: usize| {
                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&values.map(F::from_repr))
                    .and_then(|()| runner.set_private_inputs(&[F::from_bool(pick == 1)]))
                    .and_then(|()| runner.run())
                    .is_ok()
            };
            assert!(runs(chosen), "branch {chosen} selected");
            assert!(!runs(1 - chosen), "the other branch draws differently");
        }
    }
}
