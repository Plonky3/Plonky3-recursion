//! Scalar boundaries of the BaseFold query phase.

use alloc::vec::Vec;

use p3_binary_field::TowerLevel;

use super::*;

pub(crate) trait BinaryFoldPolicy<CF: Field + Eq + Hash>: BinaryTowerPolicy<CF> {
    /// Constrains raw coordinates at and above `width` to zero.
    fn constrain_word(
        b: &mut CircuitBuilder<CF>,
        value: &Self::ChallengeTarget,
        width: usize,
    ) -> Result<(), CircuitBuilderError>;
    /// Folds adjacent Cantor-domain symbols at `beta`; index bits are Boolean-constrained.
    fn fold_pair(
        b: &mut CircuitBuilder<CF>,
        index_bits: &[ExprId],
        beta: &Self::ChallengeTarget,
        lo: &Self::ChallengeTarget,
        hi: &Self::ChallengeTarget,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
    /// Returns `hi` when `bit` is one and `lo` when it is zero; `bit` must be Boolean.
    fn select(
        b: &mut CircuitBuilder<CF>,
        bit: ExprId,
        hi: &Self::ChallengeTarget,
        lo: &Self::ChallengeTarget,
    ) -> Result<Self::ChallengeTarget, CircuitBuilderError>;
    /// Natural-order bytes of a committed symbol of `width` bits.
    /// `value` must already be constrained to `width` coordinates by `constrain_word`.
    fn leaf_bytes<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        value: &Self::ChallengeTarget,
        width: usize,
    ) -> Result<Vec<ExprId>, VerificationError>;
    /// Observes one word of `width` bits in native transcript encoding.
    /// `value` must already be constrained to `width` coordinates by `constrain_word`.
    fn observe_word<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        ch: &mut BinaryTower128Challenger,
        value: &Self::ChallengeTarget,
        width: usize,
    ) -> Result<(), VerificationError>;
}

impl<CF, F, E> BinaryFoldPolicy<CF> for TowerRelation<F, E>
where
    CF: Field + Eq + Hash,
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    fn constrain_word(
        b: &mut CircuitBuilder<CF>,
        value: &BinaryTower128Target,
        width: usize,
    ) -> Result<(), CircuitBuilderError> {
        constrain_tower_width(b, value, width);
        Ok(())
    }
    fn fold_pair(
        b: &mut CircuitBuilder<CF>,
        index_bits: &[ExprId],
        beta: &BinaryTower128Target,
        lo: &BinaryTower128Target,
        hi: &BinaryTower128Target,
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        crate::pcs::binary::binary128_fold_pair(b, index_bits, beta, lo, hi)
    }
    fn select(
        b: &mut CircuitBuilder<CF>,
        bit: ExprId,
        hi: &BinaryTower128Target,
        lo: &BinaryTower128Target,
    ) -> Result<BinaryTower128Target, CircuitBuilderError> {
        let bits = core::array::from_fn(|i| b.select(bit, hi.bits()[i], lo.bits()[i]));
        b.binary128_from_bits(bits)
    }
    fn leaf_bytes<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        value: &BinaryTower128Target,
        width: usize,
    ) -> Result<Vec<ExprId>, VerificationError> {
        crate::pcs::binary::tower_bytes_with_host::<H, CF>(b, value, width)
    }
    fn observe_word<H: BinaryCircuitHost<CF>>(
        b: &mut CircuitBuilder<CF>,
        ch: &mut BinaryTower128Challenger,
        value: &BinaryTower128Target,
        width: usize,
    ) -> Result<(), VerificationError> {
        crate::pcs::binary::observe_values_with_host::<H, CF>(
            b,
            ch,
            core::slice::from_ref(value),
            width,
        )
    }
}

impl<F> BinaryFoldPolicy<BinaryField128> for NativeTower128Relation<F>
where
    F: RecursiveBinaryTowerField,
    BinaryField128: ExtensionField<F>,
{
    fn constrain_word(
        b: &mut CircuitBuilder<BinaryField128>,
        value: &NativeTower128Target,
        width: usize,
    ) -> Result<(), CircuitBuilderError> {
        if width < 128 {
            b.binary_decompose_coordinates(value.as_expr(), width)?;
        }
        Ok(())
    }
    fn fold_pair(
        b: &mut CircuitBuilder<BinaryField128>,
        index_bits: &[ExprId],
        beta: &NativeTower128Target,
        lo: &NativeTower128Target,
        hi: &NativeTower128Target,
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        if index_bits.len() >= usize::BITS as usize {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: usize::BITS as usize - 1,
                n_bits: index_bits.len(),
            });
        }
        let mut x = b.native_tower128_constant(0);
        for (r, &bit) in index_bits.iter().enumerate() {
            let term =
                Self::constant_times_bit(b, bit, BinaryField128::cantor_basis(r + 1).to_repr())?;
            x = b.native_tower128_add(&x, &term);
        }
        let f1 = b.native_tower128_add(lo, hi);
        let x_f1 = b.native_tower128_mul(&x, &f1);
        let f0 = b.native_tower128_add(lo, &x_f1);
        let slope = b.native_tower128_add(&f0, &f1);
        let increment = b.native_tower128_mul(beta, &slope);
        Ok(b.native_tower128_add(&f0, &increment))
    }
    fn select(
        b: &mut CircuitBuilder<BinaryField128>,
        bit: ExprId,
        hi: &NativeTower128Target,
        lo: &NativeTower128Target,
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        let value = b.select(bit, hi.as_expr(), lo.as_expr());
        Ok(b.native_tower128_from_expr(value))
    }
    fn leaf_bytes<H: BinaryCircuitHost<BinaryField128>>(
        b: &mut CircuitBuilder<BinaryField128>,
        value: &NativeTower128Target,
        width: usize,
    ) -> Result<Vec<ExprId>, VerificationError> {
        <Self as BinaryTowerPolicy<BinaryField128>>::word_bytes::<H>(b, value, width)
    }
    fn observe_word<H: BinaryCircuitHost<BinaryField128>>(
        b: &mut CircuitBuilder<BinaryField128>,
        ch: &mut BinaryTower128Challenger,
        value: &NativeTower128Target,
        width: usize,
    ) -> Result<(), VerificationError> {
        let bytes = <Self as BinaryTowerPolicy<BinaryField128>>::word_bytes::<H>(b, value, width)?;
        Ok(ch.observe_bytes_with_host::<H, BinaryField128>(b, &bytes)?)
    }
}
