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
    /// Low-first sixteen-bit words of the natural-order bytes of a committed
    /// symbol of `width` bits, bound to `value` but range-checked only by the
    /// leaf hash that absorbs them. `None` keeps the symbol on
    /// [`Self::leaf_bytes`], before any constraint is added.
    /// `value` must already be constrained to `width` coordinates by `constrain_word`.
    fn leaf_words(
        _b: &mut CircuitBuilder<CF>,
        _value: &Self::ChallengeTarget,
        _width: usize,
    ) -> Result<Option<Vec<ExprId>>, VerificationError> {
        Ok(None)
    }
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
    fn leaf_words(
        b: &mut CircuitBuilder<BinaryField128>,
        value: &NativeTower128Target,
        width: usize,
    ) -> Result<Option<Vec<ExprId>>, VerificationError> {
        if width > 128 || !width.is_multiple_of(16) {
            return Ok(None);
        }
        Ok(Some(b.native_tower128_unchecked_words(value, width / 16)?))
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

#[cfg(test)]
mod tests {
    use p3_binary_field::{BinaryField8, BinaryField16, BinaryField32, BinaryField64};
    use p3_circuit::Circuit;
    use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
    use p3_circuit::ops::{ByteHash, bytes_to_limbs};
    use p3_keccak::Keccak256Hash;
    use p3_symmetric::CryptographicHasher;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    type H = NativeBinaryEncoding;
    type CF = BinaryField128;

    /// A circuit binding a public symbol of `F`'s width to a public leaf
    /// digest, hashed through the policy's words or bytes. The word circuit
    /// omits `constrain_word`, so its words alone must enforce the width.
    fn leaf_digest_circuit<F>(words: bool) -> Option<Circuit<CF>>
    where
        F: RecursiveBinaryTowerField,
        CF: ExtensionField<F>,
    {
        let width = F::RAW_BITS;
        let mut b = CircuitBuilder::<CF>::new();
        b.enable_native_keccak_f1600().unwrap();
        let input = b.public_input();
        let value = b.native_tower128_from_expr(input);
        let expected = b.alloc_public_input_array::<16>("leaf digest");
        let digest = if words {
            let before = b.construction_usage().unwrap();
            let Some(words) = <NativeTower128Relation<F> as BinaryFoldPolicy<CF>>::leaf_words(
                &mut b, &value, width,
            )
            .unwrap() else {
                assert_eq!(b.construction_usage().unwrap(), before, "width {width}");
                return None;
            };
            assert_eq!(words.len() * 16, width);
            H::hash_words(&mut b, ByteHash::Keccak256, &words).unwrap()
        } else {
            <NativeTower128Relation<F> as BinaryFoldPolicy<CF>>::constrain_word(
                &mut b, &value, width,
            )
            .unwrap();
            let bytes = <NativeTower128Relation<F> as BinaryFoldPolicy<CF>>::leaf_bytes::<H>(
                &mut b, &value, width,
            )
            .unwrap();
            let digest = H::hash_bytes(&mut b, ByteHash::Keccak256, &bytes).unwrap();
            H::words_from_bytes(&mut b, &digest).unwrap()
        };
        for (actual, expected) in digest.into_iter().zip(expected) {
            b.connect(actual, expected);
        }
        Some(b.build().unwrap())
    }

    fn runs(circuit: &Circuit<CF>, value: u128, digest: &[u16]) -> bool {
        let public: Vec<_> = core::iter::once(CF::from_repr(value))
            .chain(digest.iter().map(|&word| CF::from_repr(u128::from(word))))
            .collect();
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public)
            .and_then(|()| runner.run())
            .is_ok()
    }

    /// Word-level and byte-level leaf digests both equal the Keccak-256 of
    /// the symbol's natural-order bytes, and the word digest binds the symbol
    /// and its width.
    fn word_leaf_digest_matches_bytes<F>(rng: &mut SmallRng)
    where
        F: RecursiveBinaryTowerField,
        CF: ExtensionField<F>,
    {
        let width = F::RAW_BITS;
        let bytes = leaf_digest_circuit::<F>(false).unwrap();
        let words = leaf_digest_circuit::<F>(true);
        assert_eq!(words.is_some(), width.is_multiple_of(16), "width {width}");
        let mask = u128::MAX >> (128 - width);
        for _ in 0..8 {
            let value = rng.random::<u128>() & mask;
            let digest = bytes_to_limbs(
                &Keccak256Hash.hash_iter(value.to_le_bytes()[..width / 8].iter().copied()),
            );
            assert!(runs(&bytes, value, &digest), "byte leaf, width {width}");
            let Some(words) = &words else {
                continue;
            };
            assert!(runs(words, value, &digest), "word leaf, width {width}");
            let bit = rng.random_range(0..width);
            assert!(
                !runs(words, value ^ (1u128 << bit), &digest),
                "changed symbol, width {width}"
            );
            if width < 128 {
                assert!(
                    !runs(words, value | (1u128 << width), &digest),
                    "symbol above its alphabet, width {width}"
                );
            }
        }
    }

    #[test]
    fn native_word_leaves_hash_like_byte_leaves_at_every_symbol_width() {
        let mut rng = SmallRng::seed_from_u64(0x1eaf);
        word_leaf_digest_matches_bytes::<BinaryField8>(&mut rng);
        word_leaf_digest_matches_bytes::<BinaryField16>(&mut rng);
        word_leaf_digest_matches_bytes::<BinaryField32>(&mut rng);
        word_leaf_digest_matches_bytes::<BinaryField64>(&mut rng);
        word_leaf_digest_matches_bytes::<CF>(&mut rng);
    }
}
