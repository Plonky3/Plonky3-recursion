//! Bounded full-width Poly192 rejection sampling over the Poly64 transcript.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryPoly192Target, NativePoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};

use super::nonzero::{select_nonzero_cells, select_nonzero_words};
use super::whir_plan::invalid;
use crate::verifier::binary_field_policy::{
    BinaryPolyPolicy, BinaryProtocolPolicy, NativePoly64Relation, Poly64Relation,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// Trusted count and finite draw budget for nonzero Poly192 challenges.
#[derive(Clone, Debug)]
pub struct BinaryPolyNonzeroChallengePlan {
    count: usize,
    max_draws: usize,
    usage: InputResourceUsage,
}

#[derive(Debug)]
pub struct BinaryPolyNonzeroChallengeOutput<T = BinaryPoly192Target> {
    pub values: Vec<T>,
    /// Resumes after the next nonempty native protocol observation.
    pub continuation: BinaryQueryContinuation,
}

impl BinaryPolyNonzeroChallengePlan {
    pub fn new(count: usize, max_draws: usize) -> Result<Self, VerificationError> {
        Self::with_limits(count, max_draws, &VerifierLimits::default())
    }

    pub fn with_limits(
        count: usize,
        max_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        if count == 0 || max_draws < count {
            return Err(invalid("polynomial nonzero challenge count or draw budget"));
        }
        let mut usage = InputResourceUsage::default();
        usage.add_rounds(limits, count)?;
        usage.add_query_round(limits, max_draws)?;
        let entries = count
            .checked_add(192 + 32)
            .and_then(|n| n.checked_mul(max_draws))
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "polynomial nonzero challenge selection",
            })?;
        usage.add_metadata_entries(limits, entries)?;
        Ok(Self {
            count,
            max_draws,
            usage,
        })
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Constrains the first accepted values and the digest at actual completion.
    /// Every one of the three Poly64 coefficients participates in the zero test.
    pub fn sample<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryPolyNonzeroChallengeOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.sample_using::<Poly64Relation, PrimeBinaryEncoding<BF>, EF>(b, ch)
    }

    pub(crate) fn sample_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryPolyNonzeroChallengeOutput<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryPolyPolicy<CF>,
    {
        let output = P::sample_nonzero::<H>(b, ch, self.count, self.max_draws, 0)?;
        Ok(BinaryPolyNonzeroChallengeOutput {
            values: output.values,
            continuation: output.continuation,
        })
    }

    /// Replays the same bounded draws, committing the exact native state only
    /// after the requested number of nonzero extension values has been found.
    pub fn sample_native<Ch>(&self, ch: &mut Ch) -> Result<Vec<Poly192>, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + Clone,
    {
        let mut staged = ch.clone();
        let mut values = Vec::with_capacity(self.count);
        for _ in 0..self.max_draws {
            let value = staged.sample_algebra_element::<Poly192>();
            if value != Poly192::ZERO {
                values.push(value);
                if values.len() == self.count {
                    *ch = staged;
                    return Ok(values);
                }
            }
        }
        Err(invalid(
            "polynomial nonzero challenge draw budget exhausted",
        ))
    }
}

/// A bounded nonzero prefix followed immediately by unrestricted Poly192 words.
/// The selected continuation resumes only after the next nonempty observation.
#[derive(Clone, Debug)]
pub struct BinaryPolyNonzeroChallengeTailPlan {
    prefix: BinaryPolyNonzeroChallengePlan,
    following_count: usize,
    usage: InputResourceUsage,
}

#[derive(Debug)]
pub struct BinaryPolyNonzeroChallengeTailOutput<T = BinaryPoly192Target> {
    pub values: Vec<T>,
    pub following: Vec<T>,
    pub continuation: BinaryQueryContinuation,
}

impl BinaryPolyNonzeroChallengeTailPlan {
    pub fn new(
        count: usize,
        max_draws: usize,
        following_count: usize,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(
            count,
            max_draws,
            following_count,
            &VerifierLimits::default(),
        )
    }

    pub fn with_limits(
        count: usize,
        max_draws: usize,
        following_count: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let prefix = BinaryPolyNonzeroChallengePlan::with_limits(count, max_draws, limits)?;
        let overflow = || VerificationError::ResourceArithmeticOverflow {
            component: "polynomial nonzero following challenges",
        };
        let total_draws = max_draws
            .checked_add(following_count)
            .ok_or_else(overflow)?;
        total_draws.checked_mul(24).ok_or_else(overflow)?;
        let additional_metadata = max_draws
            .checked_mul(193)
            .and_then(|n| n.checked_add(416))
            .and_then(|n| n.checked_mul(following_count))
            .ok_or_else(overflow)?;
        let mut usage = prefix.usage;
        usage.add_rounds(limits, following_count)?;
        usage.queries = 0;
        usage.add_query_round(limits, total_draws)?;
        usage.add_metadata_entries(limits, additional_metadata)?;
        Ok(Self {
            prefix,
            following_count,
            usage,
        })
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Selects the actual accepted prefix, its immediate tail, and the digest
    /// after that tail from one continuous full-width transcript stream.
    pub fn sample<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryPolyNonzeroChallengeTailOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.sample_using::<Poly64Relation, PrimeBinaryEncoding<BF>, EF>(b, ch)
    }

    pub(crate) fn sample_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryPolyNonzeroChallengeTailOutput<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryPolyPolicy<CF>,
    {
        P::sample_nonzero::<H>(
            b,
            ch,
            self.prefix.count,
            self.prefix.max_draws,
            self.following_count,
        )
    }

    /// Stops at the first accepted prefix plus exactly the fixed tail length.
    /// Exhaustion leaves the caller's challenger unchanged.
    pub fn sample_native<Ch>(
        &self,
        ch: &mut Ch,
    ) -> Result<(Vec<Poly192>, Vec<Poly192>), VerificationError>
    where
        Ch: FieldChallenger<Poly64> + Clone,
    {
        let mut staged = ch.clone();
        let values = self.prefix.sample_native(&mut staged)?;
        let following = (0..self.following_count)
            .map(|_| staged.sample_algebra_element::<Poly192>())
            .collect();
        *ch = staged;
        Ok((values, following))
    }
}

/// Draws `count` nonzero Poly192 challenges within `max_draws`, the
/// `following_count` draws after them and the continuation after those,
/// selecting each draw by its 192 checked coefficient bits.
pub(crate) fn sample_nonzero_bits<H, CF>(
    b: &mut CircuitBuilder<CF>,
    mut ch: BinaryTower128Challenger,
    count: usize,
    max_draws: usize,
    following_count: usize,
) -> Result<BinaryPolyNonzeroChallengeTailOutput, VerificationError>
where
    CF: Field + Eq + Hash,
    H: BinaryCircuitHost<CF>,
{
    let total_draws = max_draws
        .checked_add(following_count)
        .ok_or_else(|| invalid("polynomial nonzero challenge draw count"))?;
    let mut candidates = Vec::with_capacity(total_draws);
    for _ in 0..total_draws {
        let value = ch.sample_poly192_with_host::<H, CF>(b)?;
        let bits = core::array::from_fn(|i| value.coefficients()[i / 64].bits()[i % 64]);
        let (_, digest) = ch.retained_query_digest()?;
        candidates.push((bits, digest));
    }
    let (hash, _) = ch.retained_query_digest()?;
    let (values, following, digest) =
        select_nonzero_words::<192, _>(b, count, 192, max_draws, following_count, &candidates)?;
    let values = values
        .into_iter()
        .map(|bits| target_from_bits(b, bits))
        .collect::<Result<_, _>>()?;
    let following = following
        .into_iter()
        .map(|bits| target_from_bits(b, bits))
        .collect::<Result<_, _>>()?;
    Ok(BinaryPolyNonzeroChallengeTailOutput {
        values,
        following,
        continuation: BinaryQueryContinuation::from_digest(hash, digest),
    })
}

/// Draws the same challenges as [`sample_nonzero_bits`] on the native Poly64
/// carrier. Each candidate is the policy's draw, whose three coefficient
/// cells pack drawn words without decomposing them, and each coefficient is
/// tested with a hinted zero test instead of being decomposed. The
/// transcript, the selected values and the continuation are those of
/// [`sample_nonzero_bits`].
pub(crate) fn sample_nonzero_cells<H: BinaryCircuitHost<Poly64>>(
    b: &mut CircuitBuilder<Poly64>,
    mut ch: BinaryTower128Challenger,
    count: usize,
    max_draws: usize,
    following_count: usize,
) -> Result<BinaryPolyNonzeroChallengeTailOutput<NativePoly192Target>, VerificationError> {
    let total_draws = max_draws
        .checked_add(following_count)
        .ok_or_else(|| invalid("polynomial nonzero challenge draw count"))?;
    let mut candidates = Vec::with_capacity(total_draws);
    for _ in 0..total_draws {
        let value = NativePoly64Relation::sample::<H>(b, &mut ch)?;
        let (_, digest) = ch.retained_query_digest()?;
        candidates.push((*value.coefficients(), digest));
    }
    let (hash, _) = ch.retained_query_digest()?;
    let (values, following, digest) =
        select_nonzero_cells(b, count, max_draws, following_count, &candidates)?;
    Ok(BinaryPolyNonzeroChallengeTailOutput {
        values: values
            .into_iter()
            .map(|cells| b.native_poly192_from_coefficients(cells))
            .collect(),
        following: following
            .into_iter()
            .map(|cells| b.native_poly192_from_coefficients(cells))
            .collect(),
        continuation: BinaryQueryContinuation::from_digest(hash, digest),
    })
}

fn target_from_bits<EF: p3_field::Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    bits: [ExprId; 192],
) -> Result<BinaryPoly192Target, VerificationError> {
    let a0 = b.binary_poly64_from_bits(bits[..64].try_into().expect("fixed coefficient"))?;
    let a1 = b.binary_poly64_from_bits(bits[64..128].try_into().expect("fixed coefficient"))?;
    let a2 = b.binary_poly64_from_bits(bits[128..].try_into().expect("fixed coefficient"))?;
    Ok(b.binary_poly192_from_coefficients([a0, a1, a2]))
}

impl BinaryPolyNonzeroChallengePlan {
    /// Selects full-width Poly192 challenges represented by native coefficients.
    pub fn sample_native_targets(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryPolyNonzeroChallengeOutput<NativePoly192Target>, VerificationError> {
        self.sample_using::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(b, ch)
    }
}
impl BinaryPolyNonzeroChallengeTailPlan {
    /// Keeps the immediate unrestricted tail and exact completion digest.
    pub fn sample_native_targets(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryPolyNonzeroChallengeTailOutput<NativePoly192Target>, VerificationError> {
        self.sample_using::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(b, ch)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;

    use super::*;
    use crate::challenger::RetainedDigest;

    #[test]
    fn forced_zeros_and_high_coefficients_select_the_actual_completion_digest() {
        let mut b = CircuitBuilder::<BabyBear>::new();
        let candidates = (0..5)
            .map(|_| {
                let limbs = b.alloc_private_input_array::<12>("polynomial candidate");
                let value = b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap();
                let bits = core::array::from_fn(|i| value.coefficients()[i / 64].bits()[i % 64]);
                let digest = b.alloc_private_input_array::<32>("candidate digest");
                (bits, RetainedDigest::Bytes(digest))
            })
            .collect::<Vec<_>>();
        let (selected, _, digest) =
            select_nonzero_words::<192, _>(&mut b, 2, 192, 5, 0, &candidates).unwrap();
        for bits in selected {
            let value = target_from_bits(&mut b, bits).unwrap();
            let limbs = b.alloc_private_input_array::<12>("selected polynomial");
            let expected = b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap();
            for (a, e) in value.coefficients().iter().zip(expected.coefficients()) {
                for (&a, &e) in a.bits().iter().zip(e.bits()) {
                    let diff = b.sub(a, e);
                    b.assert_zero(diff);
                }
            }
        }
        let RetainedDigest::Bytes(digest) = digest else {
            panic!("byte digests select a byte digest")
        };
        for byte in digest {
            let expected = b.alloc_private_input("completion digest byte");
            let diff = b.sub(byte, expected);
            b.assert_zero(diff);
        }
        let circuit = b.build().unwrap();
        let run = |draws: [[u64; 3]; 5], expected: [[u64; 3]; 2], stop: usize| {
            let mut inputs = vec![];
            let pack = |raw: [u64; 3]| {
                raw.into_iter().flat_map(|coefficient| {
                    (0..4).map(move |j| BabyBear::from_u16((coefficient >> (16 * j)) as u16))
                })
            };
            for (index, raw) in draws.into_iter().enumerate() {
                inputs.extend(pack(raw));
                inputs.extend((0..32).map(|j| BabyBear::from_usize(32 * index + j)));
            }
            inputs.extend(expected.into_iter().flat_map(pack));
            inputs.extend((0..32).map(|j| BabyBear::from_usize(32 * stop + j)));
            let mut runner = circuit.runner();
            runner.set_private_inputs(&inputs).unwrap();
            runner.run().is_ok()
        };
        let zero = [0; 3];
        let high = [0, 0, 1];
        let dense = [7, 11, 13];
        assert!(run([zero, high, zero, dense, [19, 0, 0]], [high, dense], 3));
        assert!(run([high, dense, zero, zero, zero], [high, dense], 1));
        assert!(run([zero, zero, high, zero, dense], [high, dense], 4));
        assert!(!run(
            [zero, high, zero, dense, [19, 0, 0]],
            [high, dense],
            4
        ));
        assert!(!run(
            [zero, high, zero, dense, [19, 0, 0]],
            [dense, [19, 0, 0]],
            4
        ));
        assert!(!run([zero, zero, high, zero, zero], [high, high], 4));
    }
    #[test]
    fn forced_tail_selects_immediate_zero_and_digest_after_following_word() {
        let mut b = CircuitBuilder::<BabyBear>::new();
        let candidates = (0..5)
            .map(|_| {
                let limbs = b.alloc_private_input_array::<12>("polynomial candidate");
                let value = b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap();
                let bits = core::array::from_fn(|i| value.coefficients()[i / 64].bits()[i % 64]);
                let digest = b.alloc_private_input_array::<32>("candidate digest");
                (bits, RetainedDigest::Bytes(digest))
            })
            .collect::<Vec<_>>();
        let (selected, following, digest) =
            select_nonzero_words::<192, _>(&mut b, 1, 192, 4, 1, &candidates).unwrap();
        for bits in selected.into_iter().chain(following) {
            let value = target_from_bits(&mut b, bits).unwrap();
            let limbs = b.alloc_private_input_array::<12>("selected polynomial");
            let expected = b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap();
            for (a, e) in value.coefficients().iter().zip(expected.coefficients()) {
                for (&a, &e) in a.bits().iter().zip(e.bits()) {
                    let diff = b.sub(a, e);
                    b.assert_zero(diff);
                }
            }
        }
        let RetainedDigest::Bytes(digest) = digest else {
            panic!("byte digests select a byte digest")
        };
        for byte in digest {
            let expected = b.alloc_private_input("completion digest byte");
            let diff = b.sub(byte, expected);
            b.assert_zero(diff);
        }
        let circuit = b.build().unwrap();
        let run = |draws: [[u64; 3]; 5], expected: [[u64; 3]; 2], stop: usize| {
            let mut inputs = vec![];
            let pack = |raw: [u64; 3]| {
                raw.into_iter().flat_map(|coefficient| {
                    (0..4).map(move |j| BabyBear::from_u16((coefficient >> (16 * j)) as u16))
                })
            };
            for (index, raw) in draws.into_iter().enumerate() {
                inputs.extend(pack(raw));
                inputs.extend((0..32).map(|j| BabyBear::from_usize(32 * index + j)));
            }
            inputs.extend(expected.into_iter().flat_map(pack));
            inputs.extend((0..32).map(|j| BabyBear::from_usize(32 * stop + j)));
            let mut runner = circuit.runner();
            runner.set_private_inputs(&inputs).unwrap();
            runner.run().is_ok()
        };
        let zero = [0; 3];
        let high = [0, 0, 1];
        let dense = [7, 11, 13];
        assert!(run([zero, high, zero, dense, high], [high, zero], 2));
        assert!(run([high, dense, zero, zero, zero], [high, dense], 1));
        assert!(run([zero, zero, zero, high, dense], [high, dense], 4));
        assert!(!run([zero, high, zero, dense, high], [high, zero], 1));
        assert!(!run([zero, high, zero, dense, high], [high, dense], 3));
        assert!(!run([zero, zero, zero, zero, high], [high, high], 4));
    }

    /// Native coefficient cells: a draw is zero only when all three
    /// coefficients are, so a draw with a single nonzero coefficient is
    /// accepted. A zero draw at the first position or between accepted draws
    /// is skipped, and more zeros than the slack leave no witness. A claimed
    /// value, tail value or completion digest that differs is rejected.
    #[test]
    fn native_cells_test_every_coefficient_and_bind_the_selection() {
        let (count, max_draws, tail) = (2, 4, 1);
        let mut b = CircuitBuilder::<Poly64>::new();
        let candidates: Vec<_> = (0..max_draws + tail)
            .map(|_| {
                let cells = b.alloc_public_input_array::<3>("candidate coefficients");
                let digest = b.alloc_public_input_array::<16>("candidate digest");
                (cells, RetainedDigest::Words(digest))
            })
            .collect();
        let (values, following, digest) =
            select_nonzero_cells(&mut b, count, max_draws, tail, &candidates).unwrap();
        for cells in values.into_iter().chain(following) {
            for cell in cells {
                let claimed = b.public_input();
                b.connect(cell, claimed);
            }
        }
        let RetainedDigest::Words(digest) = digest else {
            panic!("word digests select a word digest")
        };
        for limb in digest {
            let claimed = b.public_input();
            b.connect(limb, claimed);
        }
        let circuit = b.build().unwrap();
        // Digest limbs are nonzero and distinct; `None` claims a zero digest.
        let run = |draws: [[u64; 3]; 5], claimed: [[u64; 3]; 3], digest_at: Option<usize>| {
            let limb = |index: usize, j: usize| Poly64::new((16 * index + j + 1) as u64);
            let mut public = vec![];
            for (index, raw) in draws.into_iter().enumerate() {
                public.extend(raw.map(Poly64::new));
                public.extend((0..16).map(|j| limb(index, j)));
            }
            public.extend(claimed.into_iter().flat_map(|raw| raw.map(Poly64::new)));
            public.extend((0..16).map(|j| digest_at.map_or(Poly64::ZERO, |index| limb(index, j))));
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(&public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        let zero = [0; 3];
        let low = [1 << 63, 0, 0];
        let middle = [0, 5, 0];
        let high = [0, 0, 1];
        let dense = [7, 11, u64::MAX];
        assert!(run(
            [zero, high, middle, dense, low],
            [high, middle, dense],
            Some(3)
        ));
        assert!(run(
            [low, zero, high, zero, dense],
            [low, high, zero],
            Some(3)
        ));
        assert!(run(
            [zero, zero, high, dense, low],
            [high, dense, low],
            Some(4)
        ));
        assert!(!run(
            [zero, zero, zero, high, dense],
            [high, zero, zero],
            None
        ));
        assert!(!run(
            [zero, zero, zero, high, dense],
            [high, dense, zero],
            Some(4)
        ));
        assert!(!run(
            [zero, high, middle, dense, low],
            [high, dense, low],
            Some(4)
        ));
        assert!(!run(
            [zero, high, middle, dense, low],
            [high, middle, low],
            Some(3)
        ));
        assert!(!run(
            [zero, high, middle, dense, low],
            [high, middle, dense],
            Some(2)
        ));
    }
}
