//! Bounded native nonzero challenge sampling with an observed continuation.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::BinaryField128;
use p3_challenger::FieldChallenger;
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::ops::binary_encoding::PrimeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};

use super::RecursiveBinaryChallengeField;
use super::whir_plan::invalid;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

type NonzeroSelection<T> = (Vec<T>, Vec<T>, [ExprId; 32]);

/// Verifier-owned count and draw budget for a rejection-sampled nonzero point.
/// The field identity pins the native sample width and Wiedemann coordinates.
#[derive(Clone, Debug)]
pub struct BinaryNonzeroChallengePlan<E = BinaryField128> {
    count: usize,
    max_draws: usize,
    usage: InputResourceUsage,
    field: PhantomData<E>,
}

#[derive(Debug)]
pub struct BinaryNonzeroChallengeOutput {
    pub values: Vec<BinaryTower128Target>,
    /// Only a nonempty next observation can resume the native transcript.
    pub continuation: BinaryQueryContinuation,
}

/// A bounded nonzero prefix followed by a fixed number of unrestricted draws.
/// Both counts and the rejection budget belong to the trusted verifier.
#[derive(Clone, Debug)]
pub struct BinaryNonzeroChallengeTailPlan<E = BinaryField128> {
    prefix: BinaryNonzeroChallengePlan<E>,
    following_count: usize,
    total_draws: usize,
    usage: InputResourceUsage,
}

#[derive(Debug)]
pub struct BinaryNonzeroChallengeTailOutput {
    pub values: Vec<BinaryTower128Target>,
    /// Ordinary extension-field samples immediately after the nonzero prefix.
    /// These values may be zero.
    pub following: Vec<BinaryTower128Target>,
    /// Resumes only after the next nonempty protocol observation.
    pub continuation: BinaryQueryContinuation,
}

impl<E: RecursiveBinaryChallengeField> BinaryNonzeroChallengePlan<E> {
    pub fn new(count: usize, max_draws: usize) -> Result<Self, VerificationError> {
        Self::with_limits(count, max_draws, &VerifierLimits::default())
    }

    pub fn with_limits(
        count: usize,
        max_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        if count == 0 || max_draws < count {
            return Err(invalid("binary nonzero challenge count or draw budget"));
        }
        let mut usage = InputResourceUsage::default();
        usage.add_rounds(limits, count)?;
        usage.add_query_round(limits, max_draws)?;
        let metadata = count
            .checked_add(E::RAW_BITS + 32)
            .and_then(|n| n.checked_mul(max_draws))
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary nonzero challenge selection",
            })?;
        usage.add_metadata_entries(limits, metadata)?;
        Ok(Self {
            count,
            max_draws,
            usage,
            field: PhantomData,
        })
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Draws a fixed number of candidates and derives the first `count`
    /// nonzero values. Completion must occur within the trusted budget.
    pub fn sample<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryNonzeroChallengeOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.sample_with_host::<PrimeBinaryEncoding<BF>, EF>(b, ch)
    }

    /// Uses explicit carrier coordinates and native or prime byte hashing.
    pub fn sample_with_host<H, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryNonzeroChallengeOutput, VerificationError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        let (candidates, hash) = sample_words::<E, H, EF>(b, ch, self.max_draws)?;
        let (values, digest) = select_nonzero(b, self.count, E::RAW_BITS, &candidates)?;
        Ok(BinaryNonzeroChallengeOutput {
            values,
            continuation: BinaryQueryContinuation::from_digest(hash, digest),
        })
    }

    /// Native replay uses the same finite budget. Failure leaves the caller's
    /// challenger unchanged; success preserves its exact unsampled buffer.
    pub fn sample_native<F, Ch>(&self, ch: &mut Ch) -> Result<Vec<E>, VerificationError>
    where
        F: super::RecursiveBinaryTowerField,
        E: ExtensionField<F>,
        Ch: FieldChallenger<F> + Clone,
    {
        let mut staged = ch.clone();
        let mut values = Vec::with_capacity(self.count);
        for _ in 0..self.max_draws {
            let value = staged.sample_algebra_element::<E>();
            if value != E::ZERO {
                values.push(value);
                if values.len() == self.count {
                    *ch = staged;
                    return Ok(values);
                }
            }
        }
        Err(invalid("binary nonzero challenge draw budget exhausted"))
    }
}

impl<E: RecursiveBinaryChallengeField> BinaryNonzeroChallengeTailPlan<E> {
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
        let prefix = BinaryNonzeroChallengePlan::with_limits(count, max_draws, limits)?;
        let overflow = || VerificationError::ResourceArithmeticOverflow {
            component: "binary nonzero following challenges",
        };
        let total_draws = max_draws
            .checked_add(following_count)
            .ok_or_else(overflow)?;
        total_draws
            .checked_mul(E::RAW_BITS / 8)
            .ok_or_else(overflow)?;
        let additional_metadata = max_draws
            .checked_mul(129)
            .and_then(|n| n.checked_add(288))
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
            total_draws,
            usage,
        })
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Samples one continuous stream, then selects the first successful prefix,
    /// its immediately following words, and the digest after those words.
    pub fn sample<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryNonzeroChallengeTailOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.sample_with_host::<PrimeBinaryEncoding<BF>, EF>(b, ch)
    }

    /// Uses explicit carrier coordinates and keeps the selected post-tail digest.
    pub fn sample_with_host<H, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
    ) -> Result<BinaryNonzeroChallengeTailOutput, VerificationError>
    where
        H: BinaryCircuitHost<EF>,
        EF: Field + Eq + Hash,
    {
        let (candidates, hash) = sample_words::<E, H, EF>(b, ch, self.total_draws)?;
        let (values, following, digest) = select_nonzero_with_tail(
            b,
            self.prefix.count,
            E::RAW_BITS,
            self.prefix.max_draws,
            self.following_count,
            &candidates,
        )?;
        Ok(BinaryNonzeroChallengeTailOutput {
            values,
            following,
            continuation: BinaryQueryContinuation::from_digest(hash, digest),
        })
    }

    /// Stops at the actual successful prefix plus the fixed following count.
    /// Exhausting the prefix budget leaves the caller's challenger unchanged.
    pub fn sample_native<F, Ch>(&self, ch: &mut Ch) -> Result<(Vec<E>, Vec<E>), VerificationError>
    where
        F: super::RecursiveBinaryTowerField,
        E: ExtensionField<F>,
        Ch: FieldChallenger<F> + Clone,
    {
        let mut staged = ch.clone();
        let values = self.prefix.sample_native::<F, _>(&mut staged)?;
        let following = (0..self.following_count)
            .map(|_| staged.sample_algebra_element::<E>())
            .collect();
        *ch = staged;
        Ok((values, following))
    }
}

type Candidate = (BinaryTower128Target, [ExprId; 32]);

fn sample_words<E, H, EF>(
    b: &mut CircuitBuilder<EF>,
    mut ch: BinaryTower128Challenger,
    count: usize,
) -> Result<(Vec<Candidate>, p3_circuit::ops::ByteHash), VerificationError>
where
    E: RecursiveBinaryChallengeField,
    H: BinaryCircuitHost<EF>,
    EF: Field + Eq + Hash,
{
    let mut candidates = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes = ch.sample_bytes_with_host::<H, EF>(b, E::RAW_BITS / 8)?;
        let mut bits = [ExprId::ZERO; 128];
        for (i, byte) in bytes.into_iter().enumerate() {
            let byte_bits = H::decompose_word(b, byte, 8)?;
            bits[8 * i..8 * i + 8].copy_from_slice(&byte_bits);
        }
        let value = b.binary128_from_bits(bits)?;
        let (_, digest) = ch.retained_query_digest()?;
        candidates.push((value, digest));
    }
    let (hash, _) = ch.retained_query_digest()?;
    Ok((candidates, hash))
}

// States are one-hot counts of accepted candidates. The final state is
// absorbing, so every selected value and completion digest is selected once.
fn select_nonzero<EF: p3_field::Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    count: usize,
    bits: usize,
    candidates: &[(BinaryTower128Target, [ExprId; 32])],
) -> Result<(Vec<BinaryTower128Target>, [ExprId; 32]), VerificationError> {
    let (values, _, digest) =
        select_nonzero_with_tail(b, count, bits, candidates.len(), 0, candidates)?;
    Ok((values, digest))
}

fn select_nonzero_with_tail<EF: p3_field::Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    count: usize,
    bits: usize,
    max_draws: usize,
    following_count: usize,
    candidates: &[Candidate],
) -> Result<NonzeroSelection<BinaryTower128Target>, VerificationError> {
    if !matches!(bits, 64 | 128) {
        return Err(invalid("binary nonzero selection shape"));
    }
    let candidates = candidates
        .iter()
        .map(|(value, digest)| (*value.bits(), *digest))
        .collect::<Vec<_>>();
    let (selected, following, retained) =
        select_nonzero_words(b, count, bits, max_draws, following_count, &candidates)?;
    let values = selected
        .into_iter()
        .map(|bits| {
            let value = b.binary128_from_bits(bits)?;
            b.check_construction_limits()?;
            Ok::<_, VerificationError>(value)
        })
        .collect::<Result<_, _>>()?;
    let following = following
        .into_iter()
        .map(|bits| {
            let value = b.binary128_from_bits(bits)?;
            b.check_construction_limits()?;
            Ok::<_, VerificationError>(value)
        })
        .collect::<Result<_, _>>()?;
    Ok((values, following, retained))
}

/// Selects bounded binary words without imposing a field representation.
/// Callers supply already constrained bits and reconstruct checked targets.
pub(super) fn select_nonzero_words<const W: usize, EF: p3_field::Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    count: usize,
    bits: usize,
    max_draws: usize,
    following_count: usize,
    candidates: &[([ExprId; W], [ExprId; 32])],
) -> Result<NonzeroSelection<[ExprId; W]>, VerificationError> {
    if count == 0
        || count > max_draws
        || bits == 0
        || bits > W
        || max_draws.checked_add(following_count) != Some(candidates.len())
    {
        return Err(invalid("binary nonzero selection shape"));
    }
    let state_count =
        count
            .checked_add(1)
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary nonzero selection states",
            })?;
    b.check_construction_limits()?;
    let one = b.define_const(EF::ONE);
    let mut states = vec![ExprId::ZERO; state_count];
    states[0] = one;
    let mut selected = vec![[ExprId::ZERO; W]; count];
    let mut following = vec![[ExprId::ZERO; W]; following_count];
    let mut retained = [ExprId::ZERO; 32];
    for (index, (candidate, _)) in candidates[..max_draws].iter().enumerate() {
        let factors: Vec<_> = candidate[..bits]
            .iter()
            .map(|&bit| b.sub(one, bit))
            .collect();
        b.check_construction_limits()?;
        let zero = b.mul_many(&factors);
        let accepted = b.sub(one, zero);
        b.check_construction_limits()?;
        let mut next = vec![ExprId::ZERO; state_count];
        next[count] = states[count];
        for j in 0..count {
            let take = b.mul(states[j], accepted);
            let stay = b.mul(states[j], zero);
            next[j] = b.add(next[j], stay);
            next[j + 1] = b.add(next[j + 1], take);
            for (out, &bit) in selected[j].iter_mut().zip(candidate) {
                *out = b.mul_add(take, bit, *out);
            }
            if j + 1 == count {
                let digest = &candidates[index + following_count].1;
                for (out, &byte) in retained.iter_mut().zip(digest) {
                    *out = b.mul_add(take, byte, *out);
                }
                for (offset, output) in following.iter_mut().enumerate() {
                    for (out, &bit) in output.iter_mut().zip(&candidates[index + offset + 1].0) {
                        *out = b.mul_add(take, bit, *out);
                    }
                    b.check_construction_limits()?;
                }
            }
            b.check_construction_limits()?;
        }
        states = next;
    }
    let incomplete = b.sub(states[count], one);
    b.assert_zero(incomplete);
    b.check_construction_limits()?;
    Ok((selected, following, retained))
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_binary_field::TowerLevel;
    use p3_challenger::{CanObserve, CanSample, CanSampleBits};
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[derive(Clone)]
    struct Scripted {
        draws: Vec<BinaryField128>,
        position: usize,
    }
    impl CanObserve<BinaryField128> for Scripted {
        fn observe(&mut self, _: BinaryField128) {}
    }
    impl CanSample<BinaryField128> for Scripted {
        fn sample(&mut self) -> BinaryField128 {
            let value = self.draws[self.position];
            self.position += 1;
            value
        }
    }
    impl CanSampleBits<usize> for Scripted {
        fn sample_bits(&mut self, _: usize) -> usize {
            panic!("nonzero field sampling must not draw uniform bits")
        }
    }
    impl FieldChallenger<BinaryField128> for Scripted {}

    #[test]
    fn native_budget_failure_preserves_the_challenger() {
        let plan = BinaryNonzeroChallengePlan::<BinaryField128>::new(2, 3).unwrap();
        let mut ch = Scripted {
            draws: vec![BinaryField128::ZERO; 3],
            position: 0,
        };
        assert!(plan.sample_native::<BinaryField128, _>(&mut ch).is_err());
        assert_eq!(ch.position, 0);
        ch.draws = [0, 7, 11, 19]
            .into_iter()
            .map(BinaryField128::from_repr)
            .collect();
        assert_eq!(
            plan.sample_native::<BinaryField128, _>(&mut ch).unwrap(),
            [BinaryField128::from_repr(7), BinaryField128::from_repr(11)]
        );
        assert_eq!(ch.position, 3);
    }

    #[test]
    fn zeros_are_skipped_and_completion_digest_is_selected_once() {
        let mut b = CircuitBuilder::<BabyBear>::new();
        let mut candidates = Vec::new();
        for _ in 0..6 {
            let limbs = b.alloc_private_input_array::<8>("candidate");
            let value = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
            let digest = b.alloc_private_input_array::<32>("digest");
            candidates.push((value, digest));
        }
        let (values, digest) = select_nonzero(&mut b, 2, 128, &candidates).unwrap();
        for value in &values {
            let expected = b.alloc_private_input_array::<8>("expected nonzero");
            let expected = b.binary128_from_limbs::<BabyBear>(expected).unwrap();
            for (&a, &e) in value.bits().iter().zip(expected.bits()) {
                let diff = b.sub(a, e);
                b.assert_zero(diff);
            }
        }
        for byte in digest {
            let expected = b.alloc_private_input("expected digest");
            let diff = b.sub(byte, expected);
            b.assert_zero(diff);
        }
        let circuit = b.build().unwrap();
        let inputs = |draws: [u128; 6], expected: [u128; 2], stop: usize| {
            let mut inputs = Vec::new();
            for (i, raw) in draws.into_iter().enumerate() {
                inputs.extend((0..8).map(|j| BabyBear::from_u16((raw >> (16 * j)) as u16)));
                inputs.extend((0..32).map(|j| BabyBear::from_usize(32 * i + j)));
            }
            for raw in expected {
                inputs.extend((0..8).map(|j| BabyBear::from_u16((raw >> (16 * j)) as u16)));
            }
            inputs.extend((0..32).map(|j| BabyBear::from_usize(32 * stop + j)));
            inputs
        };
        let run = |inputs: Vec<BabyBear>| {
            let mut runner = circuit.runner();
            runner.set_private_inputs(&inputs).unwrap();
            runner.run().is_ok()
        };
        assert!(run(inputs([0, 7, 0, 11, 13, 0], [7, 11], 3)));
        assert!(run(inputs([0, 0, 5, 0, 0, 17], [5, 17], 5)));
        assert!(run(inputs([3, 9, 0, 0, 15, 19], [3, 9], 1)));
        assert!(!run(inputs([0, 7, 0, 11, 13, 0], [7, 13], 4)));
        assert!(!run(inputs([0, 7, 0, 11, 13, 0], [7, 11], 4)));
        assert!(!run(inputs([0, 0, 7, 0, 0, 0], [7, 7], 5)));
    }

    #[test]
    fn native_tail_accepts_zero_words_and_preserves_failure_state() {
        let plan = BinaryNonzeroChallengeTailPlan::<BinaryField128>::new(1, 2, 1).unwrap();
        let mut ch = Scripted {
            draws: [0, 7, 0, 11]
                .into_iter()
                .map(BinaryField128::from_repr)
                .collect(),
            position: 0,
        };
        let (values, following) = plan.sample_native::<BinaryField128, _>(&mut ch).unwrap();
        assert_eq!(values, [BinaryField128::from_repr(7)]);
        assert_eq!(following, [BinaryField128::ZERO]);
        assert_eq!(ch.position, 3);
        ch.position = 0;
        ch.draws[1] = BinaryField128::ZERO;
        ch.draws[2] = BinaryField128::from_repr(7);
        assert!(plan.sample_native::<BinaryField128, _>(&mut ch).is_err());
        assert_eq!(ch.position, 0);

        let plain = BinaryNonzeroChallengePlan::<BinaryField128>::new(1, 3).unwrap();
        let zero_tail = BinaryNonzeroChallengeTailPlan::<BinaryField128>::new(1, 3, 0).unwrap();
        let mut other = ch.clone();
        let expected = plain.sample_native::<BinaryField128, _>(&mut ch).unwrap();
        let (actual, following) = zero_tail
            .sample_native::<BinaryField128, _>(&mut other)
            .unwrap();
        assert_eq!(actual, expected);
        assert!(following.is_empty());
        assert_eq!(other.position, ch.position);
    }

    #[test]
    fn native_carrier_skips_forced_zeros_and_selects_a_zero_tail() {
        use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
        type H = NativeBinaryEncoding;
        for width in [64, 128] {
            let mut b = CircuitBuilder::<BinaryField128>::new();
            let mut candidates = Vec::new();
            for index in 0..6 {
                let words = b.alloc_public_input_array::<8>("candidate coordinates");
                let mut bits = [ExprId::ZERO; 128];
                for (i, word) in words.into_iter().enumerate() {
                    bits[16 * i..16 * i + 16]
                        .copy_from_slice(&H::decompose_word(&mut b, word, 16).unwrap());
                }
                let value = b.binary128_from_bits(bits).unwrap();
                let digest = core::array::from_fn(|byte| {
                    b.define_const(H::encode_u16(128 + 16 * index + byte as u16).unwrap())
                });
                candidates.push((value, digest));
            }
            let (values, following, digest) =
                select_nonzero_with_tail(&mut b, 2, width, 4, 2, &candidates).unwrap();
            for (actual, raw) in values.iter().chain(&following).zip([7, 11, 0, 19]) {
                let expected = b.binary128_constant(raw).unwrap();
                crate::pcs::binary::assert_equal(&mut b, actual, &expected);
            }
            for (byte, actual) in digest.into_iter().enumerate() {
                let expected = b.define_const(H::encode_u16(208 + byte as u16).unwrap());
                b.connect(actual, expected);
            }
            let circuit = b.build().unwrap();
            let run = |draws: [u128; 6]| {
                let inputs: Vec<BinaryField128> = draws
                    .into_iter()
                    .flat_map(|raw| {
                        (0..8).map(move |i| H::encode_u16((raw >> (16 * i)) as u16).unwrap())
                    })
                    .collect();
                let mut runner = circuit.runner();
                runner.set_public_inputs(&inputs).unwrap();
                runner.run().is_ok()
            };
            assert!(run([0, 7, 0, 11, 0, 19]));
            assert!(!run([0, 7, 0, 0, 11, 19]));
            assert!(!run([7, 11, 0, 19, 23, 0]));
            assert!(!run([0, 7, 0, 11, 19, 0]));
        }
    }

    #[test]
    fn forced_zero_prefixes_select_the_tail_and_its_digest_for_both_widths() {
        for bits in [64, 128] {
            for (count, max_draws, tail) in [(1, 4, 1), (1, 2, 1), (2, 4, 2)] {
                let mut b = CircuitBuilder::<BabyBear>::new();
                let mut candidates = Vec::new();
                for _ in 0..max_draws + tail {
                    let limbs = b.alloc_private_input_array::<8>("candidate");
                    let value = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
                    let digest = b.alloc_private_input_array::<32>("digest");
                    candidates.push((value, digest));
                }
                let (values, following, digest) =
                    select_nonzero_with_tail(&mut b, count, bits, max_draws, tail, &candidates)
                        .unwrap();
                for actual in values.iter().chain(&following) {
                    let limbs = b.alloc_private_input_array::<8>("expected value");
                    let expected = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
                    for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
                        let diff = b.sub(a, e);
                        b.assert_zero(diff);
                    }
                }
                for byte in digest {
                    let expected = b.alloc_private_input("post-tail digest");
                    let diff = b.sub(byte, expected);
                    b.assert_zero(diff);
                }
                let circuit = b.build().unwrap();
                let run = |draws: &[u128],
                           accepted: &[u128],
                           following: &[u128],
                           digest_at: usize| {
                    let mut inputs = Vec::new();
                    for (index, &raw) in draws.iter().enumerate() {
                        inputs.extend((0..8).map(|j| BabyBear::from_u16((raw >> (16 * j)) as u16)));
                        inputs.extend((0..32).map(|j| BabyBear::from_usize(32 * index + j)));
                    }
                    for &raw in accepted.iter().chain(following) {
                        inputs.extend((0..8).map(|j| BabyBear::from_u16((raw >> (16 * j)) as u16)));
                    }
                    inputs.extend((0..32).map(|j| BabyBear::from_usize(32 * digest_at + j)));
                    let mut runner = circuit.runner();
                    runner.set_private_inputs(&inputs).unwrap();
                    runner.run().is_ok()
                };
                if count == 2 {
                    assert!(run(&[0, 7, 0, 11, 0, 19], &[7, 11], &[0, 19], 5));
                    assert!(run(&[7, 11, 0, 19, 23, 0], &[7, 11], &[0, 19], 3));
                    assert!(!run(&[0, 7, 0, 11, 0, 19], &[7, 11], &[19, 19], 5));
                    assert!(!run(&[0, 7, 0, 11, 0, 19], &[7, 11], &[0, 19], 3));
                    assert!(!run(&[0, 7, 0, 0, 11, 19], &[7, 11], &[0, 19], 5));
                } else if max_draws == 4 {
                    assert!(run(&[0, 0, 0, 7, 0], &[7], &[0], 4));
                    assert!(run(&[0, 7, 0, 11, 19], &[7], &[0], 2));
                    assert!(!run(&[0, 0, 0, 7, 0], &[7], &[0], 3));
                    assert!(!run(&[0, 0, 0, 0, 7], &[7], &[7], 4));
                } else {
                    assert!(run(&[0, 7, 0], &[7], &[0], 2));
                    assert!(run(&[7, 0, 11], &[7], &[0], 1));
                    assert!(!run(&[0, 7, 0], &[7], &[0], 1));
                    assert!(!run(&[0, 0, 7], &[7], &[7], 2));
                }
            }
        }
    }
}

#[cfg(test)]
mod construction_tests {
    use p3_circuit::{CircuitBuilderError, CircuitConstructionLimits};

    use super::*;

    #[test]
    fn nonzero_word_selection_stops_before_the_remaining_candidates() {
        let mut b =
            CircuitBuilder::<BinaryField128>::with_construction_limits(CircuitConstructionLimits {
                max_expression_nodes: 160,
                max_pending_connects: 1024,
                max_non_primitive_calls: 1024,
                max_non_primitive_slots: 1024,
            })
            .unwrap();
        let bits = b.alloc_private_input_array::<128>("candidate bits");
        let candidates = vec![(bits, [ExprId::ZERO; 32]); 3];
        assert!(matches!(
            select_nonzero_words(&mut b, 2, 128, 3, 0, &candidates),
            Err(VerificationError::CircuitBuilder(
                CircuitBuilderError::ConstructionLimitExceeded { .. }
            ))
        ));
        assert!(b.construction_usage().unwrap().expression_nodes <= 288);
        assert!(b.build().is_err());
    }
}
