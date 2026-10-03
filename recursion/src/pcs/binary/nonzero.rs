//! Bounded native nonzero challenge sampling with an observed continuation.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::BinaryField128;
use p3_challenger::FieldChallenger;
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, PrimeField64};

use super::RecursiveBinaryChallengeField;
use super::whir_plan::invalid;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

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

    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Draws a fixed number of candidates and derives the first `count`
    /// nonzero values. Completion must occur within the trusted budget.
    pub fn sample<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
    ) -> Result<BinaryNonzeroChallengeOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut candidates = Vec::with_capacity(self.max_draws);
        for _ in 0..self.max_draws {
            let bytes = ch.sample_bytes::<BF, EF>(b, E::RAW_BITS / 8)?;
            let mut bits = [ExprId::ZERO; 128];
            for (i, byte) in bytes.into_iter().enumerate() {
                let byte_bits = b.decompose_to_bits::<BF>(byte, 8)?;
                bits[8 * i..8 * i + 8].copy_from_slice(&byte_bits);
            }
            let value = b.binary128_from_bits(bits)?;
            let (_, digest) = ch.retained_query_digest()?;
            candidates.push((value, digest));
        }
        let (values, digest) = select_nonzero(b, self.count, E::RAW_BITS, &candidates)?;
        let (hash, _) = ch.retained_query_digest()?;
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

// States are one-hot counts of accepted candidates. The final state is
// absorbing, so every selected value and completion digest is selected once.
fn select_nonzero<EF: p3_field::Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    count: usize,
    bits: usize,
    candidates: &[(BinaryTower128Target, [ExprId; 32])],
) -> Result<(Vec<BinaryTower128Target>, [ExprId; 32]), VerificationError> {
    let one = b.define_const(EF::ONE);
    let mut states = vec![ExprId::ZERO; count + 1];
    states[0] = one;
    let mut selected = vec![[ExprId::ZERO; 128]; count];
    let mut retained = [ExprId::ZERO; 32];
    for (candidate, digest) in candidates {
        let factors: Vec<_> = candidate.bits()[..bits]
            .iter()
            .map(|&bit| b.sub(one, bit))
            .collect();
        let zero = b.mul_many(&factors);
        let accepted = b.sub(one, zero);
        let mut next = vec![ExprId::ZERO; count + 1];
        next[count] = states[count];
        for j in 0..count {
            let take = b.mul(states[j], accepted);
            let stay = b.mul(states[j], zero);
            next[j] = b.add(next[j], stay);
            next[j + 1] = b.add(next[j + 1], take);
            for (out, &bit) in selected[j].iter_mut().zip(candidate.bits()) {
                *out = b.mul_add(take, bit, *out);
            }
            if j + 1 == count {
                for (out, &byte) in retained.iter_mut().zip(digest) {
                    *out = b.mul_add(take, byte, *out);
                }
            }
        }
        states = next;
    }
    let incomplete = b.sub(states[count], one);
    b.assert_zero(incomplete);
    let values = selected
        .into_iter()
        .map(|bits| b.binary128_from_bits(bits).map_err(VerificationError::from))
        .collect::<Result<_, _>>()?;
    Ok((values, retained))
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
}
