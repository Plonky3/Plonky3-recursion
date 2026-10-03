//! Bounded full-width Poly192 rejection sampling over the Poly64 transcript.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::BinaryPoly192Target;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField64};

use super::nonzero::select_nonzero_words;
use super::whir_plan::invalid;
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
pub struct BinaryPolyNonzeroChallengeOutput {
    pub values: Vec<BinaryPoly192Target>,
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

    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Constrains the first accepted values and the digest at actual completion.
    /// Every one of the three Poly64 coefficients participates in the zero test.
    pub fn sample<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
    ) -> Result<BinaryPolyNonzeroChallengeOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut candidates = Vec::with_capacity(self.max_draws);
        for _ in 0..self.max_draws {
            let value = ch.sample_poly192::<BF, EF>(b)?;
            let bits = core::array::from_fn(|i| value.coefficients()[i / 64].bits()[i % 64]);
            let (_, digest) = ch.retained_query_digest()?;
            candidates.push((bits, digest));
        }
        let (hash, _) = ch.retained_query_digest()?;
        let (selected, _, digest) =
            select_nonzero_words::<192, _>(b, self.count, 192, self.max_draws, 0, &candidates)?;
        let values = selected
            .into_iter()
            .map(|bits| target_from_bits(b, bits))
            .collect::<Result<_, _>>()?;
        Ok(BinaryPolyNonzeroChallengeOutput {
            values,
            continuation: BinaryQueryContinuation::from_digest(hash, digest),
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

fn target_from_bits<EF: p3_field::Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    bits: [ExprId; 192],
) -> Result<BinaryPoly192Target, VerificationError> {
    let a0 = b.binary_poly64_from_bits(bits[..64].try_into().expect("fixed coefficient"))?;
    let a1 = b.binary_poly64_from_bits(bits[64..128].try_into().expect("fixed coefficient"))?;
    let a2 = b.binary_poly64_from_bits(bits[128..].try_into().expect("fixed coefficient"))?;
    Ok(b.binary_poly192_from_coefficients([a0, a1, a2]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p3_baby_bear::BabyBear;

    #[test]
    fn forced_zeros_and_high_coefficients_select_the_actual_completion_digest() {
        let mut b = CircuitBuilder::<BabyBear>::new();
        let candidates = (0..5)
            .map(|_| {
                let limbs = b.alloc_private_input_array::<12>("polynomial candidate");
                let value = b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap();
                let bits = core::array::from_fn(|i| value.coefficients()[i / 64].bits()[i % 64]);
                (bits, b.alloc_private_input_array::<32>("candidate digest"))
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
}
