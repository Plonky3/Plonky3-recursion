//! Trusted generic-degree binary sumcheck transcript and bounded input import.

use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::BinaryField128;
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryTower128Target, binary_encoding::PrimeBinaryEncoding};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape};

use super::verifier::{
    assert_equal, constrain_width, observe_seed, observe_values, seed_bytes_with_host,
};
use super::whir_plan::invalid;
use super::{
    Binary128SumcheckInterpolator, RecursiveBinaryChallengeField, RecursiveBinaryTowerField,
};
use crate::transcript::domain_separator_seed;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

#[derive(Clone, Debug)]
pub struct BinaryGenericSumcheckProofTargets {
    pub claimed_sum: BinaryTower128Target,
    pub round_polys: Vec<Vec<BinaryTower128Target>>,
    pub pow_witnesses: Vec<BinaryTower128Target>,
}

/// A reduction awaiting its caller's terminal committed-polynomial or AIR
/// constraint. This output alone does not establish a verified statement.
#[derive(Clone, Debug)]
pub struct BinaryGenericSumcheckOutput {
    pub point: Vec<BinaryTower128Target>,
    pub claim: BinaryTower128Target,
    pub challenger: BinaryTower128Challenger,
}

/// Pins native base/challenge encodings and the complete degree/round/PoW shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryGenericSumcheckInputShape<F, E = BinaryField128> {
    seed: Vec<F>,
    shape: GenericDegreeShape,
    challenge: PhantomData<E>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    BinaryGenericSumcheckInputShape<F, E>
{
    pub(crate) fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::GenericDecode {
        crate::artifact::binary_native::codec::GenericDecode {
            rounds: self.shape.num_rounds,
            degree: self.shape.degree,
            pow_count: self.pow_count(),
        }
    }

    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryGenericSumcheckProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut field = || {
            let limbs = b.alloc_private_input_array::<8>("binary generic sumcheck field");
            Ok(b.binary128_from_limbs::<BF>(limbs)?)
        };
        let claimed_sum = field()?;
        let round_polys = (0..self.shape.num_rounds)
            .map(|_| (0..self.shape.degree).map(|_| field()).collect())
            .collect::<Result<_, VerificationError>>()?;
        let pow_witnesses = (0..self.pow_count())
            .map(|_| field())
            .collect::<Result<_, VerificationError>>()?;
        Ok(BinaryGenericSumcheckProofTargets {
            claimed_sum,
            round_polys,
            pow_witnesses,
        })
    }

    fn pow_count(&self) -> usize {
        if self.shape.pow_bits > 0 {
            self.shape.num_rounds
        } else {
            0
        }
    }
}

#[derive(Clone, Debug)]
pub struct NativeBinaryGenericSumcheckInput<F, E = BinaryField128> {
    shape: BinaryGenericSumcheckInputShape<F, E>,
    fields: Vec<u128>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    NativeBinaryGenericSumcheckInput<F, E>
{
    pub fn shape(&self) -> &BinaryGenericSumcheckInputShape<F, E> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryGenericSumcheckInputShape<F, E>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary generic sumcheck input belongs to another verifier",
            ));
        }
        Ok(self
            .fields
            .iter()
            .flat_map(|&v| (0..8).map(move |i| EF::from_u16((v >> (16 * i)) as u16)))
            .collect())
    }
}

/// Verifier-owned schedule for released generic-degree sumcheck over Tower64 or Tower128,
/// with a byte-aligned tower base field for transcript seeds and grinding.
#[derive(Clone, Debug)]
pub struct BinaryGenericSumcheckVerifier<F = BinaryField128, E = BinaryField128> {
    input: BinaryGenericSumcheckInputShape<F, E>,
    interpolator: Binary128SumcheckInterpolator,
    usage: InputResourceUsage,
}

impl<F, E> BinaryGenericSumcheckVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    pub fn new(rounds: usize, degree: usize, pow_bits: usize) -> Result<Self, VerificationError> {
        Self::with_limits(rounds, degree, pow_bits, &VerifierLimits::default())
    }

    pub fn with_limits(
        rounds: usize,
        degree: usize,
        pow_bits: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let mut usage = InputResourceUsage::default();
        usage.add_rounds(limits, rounds)?;
        // Released BinaryChallenger::grind searches at most 64 witness bits
        // and requires eight bits of headroom. Bit sampling also requires
        // the requested count to be strictly below the pointer width.
        let pow_limit = F::RAW_BITS
            .min(64)
            .saturating_sub(8)
            .min(usize::BITS as usize - 1);
        if pow_bits > pow_limit {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "binary generic sumcheck grinding bits",
                actual: pow_bits,
                limit: pow_limit,
            });
        }
        let fields = rounds
            .checked_mul(degree)
            .and_then(|n| n.checked_add(if pow_bits > 0 { rounds } else { 0 }))
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(8))
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary generic sumcheck input limbs",
            })?;
        usage.add_scalar_elements(limits, fields)?;
        let interpolator = Binary128SumcheckInterpolator::with_limits(degree, limits)?;
        let count = degree + 1; // Interpolator checked this addition and square.
        usage.add_metadata_entries(limits, count * count)?;
        let shape = GenericDegreeShape::new(rounds, degree, pow_bits);
        let seed = domain_separator_seed(&shape.domain_separator::<F, E>());
        Ok(Self {
            input: BinaryGenericSumcheckInputShape {
                seed,
                shape,
                challenge: PhantomData,
            },
            interpolator,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryGenericSumcheckInputShape<F, E> {
        self.input.clone()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Binds the proof's initial sum to the caller's expected sum, replays all
    /// native rounds and returns an unclosed reduction. The caller must bind
    /// the terminal claim to its authenticated polynomial or AIR evaluation.
    pub fn verify_reduction<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        expected_sum: &BinaryTower128Target,
        proof: &BinaryGenericSumcheckProofTargets,
    ) -> Result<BinaryGenericSumcheckOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_impl::<BF, EF>(b, ch, expected_sum, proof, false)
    }

    /// Resumes a bounded rejection phase through this run's nonempty seed,
    /// then observes the claimed sum and messages in native order.
    pub fn verify_reduction_after_queries<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        token: BinaryQueryContinuation,
        expected_sum: &BinaryTower128Target,
        proof: &BinaryGenericSumcheckProofTargets,
    ) -> Result<BinaryGenericSumcheckOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(proof)?;
        let bytes = seed_bytes_with_host::<F, PrimeBinaryEncoding<BF>, EF>(b, &self.input.seed)?;
        let ch = token.resume_with_observation::<BF, EF>(b, &bytes)?;
        self.verify_impl::<BF, EF>(b, ch, expected_sum, proof, true)
    }

    fn verify_impl<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        expected_sum: &BinaryTower128Target,
        proof: &BinaryGenericSumcheckProofTargets,
        seeded: bool,
    ) -> Result<BinaryGenericSumcheckOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(proof)?;
        constrain_width(b, &proof.claimed_sum, E::RAW_BITS);
        assert_equal(b, &proof.claimed_sum, expected_sum);
        if !seeded {
            observe_seed::<F, BF, EF>(b, &mut ch, &self.input.seed)?;
        }
        observe_values::<BF, EF>(
            b,
            &mut ch,
            core::slice::from_ref(&proof.claimed_sum),
            E::RAW_BITS,
        )?;
        let mut claim = proof.claimed_sum.clone();
        let mut point = Vec::new();
        for (i, polynomial) in proof.round_polys.iter().enumerate() {
            for value in polynomial {
                constrain_width(b, value, E::RAW_BITS);
            }
            observe_values::<BF, EF>(b, &mut ch, polynomial, E::RAW_BITS)?;
            if self.input.shape.pow_bits > 0 {
                constrain_width(b, &proof.pow_witnesses[i], F::RAW_BITS);
                observe_values::<BF, EF>(
                    b,
                    &mut ch,
                    core::slice::from_ref(&proof.pow_witnesses[i]),
                    F::RAW_BITS,
                )?;
                for bit in ch.sample_bits::<BF, EF>(b, self.input.shape.pow_bits)? {
                    let difference = b.sub(ExprId::ZERO, bit);
                    b.assert_zero(difference);
                }
            }
            let bytes = ch.sample_bytes::<BF, EF>(b, E::RAW_BITS / 8)?;
            let mut bits = [ExprId::ZERO; 128];
            for (i, byte) in bytes.into_iter().enumerate() {
                let byte_bits = b.decompose_to_bits::<BF>(byte, 8)?;
                bits[8 * i..8 * i + 8].copy_from_slice(&byte_bits);
            }
            let challenge = b.binary128_from_bits(bits)?;
            claim = self
                .interpolator
                .reduce_claim(b, &claim, polynomial, &challenge)?;
            point.push(challenge);
        }
        Ok(BinaryGenericSumcheckOutput {
            point,
            claim,
            challenger: ch,
        })
    }

    pub(crate) fn check_targets(
        &self,
        proof: &BinaryGenericSumcheckProofTargets,
    ) -> Result<(), VerificationError> {
        if proof.round_polys.len() != self.input.shape.num_rounds
            || proof
                .round_polys
                .iter()
                .any(|poly| poly.len() != self.input.shape.degree)
            || proof.pow_witnesses.len() != self.input.pow_count()
        {
            return Err(invalid("binary generic sumcheck target shape mismatch"));
        }
        Ok(())
    }

    /// Checks every count before replaying the native reduction. Passing a
    /// mutable challenger retains its exact continuation. This extracts only
    /// witnesses; it does not close the surrounding protocol's terminal claim.
    pub fn import_native<Ch>(
        &self,
        proof: &GenericDegreeProof<F, E>,
        ch: Ch,
    ) -> Result<NativeBinaryGenericSumcheckInput<F, E>, VerificationError>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        self.import_native_with_reduction(proof, ch)
            .map(|(input, _, _)| input)
    }

    pub(crate) fn check_native(
        &self,
        proof: &GenericDegreeProof<F, E>,
    ) -> Result<(), VerificationError> {
        if proof.round_polys.len() != self.input.shape.num_rounds
            || proof
                .round_polys
                .iter()
                .any(|poly| poly.len() != self.input.shape.degree)
            || proof.pow_witnesses.len() != self.input.pow_count()
        {
            return Err(invalid("binary generic sumcheck native shape mismatch"));
        }
        Ok(())
    }

    pub(crate) fn import_native_with_reduction<Ch>(
        &self,
        proof: &GenericDegreeProof<F, E>,
        mut ch: Ch,
    ) -> Result<
        (
            NativeBinaryGenericSumcheckInput<F, E>,
            p3_multilinear_util::point::Point<E>,
            E,
        ),
        VerificationError,
    >
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        self.check_native(proof)?;
        let (point, claim) = proof
            .verify(
                &mut ch,
                self.input.shape.num_rounds,
                self.input.shape.degree,
                self.input.shape.pow_bits,
            )
            .map_err(|_| invalid("binary generic sumcheck native replay failed"))?;
        let mut fields = Vec::new();
        fields.push(proof.claimed_sum.raw_coordinates());
        fields.extend(
            proof
                .round_polys
                .iter()
                .flatten()
                .copied()
                .map(|v| v.raw_coordinates()),
        );
        fields.extend(proof.pow_witnesses.iter().copied().map(F::raw_coordinates));
        Ok((
            NativeBinaryGenericSumcheckInput {
                shape: self.input.clone(),
                fields,
            },
            point,
            claim,
        ))
    }
}
