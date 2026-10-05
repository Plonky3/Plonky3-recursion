//! Trusted generic-degree binary sumcheck transcript and bounded input import.

use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryTower128Target, NativeTower128Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape};

use super::verifier::{observe_seed_with_host, seed_bytes_with_host};
use super::whir_plan::invalid;
use super::{
    Binary128SumcheckInterpolator, RecursiveBinaryChallengeField, RecursiveBinaryTowerField,
};
use crate::transcript::domain_separator_seed;
use crate::verifier::binary_field_policy::{
    BinaryTowerPolicy, NativeTower128Relation, TowerRelation,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

#[derive(Clone, Debug)]
pub struct BinaryGenericSumcheckProofTargets<T = BinaryTower128Target> {
    pub claimed_sum: T,
    pub round_polys: Vec<Vec<T>>,
    pub pow_witnesses: Vec<T>,
}

/// A reduction awaiting its caller's terminal committed-polynomial or AIR
/// constraint. This output alone does not establish a verified statement.
#[derive(Clone, Debug)]
#[must_use = "the terminal sumcheck claim must be authenticated"]
pub struct BinaryGenericSumcheckOutput<T = BinaryTower128Target> {
    pub point: Vec<T>,
    pub claim: T,
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
    pub(crate) const fn native_decode_shape(
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
        self.allocate_with(|| {
            let limbs = b.alloc_private_input_array::<8>("binary generic sumcheck field");
            Ok(b.binary128_from_limbs::<BF>(limbs)?)
        })
    }

    fn allocate_with<T>(
        &self,
        mut field: impl FnMut() -> Result<T, VerificationError>,
    ) -> Result<BinaryGenericSumcheckProofTargets<T>, VerificationError> {
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

    const fn pow_count(&self) -> usize {
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
    pub const fn shape(&self) -> &BinaryGenericSumcheckInputShape<F, E> {
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
    pub const fn input_resource_usage(&self) -> InputResourceUsage {
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
        self.verify_using::<TowerRelation<F, E>, PrimeBinaryEncoding<BF>, EF>(
            b,
            ch,
            expected_sum,
            proof,
            false,
        )
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
        self.verify_after_queries_using::<TowerRelation<F, E>, PrimeBinaryEncoding<BF>, EF>(
            b,
            token,
            expected_sum,
            proof,
        )
    }
    pub(crate) fn verify_after_queries_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        token: BinaryQueryContinuation,
        expected_sum: &P::ChallengeTarget,
        proof: &BinaryGenericSumcheckProofTargets<P::ChallengeTarget>,
    ) -> Result<BinaryGenericSumcheckOutput<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryTowerPolicy<CF, Base = F, Challenge = E>,
    {
        self.check_targets(proof)?;
        let bytes = seed_bytes_with_host::<F, H, CF>(b, &self.input.seed)?;
        let ch = token.resume_with_observation_with_host::<H, CF>(b, &bytes)?;
        self.verify_using::<P, H, CF>(b, ch, expected_sum, proof, true)
    }

    pub(crate) fn verify_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        expected_sum: &P::ChallengeTarget,
        proof: &BinaryGenericSumcheckProofTargets<P::ChallengeTarget>,
        seeded: bool,
    ) -> Result<BinaryGenericSumcheckOutput<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryTowerPolicy<CF, Base = F, Challenge = E>,
    {
        self.check_targets(proof)?;
        P::constrain_challenge(b, &proof.claimed_sum);
        P::assert_equal(b, &proof.claimed_sum, expected_sum);
        if !seeded {
            observe_seed_with_host::<F, H, CF>(b, &mut ch, &self.input.seed)?;
        }
        P::observe::<H>(b, &mut ch, core::slice::from_ref(&proof.claimed_sum))?;
        let mut claim = proof.claimed_sum.clone();
        let mut point = Vec::new();
        for (i, polynomial) in proof.round_polys.iter().enumerate() {
            for value in polynomial {
                P::constrain_challenge(b, value);
            }
            P::observe::<H>(b, &mut ch, polynomial)?;
            if self.input.shape.pow_bits > 0 {
                // Native grinding witnesses are base-field words, even when E is wider.
                let bytes = P::word_bytes::<H>(b, &proof.pow_witnesses[i], F::RAW_BITS)?;
                ch.observe_bytes_with_host::<H, CF>(b, &bytes)?;
                for bit in ch.sample_bits_with_host::<H, CF>(b, self.input.shape.pow_bits)? {
                    let difference = b.sub(ExprId::ZERO, bit);
                    b.assert_zero(difference);
                }
            }
            let challenge = P::sample::<H>(b, &mut ch)?;
            claim = self
                .interpolator
                .reduce_claim_using::<P, CF>(b, &claim, polynomial, &challenge)?;
            point.push(challenge);
            b.check_construction_limits()?;
        }
        Ok(BinaryGenericSumcheckOutput {
            point,
            claim,
            challenger: ch,
        })
    }

    pub(crate) fn check_targets<T>(
        &self,
        proof: &BinaryGenericSumcheckProofTargets<T>,
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

impl<F: RecursiveBinaryTowerField> BinaryGenericSumcheckInputShape<F, BinaryField128>
where
    BinaryField128: ExtensionField<F>,
{
    /// One scalar input per field word, retaining the native traversal order.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
    ) -> Result<BinaryGenericSumcheckProofTargets<NativeTower128Target>, VerificationError> {
        self.allocate_with(|| {
            let value = b.alloc_private_input("native generic sumcheck field");
            b.check_construction_limits()?;
            Ok(b.native_tower128_from_expr(value))
        })
    }
}
impl<F: RecursiveBinaryTowerField> NativeBinaryGenericSumcheckInput<F, BinaryField128>
where
    BinaryField128: ExtensionField<F>,
{
    pub fn private_native_values(
        &self,
        expected: &BinaryGenericSumcheckInputShape<F, BinaryField128>,
    ) -> Result<Vec<BinaryField128>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary generic sumcheck input belongs to another verifier",
            ));
        }
        Ok(self
            .fields
            .iter()
            .copied()
            .map(BinaryField128::from_repr)
            .collect())
    }
}
impl<F: RecursiveBinaryTowerField> BinaryGenericSumcheckVerifier<F, BinaryField128>
where
    BinaryField128: ExtensionField<F>,
{
    /// Native scalar reduction; its terminal claim still needs authentication.
    pub fn verify_reduction_native(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        ch: BinaryTower128Challenger,
        expected_sum: &NativeTower128Target,
        proof: &BinaryGenericSumcheckProofTargets<NativeTower128Target>,
    ) -> Result<BinaryGenericSumcheckOutput<NativeTower128Target>, VerificationError> {
        self.verify_using::<NativeTower128Relation<F>, NativeBinaryEncoding, BinaryField128>(
            b,
            ch,
            expected_sum,
            proof,
            false,
        )
    }
    pub fn verify_reduction_after_queries_native(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        token: BinaryQueryContinuation,
        expected_sum: &NativeTower128Target,
        proof: &BinaryGenericSumcheckProofTargets<NativeTower128Target>,
    ) -> Result<BinaryGenericSumcheckOutput<NativeTower128Target>, VerificationError> {
        self.verify_after_queries_using::<NativeTower128Relation<F>, NativeBinaryEncoding, BinaryField128>(b, token, expected_sum, proof)
    }
}
