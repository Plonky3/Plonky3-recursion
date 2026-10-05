//! Released generic-degree sumcheck with Poly64 seeds and Poly192 messages.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryPoly64Target, BinaryPoly192Target, NativePoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape};

use super::poly_interpolation::Poly192SumcheckInterpolator;
use super::whir_plan::invalid;
use crate::transcript::domain_separator_seed;
use crate::verifier::binary_field_policy::{
    BinaryPolyPolicy, BinaryProtocolPolicy, NativePoly64Relation, Poly64Relation,
    poly_native_values, poly_observe_seed_with_host, poly_seed_bytes_with_host,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

#[derive(Clone, Debug)]
pub struct BinaryPolyGenericSumcheckProofTargets<T = BinaryPoly192Target, B = BinaryPoly64Target> {
    pub claimed_sum: T,
    pub round_polys: Vec<Vec<T>>,
    pub pow_witnesses: Vec<B>,
}

/// An unclosed reduction; its caller must authenticate the terminal AIR claim.
#[derive(Clone, Debug)]
pub struct BinaryPolyGenericSumcheckOutput<T = BinaryPoly192Target> {
    pub point: Vec<T>,
    pub claim: T,
    pub challenger: BinaryTower128Challenger,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyGenericSumcheckInputShape {
    seed: Vec<Poly64>,
    shape: GenericDegreeShape,
}
impl BinaryPolyGenericSumcheckInputShape {
    pub(crate) const fn native_decode_shape(
        &self,
    ) -> crate::artifact::binary_native::codec::GenericDecode {
        crate::artifact::binary_native::codec::GenericDecode {
            rounds: self.shape.num_rounds,
            degree: self.shape.degree,
            pow_count: self.pow_count(),
        }
    }

    const fn pow_count(&self) -> usize {
        if self.shape.pow_bits > 0 {
            self.shape.num_rounds
        } else {
            0
        }
    }
    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryPolyGenericSumcheckProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.allocate_with(
            b,
            |b| {
                let limbs = b.alloc_private_input_array::<12>("binary Poly generic sumcheck field");
                Ok(b.binary_poly192_from_limbs::<BF>(limbs)?)
            },
            |b| {
                let limbs = b.alloc_private_input_array::<4>(
                    "binary Poly generic sumcheck grinding witness",
                );
                Ok(b.binary_poly64_from_limbs::<BF>(limbs)?)
            },
        )
    }

    fn allocate_with<CF: Field + Eq + Hash, T, B>(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut field: impl FnMut(&mut CircuitBuilder<CF>) -> Result<T, VerificationError>,
        mut base: impl FnMut(&mut CircuitBuilder<CF>) -> Result<B, VerificationError>,
    ) -> Result<BinaryPolyGenericSumcheckProofTargets<T, B>, VerificationError> {
        let claimed_sum = field(b)?;
        let round_polys = (0..self.shape.num_rounds)
            .map(|_| (0..self.shape.degree).map(|_| field(b)).collect())
            .collect::<Result<_, VerificationError>>()?;
        let pow_witnesses = (0..self.pow_count())
            .map(|_| base(b))
            .collect::<Result<_, VerificationError>>()?;
        Ok(BinaryPolyGenericSumcheckProofTargets {
            claimed_sum,
            round_polys,
            pow_witnesses,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NativeBinaryPolyGenericSumcheckInput {
    shape: BinaryPolyGenericSumcheckInputShape,
    limbs: Vec<u16>,
}
impl NativeBinaryPolyGenericSumcheckInput {
    pub const fn shape(&self) -> &BinaryPolyGenericSumcheckInputShape {
        &self.shape
    }
    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryPolyGenericSumcheckInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary Poly generic sumcheck input belongs to another verifier",
            ));
        }
        Ok(self.limbs.iter().copied().map(EF::from_u16).collect())
    }
}

/// Frozen polynomial-basis degree, round count and grinding schedule.
#[derive(Clone, Debug)]
pub struct BinaryPolyGenericSumcheckVerifier {
    input: BinaryPolyGenericSumcheckInputShape,
    interpolator: Poly192SumcheckInterpolator,
    usage: InputResourceUsage,
}

impl BinaryPolyGenericSumcheckVerifier {
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
        let pow_limit = 56usize.min(usize::BITS as usize - 1);
        if pow_bits > pow_limit {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "binary generic sumcheck grinding bits",
                actual: pow_bits,
                limit: pow_limit,
            });
        }
        let limbs = rounds
            .checked_mul(degree)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(12))
            .and_then(|n| {
                rounds
                    .checked_mul(if pow_bits > 0 { 4 } else { 0 })
                    .and_then(|pow| n.checked_add(pow))
            })
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary Poly generic sumcheck input limbs",
            })?;
        usage.add_scalar_elements(limits, limbs)?;
        let interpolator = Poly192SumcheckInterpolator::with_limits(degree, limits)?;
        usage.add_metadata_entries(limits, interpolator.metadata_entries())?;
        let shape = GenericDegreeShape::new(rounds, degree, pow_bits);
        let seed = domain_separator_seed(&shape.domain_separator::<Poly64, Poly192>());
        usage.add_metadata_entries(limits, seed.len())?;
        Ok(Self {
            input: BinaryPolyGenericSumcheckInputShape { seed, shape },
            interpolator,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryPolyGenericSumcheckInputShape {
        self.input.clone()
    }
    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    pub fn verify_reduction<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        expected_sum: &BinaryPoly192Target,
        proof: &BinaryPolyGenericSumcheckProofTargets,
    ) -> Result<BinaryPolyGenericSumcheckOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_using::<Poly64Relation, PrimeBinaryEncoding<BF>, EF>(
            b,
            ch,
            expected_sum,
            proof,
            false,
        )
    }

    /// Resume bounded sampling only through this run's nonempty native seed.
    pub fn verify_reduction_after_queries<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        token: BinaryQueryContinuation,
        expected_sum: &BinaryPoly192Target,
        proof: &BinaryPolyGenericSumcheckProofTargets,
    ) -> Result<BinaryPolyGenericSumcheckOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_after_queries_using::<Poly64Relation, PrimeBinaryEncoding<BF>, EF>(
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
        proof: &BinaryPolyGenericSumcheckProofTargets<P::ChallengeTarget, P::BaseTarget>,
    ) -> Result<BinaryPolyGenericSumcheckOutput<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryPolyPolicy<CF> + BinaryProtocolPolicy<CF>,
    {
        self.check_targets(proof)?;
        let bytes = poly_seed_bytes_with_host::<H, CF>(b, &self.input.seed)?;
        let ch = token.resume_with_observation_with_host::<H, CF>(b, &bytes)?;
        self.verify_using::<P, H, CF>(b, ch, expected_sum, proof, true)
    }

    pub(crate) fn verify_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        expected_sum: &P::ChallengeTarget,
        proof: &BinaryPolyGenericSumcheckProofTargets<P::ChallengeTarget, P::BaseTarget>,
        seeded: bool,
    ) -> Result<BinaryPolyGenericSumcheckOutput<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryPolyPolicy<CF> + BinaryProtocolPolicy<CF>,
    {
        self.check_targets(proof)?;
        P::assert_equal(b, &proof.claimed_sum, expected_sum);
        if !seeded {
            poly_observe_seed_with_host::<H, CF>(b, &mut ch, &self.input.seed)?;
        }
        P::observe::<H>(b, &mut ch, core::slice::from_ref(&proof.claimed_sum))?;
        let mut claim = proof.claimed_sum.clone();
        let mut point = Vec::with_capacity(self.input.shape.num_rounds);
        for (i, polynomial) in proof.round_polys.iter().enumerate() {
            P::observe::<H>(b, &mut ch, polynomial)?;
            if self.input.shape.pow_bits > 0 {
                P::observe_base::<H>(b, &mut ch, core::slice::from_ref(&proof.pow_witnesses[i]))?;
                for bit in ch.sample_bits_with_host::<H, CF>(b, self.input.shape.pow_bits)? {
                    let difference = b.sub(ExprId::ZERO, bit);
                    b.assert_zero(difference);
                }
            }
            let r = P::sample::<H>(b, &mut ch)?;
            claim = self
                .interpolator
                .reduce_claim_using::<P, CF>(b, &claim, polynomial, &r)?;
            point.push(r);
            b.check_construction_limits()?;
        }
        Ok(BinaryPolyGenericSumcheckOutput {
            point,
            claim,
            challenger: ch,
        })
    }

    pub(crate) fn check_targets<T, B>(
        &self,
        proof: &BinaryPolyGenericSumcheckProofTargets<T, B>,
    ) -> Result<(), VerificationError> {
        if proof.round_polys.len() != self.input.shape.num_rounds
            || proof
                .round_polys
                .iter()
                .any(|row| row.len() != self.input.shape.degree)
            || proof.pow_witnesses.len() != self.input.pow_count()
        {
            return Err(invalid(
                "binary Poly generic sumcheck target shape mismatch",
            ));
        }
        Ok(())
    }

    pub(crate) fn check_native(
        &self,
        proof: &GenericDegreeProof<Poly64, Poly192>,
    ) -> Result<(), VerificationError> {
        if proof.round_polys.len() != self.input.shape.num_rounds
            || proof
                .round_polys
                .iter()
                .any(|row| row.len() != self.input.shape.degree)
            || proof.pow_witnesses.len() != self.input.pow_count()
        {
            return Err(invalid(
                "binary Poly generic sumcheck native shape mismatch",
            ));
        }
        Ok(())
    }

    /// Bounded witness extraction with exact native replay. A failed replay
    /// leaves the caller's challenger unchanged; it does not close an AIR claim.
    pub fn import_native<Ch>(
        &self,
        proof: &GenericDegreeProof<Poly64, Poly192>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryPolyGenericSumcheckInput, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64> + Clone,
    {
        self.import_native_with_reduction(proof, ch)
            .map(|(input, _, _)| input)
    }

    pub(crate) fn import_native_with_reduction<Ch>(
        &self,
        proof: &GenericDegreeProof<Poly64, Poly192>,
        ch: &mut Ch,
    ) -> Result<
        (
            NativeBinaryPolyGenericSumcheckInput,
            p3_multilinear_util::point::Point<Poly192>,
            Poly192,
        ),
        VerificationError,
    >
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64> + Clone,
    {
        self.check_native(proof)?;
        let mut staged = ch.clone();
        let (point, claim) = proof
            .verify(
                &mut staged,
                self.input.shape.num_rounds,
                self.input.shape.degree,
                self.input.shape.pow_bits,
            )
            .map_err(|_| invalid("binary Poly generic sumcheck native replay failed"))?;
        let mut limbs = Vec::new();
        for value in core::iter::once(&proof.claimed_sum).chain(proof.round_polys.iter().flatten())
        {
            for coefficient in value.coefficients() {
                append_base(&mut limbs, coefficient);
            }
        }
        for &value in &proof.pow_witnesses {
            append_base(&mut limbs, value);
        }
        *ch = staged;
        Ok((
            NativeBinaryPolyGenericSumcheckInput {
                shape: self.input.clone(),
                limbs,
            },
            point,
            claim,
        ))
    }
}

fn append_base(limbs: &mut Vec<u16>, value: Poly64) {
    limbs.extend((0..4).map(|i| (value.to_bits() >> (16 * i)) as u16));
}

impl BinaryPolyGenericSumcheckInputShape {
    /// Native coefficients for messages and one Poly64 cell per PoW witness.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<Poly64>,
    ) -> Result<BinaryPolyGenericSumcheckProofTargets<NativePoly192Target, ExprId>, VerificationError>
    {
        self.allocate_with(
            b,
            |b| {
                let coefficients = b.alloc_private_input_array::<3>("native Poly sumcheck field");
                b.check_construction_limits()?;
                Ok(b.native_poly192_from_coefficients(coefficients))
            },
            |b| {
                let value = b.alloc_private_input("native Poly sumcheck grinding witness");
                b.check_construction_limits()?;
                Ok(value)
            },
        )
    }
}
impl NativeBinaryPolyGenericSumcheckInput {
    /// Exact coefficient order followed by base-field grinding witnesses.
    pub fn private_native_values(
        &self,
        expected: &BinaryPolyGenericSumcheckInputShape,
    ) -> Result<Vec<Poly64>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary Poly generic sumcheck input belongs to another verifier",
            ));
        }
        let cells = 3 * (1 + self.shape.shape.num_rounds * self.shape.shape.degree)
            + self.shape.pow_count();
        poly_native_values(&self.limbs, cells)
    }
}
impl BinaryPolyGenericSumcheckVerifier {
    pub fn verify_reduction_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
        expected_sum: &NativePoly192Target,
        proof: &BinaryPolyGenericSumcheckProofTargets<NativePoly192Target, ExprId>,
    ) -> Result<BinaryPolyGenericSumcheckOutput<NativePoly192Target>, VerificationError> {
        self.verify_using::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(
            b,
            ch,
            expected_sum,
            proof,
            false,
        )
    }
    /// Observes this protocol's nonempty seed exactly once after bounded queries.
    pub fn verify_reduction_after_queries_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        token: BinaryQueryContinuation,
        expected_sum: &NativePoly192Target,
        proof: &BinaryPolyGenericSumcheckProofTargets<NativePoly192Target, ExprId>,
    ) -> Result<BinaryPolyGenericSumcheckOutput<NativePoly192Target>, VerificationError> {
        self.verify_after_queries_using::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(
            b,
            token,
            expected_sum,
            proof,
        )
    }
}
