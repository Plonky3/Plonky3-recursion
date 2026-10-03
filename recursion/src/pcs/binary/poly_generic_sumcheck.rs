//! Released generic-degree sumcheck with Poly64 seeds and Poly192 messages.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryPoly64Target, BinaryPoly192Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape};

use super::generic_sumcheck::lagrange_coefficients;
use super::poly_whir_gadgets::{assert_equal, observe_seed};
use super::whir_plan::invalid;
use crate::transcript::domain_separator_seed;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

#[derive(Clone, Debug)]
pub struct BinaryPolyGenericSumcheckProofTargets {
    pub claimed_sum: BinaryPoly192Target,
    pub round_polys: Vec<Vec<BinaryPoly192Target>>,
    pub pow_witnesses: Vec<BinaryPoly64Target>,
}

/// An unclosed reduction; its caller must authenticate the terminal AIR claim.
#[derive(Clone, Debug)]
pub struct BinaryPolyGenericSumcheckOutput {
    pub point: Vec<BinaryPoly192Target>,
    pub claim: BinaryPoly192Target,
    pub challenger: BinaryTower128Challenger,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyGenericSumcheckInputShape {
    seed: Vec<Poly64>,
    shape: GenericDegreeShape,
}
impl BinaryPolyGenericSumcheckInputShape {
    fn pow_count(&self) -> usize {
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
        let mut field = || {
            let limbs = b.alloc_private_input_array::<12>("binary Poly generic sumcheck field");
            Ok(b.binary_poly192_from_limbs::<BF>(limbs)?)
        };
        let claimed_sum = field()?;
        let round_polys = (0..self.shape.num_rounds)
            .map(|_| (0..self.shape.degree).map(|_| field()).collect())
            .collect::<Result<_, VerificationError>>()?;
        let pow_witnesses = (0..self.pow_count())
            .map(|_| {
                let limbs = b.alloc_private_input_array::<4>(
                    "binary Poly generic sumcheck grinding witness",
                );
                Ok(b.binary_poly64_from_limbs::<BF>(limbs)?)
            })
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
    pub fn shape(&self) -> &BinaryPolyGenericSumcheckInputShape {
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
    coefficients: Vec<Vec<u64>>,
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
        let native = lagrange_coefficients::<Poly192>(degree, limits)?;
        let count = native.len();
        usage.add_metadata_entries(limits, count * count)?;
        // Native Poly192 interpolation nodes lie in Poly64. Their Lagrange
        // coefficients do too, allowing exact base scaling in the circuit.
        let mut coefficients = Vec::with_capacity(count);
        for basis in native {
            let mut row = Vec::with_capacity(count);
            for coefficient in basis {
                let [base, c1, c2] = coefficient.coefficients();
                if c1 != Poly64::ZERO || c2 != Poly64::ZERO {
                    return Err(invalid(
                        "binary Poly sumcheck interpolation left the base field",
                    ));
                }
                row.push(base.to_bits());
            }
            coefficients.push(row);
        }
        let shape = GenericDegreeShape::new(rounds, degree, pow_bits);
        let seed = domain_separator_seed(&shape.domain_separator::<Poly64, Poly192>());
        usage.add_metadata_entries(limits, seed.len())?;
        Ok(Self {
            input: BinaryPolyGenericSumcheckInputShape { seed, shape },
            coefficients,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryPolyGenericSumcheckInputShape {
        self.input.clone()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
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
        self.verify_impl::<BF, EF>(b, ch, expected_sum, proof, false)
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
        self.check_targets(proof)?;
        let bytes = self
            .input
            .seed
            .iter()
            .flat_map(|v| v.to_bits().to_le_bytes())
            .map(|v| b.define_const(EF::from_u8(v)))
            .collect::<Vec<_>>();
        let ch = token.resume_with_observation::<BF, EF>(b, &bytes)?;
        self.verify_impl::<BF, EF>(b, ch, expected_sum, proof, true)
    }

    fn verify_impl<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        expected_sum: &BinaryPoly192Target,
        proof: &BinaryPolyGenericSumcheckProofTargets,
        seeded: bool,
    ) -> Result<BinaryPolyGenericSumcheckOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(proof)?;
        assert_equal(b, &proof.claimed_sum, expected_sum);
        if !seeded {
            observe_seed::<BF, EF>(b, &mut ch, &self.input.seed)?;
        }
        ch.observe_poly192::<BF, EF>(b, &proof.claimed_sum)?;
        let mut claim = proof.claimed_sum.clone();
        let mut point = Vec::with_capacity(self.input.shape.num_rounds);
        for (i, polynomial) in proof.round_polys.iter().enumerate() {
            for value in polynomial {
                ch.observe_poly192::<BF, EF>(b, value)?;
            }
            if self.input.shape.pow_bits > 0 {
                ch.observe_poly64::<BF, EF>(b, &proof.pow_witnesses[i])?;
                for bit in ch.sample_bits::<BF, EF>(b, self.input.shape.pow_bits)? {
                    let difference = b.sub(ExprId::ZERO, bit);
                    b.assert_zero(difference);
                }
            }
            let r = ch.sample_poly192::<BF, EF>(b)?;
            claim = self.reduce(b, &claim, polynomial, &r)?;
            point.push(r);
        }
        Ok(BinaryPolyGenericSumcheckOutput {
            point,
            claim,
            challenger: ch,
        })
    }

    fn reduce<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        claim: &BinaryPoly192Target,
        evaluations: &[BinaryPoly192Target],
        challenge: &BinaryPoly192Target,
    ) -> Result<BinaryPoly192Target, VerificationError> {
        let mut values = Vec::with_capacity(self.coefficients.len());
        values.push(evaluations[0].clone());
        values.push(b.binary_poly192_add(claim, &evaluations[0]));
        values.extend_from_slice(&evaluations[1..]);
        let zero = b.binary_poly192_constant([0; 3])?;
        let mut polynomial = vec![zero; self.coefficients.len()];
        for (value, basis) in values.iter().zip(&self.coefficients) {
            for (coefficient, &constant) in polynomial.iter_mut().zip(basis) {
                if constant == 0 {
                    continue;
                }
                let term = if constant == 1 {
                    value.clone()
                } else {
                    let constant = b.binary_poly64_constant(constant)?;
                    b.binary_poly192_scale(value, &constant)
                };
                *coefficient = b.binary_poly192_add(coefficient, &term);
            }
        }
        let mut iter = polynomial.into_iter().rev();
        let mut result = iter.next().expect("checked positive degree");
        for coefficient in iter {
            let product = b.binary_poly192_mul(&result, challenge);
            result = b.binary_poly192_add(&product, &coefficient);
        }
        Ok(result)
    }

    pub(crate) fn check_targets(
        &self,
        proof: &BinaryPolyGenericSumcheckProofTargets,
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
