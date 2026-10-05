//! Bounded Poly64/Poly192 Fraction-GKR and its exact observed continuation.
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::FieldChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryPoly192Target, NativePoly192Target};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_multi_stark::fractional_gkr::{FractionGkrOutput, FractionGkrProof, FractionGkrShape};
use p3_multilinear_util::point::Point;
use p3_sumcheck::generic_degree::RoundPolyInterpolator;

use super::binary_field_policy::{
    BinaryPolyPolicy, BinaryProtocolPolicy, NativePoly64Relation, Poly64Relation,
    poly_native_values, poly_observe_seed_with_host, poly_seed_bytes_with_host,
};
use super::binary_fraction::kernel::{FractionDraw, FractionLayerView, verify_layers};
use super::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::pcs::binary::{
    BinaryPolyNonzeroChallengePlan, BinaryPolyNonzeroChallengeTailPlan, Poly192SumcheckInterpolator,
};
use crate::transcript::domain_separator_seed;
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

#[derive(Clone, Debug)]
pub struct BinaryPolyFractionGkrLayerTargets<T = BinaryPoly192Target> {
    pub round_polys: Vec<[T; 3]>,
    /// Native wire order: numerator zero, denominator zero, numerator one,
    /// denominator one.
    pub claims: [T; 4],
}

#[derive(Clone, Debug)]
pub struct BinaryPolyFractionGkrProofTargets<T = BinaryPoly192Target> {
    pub root_denominator: T,
    pub layers: Vec<BinaryPolyFractionGkrLayerTargets<T>>,
}

/// An internally consistent reduction awaiting authentication of both input
/// polynomials by the surrounding protocol. This is not a verified statement.
#[must_use = "fraction numerator and denominator must be authenticated by the surrounding protocol"]
#[derive(Debug)]
pub struct BinaryPolyFractionGkrOutput<T = BinaryPoly192Target> {
    /// Most-significant-variable-first multilinear point.
    pub point: Vec<T>,
    pub numerator: T,
    pub denominator: T,
    pub continuation: BinaryQueryContinuation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyFractionGkrInputShape {
    seed: Vec<Poly64>,
    height: usize,
    max_nonzero_draws: usize,
}

impl BinaryPolyFractionGkrInputShape {
    pub(crate) fn native_decode_height(&self) -> usize {
        self.height
    }

    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryPolyFractionGkrProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.allocate_with(|| {
            let limbs = b.alloc_private_input_array::<12>("binary fraction GKR field");
            Ok(b.binary_poly192_from_limbs::<BF>(limbs)?)
        })
    }

    fn allocate_with<T>(
        &self,
        mut field: impl FnMut() -> Result<T, VerificationError>,
    ) -> Result<BinaryPolyFractionGkrProofTargets<T>, VerificationError> {
        let root_denominator = field()?;
        let layers = (0..self.height)
            .map(|layer| {
                let round_polys = (0..layer)
                    .map(|_| Ok([field()?, field()?, field()?]))
                    .collect::<Result<_, VerificationError>>()?;
                Ok(BinaryPolyFractionGkrLayerTargets {
                    round_polys,
                    claims: [field()?, field()?, field()?, field()?],
                })
            })
            .collect::<Result<_, VerificationError>>()?;
        Ok(BinaryPolyFractionGkrProofTargets {
            root_denominator,
            layers,
        })
    }
}

/// Bounded witness data carrying no independent input-polynomial authority.
#[derive(Clone, Debug)]
pub struct NativeBinaryPolyFractionGkrInput {
    shape: BinaryPolyFractionGkrInputShape,
    limbs: Vec<u16>,
}

impl NativeBinaryPolyFractionGkrInput {
    pub fn shape(&self) -> &BinaryPolyFractionGkrInputShape {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryPolyFractionGkrInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary fraction input belongs to another verifier"));
        }
        Ok(self.limbs.iter().copied().map(EF::from_u16).collect())
    }
}

/// Released degree-three Fraction-GKR over Poly64 and Poly192. Geometry and
/// every rejection budget are fixed independently of the proof.
#[derive(Clone, Debug)]
pub struct BinaryPolyFractionGkrVerifier {
    input: BinaryPolyFractionGkrInputShape,
    interpolator: Poly192SumcheckInterpolator,
    nonzero: BinaryPolyNonzeroChallengePlan,
    branch_tail: Option<BinaryPolyNonzeroChallengeTailPlan>,
    usage: InputResourceUsage,
}

impl BinaryPolyFractionGkrVerifier {
    pub fn new(height: usize, max_nonzero_draws: usize) -> Result<Self, VerificationError> {
        Self::with_limits(height, max_nonzero_draws, &VerifierLimits::default())
    }

    pub fn with_limits(
        height: usize,
        max_nonzero_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        Self::with_limits_impl(height, max_nonzero_draws, limits, true)
    }

    /// The enclosing indexed relation already accounts for its AIR instances.
    pub(crate) fn with_embedded_logup_limits(
        height: usize,
        max_nonzero_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        Self::with_limits_impl(height, max_nonzero_draws, limits, false)
    }

    fn with_limits_impl(
        height: usize,
        max_nonzero_draws: usize,
        limits: &VerifierLimits,
        account_instances: bool,
    ) -> Result<Self, VerificationError> {
        if height == 0 {
            return Err(invalid("binary fraction height must be positive"));
        }
        let mut usage = InputResourceUsage::default();
        usage.check_log_degree(limits, height)?;
        if account_instances {
            usage.add_instances(limits, 1)?;
        }
        let overflow = || VerificationError::ResourceArithmeticOverflow {
            component: "binary fraction geometry",
        };
        let rounds = height.checked_mul(height - 1).ok_or_else(overflow)? / 2;
        let challenges = height
            .checked_mul(2)
            .and_then(|n| n.checked_add(rounds))
            .ok_or_else(overflow)?;
        usage.add_rounds(limits, challenges)?;
        usage.add_query_round(limits, 1)?; // Initial unrestricted batching draw.
        usage.add_metadata_entries(limits, 192)?;
        let fields = rounds
            .checked_mul(3)
            .and_then(|n| {
                height
                    .checked_mul(4)
                    .and_then(|children| n.checked_add(children))
            })
            .and_then(|n| n.checked_add(1))
            .ok_or_else(overflow)?;
        usage.add_scalar_elements(limits, fields.checked_mul(12).ok_or_else(overflow)?)?;
        let steps = height
            .checked_mul(height)
            .and_then(|n| height.checked_mul(4).and_then(|fixed| n.checked_add(fixed)))
            .and_then(|n| n.checked_add(1))
            .ok_or_else(overflow)?;
        usage.add_metadata_entries(limits, steps)?;
        let nonzero = BinaryPolyNonzeroChallengePlan::with_limits(1, max_nonzero_draws, limits)?;
        let mut prefix_usage = nonzero.input_resource_usage();
        prefix_usage.rounds = 0; // All challenges were charged above.
        for _ in 0..rounds + 1 {
            usage.merge(limits, prefix_usage)?;
        }
        let branch_tail = if height > 1 {
            let tail =
                BinaryPolyNonzeroChallengeTailPlan::with_limits(1, max_nonzero_draws, 1, limits)?;
            let mut tail_usage = tail.input_resource_usage();
            tail_usage.rounds = 0;
            for _ in 0..height - 1 {
                usage.merge(limits, tail_usage)?;
            }
            Some(tail)
        } else {
            None
        };
        let interpolator = Poly192SumcheckInterpolator::with_limits(3, limits)?;
        usage.add_metadata_entries(limits, 16)?;
        let native = FractionGkrShape {
            num_variables: height,
        };
        let seed = domain_separator_seed(&native.domain_separator::<Poly64, Poly192>());
        usage.add_metadata_entries(limits, seed.len())?;
        Ok(Self {
            input: BinaryPolyFractionGkrInputShape {
                seed,
                height,
                max_nonzero_draws,
            },
            interpolator,
            nonzero,
            branch_tail,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryPolyFractionGkrInputShape {
        self.input.clone()
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Checks the exact messages, replays the bounded native transcript, and
    /// returns unauthenticated input claims. Targets must belong to this builder.
    pub fn verify_reduction<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        proof: &BinaryPolyFractionGkrProofTargets,
    ) -> Result<BinaryPolyFractionGkrOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_using::<Poly64Relation, PrimeBinaryEncoding<BF>, EF>(b, ch, proof, false)
    }

    /// Resumes a bounded rejection phase through this reduction's nonempty
    /// native seed. The seed is observed exactly once.
    pub fn verify_reduction_after_queries<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        token: BinaryQueryContinuation,
        proof: &BinaryPolyFractionGkrProofTargets,
    ) -> Result<BinaryPolyFractionGkrOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_after_queries_using::<Poly64Relation, PrimeBinaryEncoding<BF>, EF>(
            b, token, proof,
        )
    }

    pub(super) fn verify_after_queries_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        token: BinaryQueryContinuation,
        proof: &BinaryPolyFractionGkrProofTargets<P::ChallengeTarget>,
    ) -> Result<BinaryPolyFractionGkrOutput<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryPolyPolicy<CF> + BinaryProtocolPolicy<CF>,
    {
        self.check_targets(proof)?;
        let bytes = poly_seed_bytes_with_host::<H, CF>(b, &self.input.seed)?;
        let ch = token.resume_with_observation_with_host::<H, CF>(b, &bytes)?;
        self.verify_using::<P, H, CF>(b, ch, proof, true)
    }

    pub(super) fn verify_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        proof: &BinaryPolyFractionGkrProofTargets<P::ChallengeTarget>,
        seeded: bool,
    ) -> Result<BinaryPolyFractionGkrOutput<P::ChallengeTarget>, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryPolyPolicy<CF> + BinaryProtocolPolicy<CF>,
    {
        self.check_targets(proof)?;
        let one = b.define_const(CF::ONE);
        let root_bits = P::challenge_bits(b, &proof.root_denominator)?;
        let zero_factors = root_bits
            .iter()
            .map(|&bit| b.sub(one, bit))
            .collect::<Vec<_>>();
        let zero = b.mul_many(&zero_factors);
        b.assert_zero(zero);
        if !seeded {
            poly_observe_seed_with_host::<H, CF>(b, &mut ch, &self.input.seed)?;
        }
        let layers = proof
            .layers
            .iter()
            .map(|layer| FractionLayerView {
                messages: &layer.round_polys,
                claims: &layer.claims,
            })
            .collect::<Vec<_>>();
        let output = verify_layers::<P, H, CF>(
            b,
            ch,
            &proof.root_denominator,
            &layers,
            |b, claim, polynomial, challenge| {
                self.interpolator
                    .reduce_claim_using::<P, CF>(b, claim, polynomial, challenge)
            },
            |b, ch, with_batching| {
                if with_batching {
                    let output = self
                        .branch_tail
                        .as_ref()
                        .expect("trusted nonfinal layer")
                        .sample_using::<P, H, CF>(b, ch)?;
                    Ok(FractionDraw {
                        value: output.values[0].clone(),
                        following: Some(output.following[0].clone()),
                        continuation: output.continuation,
                    })
                } else {
                    let output = self.nonzero.sample_using::<P, H, CF>(b, ch)?;
                    Ok(FractionDraw {
                        value: output.values[0].clone(),
                        following: None,
                        continuation: output.continuation,
                    })
                }
            },
        )?;
        Ok(BinaryPolyFractionGkrOutput {
            point: output.point,
            numerator: output.numerator,
            denominator: output.denominator,
            continuation: output.continuation,
        })
    }

    pub(crate) fn check_targets<T>(
        &self,
        proof: &BinaryPolyFractionGkrProofTargets<T>,
    ) -> Result<(), VerificationError> {
        if proof.layers.len() != self.input.height
            || proof
                .layers
                .iter()
                .enumerate()
                .any(|(index, layer)| layer.round_polys.len() != index)
        {
            return Err(invalid("binary fraction target shape mismatch"));
        }
        Ok(())
    }

    pub(crate) fn check_native(
        &self,
        proof: &FractionGkrProof<Poly192>,
    ) -> Result<(), VerificationError> {
        if proof.layers.len() != self.input.height
            || proof
                .layers
                .iter()
                .enumerate()
                .any(|(index, layer)| layer.round_polys.len() != index)
        {
            return Err(invalid("binary fraction native shape mismatch"));
        }
        if proof.root_denominator == Poly192::ZERO {
            return Err(invalid("binary fraction root denominator is zero"));
        }
        Ok(())
    }

    /// Performs finite native replay without the upstream driver's unbounded
    /// rejection loops. Every failure preserves the caller's challenger.
    pub fn import_native<Ch>(
        &self,
        proof: &FractionGkrProof<Poly192>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryPolyFractionGkrInput, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + Clone,
    {
        self.import_native_with_reduction(proof, ch)
            .map(|(input, _)| input)
    }

    pub(crate) fn import_native_with_reduction<Ch>(
        &self,
        proof: &FractionGkrProof<Poly192>,
        ch: &mut Ch,
    ) -> Result<(NativeBinaryPolyFractionGkrInput, FractionGkrOutput<Poly192>), VerificationError>
    where
        Ch: FieldChallenger<Poly64> + Clone,
    {
        self.check_native(proof)?;
        let mut staged = ch.clone();
        FractionGkrShape {
            num_variables: self.input.height,
        }
        .domain_separator::<Poly64, Poly192>()
        .seed(&mut staged);
        staged.observe_algebra_element(proof.root_denominator);
        let mut lambda = staged.sample_algebra_element::<Poly192>();
        let mut numerator = Poly192::ZERO;
        let mut denominator = proof.root_denominator;
        let mut point = Point::<Poly192>::new(Vec::new());
        let interpolator = RoundPolyInterpolator::<Poly192>::new(3);
        for (index, layer) in proof.layers.iter().enumerate() {
            let mut claim = numerator + lambda * denominator;
            let mut round_point = Vec::with_capacity(index + 1);
            for polynomial in &layer.round_polys {
                staged.observe_algebra_slice(polynomial);
                let challenge = self.nonzero.sample_native(&mut staged)?[0];
                claim = interpolator.eval(polynomial, claim, challenge);
                round_point.push(challenge);
            }
            let c = layer.claims;
            let expected = Point::<Poly192>::eval_eq(point.as_slice(), &round_point)
                * (c.d1 * c.n0 + c.d0 * c.n1 + lambda * c.d0 * c.d1);
            if claim != expected {
                return Err(invalid("binary fraction native layer consistency failed"));
            }
            staged.observe_algebra_slice(&[c.n0, c.d0, c.n1, c.d1]);
            let branch = if index + 1 == self.input.height {
                self.nonzero.sample_native(&mut staged)?[0]
            } else {
                let (values, following) = self
                    .branch_tail
                    .as_ref()
                    .expect("trusted nonfinal layer")
                    .sample_native(&mut staged)?;
                lambda = following[0];
                values[0]
            };
            numerator = c.n0 + branch * (c.n1 + c.n0);
            denominator = c.d0 + branch * (c.d1 + c.d0);
            round_point.insert(0, branch);
            point = Point::new(round_point);
        }
        let mut limbs = Vec::new();
        let mut append = |value: Poly192| {
            for coefficient in value.coefficients() {
                limbs.extend((0..4).map(|i| (coefficient.to_bits() >> (16 * i)) as u16));
            }
        };
        append(proof.root_denominator);
        for layer in &proof.layers {
            for &value in layer.round_polys.iter().flatten() {
                append(value);
            }
            let c = layer.claims;
            for value in [c.n0, c.d0, c.n1, c.d1] {
                append(value);
            }
        }
        *ch = staged;
        Ok((
            NativeBinaryPolyFractionGkrInput {
                shape: self.input.clone(),
                limbs,
            },
            FractionGkrOutput {
                point,
                numerator,
                denominator,
            },
        ))
    }
}

fn invalid(message: &str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

impl BinaryPolyFractionGkrInputShape {
    /// Allocates exactly three native coefficient cells per challenge message.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<Poly64>,
    ) -> Result<BinaryPolyFractionGkrProofTargets<NativePoly192Target>, VerificationError> {
        self.allocate_with(|| {
            let coefficients = b.alloc_private_input_array::<3>("native Poly fraction GKR field");
            b.check_construction_limits()?;
            Ok(b.native_poly192_from_coefficients(coefficients))
        })
    }
}
impl NativeBinaryPolyFractionGkrInput {
    pub fn private_native_values(
        &self,
        expected: &BinaryPolyFractionGkrInputShape,
    ) -> Result<Vec<Poly64>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary fraction input belongs to another verifier"));
        }
        let rounds = self.shape.height * (self.shape.height - 1) / 2;
        let cells = 3 * (1 + 3 * rounds + 4 * self.shape.height);
        poly_native_values(&self.limbs, cells)
    }
}
impl BinaryPolyFractionGkrVerifier {
    /// Native reduction; both returned polynomials require authentication.
    pub fn verify_reduction_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        ch: BinaryTower128Challenger,
        proof: &BinaryPolyFractionGkrProofTargets<NativePoly192Target>,
    ) -> Result<BinaryPolyFractionGkrOutput<NativePoly192Target>, VerificationError> {
        self.verify_using::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(b, ch, proof, false)
    }
    pub fn verify_reduction_after_queries_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        token: BinaryQueryContinuation,
        proof: &BinaryPolyFractionGkrProofTargets<NativePoly192Target>,
    ) -> Result<BinaryPolyFractionGkrOutput<NativePoly192Target>, VerificationError> {
        self.verify_after_queries_using::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(
            b, token, proof,
        )
    }
}
