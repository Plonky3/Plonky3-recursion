//! Bounded binary FractionGKR reductions with an observed continuation.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::BinaryField128;
use p3_challenger::FieldChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{BinaryTower128Target, binary_encoding::PrimeBinaryEncoding};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_multi_stark::fractional_gkr::{FractionGkrOutput, FractionGkrProof, FractionGkrShape};
use p3_multilinear_util::point::Point;
use p3_sumcheck::generic_degree::RoundPolyInterpolator;

use super::binary_air::constrain_width;
use super::binary_field_policy::TowerRelation;
use super::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::pcs::binary::{
    Binary128SumcheckInterpolator, BinaryNonzeroChallengePlan, BinaryNonzeroChallengeTailPlan,
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField, observe_seed, seed_bytes_with_host,
};
use crate::transcript::domain_separator_seed;
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};
pub(crate) mod kernel;
use kernel::{FractionDraw, FractionLayerView, verify_layers};

#[derive(Clone, Debug)]
pub struct BinaryFractionGkrLayerTargets {
    pub round_polys: Vec<[BinaryTower128Target; 3]>,
    /// Native wire order: numerator zero, denominator zero, numerator one,
    /// denominator one.
    pub claims: [BinaryTower128Target; 4],
}

#[derive(Clone, Debug)]
pub struct BinaryFractionGkrProofTargets {
    pub root_denominator: BinaryTower128Target,
    pub layers: Vec<BinaryFractionGkrLayerTargets>,
}

/// An internally consistent reduction awaiting authentication of both input
/// polynomials by the surrounding protocol. This is not a verified statement.
#[must_use = "fraction numerator and denominator must be authenticated by the surrounding protocol"]
#[derive(Debug)]
pub struct BinaryFractionGkrOutput {
    /// Most-significant-variable-first multilinear point.
    pub point: Vec<BinaryTower128Target>,
    pub numerator: BinaryTower128Target,
    pub denominator: BinaryTower128Target,
    pub continuation: BinaryQueryContinuation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryFractionGkrInputShape<F = BinaryField128, E = BinaryField128> {
    seed: Vec<F>,
    height: usize,
    max_nonzero_draws: usize,
    challenge: PhantomData<E>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    BinaryFractionGkrInputShape<F, E>
{
    pub(crate) fn native_decode_height(&self) -> usize {
        self.height
    }

    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryFractionGkrProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let mut field = || -> Result<BinaryTower128Target, VerificationError> {
            let limbs = b.alloc_private_input_array::<8>("binary fraction GKR field");
            Ok(b.binary128_from_limbs::<BF>(limbs)?)
        };
        let root_denominator = field()?;
        let layers = (0..self.height)
            .map(|layer| {
                let round_polys = (0..layer)
                    .map(|_| Ok([field()?, field()?, field()?]))
                    .collect::<Result<_, VerificationError>>()?;
                Ok(BinaryFractionGkrLayerTargets {
                    round_polys,
                    claims: [field()?, field()?, field()?, field()?],
                })
            })
            .collect::<Result<_, VerificationError>>()?;
        Ok(BinaryFractionGkrProofTargets {
            root_denominator,
            layers,
        })
    }
}

/// Bounded witness data carrying no independent input-polynomial authority.
#[derive(Clone, Debug)]
pub struct NativeBinaryFractionGkrInput<F = BinaryField128, E = BinaryField128> {
    shape: BinaryFractionGkrInputShape<F, E>,
    fields: Vec<u128>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    NativeBinaryFractionGkrInput<F, E>
{
    pub fn shape(&self) -> &BinaryFractionGkrInputShape<F, E> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryFractionGkrInputShape<F, E>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary fraction input belongs to another verifier"));
        }
        Ok(self
            .fields
            .iter()
            .flat_map(|&value| (0..8).map(move |i| EF::from_u16((value >> (16 * i)) as u16)))
            .collect())
    }
}

/// Released degree-three FractionGKR over Tower64 or Tower128. Geometry and
/// every rejection budget are fixed independently of the proof.
#[derive(Clone, Debug)]
pub struct BinaryFractionGkrVerifier<F = BinaryField128, E = BinaryField128> {
    input: BinaryFractionGkrInputShape<F, E>,
    interpolator: Binary128SumcheckInterpolator,
    nonzero: BinaryNonzeroChallengePlan<E>,
    branch_tail: Option<BinaryNonzeroChallengeTailPlan<E>>,
    usage: InputResourceUsage,
}

impl<F, E> BinaryFractionGkrVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
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
        usage.add_metadata_entries(limits, E::RAW_BITS)?;
        let fields = rounds
            .checked_mul(3)
            .and_then(|n| {
                height
                    .checked_mul(4)
                    .and_then(|children| n.checked_add(children))
            })
            .and_then(|n| n.checked_add(1))
            .ok_or_else(overflow)?;
        usage.add_scalar_elements(limits, fields.checked_mul(8).ok_or_else(overflow)?)?;
        let steps = height
            .checked_mul(height)
            .and_then(|n| height.checked_mul(4).and_then(|fixed| n.checked_add(fixed)))
            .and_then(|n| n.checked_add(1))
            .ok_or_else(overflow)?;
        usage.add_metadata_entries(limits, steps)?;
        let nonzero = BinaryNonzeroChallengePlan::with_limits(1, max_nonzero_draws, limits)?;
        let mut prefix_usage = nonzero.input_resource_usage();
        prefix_usage.rounds = 0; // All challenges were charged above.
        for _ in 0..rounds + 1 {
            usage.merge(limits, prefix_usage)?;
        }
        let branch_tail = if height > 1 {
            let tail =
                BinaryNonzeroChallengeTailPlan::with_limits(1, max_nonzero_draws, 1, limits)?;
            let mut tail_usage = tail.input_resource_usage();
            tail_usage.rounds = 0;
            for _ in 0..height - 1 {
                usage.merge(limits, tail_usage)?;
            }
            Some(tail)
        } else {
            None
        };
        let interpolator = Binary128SumcheckInterpolator::with_limits(3, limits)?;
        usage.add_metadata_entries(limits, 16)?;
        let native = FractionGkrShape {
            num_variables: height,
        };
        let seed = domain_separator_seed(&native.domain_separator::<F, E>());
        usage.add_metadata_entries(limits, seed.len())?;
        Ok(Self {
            input: BinaryFractionGkrInputShape {
                seed,
                height,
                max_nonzero_draws,
                challenge: PhantomData,
            },
            interpolator,
            nonzero,
            branch_tail,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryFractionGkrInputShape<F, E> {
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
        proof: &BinaryFractionGkrProofTargets,
    ) -> Result<BinaryFractionGkrOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_impl::<BF, EF>(b, ch, proof, false)
    }

    /// Resumes a bounded rejection phase through this reduction's nonempty
    /// native seed. The seed is observed exactly once.
    pub fn verify_reduction_after_queries<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        token: BinaryQueryContinuation,
        proof: &BinaryFractionGkrProofTargets,
    ) -> Result<BinaryFractionGkrOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(proof)?;
        let bytes = seed_bytes_with_host::<F, PrimeBinaryEncoding<BF>, EF>(b, &self.input.seed)?;
        let ch = token.resume_with_observation::<BF, EF>(b, &bytes)?;
        self.verify_impl::<BF, EF>(b, ch, proof, true)
    }

    fn verify_impl<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        proof: &BinaryFractionGkrProofTargets,
        seeded: bool,
    ) -> Result<BinaryFractionGkrOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(proof)?;
        for value in core::iter::once(&proof.root_denominator).chain(
            proof
                .layers
                .iter()
                .flat_map(|layer| layer.round_polys.iter().flatten().chain(&layer.claims)),
        ) {
            constrain_width(b, value, E::RAW_BITS);
        }
        let one = b.define_const(EF::ONE);
        let zero_factors = proof.root_denominator.bits()[..E::RAW_BITS]
            .iter()
            .map(|&bit| b.sub(one, bit))
            .collect::<Vec<_>>();
        let zero = b.mul_many(&zero_factors);
        b.assert_zero(zero);
        if !seeded {
            observe_seed::<F, BF, EF>(b, &mut ch, &self.input.seed)?;
        }
        let layers = proof
            .layers
            .iter()
            .map(|layer| FractionLayerView {
                messages: &layer.round_polys,
                claims: &layer.claims,
            })
            .collect::<Vec<_>>();
        let output = verify_layers::<TowerRelation<F, E>, PrimeBinaryEncoding<BF>, EF>(
            b,
            ch,
            &proof.root_denominator,
            &layers,
            |b, claim, polynomial, challenge| {
                self.interpolator
                    .reduce_claim(b, claim, polynomial, challenge)
            },
            |b, ch, with_batching| {
                if with_batching {
                    let output = self
                        .branch_tail
                        .as_ref()
                        .expect("trusted nonfinal layer")
                        .sample::<BF, EF>(b, ch)?;
                    Ok(FractionDraw {
                        value: output.values[0].clone(),
                        following: Some(output.following[0].clone()),
                        continuation: output.continuation,
                    })
                } else {
                    let output = self.nonzero.sample::<BF, EF>(b, ch)?;
                    Ok(FractionDraw {
                        value: output.values[0].clone(),
                        following: None,
                        continuation: output.continuation,
                    })
                }
            },
        )?;
        Ok(BinaryFractionGkrOutput {
            point: output.point,
            numerator: output.numerator,
            denominator: output.denominator,
            continuation: output.continuation,
        })
    }

    pub(crate) fn check_targets(
        &self,
        proof: &BinaryFractionGkrProofTargets,
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
        proof: &FractionGkrProof<E>,
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
        if proof.root_denominator == E::ZERO {
            return Err(invalid("binary fraction root denominator is zero"));
        }
        Ok(())
    }

    /// Performs finite native replay without the upstream driver's unbounded
    /// rejection loops. Every failure preserves the caller's challenger.
    pub fn import_native<Ch>(
        &self,
        proof: &FractionGkrProof<E>,
        ch: &mut Ch,
    ) -> Result<NativeBinaryFractionGkrInput<F, E>, VerificationError>
    where
        Ch: FieldChallenger<F> + Clone,
    {
        self.import_native_with_reduction(proof, ch)
            .map(|(input, _)| input)
    }

    pub(crate) fn import_native_with_reduction<Ch>(
        &self,
        proof: &FractionGkrProof<E>,
        ch: &mut Ch,
    ) -> Result<(NativeBinaryFractionGkrInput<F, E>, FractionGkrOutput<E>), VerificationError>
    where
        Ch: FieldChallenger<F> + Clone,
    {
        self.check_native(proof)?;
        let mut staged = ch.clone();
        FractionGkrShape {
            num_variables: self.input.height,
        }
        .domain_separator::<F, E>()
        .seed(&mut staged);
        staged.observe_algebra_element(proof.root_denominator);
        let mut lambda = staged.sample_algebra_element::<E>();
        let mut numerator = E::ZERO;
        let mut denominator = proof.root_denominator;
        let mut point = Point::<E>::new(Vec::new());
        let interpolator = RoundPolyInterpolator::<E>::new(3);
        for (index, layer) in proof.layers.iter().enumerate() {
            let mut claim = numerator + lambda * denominator;
            let mut round_point = Vec::with_capacity(index + 1);
            for polynomial in &layer.round_polys {
                staged.observe_algebra_slice(polynomial);
                let challenge = self.nonzero.sample_native::<F, _>(&mut staged)?[0];
                claim = interpolator.eval(polynomial, claim, challenge);
                round_point.push(challenge);
            }
            let c = layer.claims;
            let expected = Point::<E>::eval_eq(point.as_slice(), &round_point)
                * (c.d1 * c.n0 + c.d0 * c.n1 + lambda * c.d0 * c.d1);
            if claim != expected {
                return Err(invalid("binary fraction native layer consistency failed"));
            }
            staged.observe_algebra_slice(&[c.n0, c.d0, c.n1, c.d1]);
            let branch = if index + 1 == self.input.height {
                self.nonzero.sample_native::<F, _>(&mut staged)?[0]
            } else {
                let (values, following) = self
                    .branch_tail
                    .as_ref()
                    .expect("trusted nonfinal layer")
                    .sample_native::<F, _>(&mut staged)?;
                lambda = following[0];
                values[0]
            };
            numerator = c.n0 + branch * (c.n1 + c.n0);
            denominator = c.d0 + branch * (c.d1 + c.d0);
            round_point.insert(0, branch);
            point = Point::new(round_point);
        }
        let mut fields = vec![proof.root_denominator.raw_coordinates()];
        for layer in &proof.layers {
            fields.extend(
                layer
                    .round_polys
                    .iter()
                    .flatten()
                    .copied()
                    .map(E::raw_coordinates),
            );
            let c = layer.claims;
            fields.extend([c.n0, c.d0, c.n1, c.d1].map(E::raw_coordinates));
        }
        *ch = staged;
        Ok((
            NativeBinaryFractionGkrInput {
                shape: self.input.clone(),
                fields,
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
