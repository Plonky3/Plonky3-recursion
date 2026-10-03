//! Native bit ring-switch verification with circuit-derived Boolean prefixes.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_sumcheck::ring_switch::bits::transcript::{BitRingSwitchClaimsShape, BitRingSwitchShape};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::transcript::SumcheckShape;

use super::verifier::{assert_equal, constrain_width, observe_seed, observe_values, seed_bytes};
use super::{
    BinaryTowerTensorTarget, RecursiveBinaryChallengeField, binary_tensor_closing_weight,
    binary128_reduce_sumcheck_claim,
};
use crate::transcript::domain_separator_seed;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// Verifier-owned readings requested from one Boolean claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinaryRingClaimSpec {
    pub current: bool,
    /// Trailing row coordinates stepped by the repeat-last successor view.
    pub next_rows: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct BinaryRingClaimTargets<E> {
    pub point: Vec<BinaryTower128Target>,
    pub current: Option<BinaryTower128Target>,
    pub next: Option<BinaryTower128Target>,
    pub tensor: BinaryTowerTensorTarget<E>,
    /// Carry and last, present exactly for a successor wider than one element.
    pub successor: Option<(BinaryTowerTensorTarget<E>, BinaryTowerTensorTarget<E>)>,
}

#[derive(Clone, Debug)]
pub struct BinaryRingProofTargets<E> {
    pub claims: Vec<BinaryRingClaimTargets<E>>,
    /// Maximum high-point round count. Native messages occupy the leading
    /// slots; every unused trailing message is constrained to zero. A native
    /// importer must reject a nonempty sumcheck PoW vector before dropping it.
    pub sumcheck: Vec<[BinaryTower128Target; 2]>,
    pub final_eval: BinaryTower128Target,
}

/// The surviving packed opening and exact transcript continuation. Its caller
/// must discharge this point and value against the Boolean commitment's PCS.
#[derive(Clone, Debug)]
pub struct BinaryRingOutput {
    pub point: Vec<BinaryTower128Target>,
    pub value: BinaryTower128Target,
    pub challenger: BinaryTower128Challenger,
}

#[derive(Clone, Debug)]
pub struct BinaryBitRingVerifier<E> {
    pub(super) num_variables: usize,
    pub(super) specs: Vec<BinaryRingClaimSpec>,
    pub(super) usage: InputResourceUsage,
    prefix_limit: usize,
    seed: Vec<E>,
    field: PhantomData<E>,
}

impl<E: RecursiveBinaryChallengeField> BinaryBitRingVerifier<E> {
    pub fn new(
        num_variables: usize,
        specs: Vec<BinaryRingClaimSpec>,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(num_variables, specs, &VerifierLimits::default())
    }

    pub fn with_limits(
        num_variables: usize,
        specs: Vec<BinaryRingClaimSpec>,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let absorbed = E::RAW_BITS.ilog2() as usize;
        if num_variables < absorbed
            || specs.is_empty()
            || specs.iter().any(|s| {
                (!s.current && s.next_rows.is_none())
                    || s.next_rows.is_some_and(|rows| rows > num_variables)
            })
        {
            return Err(invalid("binary ring-switch reading geometry is invalid"));
        }
        if num_variables > limits.max_log_domain_or_degree {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "binary ring-switch variables",
                actual: num_variables,
                limit: limits.max_log_domain_or_degree,
            });
        }
        let high = num_variables - absorbed;
        let mut usage = InputResourceUsage::default();
        usage.add_instances(limits, specs.len())?;
        usage.add_rounds(limits, high)?;
        for spec in &specs {
            let tensors = if spec.next_rows.is_some_and(|rows| rows > absorbed) {
                3usize
            } else {
                1
            };
            let fields = tensors
                .checked_mul(E::RAW_BITS)
                .and_then(|n| n.checked_add(num_variables))
                .and_then(|n| {
                    n.checked_add(usize::from(spec.current) + usize::from(spec.next_rows.is_some()))
                })
                .and_then(|n| n.checked_mul(8))
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary ring-switch fields",
                })?;
            usage.add_scalar_elements(limits, fields)?;
        }
        usage.add_scalar_elements(
            limits,
            high.checked_mul(16).and_then(|n| n.checked_add(8)).ok_or(
                VerificationError::ResourceArithmeticOverflow {
                    component: "binary ring-switch rounds",
                },
            )?,
        )?;
        let shapes: Vec<_> = specs
            .iter()
            .map(|spec| {
                if let Some(rows) = spec.next_rows.filter(|&rows| rows > absorbed) {
                    BitRingSwitchShape::with_successor_rows(num_variables, rows)
                } else {
                    BitRingSwitchShape::new(num_variables)
                }
            })
            .collect();
        let seed = if shapes.len() == 1 {
            domain_separator_seed(&shapes[0].domain_separator::<E>())
        } else {
            domain_separator_seed(
                &BitRingSwitchClaimsShape { claims: shapes }.domain_separator::<E>(),
            )
        };
        let prefix_limit = specs
            .iter()
            .map(|spec| {
                spec.next_rows
                    .map_or(high, |rows| high.min(num_variables - rows))
            })
            .min()
            .expect("nonempty specs were checked");
        Ok(Self {
            num_variables,
            specs,
            usage,
            prefix_limit,
            seed,
            field: PhantomData,
        })
    }

    pub(super) fn check_targets(
        &self,
        proof: &BinaryRingProofTargets<E>,
    ) -> Result<(), VerificationError> {
        let absorbed = E::RAW_BITS.ilog2() as usize;
        let high = self.num_variables - absorbed;
        if proof.claims.len() != self.specs.len()
            || proof.sumcheck.len() != high
            || proof.claims.iter().zip(&self.specs).any(|(claim, spec)| {
                claim.point.len() != self.num_variables
                    || claim.current.is_some() != spec.current
                    || claim.next.is_some() != spec.next_rows.is_some()
                    || claim.successor.is_some()
                        != spec.next_rows.is_some_and(|rows| rows > absorbed)
            })
        {
            return Err(invalid(
                "binary ring-switch targets do not match the verifier shape",
            ));
        }
        Ok(())
    }

    /// Installs the complete ring-switch relation. Points, tensor elements and
    /// messages are absorbed exactly as native verification does. The maximal
    /// common Boolean prefix is derived from checked point bits; no proof advice
    /// controls a skipped round. All possible prefix transcript branches use
    /// fixed geometry, then merge under those derived one-hot selectors.
    pub fn verify<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: BinaryTower128Challenger,
        proof: &BinaryRingProofTargets<E>,
    ) -> Result<BinaryRingOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_impl::<BF, EF>(circuit, challenger, proof, false)
    }

    /// Resumes from a preceding bounded query phase through this ring-switch
    /// schedule's nonempty native seed, absorbing that seed exactly once.
    pub fn verify_after_queries<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        continuation: BinaryQueryContinuation,
        proof: &BinaryRingProofTargets<E>,
    ) -> Result<BinaryRingOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(proof)?;
        let bytes = seed_bytes(circuit, &self.seed);
        let challenger = continuation.resume_with_observation::<BF, EF>(circuit, &bytes)?;
        self.verify_impl::<BF, EF>(circuit, challenger, proof, true)
    }

    fn verify_impl<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        mut challenger: BinaryTower128Challenger,
        proof: &BinaryRingProofTargets<E>,
        seed_observed: bool,
    ) -> Result<BinaryRingOutput, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(proof)?;
        let absorbed = E::RAW_BITS.ilog2() as usize;
        let high = self.num_variables - absorbed;
        for value in proof
            .claims
            .iter()
            .flat_map(|claim| {
                claim
                    .point
                    .iter()
                    .chain(claim.current.iter())
                    .chain(claim.next.iter())
            })
            .chain(proof.sumcheck.iter().flatten())
            .chain(core::slice::from_ref(&proof.final_eval))
        {
            constrain_width(circuit, value, E::RAW_BITS);
        }
        if !seed_observed {
            observe_seed::<E, BF, EF>(circuit, &mut challenger, &self.seed)?;
        }
        for claim in &proof.claims {
            observe_values::<BF, EF>(circuit, &mut challenger, &claim.point, E::RAW_BITS)?;
            observe_values::<BF, EF>(circuit, &mut challenger, claim.tensor.rows(), E::RAW_BITS)?;
            if let Some((carry, last)) = &claim.successor {
                observe_values::<BF, EF>(circuit, &mut challenger, carry.rows(), E::RAW_BITS)?;
                observe_values::<BF, EF>(circuit, &mut challenger, last.rows(), E::RAW_BITS)?;
            }
        }
        let batch = (0..absorbed)
            .map(|_| sample::<E, BF, EF>(circuit, &mut challenger))
            .collect::<Result<Vec<_>, _>>()?;
        let alpha = self
            .specs
            .iter()
            .any(|s| s.next_rows.is_some_and(|rows| rows > absorbed))
            .then(|| sample::<E, BF, EF>(circuit, &mut challenger))
            .transpose()?;
        let lambda = if self.specs.len() > 1 {
            sample::<E, BF, EF>(circuit, &mut challenger)?
        } else {
            circuit.binary128_constant(1)?
        };
        let one = circuit.binary128_constant(1)?;
        let mut power = one.clone();
        let mut initial_sum = circuit.binary128_constant(0)?;
        for (claim, spec) in proof.claims.iter().zip(&self.specs) {
            let low = &claim.point[high..];
            let columns = claim.tensor.transpose(circuit)?;
            if let Some(current) = &claim.current {
                let reading = columns.evaluate_rows(circuit, low)?;
                assert_equal(circuit, current, &reading);
            }
            if let Some(next) = &claim.next {
                let reading = successor_reading::<E, EF>(
                    circuit,
                    &columns,
                    low,
                    spec.next_rows.expect("shape checked"),
                    claim.successor.as_ref(),
                )?;
                assert_equal(circuit, next, &reading);
            }
            let mut sum = claim.tensor.evaluate_rows(circuit, &batch)?;
            if let Some((carry, last)) = &claim.successor {
                let alpha = alpha.as_ref().expect("successor shapes draw alpha");
                let carry = carry.evaluate_rows(circuit, &batch)?;
                let last = last.evaluate_rows(circuit, &batch)?;
                let alpha_squared = circuit.binary128_square(alpha);
                let carry = circuit.binary128_mul(alpha, &carry);
                let last = circuit.binary128_mul(&alpha_squared, &last);
                sum = circuit.binary128_add(&sum, &carry);
                sum = circuit.binary128_add(&sum, &last);
            }
            let term = circuit.binary128_mul(&power, &sum);
            initial_sum = circuit.binary128_add(&initial_sum, &term);
            power = circuit.binary128_mul(&power, &lambda);
        }
        let selectors = common_prefix_selectors(circuit, &proof.claims, self.prefix_limit);
        for (r, message) in proof.sumcheck.iter().enumerate() {
            let inactive = selectors
                .iter()
                .enumerate()
                .filter(|(p, _)| *p >= high - r)
                .fold(ExprId::ZERO, |sum, (_, &selector)| {
                    circuit.add(sum, selector)
                });
            for &bit in message.iter().flat_map(|value| value.bits()) {
                let masked = circuit.mul(inactive, bit);
                let difference = circuit.sub(ExprId::ZERO, masked);
                circuit.assert_zero(difference);
            }
        }
        let mut branches = Vec::new();
        let mut branch_points = Vec::new();
        let mut branch_sums = Vec::new();
        for (prefix, &selector) in selectors.iter().enumerate() {
            let rounds = high - prefix;
            let mut branch = challenger.clone();
            if rounds > 0 {
                observe_seed::<E, BF, EF>(
                    circuit,
                    &mut branch,
                    &domain_separator_seed(
                        &SumcheckShape::new(rounds, 0, Basis::Evaluation)
                            .domain_separator::<E, E>(),
                    ),
                )?;
            }
            let mut sum = initial_sum.clone();
            let mut point = proof.claims[0].point[..prefix].to_vec();
            for message in &proof.sumcheck[..rounds] {
                observe_values::<BF, EF>(circuit, &mut branch, message, E::RAW_BITS)?;
                let beta = sample::<E, BF, EF>(circuit, &mut branch)?;
                sum = binary128_reduce_sumcheck_claim(
                    circuit,
                    &sum,
                    &message[0],
                    &message[1],
                    &beta,
                )?;
                point.push(beta);
            }
            observe_values::<BF, EF>(
                circuit,
                &mut branch,
                core::slice::from_ref(&proof.final_eval),
                E::RAW_BITS,
            )?;
            branches.push((selector, branch));
            branch_points.push(point);
            branch_sums.push(sum);
        }
        let point: Vec<_> = (0..high)
            .map(|i| {
                select_field(
                    circuit,
                    &selectors,
                    &branch_points
                        .iter()
                        .map(|point| &point[i])
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Result<_, _>>()?;
        let sum = select_field(circuit, &selectors, &branch_sums.iter().collect::<Vec<_>>())?;
        let challenger = BinaryTower128Challenger::select_same_shape(circuit, &branches)?;
        let mut closing = circuit.binary128_constant(0)?;
        power = one;
        for (claim, spec) in proof.claims.iter().zip(&self.specs) {
            let successor = spec.next_rows.filter(|&rows| rows > absorbed).map(|rows| {
                (
                    rows - absorbed,
                    alpha.as_ref().expect("successor shapes draw alpha"),
                )
            });
            let weight = binary_tensor_closing_weight::<E, EF>(
                circuit,
                &claim.point[..high],
                &point,
                &batch,
                successor,
            )?;
            let term = circuit.binary128_mul(&power, &weight);
            closing = circuit.binary128_add(&closing, &term);
            power = circuit.binary128_mul(&power, &lambda);
        }
        let expected = circuit.binary128_mul(&closing, &proof.final_eval);
        assert_equal(circuit, &sum, &expected);
        Ok(BinaryRingOutput {
            point,
            value: proof.final_eval.clone(),
            challenger,
        })
    }
}

fn sample<E, BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut BinaryTower128Challenger,
) -> Result<BinaryTower128Target, VerificationError>
where
    E: RecursiveBinaryChallengeField,
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let bytes = challenger.sample_bytes::<BF, EF>(circuit, E::RAW_BITS / 8)?;
    let mut bits = [ExprId::ZERO; 128];
    for (i, byte) in bytes.into_iter().enumerate() {
        bits[8 * i..8 * i + 8].copy_from_slice(&circuit.decompose_to_bits::<BF>(byte, 8)?);
    }
    Ok(circuit.binary128_from_bits(bits)?)
}

fn common_prefix_selectors<E, F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    claims: &[BinaryRingClaimTargets<E>],
    limit: usize,
) -> Vec<ExprId> {
    let one = circuit.define_const(F::ONE);
    let mut live = one;
    let mut selectors = Vec::new();
    for coordinate in 0..limit {
        let first = claims[0].point[coordinate].bits()[0];
        let mut conditions = Vec::new();
        for claim in claims {
            let bits = claim.point[coordinate].bits();
            conditions.extend(bits[1..].iter().map(|&bit| circuit.sub(one, bit)));
            let delta = circuit.sub(first, bits[0]);
            let different = circuit.mul(delta, delta);
            conditions.push(circuit.sub(one, different));
        }
        let agreement = circuit.mul_many(&conditions);
        let next = circuit.mul(live, agreement);
        selectors.push(circuit.sub(live, next));
        live = next;
    }
    selectors.push(live);
    selectors
}

fn select_field<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    selectors: &[ExprId],
    values: &[&BinaryTower128Target],
) -> Result<BinaryTower128Target, VerificationError> {
    let bits = core::array::from_fn(|bit| {
        selectors
            .iter()
            .zip(values)
            .fold(ExprId::ZERO, |sum, (&selector, value)| {
                circuit.mul_add(selector, value.bits()[bit], sum)
            })
    });
    Ok(circuit.binary128_from_bits(bits)?)
}

fn successor_reading<E: RecursiveBinaryChallengeField, F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    columns: &BinaryTowerTensorTarget<E>,
    low: &[BinaryTower128Target],
    rows: usize,
    extra: Option<&(BinaryTowerTensorTarget<E>, BinaryTowerTensorTarget<E>)>,
) -> Result<BinaryTower128Target, VerificationError> {
    let one = circuit.binary128_constant(1)?;
    let mut weights = vec![one.clone()];
    for coordinate in low {
        let not = circuit.binary128_add(&one, coordinate);
        weights = weights
            .iter()
            .flat_map(|weight| {
                [
                    circuit.binary128_mul(weight, &not),
                    circuit.binary128_mul(weight, coordinate),
                ]
            })
            .collect();
    }
    let mut reading = circuit.binary128_constant(0)?;
    for (v, column) in columns.rows().iter().enumerate() {
        let mut weight = circuit.binary128_constant(0)?;
        if extra.is_some() {
            if v > 0 {
                weight = weights[v - 1].clone();
            }
        } else {
            let last = (1usize << rows) - 1;
            if v & last != 0 {
                weight = weights[v - 1].clone();
            }
            if v & last == last {
                weight = circuit.binary128_add(&weight, &weights[v]);
            }
        }
        let term = circuit.binary128_mul(column, &weight);
        reading = circuit.binary128_add(&reading, &term);
    }
    if let Some((carry, last)) = extra {
        let carry = carry.transpose(circuit)?;
        let last = last.transpose(circuit)?;
        let ripple = circuit.binary128_add(&carry.rows()[0], &last.rows()[E::RAW_BITS - 1]);
        let edge = circuit.binary128_mul(&weights[E::RAW_BITS - 1], &ripple);
        reading = circuit.binary128_add(&reading, &edge);
    }
    Ok(reading)
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
