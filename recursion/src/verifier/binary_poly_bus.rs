//! Bus transcript and terminal composition for trusted binary AIR programs.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_bus::{BusDirection, BusPlan, BusProof, BusTupleSlot};
use p3_challenger::FieldChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::BinaryPoly192Target;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_field::Field;

use super::binary_air::BinaryAirEvaluation;
use super::binary_field_policy::{
    BinaryPolyPolicy, BinaryProtocolPolicy, poly_observe_seed_with_host,
};
use super::{
    BinaryPolyAirConstraintPlan, BinaryPolyProductGkrInputShape, BinaryPolyProductGkrProofTargets,
    BinaryPolyProductGkrVerifier, InputResourceUsage, NativeBinaryPolyProductGkrInput,
    VerificationError, VerifierLimits,
};
use crate::BinaryTower128Challenger;
use crate::transcript::SeedTap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BinaryPolyBusInputShape {
    pub product: BinaryPolyProductGkrInputShape,
    seed: Vec<Poly64>,
    plan: BusPlan,
}

pub(super) struct BinaryPolyBusClaims<T = BinaryPoly192Target> {
    pub point: Vec<T>,
    pub values: Vec<T>,
    weights: Vec<T>,
    offset: T,
}

#[derive(Clone, Debug)]
pub(super) struct BinaryPolyBusVerifier {
    input: BinaryPolyBusInputShape,
    product: BinaryPolyProductGkrVerifier,
    degree: usize,
    usage: InputResourceUsage,
}

impl BinaryPolyBusVerifier {
    pub fn with_limits(
        plan: BusPlan,
        airs: &[BinaryPolyAirConstraintPlan],
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let geometry = plan.product_shape();
        let product = BinaryPolyProductGkrVerifier::with_embedded_bus_limits(
            geometry.log_height(),
            geometry.num_trees(),
            geometry.root_shape(),
            limits,
        )?;
        let mut usage = product.input_resource_usage();
        usage.check_matrix_width(limits, plan.fingerprint_width())?;
        usage.add_metadata_entries(limits, plan.fingerprint_width())?;
        let mut degree = 1;
        for domain in plan.domains() {
            usage.add_metadata_entries(limits, 3)?;
            usage.add_metadata_string_bytes(limits, domain.name.len())?;
        }
        for direction in BusDirection::ALL {
            for block in plan.blocks(direction) {
                usage.add_metadata_entries(limits, 6)?;
                let air = airs
                    .get(block.owner.air)
                    .ok_or_else(|| invalid("binary bus AIR owner mismatch"))?;
                let declaration = air
                    .bus_declarations()
                    .get(block.owner.declaration)
                    .ok_or_else(|| invalid("binary bus declaration owner mismatch"))?;
                if block.log_height != air.log_height()
                    || declaration.direction != direction
                    || plan.domains()[block.bus].name != declaration.name
                {
                    return Err(invalid("binary bus compiled declaration mismatch"));
                }
                degree = degree.max(declaration.factor_degree.checked_add(1).ok_or(
                    VerificationError::ResourceArithmeticOverflow {
                        component: "binary bus composition degree",
                    },
                )?);
            }
        }
        usage.check_log_degree(limits, degree)?;
        let mut tap = SeedTap::<Poly64>::new();
        let _ = plan
            .verify::<Poly64, Poly192, _>(
                &BusProof {
                    product: product.zero_native_proof(),
                },
                &mut tap,
            )
            .map_err(|_| invalid("binary bus seed capture failed"))?;
        let seed = tap.binary_seed();
        usage.add_metadata_entries(limits, seed.len())?;
        Ok(Self {
            input: BinaryPolyBusInputShape {
                product: product.input_shape(),
                seed,
                plan,
            },
            product,
            degree,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryPolyBusInputShape {
        self.input.clone()
    }
    pub fn degree(&self) -> usize {
        self.degree
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }
    pub fn check_targets<T>(
        &self,
        proof: &BinaryPolyProductGkrProofTargets<T>,
    ) -> Result<(), VerificationError> {
        self.product.check_targets(proof)
    }
    pub fn check_native(&self, proof: &BusProof<Poly192>) -> Result<(), VerificationError> {
        self.product.check_native(&proof.product)
    }

    pub(super) fn verify_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        proof: &BinaryPolyProductGkrProofTargets<P::ChallengeTarget>,
    ) -> Result<
        (
            BinaryPolyBusClaims<P::ChallengeTarget>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    >
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryPolyPolicy<CF> + BinaryProtocolPolicy<CF>,
    {
        self.check_targets(proof)?;
        poly_observe_seed_with_host::<H, CF>(b, &mut ch, &self.input.seed)?;
        let fingerprint = (0..self.input.plan.security_geometry().tuple_variables())
            .map(|_| P::sample::<H>(b, &mut ch))
            .collect::<Result<Vec<_>, _>>()?;
        let offset = P::sample::<H>(b, &mut ch)?;
        let output = self.product.verify_using::<P, H, CF>(b, ch, proof)?;
        let one = P::constant(b, 1)?;
        let mut weights = alloc::vec![one.clone()];
        for r in &fingerprint {
            let complement = P::add(b, &one, r);
            let mut next = Vec::with_capacity(weights.len() * 2);
            for weight in weights {
                next.push(P::mul(b, &weight, &complement));
                next.push(P::mul(b, &weight, r));
                b.check_construction_limits()?;
            }
            weights = next;
        }
        Ok((
            BinaryPolyBusClaims {
                point: output.point,
                values: output.values,
                weights,
                offset,
            },
            output.challenger,
        ))
    }

    /// Adds the shifted, eq-weighted bus factors at the authenticated AIR
    /// sumcheck point. Product padding vanishes only after subtracting one.
    pub(super) fn terminal_using<P, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        claims: &BinaryPolyBusClaims<P::ChallengeTarget>,
        evaluations: &[BinaryAirEvaluation<P::ChallengeTarget>],
        point: &[P::ChallengeTarget],
        lambda: &P::ChallengeTarget,
    ) -> Result<P::ChallengeTarget, VerificationError>
    where
        CF: Field + Eq + Hash,
        P: BinaryPolyPolicy<CF> + BinaryProtocolPolicy<CF>,
    {
        if claims.point.len() != self.input.plan.product_shape().log_height()
            || claims.weights.len() != self.input.plan.fingerprint_width()
            || claims.values.len() != 2
        {
            return Err(invalid("binary bus terminal geometry mismatch"));
        }
        let one = P::constant(b, 1)?;
        let mut terminal = P::constant(b, 0)?;
        for direction in BusDirection::ALL {
            for share in self.input.plan.terminal_shares(direction) {
                let evaluation = evaluations
                    .get(share.owner.air)
                    .ok_or_else(|| invalid("binary bus terminal AIR mismatch"))?;
                let fields = evaluation
                    .bus_fields
                    .get(share.owner.declaration)
                    .ok_or_else(|| invalid("binary bus terminal fields mismatch"))?;
                let activation = evaluation
                    .bus_activations
                    .get(share.owner.declaration)
                    .ok_or_else(|| invalid("binary bus terminal activation mismatch"))?;
                if point.len() < share.row_variables
                    || share.prefix_variables + share.row_variables != claims.point.len()
                {
                    return Err(invalid("binary bus terminal point mismatch"));
                }
                let mut live = claims.offset.clone();
                for (slot, weight) in claims.weights.iter().enumerate() {
                    let term = match self
                        .input
                        .plan
                        .tuple_slot(share.bus, slot)
                        .ok_or_else(|| invalid("binary bus tuple slot mismatch"))?
                    {
                        BusTupleSlot::Payload(i) => P::mul(
                            b,
                            fields
                                .get(i)
                                .ok_or_else(|| invalid("binary bus payload width mismatch"))?,
                            weight,
                        ),
                        BusTupleSlot::DomainBit(true) => weight.clone(),
                        BusTupleSlot::DomainBit(false) | BusTupleSlot::Zero => continue,
                    };
                    live = P::add(b, &live, &term);
                    b.check_construction_limits()?;
                }
                let mut shifted = P::add(b, &live, &one);
                if let Some(activation) = activation {
                    shifted = P::mul(b, activation, &shifted);
                }
                let mut weight = one.clone();
                for (bit, r) in claims.point[..share.prefix_variables].iter().enumerate() {
                    let selector =
                        if share.prefix_index >> (share.prefix_variables - 1 - bit) & 1 == 1 {
                            r.clone()
                        } else {
                            P::add(b, &one, r)
                        };
                    weight = P::mul(b, &weight, &selector);
                }
                let unused = point.len() - share.row_variables;
                for r in &point[..unused] {
                    weight = P::mul(b, &weight, r);
                }
                let equality =
                    P::eq_eval(b, &claims.point[share.prefix_variables..], &point[unused..])?;
                weight = P::mul(b, &weight, &equality);
                if direction == BusDirection::Pull {
                    weight = P::mul(b, &weight, lambda);
                }
                let term = P::mul(b, &weight, &shifted);
                terminal = P::add(b, &terminal, &term);
                b.check_construction_limits()?;
            }
        }
        Ok(terminal)
    }

    /// Returns only witness data and internally consistent unauthenticated
    /// leaf values. The surrounding verifier closes the AIR/PCS relation.
    pub fn import_native<Ch>(
        &self,
        proof: &BusProof<Poly192>,
        ch: &mut Ch,
    ) -> Result<(NativeBinaryPolyProductGkrInput, Vec<Poly192>), VerificationError>
    where
        Ch: FieldChallenger<Poly64> + Clone,
    {
        self.check_native(proof)?;
        let mut staged = ch.clone();
        staged.observe_slice(&self.input.seed);
        for _ in 0..self.input.plan.security_geometry().tuple_variables() {
            let _ = staged.sample_algebra_element::<Poly192>();
        }
        let _ = staged.sample_algebra_element::<Poly192>();
        let (input, output) = self
            .product
            .import_native_with_reduction(&proof.product, &mut staged)?;
        *ch = staged;
        Ok((input, output.values))
    }
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
