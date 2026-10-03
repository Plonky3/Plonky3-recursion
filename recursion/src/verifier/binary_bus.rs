//! Bus transcript and terminal composition for trusted binary AIR programs.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_bus::{BusDirection, BusPlan, BusProof, BusTupleSlot};
use p3_challenger::FieldChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::BinaryTower128Target;
use p3_field::{ExtensionField, Field, PrimeField64};

use super::binary_air::BinaryAirEvaluation;
use super::binary_product::sample;
use super::{
    BinaryAirConstraintPlan, BinaryProductGkrInputShape, BinaryProductGkrProofTargets,
    BinaryProductGkrVerifier, InputResourceUsage, NativeBinaryProductGkrInput, VerificationError,
    VerifierLimits,
};
use crate::BinaryTower128Challenger;
use crate::pcs::binary::{
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField, binary128_eq_eval, observe_seed,
};
use crate::transcript::SeedTap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BinaryBusInputShape<F, E> {
    pub product: BinaryProductGkrInputShape<F, E>,
    seed: Vec<F>,
    plan: BusPlan,
}

pub(super) struct BinaryBusClaims {
    pub point: Vec<BinaryTower128Target>,
    pub values: Vec<BinaryTower128Target>,
    weights: Vec<BinaryTower128Target>,
    offset: BinaryTower128Target,
}

#[derive(Clone, Debug)]
pub(super) struct BinaryBusVerifier<F, E> {
    input: BinaryBusInputShape<F, E>,
    product: BinaryProductGkrVerifier<F, E>,
    degree: usize,
    usage: InputResourceUsage,
}

impl<F, E> BinaryBusVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    pub fn with_limits(
        plan: BusPlan,
        airs: &[BinaryAirConstraintPlan<F, E>],
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let geometry = plan.product_shape();
        let product = BinaryProductGkrVerifier::<F, E>::with_limits(
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
        let mut tap = SeedTap::<F>::new();
        let _ = plan
            .verify::<F, E, _>(
                &BusProof {
                    product: product.zero_native_proof(),
                },
                &mut tap,
            )
            .map_err(|_| invalid("binary bus seed capture failed"))?;
        let seed = tap.binary_seed();
        usage.add_metadata_entries(limits, seed.len())?;
        Ok(Self {
            input: BinaryBusInputShape {
                product: product.input_shape(),
                seed,
                plan,
            },
            product,
            degree,
            usage,
        })
    }

    pub fn input_shape(&self) -> BinaryBusInputShape<F, E> {
        self.input.clone()
    }
    pub fn degree(&self) -> usize {
        self.degree
    }
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }
    pub fn check_targets(
        &self,
        proof: &BinaryProductGkrProofTargets,
    ) -> Result<(), VerificationError> {
        self.product.check_targets(proof)
    }
    pub fn check_native(&self, proof: &BusProof<E>) -> Result<(), VerificationError> {
        self.product.check_native(&proof.product)
    }

    pub fn verify<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
        proof: &BinaryProductGkrProofTargets,
    ) -> Result<(BinaryBusClaims, BinaryTower128Challenger), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(proof)?;
        observe_seed::<F, BF, EF>(b, &mut ch, &self.input.seed)?;
        let fingerprint = (0..self.input.plan.security_geometry().tuple_variables())
            .map(|_| sample::<E, BF, EF>(b, &mut ch))
            .collect::<Result<Vec<_>, _>>()?;
        let offset = sample::<E, BF, EF>(b, &mut ch)?;
        let output = self.product.verify_reduction::<BF, EF>(b, ch, proof)?;
        let one = b.binary128_constant(1)?;
        let mut weights = alloc::vec![one.clone()];
        for r in &fingerprint {
            let complement = b.binary128_add(&one, r);
            let mut next = Vec::with_capacity(weights.len() * 2);
            for weight in weights {
                next.push(b.binary128_mul(&weight, &complement));
                next.push(b.binary128_mul(&weight, r));
            }
            weights = next;
        }
        Ok((
            BinaryBusClaims {
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
    pub fn terminal<EF: Field + Eq + Hash>(
        &self,
        b: &mut CircuitBuilder<EF>,
        claims: &BinaryBusClaims,
        evaluations: &[BinaryAirEvaluation],
        point: &[BinaryTower128Target],
        lambda: &BinaryTower128Target,
    ) -> Result<BinaryTower128Target, VerificationError> {
        if claims.point.len() != self.input.plan.product_shape().log_height()
            || claims.weights.len() != self.input.plan.fingerprint_width()
            || claims.values.len() != 2
        {
            return Err(invalid("binary bus terminal geometry mismatch"));
        }
        let one = b.binary128_constant(1)?;
        let mut terminal = b.binary128_constant(0)?;
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
                        BusTupleSlot::Payload(i) => b.binary128_mul(
                            fields
                                .get(i)
                                .ok_or_else(|| invalid("binary bus payload width mismatch"))?,
                            weight,
                        ),
                        BusTupleSlot::DomainBit(true) => weight.clone(),
                        BusTupleSlot::DomainBit(false) | BusTupleSlot::Zero => continue,
                    };
                    live = b.binary128_add(&live, &term);
                }
                let mut shifted = b.binary128_add(&live, &one);
                if let Some(activation) = activation {
                    shifted = b.binary128_mul(activation, &shifted);
                }
                let mut weight = one.clone();
                for (bit, r) in claims.point[..share.prefix_variables].iter().enumerate() {
                    let selector =
                        if share.prefix_index >> (share.prefix_variables - 1 - bit) & 1 == 1 {
                            r.clone()
                        } else {
                            b.binary128_add(&one, r)
                        };
                    weight = b.binary128_mul(&weight, &selector);
                }
                let unused = point.len() - share.row_variables;
                for r in &point[..unused] {
                    weight = b.binary128_mul(&weight, r);
                }
                let equality = binary128_eq_eval(
                    b,
                    &claims.point[share.prefix_variables..],
                    &point[unused..],
                )?;
                weight = b.binary128_mul(&weight, &equality);
                if direction == BusDirection::Pull {
                    weight = b.binary128_mul(&weight, lambda);
                }
                let term = b.binary128_mul(&weight, &shifted);
                terminal = b.binary128_add(&terminal, &term);
            }
        }
        Ok(terminal)
    }

    /// Returns only witness data and internally consistent unauthenticated
    /// leaf values. The surrounding verifier closes the AIR/PCS relation.
    pub fn import_native<Ch>(
        &self,
        proof: &BusProof<E>,
        ch: &mut Ch,
    ) -> Result<(NativeBinaryProductGkrInput<F, E>, Vec<E>), VerificationError>
    where
        Ch: FieldChallenger<F> + Clone,
    {
        self.check_native(proof)?;
        let mut staged = ch.clone();
        staged.observe_slice(&self.input.seed);
        for _ in 0..self.input.plan.security_geometry().tuple_variables() {
            let _ = staged.sample_algebra_element::<E>();
        }
        let _ = staged.sample_algebra_element::<E>();
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
