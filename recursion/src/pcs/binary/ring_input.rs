//! Proof-independent ring-switch allocation and checked native witness import.

use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::BinaryTower128Target;
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_multilinear_util::point::Point;
use p3_sumcheck::ring_switch::bits::{
    BitRingSwitch, BitRingSwitchClaims, BitRingSwitchClaimsProof,
};

use super::{
    BinaryBitRingVerifier, BinaryRingClaimSpec, BinaryRingClaimTargets, BinaryRingProofTargets,
    BinaryTowerTensorTarget, RecursiveBinaryChallengeField,
};
use crate::verifier::VerificationError;

/// Shape captured solely from a resource-checked verifier. In particular, it
/// does not record any point's Boolean prefix or native sumcheck round count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryRingInputShape<E> {
    num_variables: usize,
    specs: Vec<BinaryRingClaimSpec>,
    field: PhantomData<E>,
}

impl<E: RecursiveBinaryChallengeField> BinaryRingInputShape<E> {
    pub fn allocate_targets<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryRingProofTargets<E>, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let absorbed = E::RAW_BITS.ilog2() as usize;
        let claims = self
            .specs
            .iter()
            .map(|spec| {
                let point = (0..self.num_variables)
                    .map(|_| alloc_field::<BF, EF>(circuit))
                    .collect::<Result<_, _>>()?;
                let current = spec
                    .current
                    .then(|| alloc_field::<BF, EF>(circuit))
                    .transpose()?;
                let next = spec
                    .next_rows
                    .map(|_| alloc_field::<BF, EF>(circuit))
                    .transpose()?;
                let tensor = alloc_tensor::<E, BF, EF>(circuit)?;
                let successor = spec
                    .next_rows
                    .filter(|&rows| rows > absorbed)
                    .map(|_| {
                        Ok::<_, VerificationError>((
                            alloc_tensor::<E, BF, EF>(circuit)?,
                            alloc_tensor::<E, BF, EF>(circuit)?,
                        ))
                    })
                    .transpose()?;
                Ok(BinaryRingClaimTargets {
                    point,
                    current,
                    next,
                    tensor,
                    successor,
                })
            })
            .collect::<Result<_, VerificationError>>()?;
        let sumcheck = (0..self.num_variables - absorbed)
            .map(|_| {
                Ok([
                    alloc_field::<BF, EF>(circuit)?,
                    alloc_field::<BF, EF>(circuit)?,
                ])
            })
            .collect::<Result<_, VerificationError>>()?;
        let final_eval = alloc_field::<BF, EF>(circuit)?;
        Ok(BinaryRingProofTargets {
            claims,
            sumcheck,
            final_eval,
        })
    }
}

/// Checked native witness data. Neither this value nor its native replay is a
/// verification authority: the recursive ring and packed PCS checks are required.
#[derive(Clone, Debug)]
pub struct NativeBinaryRingInput<E> {
    shape: BinaryRingInputShape<E>,
    fields: Vec<u128>,
}

impl<E: RecursiveBinaryChallengeField> NativeBinaryRingInput<E> {
    pub fn shape(&self) -> &BinaryRingInputShape<E> {
        &self.shape
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryRingInputShape<E>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary ring-switch input belongs to a different verifier",
            ));
        }
        Ok(self
            .fields
            .iter()
            .flat_map(|&raw| (0..8).map(move |i| EF::from_u16((raw >> (16 * i)) as u16)))
            .collect())
    }
}

impl<E: RecursiveBinaryChallengeField> BinaryBitRingVerifier<E> {
    pub(super) fn check_native_structure(
        &self,
        proof: &BitRingSwitchClaimsProof<E>,
    ) -> Result<(), VerificationError> {
        let absorbed = E::RAW_BITS.ilog2() as usize;
        if proof.claims.len() != self.specs.len()
            || !proof.sumcheck.pow_witnesses.is_empty()
            || proof.sumcheck.polynomial_evaluations.len() > self.num_variables - absorbed
            || proof.claims.iter().zip(&self.specs).any(|(claim, spec)| {
                !claim.tensor.is_well_formed()
                    || claim.successor.is_some()
                        != spec.next_rows.is_some_and(|rows| rows > absorbed)
                    || claim
                        .successor
                        .as_ref()
                        .is_some_and(|s| !s.carry.is_well_formed() || !s.last.is_well_formed())
            })
        {
            return Err(invalid("binary ring-switch native structural mismatch"));
        }
        Ok(())
    }

    /// Performs pure shape inspection, without a proof or transcript replay.
    pub fn input_shape(&self) -> BinaryRingInputShape<E> {
        BinaryRingInputShape {
            num_variables: self.num_variables,
            specs: self.specs.clone(),
            field: PhantomData,
        }
    }

    /// Checks native structure and readings, then replays the finite ring
    /// transcript. Returns the exact native continuation for importing the
    /// packed opening. Unused maximum-round slots are canonically zero-padded.
    pub fn import_native<Ch>(
        &self,
        points: &[Point<E>],
        readings: &[(Option<E>, Option<E>)],
        proof: &BitRingSwitchClaimsProof<E>,
        mut challenger: Ch,
    ) -> Result<(NativeBinaryRingInput<E>, Point<E>, Ch), VerificationError>
    where
        Ch: FieldChallenger<E> + GrindingChallenger<Witness = E>,
    {
        self.check_native_structure(proof)?;
        let absorbed = E::RAW_BITS.ilog2() as usize;
        let high = self.num_variables - absorbed;
        if points.len() != self.specs.len()
            || readings.len() != self.specs.len()
            || proof.claims.len() != self.specs.len()
            || !proof.sumcheck.pow_witnesses.is_empty()
        {
            return Err(invalid("binary ring-switch native proof count mismatch"));
        }
        let mut limit = high;
        for (((point, reading), claim), spec) in points
            .iter()
            .zip(readings)
            .zip(&proof.claims)
            .zip(&self.specs)
        {
            if point.num_variables() != self.num_variables
                || reading.0.is_some() != spec.current
                || reading.1.is_some() != spec.next_rows.is_some()
                || !claim.tensor.is_well_formed()
                || claim.successor.is_some() != spec.next_rows.is_some_and(|rows| rows > absorbed)
                || claim
                    .successor
                    .as_ref()
                    .is_some_and(|s| !s.carry.is_well_formed() || !s.last.is_well_formed())
            {
                return Err(invalid("binary ring-switch native claim shape mismatch"));
            }
            if let Some(rows) = spec.next_rows {
                limit = limit.min(self.num_variables - rows);
            }
        }
        let prefix = (0..limit)
            .take_while(|&j| {
                let first = points[0].as_slice()[j];
                (first == E::ZERO || first == E::ONE)
                    && points.iter().all(|p| p.as_slice()[j] == first)
            })
            .count();
        if proof.sumcheck.polynomial_evaluations.len() != high - prefix {
            return Err(invalid("binary ring-switch native round count mismatch"));
        }
        let reductions = points
            .iter()
            .zip(&self.specs)
            .map(|(point, spec)| {
                spec.next_rows
                    .map_or_else(
                        || BitRingSwitch::new(point),
                        |rows| BitRingSwitch::with_successor(point, rows),
                    )
                    .map_err(|_| invalid("binary ring-switch native setup failed"))
            })
            .collect::<Result<_, _>>()?;
        let setup = BitRingSwitchClaims::new(reductions)
            .map_err(|_| invalid("binary ring-switch native batch setup failed"))?;
        let (point, _) = setup
            .verify_readings(proof, readings, &mut challenger)
            .map_err(|_| invalid("binary ring-switch native replay failed"))?;
        let mut fields = Vec::new();
        for ((point, reading), claim) in points.iter().zip(readings).zip(&proof.claims) {
            fields.extend(point.as_slice().iter().copied().map(E::raw_coordinates));
            fields.extend(
                reading
                    .0
                    .into_iter()
                    .chain(reading.1)
                    .map(E::raw_coordinates),
            );
            fields.extend(claim.tensor.rows().iter().copied().map(E::raw_coordinates));
            if let Some(extra) = &claim.successor {
                fields.extend(
                    extra
                        .carry
                        .rows()
                        .iter()
                        .chain(extra.last.rows())
                        .copied()
                        .map(E::raw_coordinates),
                );
            }
        }
        fields.extend(
            proof
                .sumcheck
                .polynomial_evaluations
                .iter()
                .flatten()
                .copied()
                .map(E::raw_coordinates),
        );
        fields.resize(fields.len() + 2 * prefix, 0);
        fields.push(proof.final_eval.raw_coordinates());
        Ok((
            NativeBinaryRingInput {
                shape: self.input_shape(),
                fields,
            },
            point,
            challenger,
        ))
    }
}

fn alloc_field<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
) -> Result<BinaryTower128Target, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let limbs = circuit.alloc_private_input_array::<8>("binary ring-switch field");
    Ok(circuit.binary128_from_limbs::<BF>(limbs)?)
}

fn alloc_tensor<E, BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
) -> Result<BinaryTowerTensorTarget<E>, VerificationError>
where
    E: RecursiveBinaryChallengeField,
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let rows = (0..E::RAW_BITS)
        .map(|_| alloc_field::<BF, EF>(circuit))
        .collect::<Result<_, _>>()?;
    Ok(BinaryTowerTensorTarget::from_rows(circuit, rows)?)
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
