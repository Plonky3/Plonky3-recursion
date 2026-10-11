//! The mixed relation in the native Poly64 carrier.
//!
//! The transcript is the Tower128 mixed verifier's: relation prefix, dense binding, packed
//! binding, relation reduction, dense opening, packed opening, preprocessing opening, relation
//! closing. The packed opening runs the native column batch, Poly64 bit ring switch and packed
//! WHIR opening of its one table; every other part is the native dense Poly64 verifier's.

use alloc::vec::Vec;

use p3_binary_field::Poly64;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::bytes_to_limbs;
use p3_circuit::{CircuitBuilder, ExprId};

use super::super::super::binary_field_policy::NativePoly64Relation;
use super::super::relation::PolyRelationProof;
use super::{
    BinaryPolyMixedWhirMultiStarkInputShape, BinaryPolyMixedWhirMultiStarkProofTargets,
    BinaryPolyMixedWhirMultiStarkVerifier, NativeBinaryPolyMixedWhirMultiStarkInput, invalid,
};
use crate::BinaryTower128Challenger;
use crate::verifier::VerificationError;

impl BinaryPolyMixedWhirMultiStarkInputShape {
    /// Native Poly64 inputs: sixteen limbs per cap root, the bus, the AIR sumcheck, the dense
    /// opening, the packed opening and the preprocessing opening, in that order.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<Poly64>,
    ) -> Result<BinaryPolyMixedWhirMultiStarkProofTargets, VerificationError> {
        let commitment = (0..2 * self.cap_roots)
            .map(|_| {
                let digest = b
                    .alloc_private_input_array::<16>(
                        "native polynomial mixed WHIR MultiStark commitment",
                    )
                    .to_vec();
                b.check_construction_limits()?;
                Ok(digest)
            })
            .collect::<Result<_, VerificationError>>()?;
        let bus = self
            .relation
            .bus
            .as_ref()
            .map(|bus| bus.product.allocate_native_targets(b))
            .transpose()?;
        let sumcheck = self.relation.sumcheck.allocate_native_targets(b)?;
        let dense = self.dense.allocate_native_targets(b)?;
        let packed = self.packed.allocate_native_targets(b)?;
        let preprocessed_opening = self
            .preprocessed
            .as_ref()
            .map(|pp| pp.opening.allocate_native_targets(b))
            .transpose()?;
        Ok(BinaryPolyMixedWhirMultiStarkProofTargets {
            commitment,
            bus,
            sumcheck,
            dense,
            packed,
            preprocessed_opening,
        })
    }
}

impl NativeBinaryPolyMixedWhirMultiStarkInput {
    /// Raw native cells, in the order of
    /// [`BinaryPolyMixedWhirMultiStarkInputShape::allocate_native_targets`].
    pub fn private_native_values(
        &self,
        expected: &BinaryPolyMixedWhirMultiStarkInputShape,
    ) -> Result<Vec<Poly64>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "polynomial mixed WHIR MultiStark input belongs to another verifier",
            ));
        }
        let mut values: Vec<Poly64> = self
            .commitment
            .iter()
            .flat_map(|root| {
                bytes_to_limbs(root)
                    .into_iter()
                    .map(NativeBinaryEncoding::encode_u16)
            })
            .collect::<Result<_, _>>()?;
        match (&expected.relation.bus, &self.bus) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_native_values(&shape.product)?);
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "polynomial mixed WHIR MultiStark bus input shape mismatch",
                ));
            }
        }
        values.extend(
            self.sumcheck
                .private_native_values(&expected.relation.sumcheck)?,
        );
        values.extend(self.dense.private_native_values(&expected.dense)?);
        values.extend(self.packed.private_native_values(&expected.packed)?);
        match (&expected.preprocessed, &self.preprocessed_opening) {
            (Some(shape), Some(input)) => {
                values.extend(input.private_native_values(&shape.opening)?);
            }
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "polynomial mixed WHIR MultiStark preprocessing input shape mismatch",
                ));
            }
        }
        Ok(values)
    }
}

impl BinaryPolyMixedWhirMultiStarkVerifier {
    /// The native carrier verifies hashes with native circuits, and the packed table on the
    /// column-batched route only.
    pub(crate) fn check_native_circuit_support(&self) -> Result<(), VerificationError> {
        self.dense.check_host::<NativeBinaryEncoding, Poly64>()?;
        self.packed.check_native_circuit_support()?;
        if let Some(pp) = &self.preprocessed {
            pp.check_host::<NativeBinaryEncoding, Poly64>()?;
        }
        Ok(())
    }

    /// Checks all AIR obligations and authenticates both openings of the main commitment and
    /// the preprocessing opening. Public targets are the caller's actual statement, one Poly64
    /// cell per value, in instance order. Returns the exact ordinary challenger after the last
    /// opening.
    pub fn verify_native(
        &self,
        b: &mut CircuitBuilder<Poly64>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<ExprId>],
        proof: &BinaryPolyMixedWhirMultiStarkProofTargets,
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        self.check_native_circuit_support()?;
        let common = PolyRelationProof {
            bus: proof.bus.as_ref(),
            sumcheck: &proof.sumcheck,
            indexed: None,
        };
        self.relation.check_targets(public, &common)?;
        let (dense_cap, packed_cap) = self.split.split_cap(&proof.commitment)?;
        let zero = b.native_poly192_constant([0; 3]);
        let (dense_points, packed_points) = self
            .split
            .split(&self.relation.zero_points(false, zero.clone()))?;
        self.dense
            .check_targets(dense_cap, &dense_points, &proof.dense)?;
        self.packed
            .check_native_targets(b, packed_cap, &packed_points, &proof.packed)?;
        let preprocessed_cap = match (
            &self.preprocessed,
            &self.input.preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some(proof)) => {
                let cap = shape.constant_cap::<NativeBinaryEncoding, Poly64>(b)?;
                let points = self.relation.zero_points(true, zero);
                verifier.check_targets(&cap, &points, proof)?;
                Some(cap)
            }
            (None, None, None) => None,
            _ => {
                return Err(invalid(
                    "polynomial mixed WHIR MultiStark preprocessed opening shape mismatch",
                ));
            }
        };
        self.relation
            .observe_prefix_with_host::<NativeBinaryEncoding, Poly64>(
                b,
                &mut ch,
                preprocessed_cap.as_deref(),
            )?;
        self.dense
            .observe_commitment_with_host::<NativeBinaryEncoding, Poly64>(b, &mut ch, dense_cap)?;
        self.packed
            .observe_commitment_native(b, &mut ch, packed_cap)?;
        let mut reduction = self
            .relation
            .reduce_common::<NativePoly64Relation, NativeBinaryEncoding, Poly64>(
                b, ch, public, &common,
            )?;
        self.relation.set_unindexed_points(&mut reduction);
        let (dense_points, packed_points) = self.split.split(&reduction.main_points)?;
        let (dense_evals, ch) = self.dense.verify_at_native(
            b,
            reduction.challenger.clone(),
            dense_cap,
            &dense_points,
            &proof.dense,
        )?;
        let (packed_evals, mut continuation) =
            self.packed
                .verify_at_native(b, ch, packed_cap, &packed_points, &proof.packed)?;
        let main_evals = self.split.merge(dense_evals, packed_evals)?;
        let mut preprocessed_evals = None;
        if let (Some(verifier), Some(cap), Some(proof)) = (
            &self.preprocessed,
            &preprocessed_cap,
            &proof.preprocessed_opening,
        ) {
            let (evals, next) = verifier.verify_at_native(
                b,
                continuation,
                cap,
                reduction
                    .preprocessed_points
                    .as_ref()
                    .expect("checked preprocessing points"),
                proof,
            )?;
            preprocessed_evals = Some(evals);
            continuation = next;
        }
        self.relation
            .finish_common::<NativePoly64Relation, Poly64>(
                b,
                public,
                &reduction,
                &main_evals,
                preprocessed_evals.as_deref(),
            )?;
        Ok(continuation)
    }
}
