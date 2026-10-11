//! The mixed relation in the native Tower128 carrier.
//!
//! The transcript is the prime-field verifier's: relation prefix, dense binding, packed
//! binding, relation reduction, dense opening, packed opening, preprocessing opening, relation
//! closing. The packed opening runs the native column batch, bit ring switch and packed WHIR
//! opening of its one table; every other part is the native dense verifier's.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{NativeTower128Target, bytes_to_limbs};

use super::{
    BinaryMixedWhirMultiStarkInputShape, BinaryMixedWhirMultiStarkProofTargets,
    BinaryMixedWhirMultiStarkVerifier, F, NativeBinaryMixedWhirMultiStarkInput, invalid,
};
use crate::BinaryTower128Challenger;
use crate::pcs::binary::NativeBooleanWhirTraceProofTargets;
use crate::verifier::VerificationError;
use crate::verifier::binary_field_policy::NativeTower128Relation;
use crate::verifier::binary_multi_stark::relation::BinaryRelationProof;

fn indexed_unsupported() -> VerificationError {
    invalid("native mixed WHIR verifier does not support indexed relations")
}

impl BinaryMixedWhirMultiStarkInputShape {
    /// One scalar input per field, in the order of [`Self::allocate_targets`]. Indexed plans
    /// require a different native reduction and are refused before allocation.
    pub fn allocate_native_targets(
        &self,
        b: &mut CircuitBuilder<F>,
    ) -> Result<
        BinaryMixedWhirMultiStarkProofTargets<
            NativeTower128Target,
            NativeBooleanWhirTraceProofTargets,
        >,
        VerificationError,
    > {
        if self.relation.indexed.is_some() {
            return Err(indexed_unsupported());
        }
        let commitment = (0..2usize << self.cap_height)
            .map(|_| {
                let digest = b
                    .alloc_private_input_array::<16>("native mixed WHIR MultiStark commitment")
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
        Ok(BinaryMixedWhirMultiStarkProofTargets {
            commitment,
            bus,
            sumcheck,
            indexed: None,
            dense,
            packed,
            preprocessed_opening,
        })
    }
}

impl NativeBinaryMixedWhirMultiStarkInput {
    /// Raw native scalars, in the order of
    /// [`BinaryMixedWhirMultiStarkInputShape::allocate_native_targets`].
    pub fn private_native_values(
        &self,
        expected: &BinaryMixedWhirMultiStarkInputShape,
    ) -> Result<Vec<F>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary mixed WHIR MultiStark input belongs to another verifier",
            ));
        }
        if expected.relation.indexed.is_some() || self.indexed.is_some() {
            return Err(indexed_unsupported());
        }
        let mut values: Vec<F> = self
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
                    "binary mixed WHIR MultiStark bus input shape mismatch",
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
                    "binary mixed WHIR MultiStark preprocessing input shape mismatch",
                ));
            }
        }
        Ok(values)
    }
}

impl BinaryMixedWhirMultiStarkVerifier {
    /// The native carrier verifies relations without indexed reads, over hashes with native
    /// circuits, and the packed table on the column-batched route only.
    pub(crate) fn check_native_circuit_support(&self) -> Result<(), VerificationError> {
        if self.relation.indexed.is_some() {
            return Err(indexed_unsupported());
        }
        self.dense.check_host::<NativeBinaryEncoding, F>()?;
        self.packed.check_native_circuit_support()?;
        if let Some(pp) = &self.preprocessed {
            pp.check_host::<NativeBinaryEncoding, F>()?;
        }
        Ok(())
    }

    /// Native carrier counterpart of [`Self::verify`]: checks all AIR obligations and
    /// authenticates both openings of the main commitment and the preprocessing opening.
    /// Public targets are the caller's actual statement, in instance order. Returns the exact
    /// ordinary challenger after the last opening.
    pub fn verify_native(
        &self,
        b: &mut CircuitBuilder<F>,
        mut ch: BinaryTower128Challenger,
        public: &[Vec<NativeTower128Target>],
        proof: &BinaryMixedWhirMultiStarkProofTargets<
            NativeTower128Target,
            NativeBooleanWhirTraceProofTargets,
        >,
    ) -> Result<BinaryTower128Challenger, VerificationError> {
        self.check_native_circuit_support()?;
        if proof.indexed.is_some() {
            return Err(indexed_unsupported());
        }
        let common = BinaryRelationProof {
            bus: proof.bus.as_ref(),
            sumcheck: &proof.sumcheck,
            indexed: None,
        };
        self.relation.check_targets(public, &common)?;
        let (dense_cap, packed_cap) = self.split_cap(&proof.commitment)?;
        let zero = b.native_tower128_constant(0);
        let (dense_points, _) = self.split(&self.relation.zero_points(false, zero))?;
        self.dense
            .check_targets(dense_cap, &dense_points, &proof.dense)?;
        let preprocessed_cap = match (
            &self.preprocessed,
            &self.input.preprocessed,
            &proof.preprocessed_opening,
        ) {
            (Some(verifier), Some(shape), Some(proof)) => {
                let cap = shape.constant_cap::<NativeBinaryEncoding, F>(b)?;
                let points = self.relation.zero_points(true, zero);
                verifier.check_targets(&cap, &points, proof)?;
                Some(cap)
            }
            (None, None, None) => None,
            _ => {
                return Err(invalid(
                    "binary mixed WHIR MultiStark preprocessed opening shape mismatch",
                ));
            }
        };
        self.relation
            .observe_prefix_with_host::<NativeBinaryEncoding, F>(
                b,
                &mut ch,
                preprocessed_cap.as_deref(),
            )?;
        self.dense
            .observe_commitment_with_host::<NativeBinaryEncoding, F>(b, &mut ch, dense_cap)?;
        self.packed
            .observe_commitment_native(b, &mut ch, packed_cap)?;
        let mut reduction = self
            .relation
            .reduce_common::<NativeTower128Relation<F>, NativeBinaryEncoding, F>(
                b, ch, public, &common,
            )?;
        self.relation.set_unindexed_points(&mut reduction);
        let (dense_points, packed_points) = self.split(&reduction.main_points)?;
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
        let main_evals = self.merge(dense_evals, packed_evals)?;
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
            .finish_common::<NativeTower128Relation<F>, F>(
                b,
                public,
                &reduction,
                &main_evals,
                preprocessed_evals.as_deref(),
            )?;
        Ok(continuation)
    }
}
