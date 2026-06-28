use alloc::vec::Vec;

use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::ops::NpoTypeId;

use crate::air::AluExtMulKind;
use crate::batch_stark_prover::{AirVariant, BatchStarkProof, ProofMetadataError};

/// Expected metadata for a single non-primitive table in a [`VerifierManifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedNpoEntry {
    /// Expected operation type.
    pub op_type: NpoTypeId,
    /// Expected AIR variant for this table.
    pub air_variant: AirVariant,
    /// Expected length of `public_values` for this table.
    pub public_values_len: usize,
}

/// Caller-supplied structural description of what a [`BatchStarkProof`] must contain.
///
/// Call [`VerifierManifest::matches`] before AIR reconstruction to reject a proof
/// whose declared metadata diverges from the verifier's expectations.
#[derive(Debug, Clone)]
pub struct VerifierManifest<F: Copy> {
    /// Extension degree of the trace field.
    pub ext_degree: usize,
    /// How extension-field multiplication is reduced.
    pub reduction: AluExtMulKind<F>,
    /// Expected variant for the primitive ALU table.
    pub alu_variant: AirVariant,
    /// Expected non-primitive tables, in proof order.
    pub expected_npo: Vec<ExpectedNpoEntry>,
}

impl<F: Copy> VerifierManifest<F> {
    /// Returns `Ok(())` when `proof`'s declared metadata matches this manifest,
    /// or the first `ProofMetadataError` that fails.
    ///
    /// The bound `F: Into<Val<SC>>` is trivially satisfied when `F = Val<SC>`, which is the
    /// expected usage. It is spelled out explicitly because `Val<SC>` is a derived type alias
    /// (not a direct associated type on `StarkGenericConfig`) and cannot be equated directly.
    pub fn matches<SC>(&self, proof: &BatchStarkProof<SC>) -> Result<(), ProofMetadataError>
    where
        SC: StarkGenericConfig,
        Val<SC>: PartialEq,
        F: Into<Val<SC>>,
    {
        if proof.ext_degree != self.ext_degree {
            return Err(ProofMetadataError::ExtDegreeMismatch {
                expected: self.ext_degree,
                got: proof.ext_degree,
            });
        }

        let (expected_w, expected_quintic): (Option<Val<SC>>, bool) = match self.reduction {
            AluExtMulKind::Base => (None, false),
            AluExtMulKind::Binomial { w } => (Some(w.into()), false),
            AluExtMulKind::QuinticTrinomial => (None, true),
        };

        if proof.w_binomial != expected_w {
            return Err(ProofMetadataError::BinomialWMismatch);
        }
        if proof.alu_quintic_trinomial != expected_quintic {
            return Err(ProofMetadataError::QuinticReductionMismatch {
                expected: expected_quintic,
                got: proof.alu_quintic_trinomial,
            });
        }

        if proof.alu_variant != self.alu_variant {
            return Err(ProofMetadataError::AluVariantMismatch {
                expected: self.alu_variant,
                got: proof.alu_variant,
            });
        }

        if proof.non_primitives.len() != self.expected_npo.len() {
            return Err(ProofMetadataError::NpoCountMismatch {
                expected: self.expected_npo.len(),
                got: proof.non_primitives.len(),
            });
        }

        for (i, (entry, expected)) in proof
            .non_primitives
            .iter()
            .zip(&self.expected_npo)
            .enumerate()
        {
            if entry.op_type != expected.op_type {
                return Err(ProofMetadataError::NpoOpTypeMismatch {
                    index: i,
                    expected: expected.op_type.clone(),
                    got: entry.op_type.clone(),
                });
            }
            if entry.air_variant != expected.air_variant {
                return Err(ProofMetadataError::NpoAirVariantMismatch {
                    index: i,
                    expected: expected.air_variant,
                    got: entry.air_variant,
                });
            }
            if entry.public_values.len() != expected.public_values_len {
                return Err(ProofMetadataError::NpoPublicValueLenMismatch {
                    index: i,
                    expected: expected.public_values_len,
                    got: entry.public_values.len(),
                });
            }
        }

        Ok(())
    }
}
