use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_field::{ExtensionField, Field};

use crate::CircuitError;
use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::NonPrimitiveOpType;
use crate::types::{ExprId, NonPrimitiveOpId};

/// Configuration parameters for Mmcs verification operations. When
/// `base_field_digest_elems > ext_field_digest_elems`, we say the configuration
/// is packing digests into extension field elements.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MmcsVerifyConfig {
    /// The number of base field elements required for representing a digest.
    pub base_field_digest_elems: usize,
    /// The number of extension field elements required for representing a digest.
    pub ext_field_digest_elems: usize,
    /// The maximum height of the mmcs
    pub max_tree_height: usize,
}

impl MmcsVerifyConfig {
    /// Returns the number of inputs (witness elements) received.
    pub const fn input_size(&self) -> usize {
        // `ext_field_digest_elems` for the leaf and root and 1 for the index
        2 * self.ext_field_digest_elems + 1
    }

    /// Convert a digest represented as extension field elements into base field elements.
    pub fn ext_to_base<F, EF, const DIGEST_ELEMS: usize>(
        &self,
        digest: &[EF],
    ) -> Result<[F; DIGEST_ELEMS], CircuitError>
    where
        F: Field,
        EF: ExtensionField<F> + Clone,
    {
        // Ensure the number of extension limbs matches the configuration.
        if digest.len() != self.ext_field_digest_elems {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: NonPrimitiveOpType::MmcsVerify,
                expected: self.ext_field_digest_elems,
                got: digest.len(),
            });
        }

        let flattened: Vec<F> = digest
            .iter()
            .flat_map(|limb| {
                if self.is_packing() {
                    limb.as_basis_coefficients_slice()
                } else {
                    &limb.as_basis_coefficients_slice()[0..1]
                }
            })
            .copied()
            .collect();

        // Ensure the flattened base representation matches the expected compile-time size.
        let len = flattened.len();
        let arr: [F; DIGEST_ELEMS] = flattened.try_into().map_err(|_| {
            CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: NonPrimitiveOpType::MmcsVerify,
                expected: DIGEST_ELEMS,
                got: len,
            }
        })?;
        // Sanity check that runtime config aligns with compile-time expectations.
        debug_assert!(
            (!self.is_packing() && DIGEST_ELEMS == self.ext_field_digest_elems)
                || (self.is_packing()
                    && DIGEST_ELEMS == self.ext_field_digest_elems * EF::DIMENSION),
            "Config/base length mismatch (packing or EF::DIMENSION?)",
        );
        Ok(arr)
    }

    /// Convert a digest represented as base field elements into extension field elements.
    pub fn base_to_ext<F, EF>(&self, digest: &[F]) -> Result<Vec<EF>, CircuitError>
    where
        F: Field,
        EF: ExtensionField<F> + Clone,
    {
        if digest.len() != self.base_field_digest_elems {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: NonPrimitiveOpType::MmcsVerify,
                expected: self.base_field_digest_elems,
                got: digest.len(),
            });
        }
        if self.is_packing() {
            // Validate divisibility and config alignment with EF::DIMENSION
            if self.base_field_digest_elems % EF::DIMENSION != 0
                || self.ext_field_digest_elems * EF::DIMENSION != self.base_field_digest_elems
            {
                return Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                    op: NonPrimitiveOpType::MmcsVerify,
                });
            }
            Ok(digest
                .chunks(EF::DIMENSION)
                .map(|v| {
                    // Safe due to the checks above
                    EF::from_basis_coefficients_slice(v).expect("chunk size equals EF::DIMENSION")
                })
                .collect())
        } else {
            Ok(digest.iter().map(|&x| EF::from(x)).collect())
        }
    }

    pub fn mock_config() -> Self {
        Self {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 1,
        }
    }

    pub fn babybear_default() -> Self {
        Self {
            base_field_digest_elems: 8,
            ext_field_digest_elems: 8,
            max_tree_height: 32,
        }
    }

    // TODO: For now we are not considering packed inputs for BabyBear.
    pub fn babybear_quartic_extension_default() -> Self {
        let packing = false;
        Self {
            base_field_digest_elems: 8,
            ext_field_digest_elems: if packing { 2 } else { 8 },
            max_tree_height: 32,
        }
    }

    pub fn koalabear_default() -> Self {
        Self {
            base_field_digest_elems: 8,
            ext_field_digest_elems: 8,
            max_tree_height: 32,
        }
    }

    // TODO: For now we are not considering packed inputs for KoalaBear.
    pub fn koalabear_quartic_extension_default() -> Self {
        let packing = false;
        Self {
            base_field_digest_elems: 8,
            ext_field_digest_elems: if packing { 2 } else { 8 },
            max_tree_height: 32,
        }
    }

    pub fn goldilocks_default() -> Self {
        Self {
            base_field_digest_elems: 4,
            ext_field_digest_elems: 4,
            max_tree_height: 32,
        }
    }

    // TODO: For now we are not considering packed inputs for Goldilocks.
    pub fn goldilocks_quadratic_extension_default() -> Self {
        let packing = false;
        Self {
            base_field_digest_elems: 4,
            ext_field_digest_elems: if packing { 1 } else { 4 },
            max_tree_height: 32,
        }
    }

    /// Returns whether digests are packed into extension field elements or not.
    pub const fn is_packing(&self) -> bool {
        self.base_field_digest_elems > self.ext_field_digest_elems
    }
}

/// Extension trait for Mmcs-related non-primitive ops.
pub trait MmcsOps<F> {
    /// Add a Mmcs verification constraint (non-primitive operation)
    ///
    /// Non-primitive operations are complex constraints that:
    /// - Take existing expressions as inputs (leaf_expr, index_expr, root_expr)
    /// - Add verification constraints to the circuit
    /// - Don't produce new ExprIds (unlike primitive ops)
    /// - Are kept separate from primitives to avoid disrupting optimization
    ///
    /// Returns an operation ID for setting private data later during execution.
    fn add_mmcs_verify(
        &mut self,
        leaf_expr: &[ExprId],
        index_expr: &ExprId,
        root_expr: &[ExprId],
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;
}

impl<F> MmcsOps<F> for CircuitBuilder<F>
where
    F: Clone + p3_field::PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_mmcs_verify(
        &mut self,
        leaf_expr: &[ExprId],
        index_expr: &ExprId,
        root_expr: &[ExprId],
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::MmcsVerify)?;

        let mut witness_exprs = vec![];
        witness_exprs.extend(leaf_expr);
        witness_exprs.push(*index_expr);
        witness_exprs.extend(root_expr);
        Ok(self.push_non_primitive_op(NonPrimitiveOpType::MmcsVerify, witness_exprs))
    }
}
