use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::hash::Hash;
use core::ops::Range;

use p3_field::{ExtensionField, Field};

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{
    ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpConfig, NonPrimitiveOpPrivateData,
    NonPrimitiveOpType,
};
use crate::types::{ExprId, WitnessId};
use crate::{CircuitError, NonPrimitiveOpId};

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
    /// Returns the range in which valid number of inputs lie. The minimum is 3,
    /// a single leaf, a vector of directions, and a root, or self.max_tree_height leaves
    /// and a vector of directions and root.
    pub const fn input_size(&self) -> Range<usize> {
        3..self.max_tree_height + 2 + 1
    }

    /// Returns the number of inputs (witness elements) received.
    pub const fn leaves_size(&self) -> Range<usize> {
        // `ext_field_digest_elems` for the leaf and root and 1 for the index
        self.directions_size()
    }

    pub const fn directions_size(&self) -> Range<usize> {
        1..self.max_tree_height + 1
    }

    pub const fn root_size(&self) -> usize {
        self.ext_field_digest_elems
    }

    /// MMCS verify is an assert-only op and does not produce outputs.
    pub const fn output_size(&self) -> usize {
        0
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
                expected: self.ext_field_digest_elems.to_string(),
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
                expected: DIGEST_ELEMS.to_string(),
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
                expected: self.base_field_digest_elems.to_string(),
                got: digest.len(),
            });
        }
        if self.is_packing() {
            // Validate divisibility and config alignment with EF::DIMENSION
            if !self.base_field_digest_elems.is_multiple_of(EF::DIMENSION)
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

    pub const fn mock_config() -> Self {
        Self {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 1,
        }
    }

    pub const fn babybear_default() -> Self {
        Self {
            base_field_digest_elems: 8,
            ext_field_digest_elems: 8,
            max_tree_height: 32,
        }
    }

    // TODO: For now we are not considering packed inputs for BabyBear.
    pub const fn babybear_quartic_extension_default() -> Self {
        let packing = false;
        Self {
            base_field_digest_elems: 8,
            ext_field_digest_elems: if packing { 2 } else { 8 },
            max_tree_height: 32,
        }
    }

    pub const fn koalabear_default() -> Self {
        Self {
            base_field_digest_elems: 8,
            ext_field_digest_elems: 8,
            max_tree_height: 32,
        }
    }

    // TODO: For now we are not considering packed inputs for KoalaBear.
    pub const fn koalabear_quartic_extension_default() -> Self {
        let packing = false;
        Self {
            base_field_digest_elems: 8,
            ext_field_digest_elems: if packing { 2 } else { 8 },
            max_tree_height: 32,
        }
    }

    pub const fn goldilocks_default() -> Self {
        Self {
            base_field_digest_elems: 4,
            ext_field_digest_elems: 4,
            max_tree_height: 32,
        }
    }

    // TODO: For now we are not considering packed inputs for Goldilocks.
    pub const fn goldilocks_quadratic_extension_default() -> Self {
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
    /// - Take existing expressions as inputs (leaves_expr, directions_expr, root_expr)
    /// - Add verification constraints to the circuit
    /// - Don't produce new ExprIds (unlike primitive ops)
    /// - Are kept separate from primitives to avoid disrupting optimization
    ///
    /// Returns an operation ID for setting private data later during execution.
    fn add_mmcs_verify(
        &mut self,
        leaves_expr: &[Vec<ExprId>],
        directions_expr: &[ExprId],
        root_expr: &[ExprId],
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;
}

impl<F> MmcsOps<F> for CircuitBuilder<F>
where
    F: Clone + p3_field::PrimeCharacteristicRing + Eq + Hash,
{
    fn add_mmcs_verify(
        &mut self,
        leaves_expr: &[Vec<ExprId>],
        directions_expr: &[ExprId],
        root_expr: &[ExprId],
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::MmcsVerify)?;

        let mut witness_exprs = vec![];
        witness_exprs.extend(leaves_expr.to_vec());
        witness_exprs.push(directions_expr.to_vec());
        witness_exprs.push(root_expr.to_vec());
        Ok(
            self.push_non_primitive_op(
                NonPrimitiveOpType::MmcsVerify,
                witness_exprs,
                "mmcs_verify",
            ),
        )
    }
}

/// Executor for MMCS verification operations
///
/// This executor validates that the private MMCS path data is consistent with
/// the witness values. It does not compute outputs - they must be provided by the user.
#[derive(Debug, Clone)]
pub struct MmcsVerifyExecutor {
    op_type: NonPrimitiveOpType,
}

impl MmcsVerifyExecutor {
    /// Create a new MMCS verify executor
    pub const fn new() -> Self {
        Self {
            op_type: NonPrimitiveOpType::MmcsVerify,
        }
    }
}

impl Default for MmcsVerifyExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for MmcsVerifyExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        // Get the configuration
        let config = match ctx.get_config(&self.op_type)? {
            NonPrimitiveOpConfig::MmcsVerifyConfig(cfg) => cfg,
            _ => {
                return Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                    op: self.op_type.clone(),
                });
            }
        };

        // Get private data
        let NonPrimitiveOpPrivateData::MmcsVerify(private_data) = ctx.get_private_data()?;

        // Validate input size: leaf(ext) + index(1) + root(ext)
        if !config.input_size().contains(&inputs.len()) {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: format!("{:?}", config.input_size()),
                got: inputs.len(),
            });
        }

        let root = &inputs[inputs.len() - 1];
        let directions = &inputs[inputs.len() - 2];
        let leaves = &inputs[0..directions.len()];

        // Validate that the witness data is consistent with public inputs
        // Check leaf values
        let witness_leaves: Vec<Vec<F>> = leaves
            .iter()
            .map(|leaf| {
                leaf.iter()
                    .map(|&wid| ctx.get_witness(wid))
                    .collect::<Result<Vec<F>, _>>()
            })
            .collect::<Result<_, _>>()?;

        let witness_directions = directions
            .iter()
            .map(|&wid| ctx.get_witness(wid))
            .collect::<Result<Vec<F>, _>>()?;
        // Check that the number of leaves is the same as the number of directions
        if witness_directions.len() != witness_leaves.len() {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: NonPrimitiveOpType::MmcsVerify,
                operation_index: ctx.operation_id(), // TODO: What's the operation id of the curre
                expected: format!("{:?}", witness_directions.len()),
                got: format!("{:?}", witness_leaves.len()),
            });
        }

        // Check root values
        let witness_root: Vec<F> = root
            .iter()
            .map(|&wid| ctx.get_witness(wid))
            .collect::<Result<_, _>>()?;
        let computed_root = &private_data
            .path_states
            .last()
            .ok_or_else(|| CircuitError::NonPrimitiveOpMissingPrivateData {
                operation_index: ctx.operation_id(),
            })?
            .0;
        if witness_root != *computed_root {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: NonPrimitiveOpType::MmcsVerify,
                operation_index: ctx.operation_id(),
                expected: format!("root: {witness_root:?}"),
                got: format!("root: {computed_root:?}"),
            });
        }

        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}
