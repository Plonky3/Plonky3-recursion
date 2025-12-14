use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::hash::Hash;

use hashbrown::HashMap;
use p3_field::{Field, PrimeCharacteristicRing};

use crate::builder::circuit_builder::{NonPrimitiveOpParams, NonPrimitiveOperationData};
use crate::builder::compiler::get_witness_id;
use crate::builder::{BuilderConfig, CircuitBuilderError};
use crate::op::{NonPrimitiveOpType, Op};
use crate::ops::PoseidonPermExecutor;
use crate::types::{ExprId, WitnessId};

/// Responsible for lowering non-primitive operations from ExprIds to WitnessIds.
///
/// This component handles:
/// - Converting high-level non-primitive operation references to witness-based operations
/// - Validating operation configurations
/// - Checking operation arity requirements
#[derive(Debug)]
pub struct NonPrimitiveLowerer<'a, F> {
    /// Non-primitive operations to lower
    non_primitive_ops: &'a [NonPrimitiveOperationData],

    /// Expression to witness mapping
    expr_to_widx: &'a HashMap<ExprId, WitnessId>,

    /// Builder configuration with enabled operations
    config: &'a BuilderConfig<F>,
}

impl<'a, F> NonPrimitiveLowerer<'a, F> {
    /// Creates a new non-primitive lowerer.
    pub const fn new(
        non_primitive_ops: &'a [NonPrimitiveOperationData],
        expr_to_widx: &'a HashMap<ExprId, WitnessId>,
        config: &'a BuilderConfig<F>,
    ) -> Self {
        Self {
            non_primitive_ops,
            expr_to_widx,
            config,
        }
    }

    /// Lowers non-primitive operations to executable operations with explicit inputs/outputs.
    pub fn lower(self) -> Result<Vec<Op<F>>, CircuitBuilderError>
    where
        F: Field + Clone + PrimeCharacteristicRing + PartialEq + Eq + Hash,
    {
        let mut lowered_ops: Vec<Op<F>> = Vec::new();

        for data in self.non_primitive_ops {
            let op_id = data.op_id;
            let op_type = &data.op_type;
            let witness_exprs = &data.witness_exprs;
            let params = &data.params;

            let config_opt = self.config.get_op_config(op_type);
            match op_type {
                NonPrimitiveOpType::PoseidonPerm => {
                    let (new_start, merkle_path) = match params.as_ref().ok_or_else(|| {
                        CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                            op: op_type.clone(),
                        }
                    })? {
                        NonPrimitiveOpParams::PoseidonPerm {
                            new_start,
                            merkle_path,
                        } => (*new_start, *merkle_path),
                    };
                    // Operation must be enabled
                    if config_opt.is_none() {
                        return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                            op: op_type.clone(),
                        });
                    }

                    // Expected layout: [in0, in1, in2, in3, out0, out1, mmcs_index_sum, mmcs_bit]
                    if witness_exprs.len() != 8 {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "PoseidonPerm",
                            expected: "8 (in0..3, out0..1, mmcs_index_sum, mmcs_bit)".to_string(),
                            got: witness_exprs.len(),
                        });
                    }

                    let mut inputs_widx: Vec<Vec<WitnessId>> = Vec::with_capacity(8);
                    // Inputs
                    for (i, limb_exprs) in witness_exprs.iter().take(4).enumerate() {
                        if !(limb_exprs.is_empty() || limb_exprs.len() == 1) {
                            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                                op: "PoseidonPerm",
                                expected: "0 or 1 extension element per input limb".to_string(),
                                got: limb_exprs.len(),
                            });
                        }
                        let limb_widx = limb_exprs
                            .iter()
                            .map(|&expr| {
                                get_witness_id(
                                    self.expr_to_widx,
                                    expr,
                                    &format!("PoseidonPerm input limb {i}"),
                                )
                            })
                            .collect::<Result<Vec<WitnessId>, _>>()?;
                        inputs_widx.push(limb_widx);
                    }
                    // Outputs
                    for (i, limb_exprs) in witness_exprs.iter().skip(4).take(2).enumerate() {
                        if !(limb_exprs.is_empty() || limb_exprs.len() == 1) {
                            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                                op: "PoseidonPerm",
                                expected: "0 or 1 extension element per output limb".to_string(),
                                got: limb_exprs.len(),
                            });
                        }
                        let limb_widx = limb_exprs
                            .iter()
                            .map(|&expr| {
                                get_witness_id(
                                    self.expr_to_widx,
                                    expr,
                                    &format!("PoseidonPerm output limb {i}"),
                                )
                            })
                            .collect::<Result<Vec<WitnessId>, _>>()?;
                        inputs_widx.push(limb_widx);
                    }
                    // mmcs_index_sum (0 or 1 element)
                    let mmcs_exprs = &witness_exprs[6];
                    if !(mmcs_exprs.is_empty() || mmcs_exprs.len() == 1) {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "PoseidonPerm",
                            expected: "0 or 1 element for mmcs_index_sum".to_string(),
                            got: mmcs_exprs.len(),
                        });
                    }
                    let mmcs_widx = mmcs_exprs
                        .iter()
                        .map(|&expr| {
                            get_witness_id(
                                self.expr_to_widx,
                                expr,
                                "PoseidonPerm mmcs_index_sum input",
                            )
                        })
                        .collect::<Result<Vec<WitnessId>, _>>()?;
                    inputs_widx.push(mmcs_widx);
                    // mmcs_bit (0 or 1 element)
                    let mmcs_bit_exprs = &witness_exprs[7];
                    if !(mmcs_bit_exprs.is_empty() || mmcs_bit_exprs.len() == 1) {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "PoseidonPerm",
                            expected: "0 or 1 element for mmcs_bit".to_string(),
                            got: mmcs_bit_exprs.len(),
                        });
                    }
                    let mmcs_bit_widx = mmcs_bit_exprs
                        .iter()
                        .map(|&expr| {
                            get_witness_id(self.expr_to_widx, expr, "PoseidonPerm mmcs_bit input")
                        })
                        .collect::<Result<Vec<WitnessId>, _>>()?;
                    inputs_widx.push(mmcs_bit_widx);

                    lowered_ops.push(Op::NonPrimitiveOpWithExecutor {
                        inputs: inputs_widx,
                        outputs: Vec::new(),
                        executor: Box::new(PoseidonPermExecutor::new(new_start, merkle_path)),
                        op_id,
                    });
                }
            }
        }

        Ok(lowered_ops)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;

    use super::*;
    use crate::NonPrimitiveOpId;
    use crate::op::NonPrimitiveOpConfig;

    type F = BabyBear;

    /// Helper to create a simple expression to witness mapping with sequential IDs.
    fn create_expr_map(count: usize) -> HashMap<ExprId, WitnessId> {
        (0..count)
            .map(|i| (ExprId(i as u32), WitnessId(i as u32)))
            .collect()
    }

    #[test]
    fn test_lowerer_empty_operations() {
        // Empty operations list should produce empty result
        let ops = vec![];
        let expr_map = HashMap::new();
        let config = BuilderConfig::<F>::new();

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<F>> = lowerer.lower().unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_error_helper_function() {
        // Helper function error propagation
        let expr_map = HashMap::new();
        let result = get_witness_id(&expr_map, ExprId(42), "test context");

        match result {
            Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
                assert_eq!(expr_id, ExprId(42));
                assert_eq!(context, "test context");
            }
            _ => panic!("Expected MissingExprMapping error from get_witness_id"),
        }
    }

    #[test]
    fn test_poseidon_perm_lowering() {
        let mut config = BuilderConfig::<F>::new();
        config.enable_op(NonPrimitiveOpType::PoseidonPerm, NonPrimitiveOpConfig::None);

        // Layout: in0..3 (1 elem each), out0..1 (empty), mmcs_index_sum (1 elem), mmcs_bit (1 elem)
        let witness_exprs = vec![
            vec![ExprId(0)],
            vec![ExprId(1)],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![ExprId(2)],
            vec![ExprId(3)],
        ];

        let ops = vec![NonPrimitiveOperationData {
            op_id: NonPrimitiveOpId(0),
            op_type: NonPrimitiveOpType::PoseidonPerm,
            witness_exprs,
            params: Some(NonPrimitiveOpParams::PoseidonPerm {
                new_start: true,
                merkle_path: false,
            }),
        }];
        let expr_map = create_expr_map(10);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<F>> = lowerer.lower().unwrap();
        assert_eq!(result.len(), 1);

        match &result[0] {
            Op::NonPrimitiveOpWithExecutor {
                inputs,
                executor,
                outputs,
                ..
            } => {
                assert_eq!(executor.op_type(), &NonPrimitiveOpType::PoseidonPerm);
                assert!(outputs.is_empty());
                assert_eq!(inputs.len(), 8);
                // in0
                assert_eq!(inputs[0], vec![WitnessId(0)]);
                // in1
                assert_eq!(inputs[1], vec![WitnessId(1)]);
                // mmcs_index_sum
                assert_eq!(inputs[6], vec![WitnessId(2)]);
                // mmcs_bit
                assert_eq!(inputs[7], vec![WitnessId(3)]);
            }
            _ => panic!("Expected PoseidonPerm op"),
        }
    }
}
