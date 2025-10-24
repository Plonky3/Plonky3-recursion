use alloc::vec::Vec;
use core::hash::Hash;

use hashbrown::HashMap;
use p3_field::{Field, PrimeCharacteristicRing};

use crate::builder::compiler::get_witness_id;
use crate::builder::{BuilderConfig, CircuitBuilderError};
use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType, Op};
use crate::ops::{HashAbsorbExecutor, HashSqueezeExecutor, MmcsVerifyExecutor};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};

/// Responsible for lowering non-primitive operations from ExprIds to WitnessIds.
///
/// This component handles:
/// - Converting high-level non-primitive operation references to witness-based operations
/// - Validating operation configurations
/// - Checking operation arity requirements
#[derive(Debug)]
pub struct NonPrimitiveLowerer<'a> {
    /// Non-primitive operations to lower
    non_primitive_ops: &'a [(NonPrimitiveOpId, NonPrimitiveOpType, Vec<ExprId>)],

    /// Expression to witness mapping
    expr_to_widx: &'a HashMap<ExprId, WitnessId>,

    /// Builder configuration with enabled operations
    config: &'a BuilderConfig,
}

impl<'a> NonPrimitiveLowerer<'a> {
    /// Creates a new non-primitive lowerer.
    pub const fn new(
        non_primitive_ops: &'a [(NonPrimitiveOpId, NonPrimitiveOpType, Vec<ExprId>)],
        expr_to_widx: &'a HashMap<ExprId, WitnessId>,
        config: &'a BuilderConfig,
    ) -> Self {
        Self {
            non_primitive_ops,
            expr_to_widx,
            config,
        }
    }

    /// Lowers non-primitive operations to executable operations with explicit inputs/outputs.
    pub fn lower<F>(self) -> Result<Vec<Op<F>>, CircuitBuilderError>
    where
        F: Field + Clone + PrimeCharacteristicRing + PartialEq + Eq + Hash,
    {
        let mut lowered_ops: Vec<Op<F>> = Vec::new();

        for (op_id, op_type, witness_exprs) in self.non_primitive_ops {
            let config_opt = self.config.get_op_config(op_type);
            match op_type {
                NonPrimitiveOpType::MmcsVerify => {
                    let config = match config_opt {
                        Some(NonPrimitiveOpConfig::MmcsVerifyConfig(config)) => config,
                        _ => {
                            return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                                op: op_type.clone(),
                            });
                        }
                    };

                    let ext = config.ext_field_digest_elems;
                    let expected = config.input_size();
                    if witness_exprs.len() != expected {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected,
                            got: witness_exprs.len(),
                        });
                    }

                    // Map leaf inputs
                    let leaf_widx: Vec<WitnessId> = (0..ext)
                        .map(|i| {
                            get_witness_id(
                                self.expr_to_widx,
                                witness_exprs[i],
                                "MmcsVerify leaf input",
                            )
                        })
                        .collect::<Result<_, _>>()?;

                    // Map index input
                    let index_widx = get_witness_id(
                        self.expr_to_widx,
                        witness_exprs[ext],
                        "MmcsVerify index input",
                    )?;

                    // Map root inputs (assert op; no outputs)
                    let root_widx: Vec<WitnessId> = (ext + 1..expected)
                        .map(|i| {
                            get_witness_id(
                                self.expr_to_widx,
                                witness_exprs[i],
                                "MmcsVerify root input",
                            )
                        })
                        .collect::<Result<_, _>>()?;

                    // Build Op with executor: all in inputs; no outputs
                    let mut inputs = leaf_widx;
                    inputs.push(index_widx);
                    inputs.extend(root_widx);
                    lowered_ops.push(Op::NonPrimitiveOpWithExecutor {
                        inputs,
                        outputs: Vec::new(),
                        executor: alloc::boxed::Box::new(MmcsVerifyExecutor::new()),
                        op_id: *op_id,
                    });
                }
                NonPrimitiveOpType::HashAbsorb { reset } => {
                    // Operation must be enabled
                    if config_opt.is_none() {
                        return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                            op: op_type.clone(),
                        });
                    }

                    let inputs = witness_exprs
                        .iter()
                        .map(|&expr| get_witness_id(self.expr_to_widx, expr, "HashAbsorb input"))
                        .collect::<Result<_, _>>()?;

                    lowered_ops.push(Op::NonPrimitiveOpWithExecutor {
                        inputs,
                        outputs: Vec::new(),
                        executor: alloc::boxed::Box::new(HashAbsorbExecutor::new(*reset)),
                        op_id: *op_id,
                    });
                }
                NonPrimitiveOpType::HashSqueeze => {
                    // Operation must be enabled
                    if config_opt.is_none() {
                        return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                            op: op_type.clone(),
                        });
                    }

                    let outputs = witness_exprs
                        .iter()
                        .map(|&expr| get_witness_id(self.expr_to_widx, expr, "HashSqueeze output"))
                        .collect::<Result<_, _>>()?;

                    lowered_ops.push(Op::NonPrimitiveOpWithExecutor {
                        inputs: Vec::new(),
                        outputs,
                        executor: alloc::boxed::Box::new(HashSqueezeExecutor::new()),
                        op_id: *op_id,
                    });
                }
                NonPrimitiveOpType::FriVerify => {
                    todo!() // TODO: Add FRIVerify when it lands
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
    use crate::ops::MmcsVerifyConfig;

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
        let config = BuilderConfig::new();

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<BabyBear>> = lowerer.lower().unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_lowerer_empty_operations_with_config() {
        // Empty operations with populated config should still produce empty result
        let ops = vec![];
        let expr_map = create_expr_map(10);
        let mut config = BuilderConfig::new();
        config.enable_mmcs(&MmcsVerifyConfig::mock_config());

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<BabyBear>> = lowerer.lower().unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_mmcs_verify_mock_config() {
        // Test MmcsVerify with mock config (simplest case: 1 leaf + 1 index + 1 root)
        let mock_config = MmcsVerifyConfig::mock_config();
        assert_eq!(mock_config.ext_field_digest_elems, 1);
        assert_eq!(
            mock_config.input_size(),
            2 * mock_config.ext_field_digest_elems + 1
        );

        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let expr_map = create_expr_map(3);

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![ExprId(0), ExprId(1), ExprId(2)],
        )];

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<BabyBear>> = lowerer.lower().unwrap();

        assert_eq!(result.len(), 1);

        match &result[0] {
            Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                ..
            } => {
                assert_eq!(executor.op_type(), &NonPrimitiveOpType::MmcsVerify);
                assert_eq!(inputs, &vec![WitnessId(0), WitnessId(1), WitnessId(2)]);
                assert!(outputs.is_empty());
            }
            _ => panic!("Expected NonPrimitiveOpWithExecutor(MmcsVerify)"),
        }
    }

    #[test]
    fn test_mmcs_verify_babybear_config() {
        // Test MmcsVerify with BabyBear config (realistic: 8 leaf + 1 index + 8 root)
        let babybear_config = MmcsVerifyConfig::babybear_default();
        assert_eq!(babybear_config.ext_field_digest_elems, 8);
        assert_eq!(
            babybear_config.input_size(),
            2 * babybear_config.ext_field_digest_elems + 1
        );

        let mut config = BuilderConfig::new();
        config.enable_mmcs(&babybear_config);

        let expr_map = create_expr_map(17);

        let witness_exprs: Vec<ExprId> = (0..17).map(|i| ExprId(i as u32)).collect();
        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            witness_exprs,
        )];

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<BabyBear>> = lowerer.lower().unwrap();

        assert_eq!(result.len(), 1);

        match &result[0] {
            Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                ..
            } => {
                assert_eq!(executor.op_type(), &NonPrimitiveOpType::MmcsVerify);
                // Verify leaf witnesses (0..8) + index (8) + root (9..16)
                assert_eq!(inputs.len(), 17);
                for (i, &wid) in inputs.iter().enumerate().take(8) {
                    assert_eq!(wid, WitnessId(i as u32));
                }
                assert_eq!(inputs[8], WitnessId(8));
                for (i, &wid) in inputs.iter().enumerate().skip(9) {
                    assert_eq!(wid, WitnessId(i as u32));
                }
                assert!(outputs.is_empty());
            }
            _ => panic!("Expected NonPrimitiveOpWithExecutor(MmcsVerify)"),
        }
    }

    #[test]
    fn test_mmcs_verify_multiple_operations() {
        // Test multiple MmcsVerify operations in sequence
        let mock_config = MmcsVerifyConfig::mock_config();
        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let expr_map = create_expr_map(9);

        // For mock config ext=1, expected witness_exprs layout per op: [leaf, index, root]
        let ops = vec![
            (
                NonPrimitiveOpId(0),
                NonPrimitiveOpType::MmcsVerify,
                vec![ExprId(0), ExprId(1), ExprId(2)],
            ),
            (
                NonPrimitiveOpId(1),
                NonPrimitiveOpType::MmcsVerify,
                vec![ExprId(3), ExprId(4), ExprId(5)],
            ),
            (
                NonPrimitiveOpId(2),
                NonPrimitiveOpType::MmcsVerify,
                vec![ExprId(6), ExprId(7), ExprId(8)],
            ),
        ];

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<BabyBear>> = lowerer.lower().unwrap();

        assert_eq!(result.len(), 3);

        // Verify each operation independently
        for (i, op) in result.iter().enumerate() {
            match op {
                Op::NonPrimitiveOpWithExecutor {
                    inputs,
                    outputs,
                    executor,
                    op_id,
                } => {
                    assert_eq!(executor.op_type(), &NonPrimitiveOpType::MmcsVerify);
                    let base = (i * 3) as u32;
                    assert_eq!(inputs.len(), 3); // leaf (1) + index (1) + root(1)
                    assert_eq!(inputs[0], WitnessId(base));
                    assert_eq!(inputs[1], WitnessId(base + 1));
                    assert_eq!(inputs[2], WitnessId(base + 2));
                    assert!(outputs.is_empty());
                    assert_eq!(*op_id, NonPrimitiveOpId(i as u32));
                }
                _ => panic!("Expected NonPrimitiveOpWithExecutor(MmcsVerify)"),
            }
        }
    }

    #[test]
    fn test_error_operation_not_enabled() {
        // Operation not enabled (missing config)
        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![ExprId(0), ExprId(1), ExprId(2)],
        )];
        let expr_map = create_expr_map(3);
        let config = BuilderConfig::new(); // No MMCS enabled

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Result<Vec<Op<BabyBear>>, _> = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration { op }) => {
                assert_eq!(op, NonPrimitiveOpType::MmcsVerify);
            }
            _ => panic!("Expected InvalidNonPrimitiveOpConfiguration error"),
        }
    }

    #[test]
    fn test_error_wrong_arity_too_few() {
        // Wrong arity: too few inputs
        let mock_config = MmcsVerifyConfig::mock_config();
        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![ExprId(0), ExprId(1)], // Only 2 inputs, need 3
        )];
        let expr_map = create_expr_map(3);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Result<Vec<Op<BabyBear>>, _> = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::NonPrimitiveOpArity { op, expected, got }) => {
                assert_eq!(op, "MmcsVerify");
                assert_eq!(expected, 3);
                assert_eq!(got, 2);
            }
            _ => panic!("Expected NonPrimitiveOpArity error"),
        }
    }

    #[test]
    fn test_error_wrong_arity_too_many() {
        // Wrong arity: too many inputs
        let mock_config = MmcsVerifyConfig::mock_config();
        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![ExprId(0), ExprId(1), ExprId(2), ExprId(3)], // 4 inputs, need 3
        )];
        let expr_map = create_expr_map(4);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Result<Vec<Op<BabyBear>>, _> = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::NonPrimitiveOpArity { op, expected, got }) => {
                assert_eq!(op, "MmcsVerify");
                assert_eq!(expected, 3);
                assert_eq!(got, 4);
            }
            _ => panic!("Expected NonPrimitiveOpArity error"),
        }
    }

    #[test]
    fn test_error_missing_leaf_mapping() {
        // Missing expression mapping for leaf input
        let mock_config = MmcsVerifyConfig::mock_config();
        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![ExprId(99), ExprId(1), ExprId(2)], // ExprId(99) not in map
        )];
        let expr_map = create_expr_map(3);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Result<Vec<Op<BabyBear>>, _> = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
                assert_eq!(expr_id, ExprId(99));
                assert!(context.contains("leaf"));
            }
            _ => panic!("Expected MissingExprMapping error for leaf"),
        }
    }

    #[test]
    fn test_error_missing_index_mapping() {
        // Missing expression mapping for index input
        let mock_config = MmcsVerifyConfig::mock_config();
        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![ExprId(0), ExprId(88), ExprId(2)], // ExprId(88) not in map
        )];
        let expr_map = create_expr_map(3);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Result<Vec<Op<BabyBear>>, _> = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
                assert_eq!(expr_id, ExprId(88));
                assert!(context.contains("index"));
            }
            _ => panic!("Expected MissingExprMapping error for index"),
        }
    }

    #[test]
    fn test_error_missing_root_mapping() {
        // Missing expression mapping for root input
        let mock_config = MmcsVerifyConfig::mock_config();
        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![ExprId(0), ExprId(1), ExprId(77)], // ExprId(77) not in map
        )];
        let expr_map = create_expr_map(3);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Result<Vec<Op<BabyBear>>, _> = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
                assert_eq!(expr_id, ExprId(77));
                assert!(context.contains("root"));
            }
            _ => panic!("Expected MissingExprMapping error for root"),
        }
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
}
