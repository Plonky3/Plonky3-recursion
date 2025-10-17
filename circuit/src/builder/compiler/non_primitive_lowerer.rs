use alloc::format;
use alloc::vec::Vec;

use hashbrown::HashMap;

use crate::builder::circuit_builder::NonPrimitiveOperationData;
use crate::builder::{BuilderConfig, CircuitBuilderError};
use crate::op::{NonPrimitiveOp, NonPrimitiveOpConfig, NonPrimitiveOpHelper, NonPrimitiveOpType};
use crate::types::{ExprId, WitnessId};

/// Responsible for lowering non-primitive operations from ExprIds to WitnessIds.
///
/// This component handles:
/// - Converting high-level non-primitive operation references to witness-based operations
/// - Validating operation configurations
/// - Checking operation arity requirements
#[derive(Debug)]
pub struct NonPrimitiveLowerer<'a> {
    /// Non-primitive operations to lower
    non_primitive_ops: &'a [NonPrimitiveOperationData],

    /// Expression to witness mapping
    expr_to_widx: &'a HashMap<ExprId, WitnessId>,

    /// Builder configuration with enabled operations
    config: &'a BuilderConfig,
}

impl<'a> NonPrimitiveLowerer<'a> {
    /// Creates a new non-primitive lowerer.
    pub const fn new(
        non_primitive_ops: &'a [NonPrimitiveOperationData],
        expr_to_widx: &'a HashMap<ExprId, WitnessId>,
        config: &'a BuilderConfig,
    ) -> Self {
        Self {
            non_primitive_ops,
            expr_to_widx,
            config,
        }
    }

    /// Lowers non-primitive operations to their witness-based forms.
    pub fn lower(self) -> Result<Vec<NonPrimitiveOp>, CircuitBuilderError> {
        let mut lowered_ops = Vec::new();

        for (_op_id, op_type, helper, witness_exprs) in self.non_primitive_ops {
            let config = self.config.get_op_config(op_type);
            match op_type {
                NonPrimitiveOpType::MmcsVerify => {
                    let config = match config {
                        Some(NonPrimitiveOpConfig::MmcsVerifyConfig(config)) => Ok(config),
                        _ => Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                            op: op_type.clone(),
                        }),
                    }?;
                    if !config.input_size().contains(&witness_exprs.len()) {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected: format!("{:?}", config.input_size()),
                            got: witness_exprs.len(),
                        });
                    }

                    let directions_len = witness_exprs[witness_exprs.len() - 2].len();
                    if !config.directions_size().contains(&directions_len) {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected: format!("{:?}", config.directions_size()),
                            got: witness_exprs[1].len(),
                        });
                    }

                    // The length must be directions_len + 2: directions_len leaves + direction + root
                    if witness_exprs.len() != directions_len + 2 {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected: format!("{}", directions_len + 2),
                            got: witness_exprs.len(),
                        });
                    }

                    // The leaves are represented as the first witness_exprs.len() - 2 elements
                    // Each leave should be either a vector of length config.ext_field_digest_elems,
                    // or an empty vec, meaning that there's no matrix in the Mmcs scheme at that level.
                    let leaves_expr = &witness_exprs[..directions_len];
                    if !leaves_expr
                        .iter()
                        .all(|leaf| leaf.len() == config.ext_field_digest_elems || leaf.is_empty())
                    {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected: format!("{}", config.ext_field_digest_elems),
                            got: witness_exprs[0].len(),
                        });
                    }
                    let leaves_widx: Vec<Vec<WitnessId>> = leaves_expr
                        .iter()
                        .map(|leaf| {
                            leaf.iter()
                                .map(|expr_id| {
                                    Self::get_witness_id(
                                        self.expr_to_widx,
                                        *expr_id,
                                        "MmcsVerify leaf input",
                                    )
                                })
                                .collect::<Result<Vec<WitnessId>, _>>()
                        })
                        .collect::<Result<_, _>>()?;

                    // directions are witnesses at position directions_len
                    let directions_widx = witness_exprs[directions_len]
                        .iter()
                        .map(|expr_id| {
                            Self::get_witness_id(
                                self.expr_to_widx,
                                *expr_id,
                                "MmcsVerify directions input",
                            )
                        })
                        .collect::<Result<_, _>>()?;

                    let root_widx = witness_exprs[directions_len + 1]
                        .iter()
                        .map(|expr_id| {
                            Self::get_witness_id(
                                self.expr_to_widx,
                                *expr_id,
                                "MmcsVerify root input",
                            )
                        })
                        .collect::<Result<_, _>>()?;

                    lowered_ops.push(NonPrimitiveOp::MmcsVerify {
                        leaves: leaves_widx,
                        directions: directions_widx,
                        root: root_widx,
                        helper: helper.clone(),
                    });
                }
                NonPrimitiveOpType::HashAbsorb { reset } => {
                    // Map inputs from ExprId to WitnessId
                    let inputs = witness_exprs
                        .iter()
                        .flatten()
                        .map(|&expr| {
                            Self::get_witness_id(self.expr_to_widx, expr, "HashAbsorb input")
                        })
                        .collect::<Result<_, _>>()?;

                    lowered_ops.push(NonPrimitiveOp::HashAbsorb {
                        reset_flag: *reset,
                        inputs,
                        helper: helper.clone(),
                    });
                }
                NonPrimitiveOpType::HashSqueeze => {
                    // Map outputs from ExprId to WitnessId
                    let outputs = witness_exprs
                        .iter()
                        .flatten()
                        .map(|&expr| {
                            Self::get_witness_id(self.expr_to_widx, expr, "HashSqueeze output")
                        })
                        .collect::<Result<_, _>>()?;

                    lowered_ops.push(NonPrimitiveOp::HashSqueeze {
                        outputs,
                        helper: helper.clone(),
                    });
                }
                NonPrimitiveOpType::FriVerify => {
                    todo!() // TODO: Add FRIVerify when it lands
                }
            }
        }

        Ok(lowered_ops)
    }

    /// Helper function to get WitnessId with descriptive error messages
    fn get_witness_id(
        expr_to_widx: &HashMap<ExprId, WitnessId>,
        expr_id: ExprId,
        context: &str,
    ) -> Result<WitnessId, CircuitBuilderError> {
        expr_to_widx
            .get(&expr_id)
            .copied()
            .ok_or_else(|| CircuitBuilderError::MissingExprMapping {
                expr_id,
                context: context.into(),
            })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_matrix::Dimensions;

    use super::*;
    use crate::NonPrimitiveOpId;
    use crate::op::NonPrimitiveOpHelper;
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
        let result = lowerer.lower().unwrap();

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
        let result = lowerer.lower().unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn test_mmcs_verify_mock_config() {
        // Test MmcsVerify with mock config (simplest case: 1 leaf + 1 index + 1 root)
        let mock_config = MmcsVerifyConfig::mock_config();
        assert_eq!(mock_config.ext_field_digest_elems, 1);
        assert_eq!(mock_config.input_size(), (3..4));

        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let expr_map = create_expr_map(3);

        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpHelper::MmcsVerify(dimensions.clone()),
            vec![vec![ExprId(0)], vec![ExprId(1)], vec![ExprId(2)]],
        )];

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result = lowerer.lower().unwrap();

        assert_eq!(result.len(), 1);

        match &result[0] {
            NonPrimitiveOp::MmcsVerify {
                leaves,
                directions,
                root,
                helper: NonPrimitiveOpHelper::MmcsVerify(result_dimensions),
            } => {
                assert_eq!(leaves.len(), 1);
                assert_eq!(leaves[0], vec![WitnessId(0)]);
                assert_eq!(*directions, vec![WitnessId(1)]);
                assert_eq!(root.len(), 1);
                assert_eq!(root[0], WitnessId(2));
                assert_eq!(dimensions, *result_dimensions);
            }
            _ => panic!("Expected MmcsVerify operation"),
        }
    }

    #[test]
    fn test_mmcs_verify_babybear_config() {
        // Test MmcsVerify with BabyBear config (realistic: 8 leaf + 1 directions + 8 root)
        let babybear_config = MmcsVerifyConfig::babybear_default();
        assert_eq!(babybear_config.ext_field_digest_elems, 8);
        assert_eq!(babybear_config.input_size(), 3..35);

        let mut config = BuilderConfig::new();
        config.enable_mmcs(&babybear_config);

        let expr_map = create_expr_map(17);

        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];

        let witness_exprs: Vec<Vec<ExprId>> = vec![
            (0..8).map(|i| ExprId(i as u32)).collect(),
            vec![ExprId(8)],
            (9..17).map(|i| ExprId(i as u32)).collect(),
        ];
        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpHelper::MmcsVerify(dimensions.clone()),
            witness_exprs,
        )];

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result = lowerer.lower().unwrap();

        assert_eq!(result.len(), 1);

        match &result[0] {
            NonPrimitiveOp::MmcsVerify {
                leaves,
                directions,
                root,
                helper: NonPrimitiveOpHelper::MmcsVerify(result_dimensions),
            } => {
                // Verify leaf witnesses (0..8)
                assert_eq!(leaves.len(), 1);
                assert_eq!(leaves[0].len(), 8);
                for (i, &leaf_witness) in leaves[0].iter().enumerate() {
                    assert_eq!(leaf_witness, WitnessId(i as u32));
                }

                // Verify index witness (8)
                assert_eq!(*directions, vec![WitnessId(8)]);

                // Verify root witnesses (9..17)
                assert_eq!(root.len(), 8);
                for (i, &root_witness) in root.iter().enumerate() {
                    assert_eq!(root_witness, WitnessId((9 + i) as u32));
                }

                assert_eq!(dimensions, *result_dimensions);
            }
            _ => panic!("Expected MmcsVerify operation"),
        }
    }

    #[test]
    fn test_mmcs_verify_multiple_operations() {
        // Test multiple MmcsVerify operations in sequence
        let mock_config = MmcsVerifyConfig::mock_config();
        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let expr_map = create_expr_map(9);

        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];

        let ops = vec![
            (
                NonPrimitiveOpId(0),
                NonPrimitiveOpType::MmcsVerify,
                NonPrimitiveOpHelper::MmcsVerify(dimensions.clone()),
                vec![vec![ExprId(0)], vec![ExprId(1)], vec![ExprId(2)]],
            ),
            (
                NonPrimitiveOpId(1),
                NonPrimitiveOpType::MmcsVerify,
                NonPrimitiveOpHelper::MmcsVerify(dimensions.clone()),
                vec![vec![ExprId(3)], vec![ExprId(4)], vec![ExprId(5)]],
            ),
            (
                NonPrimitiveOpId(2),
                NonPrimitiveOpType::MmcsVerify,
                NonPrimitiveOpHelper::MmcsVerify(dimensions.clone()),
                vec![vec![ExprId(6)], vec![ExprId(7)], vec![ExprId(8)]],
            ),
        ];

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result = lowerer.lower().unwrap();

        assert_eq!(result.len(), 3);

        // Verify each operation independently
        for (i, op) in result.iter().enumerate() {
            match op {
                NonPrimitiveOp::MmcsVerify {
                    leaves,
                    directions,
                    root,
                    helper: NonPrimitiveOpHelper::MmcsVerify(result_dimensions),
                } => {
                    let base = (i * 3) as u32;
                    assert_eq!(leaves.len(), 1);
                    assert_eq!(leaves[0], vec![WitnessId(base)]);
                    assert_eq!(*directions, vec![WitnessId(base + 1)]);
                    assert_eq!(root.len(), 1);
                    assert_eq!(*root, vec![WitnessId(base + 2)]);
                    assert_eq!(dimensions, *result_dimensions);
                }
                _ => panic!("Expected MmcsVerify operation"),
            }
        }
    }

    #[test]
    fn test_error_operation_not_enabled() {
        // Operation not enabled (missing config)
        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];
        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpHelper::MmcsVerify(dimensions),
            vec![vec![ExprId(0)], vec![ExprId(1)], vec![ExprId(2)]],
        )];
        let expr_map = create_expr_map(3);
        let config = BuilderConfig::new(); // No MMCS enabled

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result = lowerer.lower();

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

        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpHelper::MmcsVerify(dimensions),
            vec![vec![ExprId(0)], vec![ExprId(1)]], // Only 2 inputs, need 3
        )];
        let expr_map = create_expr_map(3);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::NonPrimitiveOpArity { op, expected, got }) => {
                assert_eq!(op, "MmcsVerify");
                assert_eq!(expected, format!("{:?}", 3..4));
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

        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];
        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpHelper::MmcsVerify(dimensions),
            vec![
                vec![ExprId(0)],
                vec![ExprId(1)],
                vec![ExprId(2)],
                vec![ExprId(3)],
            ], // 4 inputs, need 3
        )];
        let expr_map = create_expr_map(4);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::NonPrimitiveOpArity { op, expected, got }) => {
                assert_eq!(op, "MmcsVerify");
                assert_eq!(expected, format!("{:?}", 3..4));
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

        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];
        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpHelper::MmcsVerify(dimensions),
            vec![vec![ExprId(99)], vec![ExprId(1)], vec![ExprId(2)]], // ExprId(99) not in map
        )];
        let expr_map = create_expr_map(3);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result = lowerer.lower();

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

        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];
        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpHelper::MmcsVerify(dimensions),
            vec![vec![ExprId(0)], vec![ExprId(88)], vec![ExprId(2)]], // ExprId(88) not in map
        )];
        let expr_map = create_expr_map(3);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
                assert_eq!(expr_id, ExprId(88));
                assert!(context.contains("directions"));
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

        let dimensions = vec![Dimensions {
            height: 1,
            width: 1,
        }];
        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpHelper::MmcsVerify(dimensions),
            vec![vec![ExprId(0)], vec![ExprId(1)], vec![ExprId(77)]], // ExprId(77) not in map
        )];
        let expr_map = create_expr_map(3);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result = lowerer.lower();

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
        let result = NonPrimitiveLowerer::get_witness_id(&expr_map, ExprId(42), "test context");

        match result {
            Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
                assert_eq!(expr_id, ExprId(42));
                assert_eq!(context, "test context");
            }
            _ => panic!("Expected MissingExprMapping error from get_witness_id"),
        }
    }
}
