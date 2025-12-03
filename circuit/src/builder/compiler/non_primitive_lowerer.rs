use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::hash::Hash;

use hashbrown::HashMap;
use p3_field::{Field, PrimeCharacteristicRing};

use crate::builder::circuit_builder::NonPrimitiveOperationData;
use crate::builder::compiler::get_witness_id;
use crate::builder::{BuilderConfig, CircuitBuilderError};
use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType, Op};
use crate::ops::{MmcsVerifyExecutor, PoseidonPermExecutor};
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
                            got: directions_len,
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
                                    get_witness_id(
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
                            get_witness_id(self.expr_to_widx, *expr_id, "MmcsVerify index input")
                        })
                        .collect::<Result<_, _>>()?;

                    let root_widx = witness_exprs[directions_len + 1]
                        .iter()
                        .map(|expr_id| {
                            get_witness_id(self.expr_to_widx, *expr_id, "MmcsVerify root input")
                        })
                        .collect::<Result<_, _>>()?;

                    // Build Op with executor: all in inputs; no outputs
                    let mut inputs = leaves_widx;
                    inputs.push(directions_widx);
                    inputs.push(root_widx);
                    lowered_ops.push(Op::NonPrimitiveOpWithExecutor {
                        inputs,
                        outputs: Vec::new(),
                        executor: Box::new(MmcsVerifyExecutor::new()),
                        op_id: *op_id,
                    });
                }
                NonPrimitiveOpType::PoseidonPerm {
                    new_start,
                    merkle_path,
                    mmcs_bit,
                } => {
                    // Operation must be enabled
                    if config_opt.is_none() {
                        return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                            op: op_type.clone(),
                        });
                    }

                    // Expected layout: [in0, in1, in2, in3, out0, out1, mmcs_index_sum]
                    if witness_exprs.len() != 7 {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "PoseidonPerm",
                            expected: "7 (in0..3, out0..1, mmcs_index_sum)".to_string(),
                            got: witness_exprs.len(),
                        });
                    }

                    let mut inputs_widx: Vec<Vec<WitnessId>> = Vec::with_capacity(7);
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
                                    &format!("PoseidonPerm input limb {}", i),
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
                                    &format!("PoseidonPerm output limb {}", i),
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

                    lowered_ops.push(Op::NonPrimitiveOpWithExecutor {
                        inputs: inputs_widx,
                        outputs: Vec::new(),
                        executor: Box::new(PoseidonPermExecutor::new(
                            *new_start,
                            *merkle_path,
                            *mmcs_bit,
                        )),
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
    use crate::NonPrimitiveOpId;
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
        let mock_config = MmcsVerifyConfig {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 2,
        };
        assert_eq!(mock_config.ext_field_digest_elems, 1);
        assert_eq!(mock_config.input_size(), (3..5));

        let mut config = BuilderConfig::new();
        config.enable_mmcs(&mock_config);

        let expr_map = create_expr_map(4);

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![
                vec![ExprId(0)],            // first leaf
                vec![],                     // second leaf
                vec![ExprId(1), ExprId(2)], // directions
                vec![ExprId(3)],            // root
            ],
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
                assert_eq!(
                    inputs,
                    &vec![
                        vec![WitnessId(0)],
                        vec![],
                        vec![WitnessId(1), WitnessId(2)],
                        vec![WitnessId(3)]
                    ]
                );
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
        assert_eq!(babybear_config.input_size(), 3..35);

        let mut config = BuilderConfig::new();
        config.enable_mmcs(&babybear_config);

        let expr_map = create_expr_map(26);

        let witness_exprs: Vec<Vec<ExprId>> = vec![
            (0..8).map(|i| ExprId(i as u32)).collect(),   // leaf 1
            (8..16).map(|i| ExprId(i as u32)).collect(),  // leaf 2
            vec![ExprId(16), ExprId(17)],                 // directions
            (18..26).map(|i| ExprId(i as u32)).collect(), // root
        ];
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
                assert_eq!(inputs.len(), 4);
                for (i, &wid) in inputs[0].iter().enumerate() {
                    assert_eq!(wid, WitnessId(i as u32));
                }
                for (i, &wid) in inputs[1].iter().enumerate() {
                    assert_eq!(wid, WitnessId((i + 8) as u32));
                }
                assert_eq!(inputs[2], vec![WitnessId(16), WitnessId(17)]);
                for (i, &wid) in inputs[3].iter().enumerate() {
                    assert_eq!(wid, WitnessId((i + 18) as u32));
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
                vec![vec![ExprId(0)], vec![ExprId(1)], vec![ExprId(2)]],
            ),
            (
                NonPrimitiveOpId(1),
                NonPrimitiveOpType::MmcsVerify,
                vec![vec![ExprId(3)], vec![ExprId(4)], vec![ExprId(5)]],
            ),
            (
                NonPrimitiveOpId(2),
                NonPrimitiveOpType::MmcsVerify,
                vec![vec![ExprId(6)], vec![ExprId(7)], vec![ExprId(8)]],
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
                    assert_eq!(inputs.len(), 3); // leaves (1) + index (1) + root(1)
                    assert_eq!(inputs[0], vec![WitnessId(base)]);
                    assert_eq!(inputs[1], vec![WitnessId(base + 1)]);
                    assert_eq!(inputs[2], vec![WitnessId(base + 2)]);
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
            vec![vec![ExprId(0)], vec![ExprId(1)], vec![ExprId(2)]],
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
            vec![vec![ExprId(0)], vec![ExprId(1)]], // Only 2 inputs, need 3
        )];
        let expr_map = create_expr_map(3);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Result<Vec<Op<BabyBear>>, _> = lowerer.lower();

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

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![
                vec![ExprId(0)],
                vec![ExprId(1)],
                vec![ExprId(2)],
                vec![ExprId(3)],
            ], // 4 inputs, max 3
        )];
        let expr_map = create_expr_map(4);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Result<Vec<Op<BabyBear>>, _> = lowerer.lower();

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

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::MmcsVerify,
            vec![vec![ExprId(99)], vec![ExprId(1)], vec![ExprId(2)]], // ExprId(99) not in map
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
            vec![vec![ExprId(0)], vec![ExprId(88)], vec![ExprId(2)]], // ExprId(88) not in map
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
            vec![vec![ExprId(0)], vec![ExprId(1)], vec![ExprId(77)]], // ExprId(77) not in map
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

    #[test]
    fn test_poseidon_perm_lowering() {
        let mut config = BuilderConfig::new();
        config.enable_poseidon_perm();

        // Layout: in0..3 (1 elem each), out0..1 (empty), mmcs_index_sum (1 elem)
        let witness_exprs = vec![
            vec![ExprId(0)],
            vec![ExprId(1)],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![ExprId(2)],
        ];

        let ops = vec![(
            NonPrimitiveOpId(0),
            NonPrimitiveOpType::PoseidonPerm {
                new_start: true,
                merkle_path: false,
                mmcs_bit: false,
            },
            witness_exprs,
        )];
        let expr_map = create_expr_map(10);

        let lowerer = NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<BabyBear>> = lowerer.lower().unwrap();
        assert_eq!(result.len(), 1);

        match &result[0] {
            Op::NonPrimitiveOpWithExecutor {
                inputs,
                executor,
                outputs,
                ..
            } => {
                assert_eq!(
                    executor.op_type(),
                    &NonPrimitiveOpType::PoseidonPerm {
                        new_start: true,
                        merkle_path: false,
                        mmcs_bit: false,
                    }
                );
                assert!(outputs.is_empty());
                assert_eq!(inputs.len(), 7);
                // in0
                assert_eq!(inputs[0], vec![WitnessId(0)]);
                // in1
                assert_eq!(inputs[1], vec![WitnessId(1)]);
                // mmcs_index_sum
                assert_eq!(inputs[6], vec![WitnessId(2)]);
            }
            _ => panic!("Expected PoseidonPerm op"),
        }
    }
}
