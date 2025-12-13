use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
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
    pub fn new(
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
        F: Field + Clone + PrimeCharacteristicRing + PartialEq + Eq + Hash + 'static,
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

                    // Get the config to extract the execution function
                    let config = config_opt.ok_or_else(|| {
                        CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                            op: op_type.clone(),
                        }
                    })?;

                    // Get the execution function from config and wrap it as a PermComputer
                    let exec_fn = match config {
                        crate::op::NonPrimitiveOpConfig::PoseidonPerm(cfg) => cfg.exec.clone(),
                        _ => {
                            return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                                op: op_type.clone(),
                            });
                        }
                    };

                    // Convert legacy flags to explicit input mode
                    let input_mode = crate::ops::poseidon_perm::PoseidonInputMode::from_flags(
                        new_start,
                        merkle_path,
                        false, // mmcs_bit will be determined at runtime
                    );

                    let mut inputs_widx: Vec<Vec<WitnessId>> = Vec::with_capacity(6);
                    // Inputs: [in0, in1, in2, in3]
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

                    // Outputs: [out0, out1]
                    let mut outputs_widx: Vec<Vec<WitnessId>> = Vec::with_capacity(2);
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
                        outputs_widx.push(limb_widx);
                    }

                    // Wrap the execution function as a PermComputer
                    use crate::ops::poseidon_perm::PermComputerWrapper;
                    let computer: Arc<
                        dyn crate::ops::poseidon_perm::PermComputer<F> + Send + Sync,
                    > = Arc::new(PermComputerWrapper(exec_fn));

                    lowered_ops.push(Op::NonPrimitiveOpWithExecutor {
                        inputs: inputs_widx,
                        outputs: outputs_widx,
                        executor: Box::new(PoseidonPermExecutor::new(input_mode, computer)),
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

        let lowerer: NonPrimitiveLowerer<'_, BabyBear> =
            NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<BabyBear>> = lowerer.lower().unwrap();

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
        let mut config: BuilderConfig<BabyBear> = BuilderConfig::new();

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

        // Create a simple identity execute function for testing
        let execute_fn = alloc::sync::Arc::new(|input: &[BabyBear; 4]| *input);
        let poseidon_config =
            crate::op::NonPrimitiveOpConfig::PoseidonPerm(crate::op::PoseidonPermConfig::<
                BabyBear,
            > {
                exec: execute_fn,
            });
        config.enable_op(crate::op::NonPrimitiveOpType::PoseidonPerm, poseidon_config);

        let lowerer: NonPrimitiveLowerer<'_, BabyBear> =
            NonPrimitiveLowerer::new(&ops, &expr_map, &config);
        let result: Vec<Op<BabyBear>> = lowerer.lower().unwrap();
        assert_eq!(result.len(), 1);

        match &result[0] {
            Op::NonPrimitiveOpWithExecutor {
                inputs,
                executor,
                outputs,
                ..
            } => {
                assert_eq!(executor.op_type(), &NonPrimitiveOpType::PoseidonPerm);
                assert_eq!(outputs.len(), 2);
                assert_eq!(inputs.len(), 6);
                // in0
                assert_eq!(inputs[0], vec![WitnessId(0)]);
                // in1
                assert_eq!(inputs[1], vec![WitnessId(1)]);
                // mmcs_index_sum (at index 4)
                assert_eq!(inputs[4], vec![WitnessId(2)]);
                // mmcs_bit (at index 5)
                assert_eq!(inputs[5], vec![WitnessId(3)]);
            }
            _ => panic!("Expected PoseidonPerm op"),
        }
    }
}
