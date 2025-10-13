use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use itertools::izip;
use p3_field::{ExtensionField, Field};
use p3_symmetric::PseudoCompressionFunction;

use crate::CircuitError;
use crate::circuit::{Circuit, CircuitField};
use crate::op::{
    NonPrimitiveOp, NonPrimitiveOpConfig, NonPrimitiveOpPrivateData, NonPrimitiveOpType,
};
use crate::ops::MmcsVerifyConfig;
use crate::types::WitnessId;

#[derive(Debug, Clone)]
pub struct MmcsTrace<F> {
    /// All the mmcs paths computed in this trace
    pub mmcs_paths: Vec<MmcsPathTrace<F>>,
}

/// A single Mmcs Path verification table
#[derive(Debug, Clone, Default)]
pub struct MmcsPathTrace<F> {
    /// Left operand values (current hash). A vector of field elements representing a digest.
    pub left_values: Vec<Vec<F>>,
    /// Left operand indices.
    pub left_index: Vec<Vec<u32>>,
    /// Right operand values (sibling hash). A vector of field elements representing a digest
    pub right_values: Vec<Vec<F>>,
    /// Right operand indices (not on witness bus - private)
    pub right_index: Vec<u32>,
    /// Path direction bits (0 = left, 1 = right) - private
    pub path_directions: Vec<bool>,
    /// Indicates if the current row is processing a smaller
    /// matrix of the Mmcs.
    pub is_extra: Vec<bool>,
    /// Final digest after traversing the path (expected root value).
    pub final_value: Vec<F>,
    /// Witness indices corresponding to the final digest wires.
    pub final_index: Vec<u32>,
}

/// Private Mmcs path data for Mmcs verification
///
/// This represents the private witness information that the prover needs
/// to demonstrate knowledge of a valid Mmcs path from leaf to root.
#[derive(Debug, Clone, PartialEq)]
pub struct MmcsPrivateData<F> {
    /// Sibling and state hash values along the Mmcs path
    ///
    /// The sequence of states along the path.
    pub path_states: Vec<Vec<F>>,
    /// The sequence of sibling with optional tuple of extra state
    /// and siblings, present when the Mmcs has a smaller matrix at this step.
    pub path_siblings: Vec<SiblingWithExtra<F>>,
}

type SiblingWithExtra<F> = (Vec<F>, Option<(Vec<F>, Vec<F>)>);

impl<F: Field + Clone + Default> MmcsPrivateData<F> {
    /// Computes the private mmcs data for the mmcs path defined by `leaf`, `siblings` and `directions`,
    /// for a given a compression function.
    pub fn new<BF, C, const DIGEST_ELEMS: usize>(
        compress: &C,
        config: &MmcsVerifyConfig,
        leaf: &[F],
        siblings: &[(Vec<F>, Option<Vec<F>>)],
        directions: &[bool],
    ) -> Result<Self, CircuitError>
    where
        BF: Field,
        F: ExtensionField<BF> + Clone,
        C: PseudoCompressionFunction<[BF; DIGEST_ELEMS], 2>,
    {
        // The last sibling can't contain an extra sibling
        if let Some((_, extra_sibling)) = siblings.last()
            && extra_sibling.is_some()
        {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: NonPrimitiveOpType::MmcsVerify,
                operation_index: 0, // Unknown at construction time
                expected: "last sibling should not have extra sibling (None)".to_string(),
                got: format!("last sibling has extra sibling: {extra_sibling:?}"),
            });
        }
        // Worst case we push two states per step (if `other_sibling` is Some).
        let mut private_data = Self {
            path_states: Vec::with_capacity(siblings.len() + 1),
            path_siblings: Vec::with_capacity(siblings.len()),
        };
        let path_states = &mut private_data.path_states;
        let path_siblings = &mut private_data.path_siblings;

        let mut state = leaf.to_vec();
        for (&dir, (sibling, other)) in directions.iter().zip(siblings.iter()) {
            path_states.push(state.to_vec());

            let state_as_slice = config.ext_to_base(&state)?;
            let sibling_as_slice = config.ext_to_base(sibling)?;

            let input = if dir {
                [state_as_slice, sibling_as_slice]
            } else {
                [sibling_as_slice, state_as_slice]
            };
            state = config.base_to_ext(&compress.compress(input))?;

            // Optional second hash when the step has an extra sibling.
            if let Some(other) = other {
                let intermediate = state.to_vec();
                path_siblings.push((
                    sibling.to_vec(),
                    Some((intermediate.clone(), other.clone())),
                ));
                let state_as_slice = config.ext_to_base(&intermediate)?;
                let other = config.ext_to_base(other)?;
                state = config.base_to_ext(&compress.compress([state_as_slice, other]))?;
            } else {
                path_siblings.push((sibling.to_vec(), None));
            }
        }
        // Append the final state (root).
        path_states.push(state.to_vec());
        Ok(private_data)
    }

    /// Builds a valid `MmcsVerifyAir` trace from a private Mmcs proof,
    /// given also the leaf's digest wires and value used in the circuit, and the leaf's index in the tree.
    pub fn to_trace(
        &self,
        mmcs_config: &MmcsVerifyConfig,
        leaf_wires: &[WitnessId],
        root_wires: &[WitnessId],
        index_value: u32,
    ) -> Result<MmcsPathTrace<F>, CircuitError> {
        let mut trace = MmcsPathTrace::default();

        // Get the adrresses of the leaf wires
        let leaf_indices: Vec<u32> = leaf_wires.iter().map(|wid| wid.0).collect();
        let root_indices: Vec<u32> = root_wires.iter().map(|wid| wid.0).collect();

        debug_assert!(self.path_siblings.len() <= mmcs_config.max_tree_height);
        let path_directions = (0..mmcs_config.max_tree_height).map(|i| (index_value >> i) & 1 == 1);

        // For each step in the Mmcs path (excluding the final state which is the root)
        debug_assert_eq!(self.path_states.len(), self.path_siblings.len() + 1);
        for (state, (sibling, extra), direction) in izip!(
            self.path_states.iter().take(self.path_siblings.len()),
            self.path_siblings.iter(),
            path_directions
        ) {
            // Add a row to the trace.
            let mut add_trace_row = |left_v: &Vec<F>, right_v: &Vec<F>, is_extra_flag: bool| {
                // Current hash becomes left operand
                trace.left_values.push(left_v.clone());
                // Points to witness bus
                trace.left_index.push(leaf_indices.clone());
                // Sibling becomes right operand (private data - not on witness bus)
                trace.right_values.push(right_v.clone());
                // Not on witness bus - private data
                trace.right_index.push(0);
                trace.path_directions.push(direction);
                trace.is_extra.push(is_extra_flag);
            };

            // Add the primary trace row for the current Merkle path step.
            add_trace_row(state, sibling, false);

            // If there's an extra sibling (due to tree structure), add another trace row.
            if let Some((extra_state, extra_sibling)) = extra {
                add_trace_row(extra_state, extra_sibling, true);
            }
        }
        trace.final_value = self.path_states.last().cloned().unwrap_or_default();
        trace.final_index = root_indices;
        Ok(trace)
    }
}

/// Generate MMCS trace from circuit runner state
pub fn generate_mmcs_trace<F: CircuitField>(
    circuit: &Circuit<F>,
    _witness: &[Option<F>],
    non_primitive_op_private_data: &[Option<NonPrimitiveOpPrivateData<F>>],
    get_witness: impl Fn(WitnessId) -> Result<F, CircuitError>,
) -> Result<MmcsTrace<F>, CircuitError> {
    let mut mmcs_paths = Vec::new();

    // Process each complex operation by index to avoid borrowing conflicts
    for op_idx in 0..circuit.non_primitive_ops.len() {
        // Copy out leaf/root to end immutable borrow immediately
        let NonPrimitiveOp::MmcsVerify { leaf, index, root } = &circuit.non_primitive_ops[op_idx];

        if let Some(Some(NonPrimitiveOpPrivateData::MmcsVerify(private_data))) =
            non_primitive_op_private_data.get(op_idx).cloned()
        {
            let config = match circuit.enabled_ops.get(&NonPrimitiveOpType::MmcsVerify) {
                Some(NonPrimitiveOpConfig::MmcsVerifyConfig(config)) => Ok(config),
                _ => Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                    op: NonPrimitiveOpType::MmcsVerify,
                }),
            }?;

            // Validate that the witness data is consistent with public inputs
            // Check leaf values
            let witness_leaf: Vec<F> = leaf
                .iter()
                .map(|&wid| get_witness(wid))
                .collect::<Result<_, _>>()?;
            let private_data_leaf = private_data.path_states.first().ok_or(
                CircuitError::NonPrimitiveOpMissingPrivateData {
                    operation_index: op_idx,
                },
            )?;
            if witness_leaf != *private_data_leaf {
                return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                    op: NonPrimitiveOpType::MmcsVerify,
                    operation_index: op_idx,
                    expected: alloc::format!("leaf: {witness_leaf:?}"),
                    got: alloc::format!("leaf: {private_data_leaf:?}"),
                });
            }

            // Check root values
            let witness_root: Vec<F> = root
                .iter()
                .map(|&wid| get_witness(wid))
                .collect::<Result<_, _>>()?;
            let computed_root = private_data.path_states.last().ok_or(
                CircuitError::NonPrimitiveOpMissingPrivateData {
                    operation_index: op_idx,
                },
            )?;
            if witness_root != *computed_root {
                return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                    op: NonPrimitiveOpType::MmcsVerify,
                    operation_index: op_idx,
                    expected: alloc::format!("root: {witness_root:?}"),
                    got: alloc::format!("root: {computed_root:?}"),
                });
            }

            let trace = private_data.to_trace(config, leaf, root, index.0)?;
            mmcs_paths.push(trace);
        } else {
            return Err(CircuitError::NonPrimitiveOpMissingPrivateData {
                operation_index: op_idx,
            });
        }
    }

    Ok(MmcsTrace { mmcs_paths })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_symmetric::PseudoCompressionFunction;

    use super::*;
    use crate::builder::CircuitBuilder;
    use crate::ops::MmcsOps;

    #[derive(Clone, Debug)]
    struct MockCompression {}

    impl PseudoCompressionFunction<[BabyBear; 1], 2> for MockCompression {
        fn compress(&self, input: [[BabyBear; 1]; 2]) -> [BabyBear; 1] {
            input[0]
        }
    }

    #[test]
    fn test_mmcs_private_data() {
        let leaf = [BabyBear::from_u64(1)];
        let siblings = [
            (vec![BabyBear::from_u64(2)], None),
            (
                vec![BabyBear::from_u64(3)],
                Some(vec![BabyBear::from_u64(4)]),
            ),
            (vec![BabyBear::from_u64(5)], None),
        ];
        let directions = [false, true, true];

        let expected_private_data = MmcsPrivateData {
            path_states: vec![
                // The first state is the leaf
                vec![BabyBear::from_u64(1)],
                // here there's an extra sibling, so we do two compressions.
                // Since dir = false, the first input is [2, 1] and thus compress.compress(input) = 2.
                // The extra input is [2, 4] and compress.compress(input) = 2
                vec![BabyBear::from_u64(2)],
                // direction = true and then input is [2, 5] compress.compress(input) = 2
                vec![BabyBear::from_u64(2)],
                // final root state after the full path
                vec![BabyBear::from_u64(2)],
            ],
            path_siblings: vec![
                (vec![BabyBear::from_u64(2)], None), // The first sibling
                // The second sibling with the extra state and sibling
                (
                    vec![BabyBear::from_u64(3)],
                    Some((vec![BabyBear::from_u64(2)], vec![BabyBear::from_u64(4)])),
                ),
                // The third sibling
                (vec![BabyBear::from_u64(5)], None),
            ],
        };

        let compress = MockCompression {};
        let config = MmcsVerifyConfig::mock_config();

        let private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &leaf,
            &siblings,
            &directions,
        )
        .unwrap();

        assert_eq!(private_data, expected_private_data);
    }

    #[test]
    fn test_mmcs_witness_validation() {
        use crate::errors::CircuitError;

        type F = BinomialExtensionField<BabyBear, 4>;

        let compress = MockCompression {};
        // Use config with max_tree_height=4 to support 3 layers + 1 extra sibling
        let config = MmcsVerifyConfig {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 4,
        };

        // Build circuit once
        let mut builder = CircuitBuilder::new();
        builder.enable_mmcs(&config);
        let leaf = (0..config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<alloc::vec::Vec<_>>();
        let index = builder.add_public_input();
        let root = (0..config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<alloc::vec::Vec<_>>();
        let mmcs_op_id = builder.add_mmcs_verify(&leaf, &index, &root).unwrap();
        let circuit = builder.build().unwrap();

        // Create test data with 3 layers, varying directions, and one extra sibling
        let leaf_value = [F::from_u64(42)];
        let siblings = [
            // Layer 0: direction=false, no extra sibling
            (vec![F::from_u64(10)], None),
            // Layer 1: direction=true, WITH extra sibling
            (vec![F::from_u64(20)], Some(vec![F::from_u64(25)])),
            // Layer 2: direction=false, no extra sibling
            (vec![F::from_u64(30)], None),
        ];
        let directions = [false, true, false];

        // Compute what the CORRECT root should be
        let correct_private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &leaf_value,
            &siblings,
            &directions,
        )
        .unwrap();
        let correct_root = correct_private_data.path_states.last().unwrap();

        // Index corresponds to directions: [false, true, false] -> 0b010 = 2
        let index_value = F::from_u64(
            directions
                .iter()
                .enumerate()
                .filter(|(_, dir)| **dir)
                .map(|(i, _)| 1 << i)
                .sum::<u64>(),
        );

        // Helper to run test with given inputs and private data
        let run_test = |leaf: &[F], root: &[F], private_data: &MmcsPrivateData<F>| {
            let mut public_inputs = vec![];
            public_inputs.extend(leaf);
            public_inputs.push(index_value);
            public_inputs.extend(root);

            let mut runner = circuit.clone().runner();
            runner.set_public_inputs(&public_inputs).unwrap();
            runner
                .set_non_primitive_op_private_data(
                    mmcs_op_id,
                    NonPrimitiveOpPrivateData::MmcsVerify(private_data.clone()),
                )
                .unwrap();
            runner.run()
        };

        // Test 1: Valid witness should be accepted
        assert!(
            run_test(&leaf_value, correct_root, &correct_private_data).is_ok(),
            "Valid witness should be accepted"
        );

        // Test 2: Invalid witness (wrong root) should be rejected
        let wrong_root = [F::from_u64(999)];
        match run_test(&leaf_value, &wrong_root, &correct_private_data) {
            Err(CircuitError::IncorrectNonPrimitiveOpPrivateData { .. }) => {
                // Expected! The witness validation caught the mismatch
            }
            Ok(_) => panic!("Expected witness validation to fail, but it succeeded!"),
            Err(e) => panic!(
                "Expected IncorrectNonPrimitiveOpPrivateData error, got: {:?}",
                e
            ),
        }

        // Test 3: Invalid witness (wrong leaf) should be rejected
        let wrong_leaf_value = [F::from_u64(999)];
        let wrong_private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &wrong_leaf_value,
            &siblings,
            &directions,
        )
        .unwrap();

        match run_test(&leaf_value, correct_root, &wrong_private_data) {
            Err(CircuitError::IncorrectNonPrimitiveOpPrivateData { .. }) => {
                // Expected! The witness validation caught the mismatch
            }
            Ok(_) => {
                panic!("Expected witness validation to fail for wrong leaf, but it succeeded!")
            }
            Err(e) => panic!(
                "Expected IncorrectNonPrimitiveOpPrivateData error, got: {:?}",
                e
            ),
        }
    }
}
