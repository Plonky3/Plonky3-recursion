use alloc::vec;
use alloc::vec::Vec;
use core::iter;

use itertools::izip;
use p3_field::{ExtensionField, Field};
use p3_symmetric::PseudoCompressionFunction;

use crate::circuit::Circuit;
use crate::op::{
    NonPrimitiveOp, NonPrimitiveOpConfig, NonPrimitiveOpPrivateData, NonPrimitiveOpType,
};
use crate::ops::MmcsVerifyConfig;
use crate::types::WitnessId;
use crate::{CircuitError, CircuitField};

/// MMCS Merkle path verification table.
///
/// Stores all Merkle path verification operations in the circuit.
/// Each operation proves a leaf is included in a Merkle tree.
#[derive(Debug, Clone)]
pub struct MmcsTrace<F> {
    /// All Merkle path verifications in this trace.
    ///
    /// Each entry is one complete leaf-to-root verification.
    pub mmcs_paths: Vec<MmcsPathTrace<F>>,
}

/// Single Merkle path verification trace.
///
/// Represents one complete leaf-to-root path verification.
/// Each row corresponds to one tree layer.
/// Some layers have extra rows for variable-sized matrices.
#[derive(Debug, Clone, Default)]
pub struct MmcsPathTrace<F> {
    /// Current hash state at each layer.
    ///
    /// Left operand in the hash compression function.
    /// State evolves as we climb the tree.
    pub left_values: Vec<Vec<F>>,

    /// Witness IDs for the leaf digest.
    ///
    /// Points to leaf values in the witness table.
    /// Intermediate states are private (not on witness bus).
    pub left_index: Vec<Vec<u32>>,

    /// Sibling hash values at each layer.
    ///
    /// Right operand in the hash compression function.
    /// Private data provided by the prover.
    pub right_values: Vec<Vec<F>>,

    /// Witness IDs for siblings (private, set to 0).
    pub right_index: Vec<u32>,

    /// Path direction bits.
    ///
    /// - false = hash(sibling, state),
    /// - true = hash(state, sibling).
    pub path_directions: Vec<bool>,

    /// Flags for extra hashing steps in variable-sized trees.
    pub is_extra: Vec<bool>,

    /// Final root digest value.
    ///
    /// Expected root after traversing the path.
    pub final_value: Vec<F>,

    /// Witness IDs for the root digest.
    pub final_index: Vec<u32>,
}

/// Private Merkle path witness data.
///
/// Prover's private information demonstrating a valid leaf-to-root path.
/// - It includes all intermediate hash states and sibling hashes.
/// - Some layers have extra siblings for variable-sized trees.
#[derive(Debug, Clone, PartialEq)]
pub struct MmcsPrivateData<F> {
    /// Hash states along the path: [leaf, state1, state2, ..., root].
    ///
    /// The sequence of states along the path, with an optional
    /// state when there was an extra leaf at that level of the path.
    pub path_states: Vec<(Vec<F>, Option<Vec<F>>)>,
    /// Sibling hashes at each layer.
    pub path_siblings: Vec<Vec<F>>,
    /// Direction bits encoding the leaf's position.
    ///
    /// - false = sibling on left,
    /// - true = sibling on right.
    pub directions: Vec<bool>,
}

impl<F: Field + Clone + Default> MmcsPrivateData<F> {
    /// Computes private data for a Merkle path verification.
    ///
    /// Takes public inputs and computes all intermediate hash states.
    /// Uses the compression function to hash at each layer.
    pub fn new<BF, C, const DIGEST_ELEMS: usize>(
        compress: &C,
        config: &MmcsVerifyConfig,
        leaves: &[Vec<F>],
        siblings: &[Vec<F>],
        directions: &[bool],
    ) -> Result<Self, CircuitError>
    where
        BF: Field,
        F: ExtensionField<BF> + Clone,
        C: PseudoCompressionFunction<[BF; DIGEST_ELEMS], 2>,
    {
        // Ensure we have one direction bit per sibling step.
        if siblings.len() != directions.len() {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: NonPrimitiveOpType::MmcsVerify,
                expected: siblings.len(),
                got: directions.len(),
            });
        }
        // Enforce configured maximum height to avoid creating unreachable path rows.
        if siblings.len() > config.max_tree_height {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: NonPrimitiveOpType::MmcsVerify,
                operation_index: 0,
                expected: alloc::format!(
                    "path length <= max_tree_height ({})",
                    config.max_tree_height
                ),
                got: alloc::format!("{}", siblings.len()),
            });
        }

        let mut private_data = Self {
            path_states: Vec::with_capacity(siblings.len() + 1),
            path_siblings: siblings.to_vec(),
            directions: directions.to_vec(),
        };
        let path_states = &mut private_data.path_states;

        // TODO: Add errors
        let mut state = leaves
            .first()
            .expect("There must be at leas to one leaf")
            .clone();
        if state.len() != config.ext_field_digest_elems {
            panic!(
                "The last leaf must be of size {}",
                config.ext_field_digest_elems
            )
        }
        // We need an empty leaf to replace the one we already assigned to the state;
        let empty_leaf = vec![];
        for (&dir, sibling, leaf) in izip!(
            directions.iter(),
            siblings.iter(),
            iter::once(&empty_leaf).chain(leaves.iter().skip(1))
        ) {
            path_states.push((
                state.to_vec(),
                // If there's a leaf at this depth we need to compute an extra state
                if leaf.is_empty() {
                    None
                } else {
                    let state_as_slice = config.ext_to_base(&state)?;
                    let leaf_as_slice = config.ext_to_base(leaf)?;
                    let new_state =
                        config.base_to_ext(&compress.compress([state_as_slice, leaf_as_slice]))?;
                    state = new_state.clone();
                    Some(new_state)
                },
            ));

            let state_as_slice = config.ext_to_base(&state)?;
            let sibling_as_slice = config.ext_to_base(sibling)?;

            let input = if dir {
                [state_as_slice, sibling_as_slice]
            } else {
                [sibling_as_slice, state_as_slice]
            };
            state = config.base_to_ext(&compress.compress(input))?;
        }
        // Append the final state (root). There's no extra state in the last step
        path_states.push((state.to_vec(), None));
        Ok(private_data)
    }

    /// Converts private data to trace format for AIR verification.
    ///
    /// References the witness table for leaf and root digests.
    /// Includes all intermediate states and direction bits.
    pub fn to_trace(
        &self,
        mmcs_config: &MmcsVerifyConfig,
        leaves: &[Vec<F>],
        leaves_wids: &[Vec<WitnessId>],
        root_wids: &[WitnessId],
    ) -> Result<MmcsPathTrace<F>, CircuitError> {
        let mut trace = MmcsPathTrace::default();

        // Get the witness indices for the leaf and root digests
        let leaf_indices: Vec<u32> = leaves_wids
            .first()
            .expect("There must be at least one leaf")
            .iter()
            .map(|wid| wid.0)
            .collect();
        let root_indices: Vec<u32> = root_wids.iter().map(|wid| wid.0).collect();

        debug_assert!(self.path_siblings.len() <= mmcs_config.max_tree_height);
        // Pad directions in case they start with 0s.
        let path_directions =
            (0..mmcs_config.max_tree_height).map(|i| *self.directions.get(i).unwrap_or(&false));

        // For each step in the Mmcs path (excluding the final state which is the root)
        debug_assert_eq!(self.path_states.len(), self.path_siblings.len() + 1);
        let empty_leaf = vec![];
        for ((state, extra_state), sibling, direction, leaf_indices, leaf) in izip!(
            self.path_states.iter().take(self.path_siblings.len()),
            self.path_siblings.iter(),
            path_directions,
            // TODO: For now we repeat the leaf indices here, but will need to add the right ones when we
            // ass CTLs to connect the Mmcs verify table.
            iter::repeat(leaf_indices),
            // Skip the first leaf, as it was already assigned to the first state
            iter::once(&empty_leaf).chain(leaves.iter().skip(1)),
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
            if let Some(extra_state) = extra_state {
                if leaf.len() != mmcs_config.ext_field_digest_elems {
                    return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                        op: NonPrimitiveOpType::MmcsVerify,
                        expected: mmcs_config.ext_field_digest_elems,
                        got: leaf.len(),
                    });
                }
                add_trace_row(extra_state, leaf, true);
            } else if !leaf.is_empty() {
                return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                    op: NonPrimitiveOpType::MmcsVerify,
                    expected: 0,
                    got: leaf.len(),
                });
            }
        }
        trace.final_value = self.path_states.last().cloned().unwrap_or_default().0;
        trace.final_index = root_indices;
        Ok(trace)
    }
}

/// Builder for generating MMCS traces.
pub struct MmcsTraceBuilder<'a, F> {
    circuit: &'a Circuit<F>,
    witness: &'a [Option<F>],
    non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],
}

impl<'a, F: CircuitField> MmcsTraceBuilder<'a, F> {
    /// Creates a new MMCS trace builder.
    pub fn new(
        circuit: &'a Circuit<F>,
        witness: &'a [Option<F>],
        non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],
    ) -> Self {
        Self {
            circuit,
            witness,
            non_primitive_op_private_data,
        }
    }

    fn get_witness(&self, index: &WitnessId) -> Result<F, CircuitError> {
        self.witness
            .get(index.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: *index })
    }

    /// Builds the MMCS trace from non-primitive operations.
    ///
    /// Validates that private data matches public witness values
    /// for leaf, root, and index. Converts private data to trace format.
    pub fn build(self) -> Result<MmcsTrace<F>, CircuitError> {
        let mut mmcs_paths = Vec::new();

        for op_idx in 0..self.circuit.non_primitive_ops.len() {
            // Copy out leaf/root to end immutable borrow immediately
            let NonPrimitiveOp::MmcsVerify {
                leaves,
                directions,
                root,
            } = &self.circuit.non_primitive_ops[op_idx]
            else {
                // Skip non-MMCS operations (e.g., HashAbsorb, HashSqueeze)
                continue;
            };

            if let Some(Some(NonPrimitiveOpPrivateData::MmcsVerify(private_data))) =
                self.non_primitive_op_private_data.get(op_idx).cloned()
            {
                let config = match self
                    .circuit
                    .enabled_ops
                    .get(&NonPrimitiveOpType::MmcsVerify)
                {
                    Some(NonPrimitiveOpConfig::MmcsVerifyConfig(config)) => Ok(config),
                    _ => Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                        op: NonPrimitiveOpType::MmcsVerify,
                    }),
                }?;

                // Validate that the witness data is consistent with public inputs
                // Check leaf values
                let witness_leaves: Vec<Vec<F>> = leaves
                    .iter()
                    .map(|leaf| {
                        leaf.iter()
                            .map(|wid| self.get_witness(wid))
                            .collect::<Result<Vec<F>, _>>()
                    })
                    .collect::<Result<_, _>>()?;

                let witness_directions = directions
                    .iter()
                    .map(|wid| self.get_witness(wid))
                    .collect::<Result<Vec<F>, _>>()?;
                // Check that the number of leaves is the same as the number of directions
                if witness_directions.len() != witness_leaves.len() {
                    return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                        op: NonPrimitiveOpType::MmcsVerify,
                        operation_index: op_idx,
                        expected: alloc::format!("{:?}", witness_directions.len()),
                        got: alloc::format!("{:?}", witness_leaves.len()),
                    });
                }

                // Check root values
                let witness_root: Vec<F> = root
                    .iter()
                    .map(|wid| self.get_witness(wid))
                    .collect::<Result<_, _>>()?;
                let computed_root = &private_data
                    .path_states
                    .last()
                    .ok_or(CircuitError::NonPrimitiveOpMissingPrivateData {
                        operation_index: op_idx,
                    })?
                    .0;
                if witness_root != *computed_root {
                    return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                        op: NonPrimitiveOpType::MmcsVerify,
                        operation_index: op_idx,
                        expected: alloc::format!("root: {witness_root:?}"),
                        got: alloc::format!("root: {computed_root:?}"),
                    });
                }

                let trace = private_data.to_trace(config, &witness_leaves, leaves, root)?;
                mmcs_paths.push(trace);
            } else {
                return Err(CircuitError::NonPrimitiveOpMissingPrivateData {
                    operation_index: op_idx,
                });
            }
        }

        Ok(MmcsTrace { mmcs_paths })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_symmetric::PseudoCompressionFunction;

    use super::*;
    use crate::NonPrimitiveOpPrivateData;
    use crate::builder::CircuitBuilder;
    use crate::errors::CircuitError;
    use crate::ops::MmcsOps;

    type F = BinomialExtensionField<BabyBear, 4>;

    #[derive(Clone, Debug)]
    /// A trivial compression function which compress [a, b] by returning a.
    struct MockCompression {}

    impl PseudoCompressionFunction<[BabyBear; 1], 2> for MockCompression {
        fn compress(&self, input: [[BabyBear; 1]; 2]) -> [BabyBear; 1] {
            input[0]
        }
    }

    #[test]
    fn test_mmcs_private_data() {
        let leaves = vec![
            vec![BabyBear::from_u64(1)],
            vec![BabyBear::from_u64(4)],
            vec![],
        ];
        let siblings = [
            vec![BabyBear::from_u64(2)],
            vec![BabyBear::from_u64(3)],
            vec![BabyBear::from_u64(5)],
        ];
        let directions = [false, true, true];

        let expected_private_data = MmcsPrivateData {
            path_states: vec![
                // The first state is the leaf.
                (vec![BabyBear::from_u64(1)], None),
                // At level 1 there is a leaf, so we do two compressions.
                // Since dir = false, the first input is [2, 1] and thus compress.compress(input) = 2.
                // The leaf is 4 thu input is [2, 4] and compress.compress(input) = 2
                (
                    vec![BabyBear::from_u64(2)],
                    Some(vec![BabyBear::from_u64(2)]),
                ),
                // direction = true and then input is [2, 5] compress.compress(input) = 2
                (vec![BabyBear::from_u64(2)], None),
                // final root state after the full path
                (vec![BabyBear::from_u64(2)], None),
            ],
            path_siblings: siblings.to_vec(),
            directions: directions.to_vec(),
        };

        let compress = MockCompression {};
        // Use a config that supports the path length used in this test.
        let config = MmcsVerifyConfig {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 3,
        };

        let private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &leaves,
            &siblings,
            &directions,
        )
        .unwrap();

        assert_eq!(private_data, expected_private_data);
    }

    #[test]
    fn test_mmcs_path_too_tall_rejected() {
        // Path length (3) exceeds configured max_tree_height (2)
        let compress = MockCompression {};
        let config = MmcsVerifyConfig {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 2,
        };

        let leaf = [vec![F::from_u64(1)], vec![], vec![]];
        let siblings = [
            vec![F::from_u64(2)],
            vec![F::from_u64(3)],
            vec![F::from_u64(4)],
        ];
        let directions = [false, true, false];

        let res = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &leaf,
            &siblings,
            &directions,
        );
        assert!(
            res.is_err(),
            "Expected path taller than max_tree_height to be rejected"
        );
    }

    // We need to add a less simple compression function for the next test.
    // Otherwise, it will not catch some errors.
    #[derive(Clone)]
    struct AddCompression {}

    impl PseudoCompressionFunction<[BabyBear; 1], 2> for AddCompression {
        fn compress(&self, input: [[BabyBear; 1]; 2]) -> [BabyBear; 1] {
            [input[0][0] + input[1][0]]
        }
    }

    #[test]
    fn test_mmcs_witness_validation() {
        let compress = AddCompression {};
        // Use config with max_tree_height=4 to support 3 layers + 1 extra sibling
        let config = MmcsVerifyConfig {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 4,
        };

        // Build circuit once
        let mut builder = CircuitBuilder::new();
        builder.enable_mmcs(&config);
        let leaves = vec![
            vec![builder.add_public_input()],
            vec![builder.add_public_input()],
            vec![],
        ];
        let directions = vec![
            builder.add_public_input(),
            builder.add_public_input(),
            builder.add_public_input(),
        ];
        let root = (0..config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<alloc::vec::Vec<_>>();
        let mmcs_op_id = builder
            .add_mmcs_verify(&leaves, &directions, &root)
            .unwrap();
        let circuit = builder.build().unwrap();

        // Create test data with 3 layers, varying directions, and one extra sibling
        let leaves_value = [vec![F::from_u64(42)], vec![F::from_u64(25)], vec![]];
        let siblings = [
            vec![F::from_u64(10)],
            vec![F::from_u64(20)],
            vec![F::from_u64(30)],
        ];
        // Directions [false, true, false] corresponds to index 0b010 = 2
        let directions = [true, true, false];

        // Compute what the CORRECT root should be
        let correct_private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &leaves_value,
            &siblings,
            &directions,
        )
        .unwrap();
        let correct_root = &correct_private_data.path_states.last().unwrap().0;

        // Helper to run test with given inputs and private data
        let run_test = |leaves: &[Vec<F>], root: &[F], private_data: &MmcsPrivateData<F>| {
            let mut public_inputs = vec![];
            public_inputs.extend(leaves.iter().flatten());
            public_inputs.extend(directions.map(F::from_bool));
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
        let result = run_test(&leaves_value, correct_root, &correct_private_data);
        assert!(
            result.is_ok(),
            "Valid witness should be accepted but got {:?}",
            result
        );

        // Test 2: Invalid witness (wrong root) should be rejected
        let wrong_root = [F::from_u64(999)];
        match run_test(&leaves_value, &wrong_root, &correct_private_data) {
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
        let wrong_leaves_value = [vec![F::from_u64(998)], vec![F::from_u64(999)], vec![]];
        let wrong_private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &wrong_leaves_value,
            &siblings,
            &directions,
        )
        .unwrap();

        match run_test(&leaves_value, correct_root, &wrong_private_data) {
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

    #[test]
    fn test_mmcs_traces_fields() {
        let compress = MockCompression {};
        let config = MmcsVerifyConfig {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 4,
        };

        // Build circuit
        let mut builder = CircuitBuilder::new();
        builder.enable_mmcs(&config);
        let leaves_expr = [
            vec![builder.add_public_input()],
            vec![],
            vec![builder.add_public_input()],
            vec![],
        ];
        let directions_expr = [
            builder.add_public_input(),
            builder.add_public_input(),
            builder.add_public_input(),
            builder.add_public_input(),
        ];
        let root_exprs = (0..config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<alloc::vec::Vec<_>>();
        let mmcs_op_id = builder
            .add_mmcs_verify(&leaves_expr, &directions_expr, &root_exprs)
            .unwrap();
        let circuit = builder.build().unwrap();

        // 4 layers; one extra sibling at layer 1; directions 0b1010
        let leaves_value = [vec![F::from_u64(7)], vec![], vec![F::from_u64(25)], vec![]];
        let siblings = [
            vec![F::from_u64(10)],
            vec![F::from_u64(20)],
            vec![F::from_u64(30)],
            vec![F::from_u64(40)],
        ];
        let directions = [false, true, false, true];

        // Compute private data and expected values
        let private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &leaves_value,
            &siblings,
            &directions,
        )
        .unwrap();
        let correct_root = &private_data.path_states.last().unwrap().0;

        // Run circuit
        let mut public_inputs = vec![];
        public_inputs.extend(leaves_value.iter().flatten());
        public_inputs.extend(directions.map(F::from_bool));
        public_inputs.extend(correct_root.iter().copied());
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).unwrap();
        runner
            .set_non_primitive_op_private_data(
                mmcs_op_id,
                NonPrimitiveOpPrivateData::MmcsVerify(private_data.clone()),
            )
            .unwrap();
        let traces = runner.run().unwrap();

        // Validate trace fields
        assert_eq!(traces.mmcs_trace.mmcs_paths.len(), 1);
        let path = &traces.mmcs_trace.mmcs_paths[0];

        // Expected expansions for directions, is_extra, and right_values
        let mut expected_dirs = alloc::vec::Vec::new();
        let mut expected_is_extra = alloc::vec::Vec::new();
        let mut expected_right_values = alloc::vec::Vec::new();
        // We skip the first leaf replacing it by an empty vec.
        let empty_leaf = vec![];
        for (dir, sibling, leaf) in izip!(
            directions.iter(),
            siblings.iter(),
            iter::once(&empty_leaf).chain(leaves_value.iter().skip(1))
        ) {
            expected_dirs.push(*dir);
            expected_is_extra.push(false);
            expected_right_values.push(sibling.clone());
            if !leaf.is_empty() {
                expected_dirs.push(*dir);
                expected_is_extra.push(true);
                expected_right_values.push(leaf.clone());
            }
        }

        assert_eq!(path.path_directions, expected_dirs);
        assert_eq!(path.is_extra, expected_is_extra);
        assert_eq!(path.right_values, expected_right_values);
        assert!(path.right_index.iter().all(|&x| x == 0));

        // Left values follow private_data path states (with intermediate state on extra row)
        let mut expected_left_values = alloc::vec::Vec::new();
        for ((state, extra_state), leaf) in private_data
            .path_states
            .iter()
            .zip(iter::once(&empty_leaf).chain(leaves_value.iter().skip(1)))
        {
            expected_left_values.push(state.clone());
            if let Some(extra_state) = extra_state {
                assert!(!leaf.is_empty()); // Ensure that there was a leaf for producing the extra state
                expected_left_values.push(extra_state.clone());
            } else {
                assert!(leaf.is_empty()); // No extra state means there was no leaf at this level. 
            }
        }
        assert_eq!(path.left_values, expected_left_values);

        // Final value and final indices width
        assert_eq!(path.final_value, *correct_root);
        assert_eq!(path.final_index.len(), config.ext_field_digest_elems);
    }
}
