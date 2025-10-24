use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use itertools::izip;
use p3_field::{ExtensionField, Field};
use p3_symmetric::PseudoCompressionFunction;

use crate::CircuitError;
use crate::circuit::{Circuit, CircuitField};
use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpPrivateData, NonPrimitiveOpType, Op};
use crate::ops::MmcsVerifyConfig;
use crate::types::{NonPrimitiveOpId, WitnessId};

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
    /// Each state results from hashing the previous state with a sibling.
    pub path_states: Vec<Vec<F>>,

    /// Sibling hashes at each layer.
    ///
    /// Optional extra (state, sibling) pair for variable-sized MMCS layers.
    pub path_siblings: Vec<SiblingWithExtra<F>>,

    /// Direction bits encoding the leaf's position.
    ///
    /// - false = sibling on left,
    /// - true = sibling on right.
    pub directions: Vec<bool>,
}

type SiblingWithExtra<F> = (Vec<F>, Option<(Vec<F>, Vec<F>)>);

impl<F: Field + Clone + Default> MmcsPrivateData<F> {
    /// Computes private data for a Merkle path verification.
    ///
    /// Takes public inputs and computes all intermediate hash states.
    /// Uses the compression function to hash at each layer.
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
                operation_index: NonPrimitiveOpId(0),
                expected: alloc::format!(
                    "path length <= max_tree_height ({})",
                    config.max_tree_height
                ),
                got: alloc::format!("{}", siblings.len()),
            });
        }
        // The last sibling can't contain an extra sibling
        if let Some((_, extra_sibling)) = siblings.last()
            && extra_sibling.is_some()
        {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: NonPrimitiveOpType::MmcsVerify,
                operation_index: NonPrimitiveOpId(0), // Unknown at construction time
                expected: "last sibling should not have extra sibling (None)".to_string(),
                got: format!("last sibling has extra sibling: {extra_sibling:?}"),
            });
        }
        // Worst case we push two states per step (if `other_sibling` is Some).
        let mut private_data = Self {
            path_states: Vec::with_capacity(siblings.len() + 1),
            path_siblings: Vec::with_capacity(siblings.len()),
            directions: directions.to_vec(),
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

    /// Converts private data to trace format for AIR verification.
    ///
    /// References the witness table for leaf and root digests.
    /// Includes all intermediate states and direction bits.
    pub fn to_trace(
        &self,
        mmcs_config: &MmcsVerifyConfig,
        leaf_wids: &[WitnessId],
        root_wids: &[WitnessId],
    ) -> Result<MmcsPathTrace<F>, CircuitError> {
        let mut trace = MmcsPathTrace::default();

        // Get the witness indices for the leaf and root digests
        let leaf_indices: Vec<u32> = leaf_wids.iter().map(|wid| wid.0).collect();
        let root_indices: Vec<u32> = root_wids.iter().map(|wid| wid.0).collect();

        debug_assert!(self.path_siblings.len() <= mmcs_config.max_tree_height);
        let path_directions =
            (0..mmcs_config.max_tree_height).map(|i| *self.directions.get(i).unwrap_or(&false));

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

/// Builder for generating MMCS traces.
pub struct MmcsTraceBuilder<'a, F> {
    circuit: &'a Circuit<F>,
    non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],
}

impl<'a, F: CircuitField> MmcsTraceBuilder<'a, F> {
    /// Creates a new MMCS trace builder.
    pub fn new(
        circuit: &'a Circuit<F>,
        non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],
    ) -> Self {
        Self {
            circuit,
            non_primitive_op_private_data,
        }
    }

    /// Builds the MMCS trace by scanning non-primitive ops with MMCS executors.
    pub fn build(self) -> Result<MmcsTrace<F>, CircuitError> {
        let mut mmcs_paths = Vec::new();

        let config = match self
            .circuit
            .enabled_ops
            .get(&NonPrimitiveOpType::MmcsVerify)
        {
            Some(NonPrimitiveOpConfig::MmcsVerifyConfig(config)) => config,
            _ => return Ok(MmcsTrace { mmcs_paths }),
        };

        for op in &self.circuit.non_primitive_ops {
            let Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs: _outputs,
                executor,
                op_id,
            } = op
            else {
                continue;
            };
            if executor.op_type() != &NonPrimitiveOpType::MmcsVerify {
                continue;
            }

            let ext = config.ext_field_digest_elems;
            let leaf = &inputs[..ext];
            let root = &inputs[ext + 1..ext + 1 + ext];

            let private_data = self
                .non_primitive_op_private_data
                .get(op_id.0 as usize)
                .and_then(|opt| opt.as_ref())
                .ok_or(CircuitError::NonPrimitiveOpMissingPrivateData {
                    operation_index: *op_id,
                })?;
            let NonPrimitiveOpPrivateData::MmcsVerify(priv_data) = private_data;

            let trace = priv_data.to_trace(config, leaf, root)?;
            mmcs_paths.push(trace);
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
            &leaf,
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

        let leaf = [F::from_u64(1)];
        let siblings = [
            (vec![F::from_u64(2)], None),
            (vec![F::from_u64(3)], None),
            (vec![F::from_u64(4)], None),
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

    #[test]
    fn test_mmcs_witness_validation() {
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

    #[test]
    fn test_mmcs_traces_fields() -> Result<(), CircuitError> {
        let compress = MockCompression {};
        let config = MmcsVerifyConfig {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 4,
        };

        // Build circuit
        let mut builder = CircuitBuilder::new();
        builder.enable_mmcs(&config);
        let leaf_exprs = (0..config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<alloc::vec::Vec<_>>();
        let index_expr = builder.add_public_input();
        let root_exprs = (0..config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<alloc::vec::Vec<_>>();
        let mmcs_op_id = builder
            .add_mmcs_verify(&leaf_exprs, &index_expr, &root_exprs)
            .unwrap();
        let circuit = builder
            .build()
            .map_err(|e| CircuitError::InvalidCircuit { error: e })?;

        // 4 layers; one extra sibling at layer 1; directions 0b1010
        let leaf_value = [F::from_u64(7)];
        let siblings = [
            (vec![F::from_u64(10)], None),
            (vec![F::from_u64(20)], Some(vec![F::from_u64(25)])),
            (vec![F::from_u64(30)], None),
            (vec![F::from_u64(40)], None),
        ];
        let directions = [false, true, false, true];

        // Compute private data and expected values
        let private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &leaf_value,
            &siblings,
            &directions,
        )
        .unwrap();
        let correct_root = private_data.path_states.last().unwrap();
        let index_value = F::from_u64(
            directions
                .iter()
                .enumerate()
                .filter(|(_, d)| **d)
                .map(|(i, _)| 1u64 << i)
                .sum(),
        );

        // Run circuit
        let mut public_inputs = vec![];
        public_inputs.extend(leaf_value);
        public_inputs.push(index_value);
        public_inputs.extend(correct_root.iter().copied());
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public_inputs).unwrap();
        runner
            .set_non_primitive_op_private_data(
                mmcs_op_id,
                NonPrimitiveOpPrivateData::MmcsVerify(private_data.clone()),
            )
            .unwrap();
        let traces = runner.run()?;

        // Validate trace fields
        assert_eq!(traces.mmcs_trace.mmcs_paths.len(), 1);
        let path = &traces.mmcs_trace.mmcs_paths[0];

        // Expected expansions for directions, is_extra, and right_values
        let mut expected_dirs = alloc::vec::Vec::new();
        let mut expected_is_extra = alloc::vec::Vec::new();
        let mut expected_right_values = alloc::vec::Vec::new();
        for (i, (sib, extra)) in siblings.iter().enumerate() {
            expected_dirs.push(directions[i]);
            expected_is_extra.push(false);
            expected_right_values.push(sib.clone());
            if let Some(extra_sib) = extra {
                expected_dirs.push(directions[i]);
                expected_is_extra.push(true);
                expected_right_values.push(extra_sib.clone());
            }
        }

        assert_eq!(path.path_directions, expected_dirs);
        assert_eq!(path.is_extra, expected_is_extra);
        assert_eq!(path.right_values, expected_right_values);
        assert!(path.right_index.iter().all(|&x| x == 0));

        // Left indices are consistent across rows
        assert!(!path.left_index.is_empty());
        let first_left_idx = &path.left_index[0];
        for idx in &path.left_index {
            assert_eq!(idx, first_left_idx);
        }

        // Left values follow private_data path states (with intermediate state on extra row)
        let mut expected_left_values = alloc::vec::Vec::new();
        for (i, (_sib, extra)) in siblings.iter().enumerate() {
            expected_left_values.push(private_data.path_states[i].clone());
            if let Some((extra_state, _)) = &private_data.path_siblings[i].1 {
                assert!(extra.is_some());
                expected_left_values.push(extra_state.clone());
            }
        }
        assert_eq!(path.left_values, expected_left_values);

        // Final value and final indices width
        assert_eq!(path.final_value, *correct_root);
        assert_eq!(path.final_index.len(), config.ext_field_digest_elems);

        Ok(())
    }
}
