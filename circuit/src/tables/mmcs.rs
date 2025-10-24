use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::fmt::Debug;
use core::iter;

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
#[derive(Clone)]
pub struct MmcsPrivateData<F> {
    // /// Hash states along the path: [leaf, state1, state2, ..., root].
    // ///
    // /// The sequence of states along the path, with an optional
    // /// state when there was an extra leaf at that level of the path.
    // pub path_states: Vec<(Vec<F>, Option<Vec<F>>)>,
    /// Sibling hashes at each layer.
    pub path_siblings: Vec<Vec<F>>,

    pub compress: Arc<dyn MmcsPrivatedataCompressionFunction<F>>,
    // /// Direction bits encoding the leaf's position.
    // ///
    // // /// - false = sibling on left,
    // // /// - true = sibling on right.
    // pub directions: Vec<bool>,
}

pub trait MmcsPrivatedataCompressionFunction<F>:
    Fn([&[F]; 2]) -> Result<Vec<F>, CircuitError>
{
}

impl<F, C: Fn([&[F]; 2]) -> Result<Vec<F>, CircuitError>> MmcsPrivatedataCompressionFunction<F>
    for C
{
}

impl<F: Debug> Debug for MmcsPrivateData<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MmcsPrivateData")
            .field("path_siblings", &self.path_siblings)
            .finish()
    }
}

impl<F> PartialEq for MmcsPrivateData<F>
where
    F: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.path_siblings == other.path_siblings
    }
}

type OneOrTwoStates<F> = (Vec<F>, Option<Vec<F>>);

impl<F: Field + Clone + Default> MmcsPrivateData<F> {
    /// Computes the private data required for MMCS path verification.
    ///
    /// This function takes public inputs and calculates all intermediate hash states
    /// along the MMCS path.
    ///
    /// At each level:
    /// - The next state is computed using the compression function `compress.compress()`.
    /// - The order of inputs depends on the `direction`:
    ///   - If `direction` is `false`, compute the next state as `compress.compress(sibling, state)`.
    ///   - If `direction` is `true`, compute the next state as `compress.compress(state, sibling)`.
    ///
    /// If a leaf exists at the current level:
    /// - On the first level, the leaf is directly assigned as the current state.
    /// - On subsequent levels, the next state is obtained by additionally compressing the next state with the leaf.
    ///
    /// **Parameters**
    /// - `compress`: Compression function mapping `[[BF, DIGEST_ELEMS]; 2]` → `[BF, DIGEST_ELEMS]`.
    /// - `config`: MMCS configuration parameters.
    /// - `leaves`: A slice of vectors. Each entry is either empty or of size `DIGEST_ELEMS`,
    ///   indicating whether a leaf is present at that level.
    /// - `siblings`: A slice containing the sibling node for each level.
    /// - `directions`: A list of booleans determining the order of inputs to `compress()`
    ///   at each level.
    pub fn new<BF, C, const DIGEST_ELEMS: usize>(
        config: &MmcsVerifyConfig,
        siblings: &[Vec<F>],
        compress: C,
    ) -> Self
    where
        BF: Field,
        F: ExtensionField<BF> + Clone,
        C: PseudoCompressionFunction<[BF; DIGEST_ELEMS], 2> + 'static,
    {
        let config = config.clone();
        Self {
            path_siblings: siblings.to_vec(),
            compress: Arc::new(move |[left, right]| {
                let left_as_slice = config.ext_to_base(left)?;
                let right_as_slice = config.ext_to_base(right)?;
                let result = compress.compress([left_as_slice, right_as_slice]);
                config.base_to_ext(&result)
            }),
        }
    }

    pub fn compute_all_states(
        &self,
        config: &MmcsVerifyConfig,
        leaves: &[Vec<F>],
        directions: &[bool],
    ) -> Result<Vec<OneOrTwoStates<F>>, CircuitError> {
        // Ensure we have one direction bit per sibling step.
        if self.path_siblings.len() != directions.len() {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: NonPrimitiveOpType::MmcsVerify,
                expected: self.path_siblings.len().to_string(),
                got: directions.len(),
            });
        }
        // Enforce configured maximum height to avoid creating unreachable path rows.
        if self.path_siblings.len() > config.max_tree_height {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: NonPrimitiveOpType::MmcsVerify,
                operation_index: NonPrimitiveOpId(0),
                expected: alloc::format!(
                    "path length <= max_tree_height ({})",
                    config.max_tree_height
                ),
                got: alloc::format!("{}", self.path_siblings.len()),
            });
        }
        let mut path_states = Vec::with_capacity(self.path_siblings.len() + 1);

        let mut state = leaves
            .first()
            .expect("There must be at leas to one leaf")
            .clone();

        // Ensure there's no leaf in the last level
        if let Some(last) = leaves.last()
            && !last.is_empty()
        {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: NonPrimitiveOpType::MmcsVerify,
                expected: "[]".to_string(),
                got: format!("{:?}", last),
                operation_index: NonPrimitiveOpId(0), //TODO: What's the index of this op?
            });
        }

        // The first element is just the leaf.

        let empty_leaf = vec![];
        for (&dir, sibling, leaf) in izip!(
            directions.iter(),
            self.path_siblings.iter(),
            iter::once(&empty_leaf).chain(leaves.iter().skip(1))
        ) {
            let input = if dir {
                [state.as_slice(), sibling]
            } else {
                [sibling, state.as_slice()]
            };
            let new_state = (self.compress)(input)?;
            path_states.push((
                state.clone(),
                // If there's a leaf at this depth we need to compute an extra state
                if leaf.is_empty() {
                    state = new_state;
                    None
                } else {
                    state = (self.compress)([&new_state, leaf])?;
                    Some(new_state)
                },
            ));
        }
        // Finally, push the root
        path_states.push((state.clone(), None));

        Ok(path_states)
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
        directions: &[bool],
        root: &[F],
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
        debug_assert!(if let Ok(leaf) =
            leaves
                .last()
                .ok_or(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                    op: NonPrimitiveOpType::MmcsVerify,
                    expected: "Non empty".to_string(),
                    got: leaves.len()
                }) {
            leaf.is_empty()
        } else {
            false
        });

        // Pad directions in case they start with 0s.
        let path_directions =
            (0..mmcs_config.max_tree_height).map(|i| *directions.get(i).unwrap_or(&false));

        let all_states = self.compute_all_states(mmcs_config, leaves, directions)?;

        let computed_root = &all_states
            .last()
            .ok_or(CircuitError::NonPrimitiveOpMissingPrivateData {
                operation_index: NonPrimitiveOpId(0),
            })? // TODO: What the operation id?
            .0;

        if root != computed_root {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: NonPrimitiveOpType::MmcsVerify,
                operation_index: NonPrimitiveOpId(0), //TODO: What is the id of this op?
                expected: alloc::format!("root: {root:?}"),
                got: alloc::format!("root: {computed_root:?}"),
            });
        }

        // For each step in the Mmcs path (excluding the final state which is the root)
        debug_assert_eq!(all_states.len(), self.path_siblings.len() + 1);
        let empty_leaf = vec![];
        for ((state, extra_state), sibling, direction, leaf_indices, leaf) in izip!(
            all_states.iter().take(self.path_siblings.len()),
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
                        expected: mmcs_config.ext_field_digest_elems.to_string(),
                        got: leaf.len(),
                    });
                }
                add_trace_row(extra_state, leaf, true);
            } else if !leaf.is_empty() {
                return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                    op: NonPrimitiveOpType::MmcsVerify,
                    expected: 0.to_string(),
                    got: leaf.len(),
                });
            }
        }
        trace.final_value = all_states.last().cloned().unwrap_or_default().0;
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
                // Skip non-MMCS operations (e.g., HashAbsorb, HashSqueeze)
                continue;
            };
            if executor.op_type() != &NonPrimitiveOpType::MmcsVerify {
                continue;
            }

            let private_data = self
                .non_primitive_op_private_data
                .get(op_id.0 as usize)
                .and_then(|opt| opt.as_ref())
                .ok_or(CircuitError::NonPrimitiveOpMissingPrivateData {
                    operation_index: *op_id,
                })?;
            let NonPrimitiveOpPrivateData::MmcsVerify(priv_data) = private_data;

            let root = &inputs[inputs.len() - 1];
            let directions = &inputs[inputs.len() - 2];
            let leaves = &inputs[0..directions.len()];

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
                .map(|wid| self.get_witness(wid).map(|x| x == F::ONE))
                .collect::<Result<Vec<bool>, _>>()?;
            // Check that the number of leaves is the same as the number of directions
            if witness_directions.len() != witness_leaves.len() {
                return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                    op: NonPrimitiveOpType::MmcsVerify,
                    operation_index: *op_id,
                    expected: alloc::format!("{:?}", witness_directions.len()),
                    got: alloc::format!("{:?}", witness_leaves.len()),
                });
            }

            // Check root values
            let witness_root: Vec<F> = root
                .iter()
                .map(|wid| self.get_witness(wid))
                .collect::<Result<_, _>>()?;

            let trace = priv_data.to_trace(
                config,
                &witness_leaves,
                leaves,
                &witness_directions,
                &witness_root,
                root,
            )?;
            mmcs_paths.push(trace);
        }

        Ok(MmcsTrace { mmcs_paths })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_symmetric::{PseudoCompressionFunction, TruncatedPermutation};

    use super::*;
    use crate::NonPrimitiveOpPrivateData;
    use crate::builder::CircuitBuilder;
    use crate::ops::MmcsOps;

    type F = BinomialExtensionField<BabyBear, 4>;

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

        let perm = default_babybear_poseidon2_16();
        let compress: TruncatedPermutation<Poseidon2BabyBear<16>, 2, 1, 16> =
            TruncatedPermutation::new(perm);

        // At level 1 dir = false and state0 = leaf, the first input is [2, 1] and thus compress.compress(input) = state1.
        let state1 = compress.compress([[BabyBear::from_u64(2)], [BabyBear::from_u64(1)]]);
        // At level 2 there is an extra leaf, so we do two compressions.
        // In the first one direction = true then input is [state1, 3] and compress.compress(input) = state2
        let state2 = compress.compress([state1, [BabyBear::from_u64(3)]]);
        // In the second compression of level 2 input is [state2, 4] and compress.compress(input) = state3
        let state3 = compress.compress([state2, [BabyBear::from_u64(4)]]);
        // direction = true and then input is [state3, 5] compress.compress(input) = state4
        let state4 = compress.compress([state3, [BabyBear::from_u64(5)]]);

        let expected_path_states = vec![
            // The first state is the leaf.
            (vec![BabyBear::from_u64(1)], None),
            // Here there's an extra leaf
            (state1.to_vec(), Some(state2.to_vec())),
            (state3.to_vec(), None),
            // final root state after the full path
            (state4.to_vec(), None),
        ];

        // Use a config that supports the path length used in this test.
        let config = MmcsVerifyConfig {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 3,
        };

        let private_data = MmcsPrivateData::new::<BabyBear, _, 1>(&config, &siblings, compress);
        let path_states = private_data
            .compute_all_states(&config, &leaves, &directions)
            .unwrap();

        assert_eq!(path_states, expected_path_states);
    }

    #[test]
    fn test_mmcs_path_too_tall_rejected() {
        // Path length (3) exceeds configured max_tree_height (2)
        let perm = default_babybear_poseidon2_16();
        let compress: TruncatedPermutation<Poseidon2BabyBear<16>, 2, 1, 16> =
            TruncatedPermutation::new(perm);
        let config = MmcsVerifyConfig {
            base_field_digest_elems: 8,
            ext_field_digest_elems: 8,
            max_tree_height: 2,
        };

        let leaves = [vec![F::from_u64(1)], vec![], vec![]];
        let siblings = [
            vec![F::from_u64(2)],
            vec![F::from_u64(3)],
            vec![F::from_u64(4)],
        ];
        let directions = [false, true, false];

        let private_data = MmcsPrivateData::new::<BabyBear, _, 1>(&config, &siblings, compress);
        let res = private_data.compute_all_states(&config, &leaves, &directions);
        assert!(
            res.is_err(),
            "Expected path taller than max_tree_height to be rejected"
        );
    }

    #[test]
    fn test_mmcs_witness_validation() {
        let perm = default_babybear_poseidon2_16();
        let compress: TruncatedPermutation<Poseidon2BabyBear<16>, 2, 1, 16> =
            TruncatedPermutation::new(perm);
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
        let correct_private_data =
            MmcsPrivateData::new::<BabyBear, _, 1>(&config, &siblings, compress);
        let correct_path_states = correct_private_data
            .compute_all_states(&config, &leaves_value, &directions)
            .unwrap();
        let correct_root = &correct_path_states.last().unwrap().0;

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

        // Valid witness should be accepted
        let result = run_test(&leaves_value, correct_root, &correct_private_data);
        assert!(
            result.is_ok(),
            "Valid witness should be accepted but got {:?}",
            result
        );
    }

    #[test]
    fn test_mmcs_traces_fields() {
        let perm = default_babybear_poseidon2_16();
        let compress: TruncatedPermutation<Poseidon2BabyBear<16>, 2, 1, 16> =
            TruncatedPermutation::new(perm);
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
        let circuit = builder
            .build()
            .map_err(|e| CircuitError::InvalidCircuit { error: e })
            .unwrap();

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
        let private_data = MmcsPrivateData::new::<BabyBear, _, 1>(&config, &siblings, compress);
        let path_states = private_data
            .compute_all_states(&config, &leaves_value, &directions)
            .unwrap();
        let correct_root = &path_states.last().unwrap().0;

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
        for ((state, extra_state), leaf) in path_states
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
