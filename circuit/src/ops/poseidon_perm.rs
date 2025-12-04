//! Poseidon permutation non-primitive operation (one Poseidon call per row).
//! Only supports extension degree D=4 for now.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::iter;

use p3_baby_bear::BabyBear;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};
use p3_symmetric::Permutation;

use crate::builder::{CircuitBuilder, NonPrimitiveOpParams};
use crate::op::{ExecutionContext, HashSqueezeHint, NonPrimitiveExecutor, NonPrimitiveOpType};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};
use crate::{CircuitBuilderError, CircuitError};

/// User-facing arguments for adding a Poseidon perm row.
pub struct PoseidonPermCall {
    pub new_start: bool,
    pub merkle_path: bool,
    /// Optional mmcs direction bit input (base field, boolean). If None, defaults to 0/private.
    pub mmcs_bit: Option<ExprId>,
    /// Optional CTL exposure for each input limb (one extension element).
    /// If `None`, the limb is considered private/unexposed (in_ctl = 0).
    pub inputs: [Option<ExprId>; 4],
    /// Optional CTL exposure for output limbs 0 and 1 (one extension element).
    /// Limbs 2–3 are never exposed.
    pub outputs: [Option<ExprId>; 2],
    /// Optional MMCS index accumulator value to expose.
    pub mmcs_index_sum: Option<ExprId>,
}

/// Convenience helpers to build calls with defaults.
impl Default for PoseidonPermCall {
    fn default() -> Self {
        Self {
            new_start: false,
            merkle_path: false,
            mmcs_bit: None,
            inputs: [None, None, None, None],
            outputs: [None, None],
            mmcs_index_sum: None,
        }
    }
}

pub trait PoseidonPermOps<F: Clone + PrimeCharacteristicRing + Eq> {
    /// Add a Poseidon perm row (one permutation).
    ///
    /// - `new_start`: if true, this row starts a new chain (no chaining from previous row).
    /// - `merkle_path`: if true, Merkle chaining semantics apply for limbs 0–1.
    /// - `mmcs_bit`: Merkle direction bit witness for this row (used when `merkle_path` is true).
    /// - `inputs`: optional CTL exposure per limb (extension element, length 4 if provided).
    /// - `outputs`: optional CTL exposure for limbs 0–1 (extension element, length 4 if provided).
    /// - `mmcs_index_sum`: optional exposure of the MMCS index accumulator (base field element).
    fn add_poseidon_perm(
        &mut self,
        call: PoseidonPermCall,
    ) -> Result<NonPrimitiveOpId, crate::CircuitBuilderError>;
}

impl<F> PoseidonPermOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_poseidon_perm(
        &mut self,
        call: PoseidonPermCall,
    ) -> Result<NonPrimitiveOpId, crate::CircuitBuilderError> {
        let op_type = NonPrimitiveOpType::PoseidonPerm;
        self.ensure_op_enabled(op_type.clone())?;

        // Build witness_exprs layout:
        // [in0, in1, in2, in3, out0, out1, mmcs_index_sum, mmcs_bit]
        let mut witness_exprs: Vec<Vec<ExprId>> = Vec::with_capacity(8);

        for limb in call.inputs.iter() {
            if let Some(val) = limb {
                witness_exprs.push(vec![*val]);
            } else {
                witness_exprs.push(Vec::new());
            }
        }

        for out in call.outputs.iter() {
            if let Some(val) = out {
                witness_exprs.push(vec![*val]);
            } else {
                witness_exprs.push(Vec::new());
            }
        }

        if let Some(idx_sum) = call.mmcs_index_sum {
            witness_exprs.push(vec![idx_sum]);
        } else {
            witness_exprs.push(Vec::new());
        }
        // mmcs_bit
        if let Some(bit) = call.mmcs_bit {
            witness_exprs.push(vec![bit]);
        } else {
            witness_exprs.push(Vec::new());
        }

        Ok(self.push_non_primitive_op(
            op_type,
            witness_exprs,
            Some(NonPrimitiveOpParams::PoseidonPerm {
                new_start: call.new_start,
                merkle_path: call.merkle_path,
            }),
            "poseidon_perm",
        ))
    }
}

pub fn add_hash_squeeze<F: Field>(
    builder: &mut CircuitBuilder<F>,
    hash_config: &HashConfig<F>,
    state_id: &str,
    inputs: &[ExprId],
    reset: bool,
) -> Result<Vec<ExprId>, CircuitBuilderError> {
    let filler = HashSqueezeHint::new(
        state_id.to_string(),
        inputs.to_vec(),
        hash_config.clone(),
        reset,
    );
    let outputs = builder.alloc_witness_hints(filler, "hash squeeze");

    let chunks = inputs.chunks(4);
    let last_idx = chunks.len() - 1;
    for (i, input) in chunks.enumerate() {
        let is_first = i == 0;
        let is_last = i == last_idx;
        let _ = builder.add_poseidon_perm(PoseidonPermCall {
            new_start: if is_first { reset } else { false },
            merkle_path: false,
            mmcs_bit: None,
            inputs: input
                .iter()
                .cloned()
                .map(Some)
                .chain(iter::repeat(None))
                .take(4)
                .collect::<Vec<_>>()
                .try_into()
                .expect("We have already taken 4 elements"),
            outputs: if is_last {
                outputs
                    .iter()
                    .cloned()
                    .map(Some)
                    .chain(iter::repeat(None))
                    .take(2)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("We have already taken 2 elements")
            } else {
                [None, None]
            },
            mmcs_index_sum: None,
        })?;
    }

    Ok(outputs)
}

/// Executor for Poseidon perm operations.
///
/// This currently does not mutate the witness; the AIR enforces correctness.
#[derive(Debug, Clone)]
pub struct PoseidonPermExecutor {
    op_type: NonPrimitiveOpType,
    pub new_start: bool,
    pub merkle_path: bool,
}

impl PoseidonPermExecutor {
    pub const fn new(new_start: bool, merkle_path: bool) -> Self {
        Self {
            op_type: NonPrimitiveOpType::PoseidonPerm,
            new_start,
            merkle_path,
        }
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for PoseidonPermExecutor {
    fn execute(
        &self,
        _inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

/// Configuration parameters for hash operations.
pub struct HashConfig<F> {
    /// Rate (number of elements absorbed/squeezed per operation)
    pub rate: usize,
    /// Width of the permutation
    pub width: usize,
    /// The permutation function used in this configuration
    pub permutation: Arc<PermutationFn<F>>,
}

type PermutationFn<F> = dyn Fn(&[F]) -> Result<Vec<F>, CircuitError>;

impl<F> Clone for HashConfig<F> {
    fn clone(&self) -> Self {
        Self {
            rate: self.rate,
            width: self.width,
            permutation: Arc::clone(&self.permutation),
        }
    }
}

impl<F> HashConfig<F> {
    /// New hash configuration using Babybear and poseidon2 permutation.
    pub fn babybear_poseidon2_16(rate: usize) -> Self
    where
        F: ExtensionField<BabyBear>,
    {
        use p3_baby_bear::default_babybear_poseidon2_16;
        let permutation = default_babybear_poseidon2_16();
        Self {
            rate,
            width: 16,
            permutation: Arc::new(move |input: &[F]| {
                let input = input
                    .iter()
                    .flat_map(|e| e.as_basis_coefficients_slice()[0..1].to_vec())
                    .collect::<Vec<BabyBear>>()
                    .try_into()
                    .map_err(|_| CircuitError::IncorrectNonPrimitiveOpInputSize {
                        op: NonPrimitiveOpType::PoseidonPerm,
                        expected: 16.to_string(),
                        got: input.len(),
                    })?;
                let output = permutation.permute(input);
                Ok(output.iter().map(|e| F::from(*e)).collect::<Vec<F>>())
            }),
        }
    }
}

impl<F> alloc::fmt::Debug for HashConfig<F> {
    fn fmt(&self, f: &mut alloc::fmt::Formatter<'_>) -> alloc::fmt::Result {
        f.debug_struct("HashConfig")
            .field("rate", &self.rate)
            .field("width", &self.width)
            .field("permutation", &"<dyn Fn(&[F]) -> Vec<F>>")
            .finish()
    }
}

impl<F> PartialEq for HashConfig<F> {
    fn eq(&self, other: &Self) -> bool {
        // Intentional: only compare rate, not the closure
        self.rate == other.rate && self.width == other.width
    }
}

impl<F> Eq for HashConfig<F> {}

impl<F> core::hash::Hash for HashConfig<F> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Same idea: hash only rate
        self.rate.hash(state);
    }
}

impl<F: Clone> Default for HashConfig<F> {
    fn default() -> Self {
        Self {
            rate: 0,
            width: 0,
            // Default permutation: identity over the slice (clones elements)
            permutation: Arc::new(|_| Ok(vec![])),
        }
    }
}
