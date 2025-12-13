//! Poseidon permutation non-primitive operation (one Poseidon call per row).
//!
//! This operation is designed to support both standard hashing and specific logic required for
//! Merkle path verification within a circuit. Its features include:
//!
//! - **Hashing**: Performs a standard Poseidon permutation.
//! - **Chaining**: Can start a new hash computation or continue from the output of the previous row
//!   (controlled by `new_start`).
//! - **Merkle Path Verification**: When `merkle_path` is enabled, it supports logic for verifying
//!   a path up a Merkle tree. This involves conditionally arranging inputs (sibling vs. computed hash)
//!   based on a direction bit (`mmcs_bit`).
//! - **Index Accumulation**: Supports accumulating path indices (`mmcs_index_sum`) to verify the
//!   leaf's position in the tree.
//!
//! Only supports extension degree D=4 for now.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing};

use crate::CircuitError;
use crate::builder::{CircuitBuilder, NonPrimitiveOpParams};
use crate::op::{
    ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpPrivateData, NonPrimitiveOpType,
};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};

/// Explicit input mode for Poseidon permutation operations.
///
/// This enum makes chaining semantics explicit and clear, replacing the implicit
/// combination of `new_start`, `merkle_path`, and `mmcs_bit` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoseidonInputMode {
    /// Start a new independent chain (no chaining from previous output).
    /// All inputs come from private data or CTL exposure.
    NewChain,
    /// Normal sponge/Challenger mode: chain all 4 limbs from previous output.
    /// Inputs are: in[i] = out_prev[i] for i in 0..4 (unless overridden by private data or CTL).
    SpongeChain,
    /// Merkle path mode: chain limbs 0-1 from previous output based on `mmcs_bit` at runtime.
    /// - If `mmcs_bit = 0` (left): in[0-1] = out_prev[0-1]
    /// - If `mmcs_bit = 1` (right): in[0-1] = out_prev[2-3]
    /// Limbs 2-3 come from private data.
    MerklePath,
}

impl PoseidonInputMode {
    /// Convert from legacy flags (for backward compatibility during migration).
    pub fn from_flags(new_start: bool, merkle_path: bool, _mmcs_bit: bool) -> Self {
        if new_start {
            Self::NewChain
        } else if merkle_path {
            Self::MerklePath
        } else {
            Self::SpongeChain
        }
    }

    /// Convert to legacy flags (for compatibility with existing code).
    pub fn to_flags(self) -> (bool, bool, bool) {
        match self {
            Self::NewChain => (true, false, false),
            Self::SpongeChain => (false, false, false),
            Self::MerklePath => (false, true, false), // mmcs_bit determined at runtime
        }
    }

    /// Returns true if this mode requires chaining from previous output.
    pub fn is_chained(self) -> bool {
        !matches!(self, Self::NewChain)
    }

    /// Returns true if this is a Merkle path mode.
    pub fn is_merkle(self) -> bool {
        matches!(self, Self::MerklePath)
    }
}

/// Trait for computing Poseidon permutations.
///
/// This trait separates the computation logic from witness I/O, making the code
/// more modular and testable. The executor handles witness I/O, while this
/// trait handles the actual permutation computation.
pub trait PermComputer<F: Field> {
    /// Compute the Poseidon permutation output given input limbs.
    ///
    /// # Arguments
    /// * `input_limbs` - The 4 extension field limbs to permute
    ///
    /// # Returns
    /// The 4 extension field limbs after permutation
    fn compute(&self, input_limbs: &[F; 4]) -> [F; 4];
}

/// Wrapper to make `Arc<dyn Fn(...)>` implement `PermComputer`.
pub struct PermComputerWrapper<F: Field>(pub Arc<dyn Fn(&[F; 4]) -> [F; 4] + Send + Sync>);

impl<F: Field> PermComputer<F> for PermComputerWrapper<F> {
    fn compute(&self, input_limbs: &[F; 4]) -> [F; 4] {
        self.0(input_limbs)
    }
}

impl<F: Field> Clone for PermComputerWrapper<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// User-facing arguments for adding a Poseidon perm row.
pub struct PoseidonPermCall {
    /// Explicit input mode specifying how inputs are determined.
    pub input_mode: PoseidonInputMode,
    /// Optional mmcs direction bit input (base field, boolean).
    /// Only used when `input_mode` is `MerkleLeft` or `MerkleRight`.
    /// If None, defaults to 0 (MerkleLeft) for Merkle modes.
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
            input_mode: PoseidonInputMode::SpongeChain,
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
    /// - `input_mode`: explicit mode specifying how inputs are determined (chaining semantics).
    /// - `mmcs_bit`: optional Merkle direction bit witness (only used for Merkle modes).
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

        // Convert input_mode to legacy flags for compatibility with existing infrastructure
        let (new_start, merkle_path, _) = call.input_mode.to_flags();

        Ok(self.push_non_primitive_op(
            op_type,
            witness_exprs,
            Some(NonPrimitiveOpParams::PoseidonPerm {
                new_start,
                merkle_path,
            }),
            "poseidon_perm",
        ))
    }
}

/// Executor for Poseidon perm operations.
///
/// This executor handles witness I/O and delegates the actual computation
/// to a `PermComputer`, making the code more modular and testable.
pub struct PoseidonPermExecutor<F> {
    op_type: NonPrimitiveOpType,
    /// Explicit input mode specifying chaining semantics
    input_mode: PoseidonInputMode,
    /// Computer for performing the actual permutation computation
    computer: Arc<dyn PermComputer<F> + Send + Sync>,
}

impl<F> Clone for PoseidonPermExecutor<F> {
    fn clone(&self) -> Self {
        Self {
            op_type: self.op_type.clone(),
            input_mode: self.input_mode,
            computer: self.computer.clone(),
        }
    }
}

impl<F> core::fmt::Debug for PoseidonPermExecutor<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoseidonPermExecutor")
            .field("op_type", &self.op_type)
            .field("input_mode", &self.input_mode)
            .field("computer", &"<PermComputer>")
            .finish()
    }
}

impl<F> PoseidonPermExecutor<F> {
    /// Create a new executor with the given input mode and computer.
    pub fn new(
        input_mode: PoseidonInputMode,
        computer: Arc<dyn PermComputer<F> + Send + Sync>,
    ) -> Self {
        Self {
            op_type: NonPrimitiveOpType::PoseidonPerm,
            input_mode,
            computer,
        }
    }

    /// Get the input mode for this executor.
    pub fn input_mode(&self) -> PoseidonInputMode {
        self.input_mode
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for PoseidonPermExecutor<F> {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        // Layout: inputs = [in0, in1, in2, in3, mmcs_index_sum, mmcs_bit]
        //         outputs = [out0, out1]
        if inputs.len() < 4 {
            return Ok(()); // Invalid layout, skip execution
        }

        // Build input state: start with private data (if available), then apply chaining, then CTL
        // This matches the trace builder's semantics: private data is the initial state
        let mut input_limbs: [F; 4] = [F::ZERO; 4];

        // Step 1: Initialize from private data (if available)
        if let Ok(NonPrimitiveOpPrivateData::PoseidonPerm(perm_data)) = ctx.get_private_data() {
            for (i, limb) in perm_data.input_values.iter().enumerate().take(4) {
                input_limbs[i] = *limb;
            }
        }

        // Step 2: Apply chaining rules based on explicit input mode
        // Chaining only applies to limbs that are ZERO (not set by private data)
        // This matches the AIR: chaining is gated by (1 - in_ctl[i]), and private data doesn't set in_ctl
        if self.input_mode.is_chained() {
            if let Some(prev_output) = ctx.get_last_poseidon_output() {
                match self.input_mode {
                    PoseidonInputMode::SpongeChain => {
                        // Normal sponge mode: chain all 4 limbs if not set by private data
                        for i in 0..4 {
                            if input_limbs[i] == F::ZERO {
                                input_limbs[i] = prev_output[i];
                            }
                        }
                    }
                    PoseidonInputMode::MerklePath => {
                        // Merkle path mode: chain based on mmcs_bit (read at runtime)
                        // Get mmcs_bit from inputs[5] if provided
                        let mmcs_bit = if inputs.len() > 5 && inputs[5].len() == 1 {
                            if let Ok(bit_val) = ctx.get_witness(inputs[5][0]) {
                                bit_val != F::ZERO
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        // Only chain limbs that are ZERO (not set by private data)
                        if mmcs_bit {
                            // mmcs_bit = 1 (right): chain limbs 0-1 from prev_out[2-3] if not set
                            if input_limbs[0] == F::ZERO {
                                input_limbs[0] = prev_output[2];
                            }
                            if input_limbs[1] == F::ZERO {
                                input_limbs[1] = prev_output[3];
                            }
                        } else {
                            // mmcs_bit = 0 (left): chain limbs 0-1 from prev_out[0-1] if not set
                            if input_limbs[0] == F::ZERO {
                                input_limbs[0] = prev_output[0];
                            }
                            if input_limbs[1] == F::ZERO {
                                input_limbs[1] = prev_output[1];
                            }
                        }
                    }
                    PoseidonInputMode::NewChain => {
                        // No chaining for new chains
                    }
                }
            }
        }

        // Override with witness values where explicitly provided (CTL exposure)
        // CTL always overrides chaining and private data
        for (i, limb_wids) in inputs.iter().take(4).enumerate() {
            if limb_wids.len() == 1
                && let Ok(val) = ctx.get_witness(limb_wids[0])
            {
                input_limbs[i] = val;
            }
        }

        // Execute the permutation using the computer (separated from witness I/O)
        let output_limbs = self.computer.compute(&input_limbs);

        // Store output for chaining to next operation
        ctx.set_last_poseidon_output(output_limbs);

        // Write output values to witness where output slots are specified
        // Use set_if_unset_or_equal to allow overwriting ZERO (from default hints) and matching values (for public inputs)
        for (i, output_wids) in outputs.iter().take(2).enumerate() {
            if output_wids.len() == 1 {
                ctx.set_if_unset_or_equal(output_wids[0], output_limbs[i])?;
            }
        }

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
