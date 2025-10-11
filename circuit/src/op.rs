use alloc::vec::Vec;
use core::hash::Hash;

use crate::tables::MmcsPrivateData;
use crate::types::WitnessId;

/// Primitive operations that represent basic field arithmetic
///
/// These operations form the core computational primitives after expression lowering.
/// All primitive operations:
/// - Operate on witness table slots (WitnessId)
/// - Can be heavily optimized (constant folding, CSE, etc.)
/// - Are executed in topological order during circuit evaluation
/// - Form a directed acyclic graph (DAG) of dependencies
///
/// Primitive operations are kept separate from complex operations to maintain
/// clean optimization boundaries and enable aggressive compiler transformations.
#[derive(Debug, Clone, PartialEq)]
pub enum Prim<F> {
    /// Load a constant value into the witness table
    ///
    /// Sets `witness[out] = val`. Used for literal constants and
    /// supports constant pooling optimization where identical constants
    /// reuse the same witness slot.
    Const { out: WitnessId, val: F },

    /// Load a public input value into the witness table
    ///
    /// Sets `witness[out] = public_inputs[public_pos]`. Public inputs
    /// are values known to both prover and verifier, typically used
    /// for circuit inputs and expected outputs.
    Public { out: WitnessId, public_pos: usize },

    /// Field addition: witness[out] = witness[a] + witness[b]
    Add {
        a: WitnessId,
        b: WitnessId,
        out: WitnessId,
    },

    /// Field multiplication: witness[out] = witness[a] * witness[b]
    Mul {
        a: WitnessId,
        b: WitnessId,
        out: WitnessId,
    },
}

/// Non-primitive operation types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NonPrimitiveOpType {
    // Mmcs Verify gate with the argument is the size of the path
    MmcsVerify,
    FriVerify,
    /// Poseidon2 permutation - applies permutation to state
    Poseidon2Permutation,
    /// Hash absorb operation - absorbs field elements into sponge state (LEGACY - unused)
    HashAbsorb {
        reset: bool,
    },
    /// Hash squeeze operation - extracts field elements from sponge state (LEGACY - unused)
    HashSqueeze,
}

/// Non-primitive operation types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NonPrimitiveOpConfig {
    MmcsVerifyConfig(crate::ops::MmcsVerifyConfig),
    None,
}

/// Non-primitive operations representing complex cryptographic constraints.
///
/// These operations implement sophisticated cryptographic primitives that:
/// - Have dedicated AIR tables for constraint verification
/// - Take witness values as public interface
/// - May require separate private data for complete specification
/// - Are NOT subject to primitive optimizations (CSE, constant folding)
/// - Enable modular addition of complex functionality
///
/// Non-primitive operations are isolated from primitive optimizations to:
/// 1. Maintain clean separation between basic arithmetic and complex crypto
/// 2. Allow specialized constraint systems for each operation type
/// 3. Enable parallel development of different cryptographic primitives
/// 4. Avoid optimization passes breaking complex constraint relationships
#[derive(Debug, Clone, PartialEq)]
pub enum NonPrimitiveOp {
    /// Verifies that a leaf value is contained in a Mmcs with given root.
    /// The actual Mmcs path verification logic is implemented in a dedicated
    /// AIR table that constrains the relationship between leaf and root.
    ///
    /// Public interface (on witness bus):
    /// - `leaf`: The leaf value being verified (single field element)
    /// - `index`: The index of the leaf
    /// - `root`: The expected Mmcs root (single field element)
    ///
    /// Private data (set via NonPrimitiveOpId):
    /// - Mmcs path siblings and direction bits
    /// - See `MmcsPrivateData` for complete specification
    MmcsVerify {
        leaf: MmcsWitnessId,
        index: WitnessId,
        root: MmcsWitnessId,
    },

    /// Poseidon2 permutation - applies Poseidon2 permutation to full state.
    ///
    /// Public interface (on witness bus):
    /// - `input_state`: Full permutation state (WIDTH elements)
    /// - `output_state`: Full permutation state after applying Poseidon2 (WIDTH elements)
    ///
    /// The ExtendedPoseidon2Air validates: output_state = Poseidon2(input_state)
    Poseidon2Permutation {
        input_state: Vec<WitnessId>,
        output_state: Vec<WitnessId>,
    },

    /// Hash absorb operation - absorbs inputs into sponge state (LEGACY - unused).
    ///
    /// NOTE: This is legacy code. Sponge construction is now handled in-circuit
    /// via CircuitChallenger managing state as Targets.
    HashAbsorb {
        reset_flag: bool,
        inputs: Vec<WitnessId>,
    },

    /// Hash squeeze operation - extracts outputs from sponge state (LEGACY - unused).
    ///
    /// NOTE: This is legacy code. Sponge construction is now handled in-circuit
    /// via CircuitChallenger managing state as Targets.
    HashSqueeze { outputs: Vec<WitnessId> },
}

pub type MmcsWitnessId = Vec<WitnessId>;

/// Private auxiliary data for non-primitive operations
///
/// This data is NOT part of the witness table but provides additional
/// parameters needed to fully specify complex operations. Private data:
/// - Is set during circuit execution via `NonPrimitiveOpId`
/// - Contains sensitive information like cryptographic witnesses
/// - Is used by AIR tables to generate the appropriate constraints
#[derive(Debug, Clone, PartialEq)]
pub enum NonPrimitiveOpPrivateData<F> {
    /// Private data for Mmcs verification
    ///
    /// Contains the complete Mmcs path information needed by the prover
    /// to generate a valid proof. This data is not part of the public
    /// circuit specification.
    MmcsVerify(MmcsPrivateData<F>),
}
