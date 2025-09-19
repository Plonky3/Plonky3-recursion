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
#[derive(Debug, Clone)]
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

    /// Field subtraction: witness[out] = witness[a] - witness[b]
    Sub {
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
#[derive(Debug, Clone, PartialEq)]
pub enum NonPrimitiveOpType {
    FakeMerkleVerify,
    HashAbsorb(bool), // bool: If true, reset the capacity before absorbing
    HashSqueeze,
    // Future: FriVerify, HashAbsorb, etc.
}

/// Non-primitive operations representing complex cryptographic constraints
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
    /// Fake Merkle tree path verification (simplified for testing)
    ///
    /// Verifies that a leaf value is contained in a Merkle tree with given root.
    /// The actual Merkle path verification logic is implemented in a dedicated
    /// AIR table that constrains the relationship between leaf and root.
    ///
    /// Public interface (on witness bus):
    /// - `leaf`: The leaf value being verified (single field element)
    /// - `root`: The expected Merkle tree root (single field element)
    ///
    /// Private data (set via NonPrimitiveOpId):
    /// - Merkle path siblings and direction bits
    /// - See `FakeMerklePrivateData` for complete specification
    FakeMerkleVerify { leaf: WitnessId, root: WitnessId },
    /// Sponge hash absorb operation. Absorbs a single chunk of input.
    ///
    /// Public interface (on witness bus):
    /// - `reset_flag`: Whether to reset the capacity before absorbing
    /// - `inputs`: The input chunk to be absorbed.
    ///
    /// Private data (set via NonPrimitiveOpId):
    /// - `reset`: Whether to reset the capacity before absorbing.
    /// - `capacity`: Elements of the state not directly affected by input.`
    HashAbsorb {
        reset_flag: bool,
        inputs: Vec<WitnessId>,
    },
    /// Sponge hash squeeze operation. Produces a single chunk of output.
    /// - `capacity`: The rest of the state, not part of the output.
    HashSqueeze { outputs: Vec<WitnessId> },
}

/// Private auxiliary data for non-primitive operations
///
/// This data is NOT part of the witness table but provides additional
/// parameters needed to fully specify complex operations. Private data:
/// - Is set during circuit execution via `NonPrimitiveOpId`
/// - Contains sensitive information like cryptographic witnesses
/// - Is used by AIR tables to generate the appropriate constraints
#[derive(Debug, Clone, PartialEq)]
pub enum NonPrimitiveOpPrivateData<F> {
    /// Private data for fake Merkle verification
    ///
    /// Contains the complete Merkle path information needed by the prover
    /// to generate a valid proof. This data is not part of the public
    /// circuit specification.
    FakeMerkleVerify(FakeMerklePrivateData<F>),
    /// Private data for the hash absorb operation
    HashAbsorb(HashAbsorbPrivateData<F>),
    /// Private data for the hash squeeze operation
    HashSqueeze(HashSqueezePrivateData<F>),
}

/// Private Merkle path data for fake Merkle verification (simplified)
///
/// This represents the private witness information that the prover needs
/// to demonstrate knowledge of a valid Merkle path from leaf to root.
/// In a real implementation, this would contain cryptographic hash values
/// and tree structure information.
///
/// Note: This is a simplified "fake" implementation for demonstration.
/// Production Merkle verification would use proper cryptographic hashes
/// and handle multi-element hash digests, not single field elements.
#[derive(Debug, Clone, PartialEq)]
pub struct FakeMerklePrivateData<F> {
    /// Sibling hash values along the Merkle path
    ///
    /// For each level of the tree (from leaf to root), contains the
    /// sibling hash needed to compute the parent hash. In a real
    /// implementation, these would be cryptographic hash outputs.
    pub path_siblings: Vec<F>,

    /// Direction bits indicating path through the tree
    ///
    /// For each level: `false` = current node is left child,
    /// `true` = current node is right child. Used to determine
    /// hash input ordering: `hash(current, sibling)` vs `hash(sibling, current)`.
    pub path_directions: Vec<bool>,
}

/// Private data for the hash absorb operation
#[derive(Debug, Clone, PartialEq)]
pub struct HashAbsorbPrivateData<F> {
    _phantom: core::marker::PhantomData<F>,
}

/// Private data for the hash squeeze operation
#[derive(Debug, Clone, PartialEq)]
pub struct HashSqueezePrivateData<F> {
    _phantom: core::marker::PhantomData<F>,
}
