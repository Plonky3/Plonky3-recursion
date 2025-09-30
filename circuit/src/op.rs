use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::tables::MerklePrivateData;
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
#[derive(Debug, Clone, PartialEq)]
pub enum NonPrimitiveOpType<T> {
    // Future: FriVerify, HashAbsorb, etc.
    MerkleVerify(MerkleVerifyConfig<T>),
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
pub enum NonPrimitiveOp<T> {
    /// Verifies that a leaf value is contained in a Merkle tree with given root.
    /// The actual Merkle path verification logic is implemented in a dedicated
    /// AIR table that constrains the relationship between leaf and root.
    ///
    /// Public interface (on witness bus):
    /// - `leaf`: The leaf value being verified (single field element)
    /// - `index`: The index of the leaf
    /// - `root`: The expected Merkle tree root (single field element)
    /// - `config`: The configuration of this gate.
    ///
    /// Private data (set via NonPrimitiveOpId):
    /// - Merkle path siblings and direction bits
    /// - See `MerklePrivateData` for complete specification
    MerkleVerify {
        leaf: MerkleWitnessId,
        index: WitnessId,
        root: MerkleWitnessId,
        config: MerkleVerifyConfig<T>,
    },
}

#[derive(Clone)]
pub struct MerkleVerifyConfig<T> {
    /// The number of base field elements required for represeting a digest.
    pub base_field_digest_elems: usize,
    /// The number of extension field elements required for representing a digest.
    pub ext_field_digest_elems: usize,
    /// The maximum height of the merkle tree
    pub max_tree_height: usize,
    /// The compression function
    #[allow(clippy::type_complexity)]
    pub compress: Arc<dyn Fn([&[T]; 2]) -> Vec<T>>,
}

impl<T> fmt::Debug for MerkleVerifyConfig<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleVerifyConfig")
            .field("base_field_digest_elems", &self.base_field_digest_elems)
            .field("ext_field_digest_elems", &self.ext_field_digest_elems)
            .field("max_tree_height", &self.max_tree_height)
            .field("compress", &"<omitted>") // placeholder; not printing closure
            .finish()
    }
}

impl<T> PartialEq for MerkleVerifyConfig<T> {
    fn eq(&self, other: &Self) -> bool {
        self.base_field_digest_elems == other.base_field_digest_elems
            && self.ext_field_digest_elems == other.ext_field_digest_elems
            && self.max_tree_height == other.max_tree_height
        // `compress` intentionally ignored: closures/trait objects have no general equality
    }
}

impl<T> MerkleVerifyConfig<T> {
    /// Returns the number of wires received as input.
    pub const fn input_size(&self) -> usize {
        // ext_field_digest_elems for the leaf and root and 1 for the leaf index
        2 * self.ext_field_digest_elems + 1
    }
    // /// Derive the merkle configuration from a given RecursiveMmcs
    // pub const fn from_recursive_mmcs<Recur>()
}

pub type MerkleWitnessId = Vec<WitnessId>;

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
    MerkleVerify(MerklePrivateData<F>),
}
