use crate::types::WitnessId;

/// Primitive operations after lowering from expressions  
/// These are the basic extension field arithmetic operations only
#[derive(Debug, Clone)]
pub enum Prim<F> {
    /// Set output to constant value
    Const { out: WitnessId, val: F },
    /// Set output to public input at position
    Public { out: WitnessId, public_pos: usize },
    /// Addition operation
    Add {
        a: WitnessId,
        b: WitnessId,
        out: WitnessId,
    },
    /// Subtraction operation  
    Sub {
        a: WitnessId,
        b: WitnessId,
        out: WitnessId,
    },
    /// Multiplication operation
    Mul {
        a: WitnessId,
        b: WitnessId,
        out: WitnessId,
    },
}

/// Non-primitive operations that are not basic arithmetic
/// These have their own dedicated tables and only contain public interface (witness indices)
#[derive(Debug, Clone, PartialEq)]
pub enum NonPrimitiveOp {
    /// Fake Merkle verification operation (simplified: single field elements)
    FakeMerkleVerify {
        leaf: WitnessId, // Public input - on witness bus (single field element)
        root: WitnessId, // Public output - on witness bus (single field element)
                         // Private data is set separately via NonPrimitiveOpId
    },
    // Future: FriVerify, HashAbsorb, etc.
}

/// Private auxiliary data for non-primitive operations (not on witness bus)
#[derive(Debug, Clone, PartialEq)]
pub enum NonPrimitiveOpPrivateData<F> {
    FakeMerkleVerify(FakeMerklePrivateData<F>),
}

/// Private data for fake Merkle verification (simplified)
#[derive(Debug, Clone, PartialEq)]
pub struct FakeMerklePrivateData<F> {
    /// Private sibling values for the Merkle path (single field elements)
    pub path_siblings: Vec<F>,
    /// Path direction bits (0 = left, 1 = right)
    pub path_directions: Vec<bool>,
}
