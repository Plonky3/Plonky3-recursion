use crate::types::WitnessIndex;

/// Primitive operations after lowering from expressions  
/// These are the basic extension field arithmetic operations only
#[derive(Debug, Clone)]
pub enum Prim<F> {
    /// Set output to constant value
    Const { out: WitnessIndex, val: F },
    /// Set output to public input at position
    Public {
        out: WitnessIndex,
        public_pos: usize,
    },
    /// Addition operation
    Add {
        a: WitnessIndex,
        b: WitnessIndex,
        out: WitnessIndex,
    },
    /// Subtraction operation  
    Sub {
        a: WitnessIndex,
        b: WitnessIndex,
        out: WitnessIndex,
    },
    /// Multiplication operation
    Mul {
        a: WitnessIndex,
        b: WitnessIndex,
        out: WitnessIndex,
    },
}

/// Complex operations that are not primitive arithmetic
/// These have their own dedicated tables and only contain public interface (witness indices)
#[derive(Debug, Clone, PartialEq)]
pub enum ComplexOp {
    /// Fake Merkle verification operation (simplified: single field elements)
    FakeMerkleVerify {
        leaf: WitnessIndex, // Public input - on witness bus (single field element)
        root: WitnessIndex, // Public output - on witness bus (single field element)
                            // Private data is set separately via ComplexOpId
    },
    // Future: FriVerify, HashAbsorb, etc.
}

/// Private auxiliary data for complex operations (not on witness bus)
#[derive(Debug, Clone, PartialEq)]
pub enum ComplexOpPrivateData<F> {
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
