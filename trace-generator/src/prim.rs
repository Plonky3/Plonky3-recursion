use crate::types::WIdx;

/// Primitive operations after lowering from expressions  
/// These are the basic extension field arithmetic operations only
#[derive(Debug, Clone)]
pub enum Prim<F> {
    /// Set output to constant value
    Const { out: WIdx, val: F },
    /// Set output to public input at position
    Public { out: WIdx, public_pos: usize },
    /// Addition operation
    Add { a: WIdx, b: WIdx, out: WIdx },
    /// Subtraction operation  
    Sub { a: WIdx, b: WIdx, out: WIdx },
    /// Multiplication operation
    Mul { a: WIdx, b: WIdx, out: WIdx },
}

/// Complex operations that are not primitive arithmetic
/// These have their own dedicated tables and include private auxiliary data
#[derive(Debug, Clone, PartialEq)]
pub enum ComplexOp<F> {
    /// Merkle verification operation
    MerkleVerify {
        leaf: Vec<WIdx>, // Multiple extension elements for large hashes
        root: Vec<WIdx>, // Multiple extension elements for large hashes
        /// Private sibling values for the Merkle path (not on witness bus)
        /// Each sibling is a vector of extension elements
        path_siblings: Vec<Vec<F>>,
        /// Path direction bits (0 = left, 1 = right)  
        path_directions: Vec<bool>,
    },
    // Future: FriVerify, HashAbsorb, etc.
}
