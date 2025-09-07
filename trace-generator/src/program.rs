use crate::prim::{ComplexOp, Prim};
use crate::types::WIdx;

/// Verifier key containing AIR metadata
#[derive(Debug, Clone)]
pub struct VerifierKey {
    /// Number of Add table rows
    pub add_height: usize,
    /// Number of Mul table rows
    pub mul_height: usize,
    /// Number of Sub table rows  
    pub sub_height: usize,
    /// Number of Merkle verification rows
    pub merkle_height: usize,
    /// AIR identifiers for operation tables
    pub operation_air_ids: Vec<String>,
    /// Placeholder for future cryptographic commitments
    pub air_commitment: Vec<u8>,
}

/// Main program artifact - serializable and immutable
#[derive(Debug, Clone)]
pub struct Program<F> {
    /// Verifier key with AIR/layout metadata
    pub vk: VerifierKey,
    /// Number of witness table rows
    pub slot_count: u32,
    /// Primitive operations in topological order
    pub prim_ops: Vec<Prim<F>>,
    /// Complex operations (non-primitive)
    pub complex_ops: Vec<ComplexOp<F>>,
    /// Public input witness indices
    pub public_rows: Vec<WIdx>,
    /// Total number of public field elements
    pub public_flat_len: usize,
}

impl<F> Program<F> {
    pub fn new(slot_count: u32) -> Self {
        let vk = VerifierKey {
            add_height: 0,
            mul_height: 0,
            sub_height: 0,
            merkle_height: 0,
            operation_air_ids: vec![
                "AddExtAir-v1".to_string(),
                "MulExtAir-v1".to_string(),
                "SubExtAir-v1".to_string(),
                "MerkleVerifyAir-v1".to_string(),
            ],
            air_commitment: Vec::new(),
        };

        Self {
            vk,
            slot_count,
            prim_ops: Vec::new(),
            complex_ops: Vec::new(),
            public_rows: Vec::new(),
            public_flat_len: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WIdx;

    // Mock extension field element for testing
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct MockExtField(u64);

    #[test]
    fn test_program_creation() {
        let program = Program::<MockExtField>::new(10);

        assert_eq!(program.slot_count, 10);
        assert_eq!(program.vk.operation_air_ids.len(), 4); // Add/Mul/Sub/MerkleVerify
    }

    #[test]
    fn test_merkle_verification_design() {
        let mut program = Program::<MockExtField>::new(10);

        // Merkle verification: prove leaf is in tree with given root
        // For SHA256 hashes, we need 2 extension elements (8 Baby Bear field elements when D=4)
        let leaf_widx = vec![WIdx(0), WIdx(1)]; // 2 extension elements for leaf hash
        let root_widx = vec![WIdx(2), WIdx(3)]; // 2 extension elements for root hash

        // Add Merkle verification complex operation with private data included
        let merkle_op = ComplexOp::MerkleVerify {
            leaf: leaf_widx.clone(),
            root: root_widx.clone(),
            path_siblings: vec![
                // Each sibling is 2 extension elements
                vec![MockExtField(0x1111), MockExtField(0x1112)],
                vec![MockExtField(0x2221), MockExtField(0x2222)],
                vec![MockExtField(0x3331), MockExtField(0x3332)],
            ],
            path_directions: vec![false, true, false], // left, right, left
        };
        program.complex_ops.push(merkle_op);

        assert_eq!(program.complex_ops.len(), 1);
        assert_eq!(program.vk.operation_air_ids.len(), 4); // includes MerkleVerifyAir-v1
    }
}
