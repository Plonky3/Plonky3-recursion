//! Byte-digest Merkle commitments whose openings binary WHIR verifiers import.

use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::PackedValue;
use p3_matrix::Dimensions;
use p3_merkle_tree::{
    MerkleAuthPath, MerkleCap, MerkleTreeError, MerkleTreeMmcs, PrunedMerklePaths,
};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

/// A Merkle commitment over 32-byte digests whose pruned multi-openings a
/// binary WHIR verifier restores into one authentication path per query.
pub trait ByteDigestMmcs<F: Send + Sync + Clone>:
    Mmcs<F, Commitment = MerkleCap<F, [u8; 32]>, MultiProof = PrunedMerklePaths<u8, 32>>
{
    /// The digests one node compresses.
    fn compression_arity(&self) -> usize;

    /// The top tree levels the cap replaces.
    fn cap_height(&self) -> usize;

    /// Every query's full authentication path, as
    /// [`MerkleTreeMmcs::restore_and_recompute_paths`] restores it: siblings
    /// from the leaves up, each level's in increasing position.
    ///
    /// # Errors
    ///
    /// The tree's error when the rows or the frontier do not fit `dimensions`
    /// and `indices`.
    fn restore_paths(
        &self,
        dimensions: &[Dimensions],
        indices: &[usize],
        rows: &[Vec<&[F]>],
        proof: &PrunedMerklePaths<u8, 32>,
    ) -> Result<Vec<MerkleAuthPath<u8, 32>>, MerkleTreeError>;
}

impl<F, H, C, const N: usize> ByteDigestMmcs<F> for MerkleTreeMmcs<F, u8, H, C, N, 32>
where
    F: PackedValue<Value = F> + PartialEq,
    H: CryptographicHasher<F, [u8; 32]> + Sync,
    C: PseudoCompressionFunction<[u8; 32], N> + Sync,
{
    fn compression_arity(&self) -> usize {
        N
    }

    fn cap_height(&self) -> usize {
        Self::cap_height(self)
    }

    fn restore_paths(
        &self,
        dimensions: &[Dimensions],
        indices: &[usize],
        rows: &[Vec<&[F]>],
        proof: &PrunedMerklePaths<u8, 32>,
    ) -> Result<Vec<MerkleAuthPath<u8, 32>>, MerkleTreeError> {
        self.restore_and_recompute_paths(dimensions, indices, rows, proof)
    }
}
