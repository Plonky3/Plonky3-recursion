//! The native byte-hash Merkle tree of a WHIR commitment, at the arity its parameters configure.

use alloc::vec::Vec;

use p3_circuit::ops::ByteHash;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::Field;
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::{MerkleAuthPath, MerkleCap, MerkleTree, MerkleTreeError, PrunedMerklePaths};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};

use super::{BinaryNativeHash, NativeArityMmcs};
use crate::pcs::binary::{ByteDigestMmcs, MerkleArity};

/// A native byte-hash Merkle tree whose nodes compress two or four digests.
///
/// Commitments, opening proofs and pruned multi-openings have the same types at
/// both arities; only the prover's tree differs.
#[derive(Clone, Debug)]
pub enum NativeWhirMmcs<F> {
    Two(NativeArityMmcs<F, 2>),
    Four(NativeArityMmcs<F, 4>),
}

/// The prover data of a [`NativeWhirMmcs`] commitment: the tree of its arity.
#[derive(Clone, Debug)]
pub enum NativeWhirTree<F, M> {
    Two(MerkleTree<F, u8, M, 2, 32>),
    Four(MerkleTree<F, u8, M, 4, 32>),
}

impl<F> NativeWhirMmcs<F> {
    /// The tree of `arity` that hashes with `hash` and whose cap replaces its
    /// top `cap_height` levels.
    pub(crate) const fn new(hash: ByteHash, arity: MerkleArity, cap_height: usize) -> Self {
        let leaf = SerializingHasher::new(BinaryNativeHash(hash));
        match arity {
            MerkleArity::Two => Self::Two(NativeArityMmcs::new(
                leaf,
                CompressionFunctionFromHasher::new(BinaryNativeHash(hash)),
                cap_height,
            )),
            MerkleArity::Four => Self::Four(NativeArityMmcs::new(
                leaf,
                CompressionFunctionFromHasher::new(BinaryNativeHash(hash)),
                cap_height,
            )),
        }
    }
}

/// Opens prover data committed by a tree of the other arity: a caller error,
/// as every WHIR prover opens the data its own tree committed.
fn foreign_tree() -> ! {
    panic!("native WHIR prover data was committed by a tree of another arity")
}

impl<F: Field> Mmcs<F> for NativeWhirMmcs<F> {
    type ProverData<M> = NativeWhirTree<F, M>;
    type Commitment = MerkleCap<F, [u8; 32]>;
    type Proof = Vec<[u8; 32]>;
    type MultiProof = PrunedMerklePaths<u8, 32>;
    type Error = MerkleTreeError;

    fn commit<M: Matrix<F>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        match self {
            Self::Two(tree) => {
                let (cap, data) = tree.commit(inputs);
                (cap, NativeWhirTree::Two(data))
            }
            Self::Four(tree) => {
                let (cap, data) = tree.commit(inputs);
                (cap, NativeWhirTree::Four(data))
            }
        }
    }

    fn open_batch<M: Matrix<F>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<F, Self> {
        let (rows, proof) = match (self, prover_data) {
            (Self::Two(tree), NativeWhirTree::Two(data)) => tree.open_batch(index, data).unpack(),
            (Self::Four(tree), NativeWhirTree::Four(data)) => tree.open_batch(index, data).unpack(),
            _ => foreign_tree(),
        };
        BatchOpening::new(rows, proof)
    }

    fn get_matrices<'a, M: Matrix<F>>(&self, prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        match (self, prover_data) {
            (Self::Two(tree), NativeWhirTree::Two(data)) => tree.get_matrices(data),
            (Self::Four(tree), NativeWhirTree::Four(data)) => tree.get_matrices(data),
            _ => foreign_tree(),
        }
    }

    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, F, Self>,
    ) -> Result<(), Self::Error> {
        let (rows, proof) = batch_opening.unpack();
        match self {
            Self::Two(tree) => {
                tree.verify_batch(commit, dimensions, index, BatchOpeningRef::new(rows, proof))
            }
            Self::Four(tree) => {
                tree.verify_batch(commit, dimensions, index, BatchOpeningRef::new(rows, proof))
            }
        }
    }

    fn open_multi_batch<M: Matrix<F>>(
        &self,
        indices: &[usize],
        prover_data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<F>>>, Self::MultiProof) {
        match (self, prover_data) {
            (Self::Two(tree), NativeWhirTree::Two(data)) => tree.open_multi_batch(indices, data),
            (Self::Four(tree), NativeWhirTree::Four(data)) => tree.open_multi_batch(indices, data),
            _ => foreign_tree(),
        }
    }

    fn verify_multi_batch<R: AsRef<[F]> + PartialEq>(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        opened_values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        match self {
            Self::Two(tree) => {
                tree.verify_multi_batch(commit, dimensions, indices, opened_values, proof)
            }
            Self::Four(tree) => {
                tree.verify_multi_batch(commit, dimensions, indices, opened_values, proof)
            }
        }
    }
}

impl<F: Field> ByteDigestMmcs<F> for NativeWhirMmcs<F> {
    fn compression_arity(&self) -> usize {
        match self {
            Self::Two(tree) => tree.compression_arity(),
            Self::Four(tree) => tree.compression_arity(),
        }
    }

    fn cap_height(&self) -> usize {
        match self {
            Self::Two(tree) => tree.cap_height(),
            Self::Four(tree) => tree.cap_height(),
        }
    }

    fn restore_paths(
        &self,
        dimensions: &[Dimensions],
        indices: &[usize],
        rows: &[Vec<&[F]>],
        proof: &PrunedMerklePaths<u8, 32>,
    ) -> Result<Vec<MerkleAuthPath<u8, 32>>, MerkleTreeError> {
        match self {
            Self::Two(tree) => tree.restore_paths(dimensions, indices, rows, proof),
            Self::Four(tree) => tree.restore_paths(dimensions, indices, rows, proof),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_binary_field::BinaryField128;
    use p3_circuit::ops::ByteHash;
    use p3_commit::Mmcs;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::Dimensions;
    use p3_matrix::dense::RowMajorMatrix;

    use super::NativeWhirMmcs;
    use crate::pcs::binary::{ByteDigestMmcs, MerkleArity};

    type F = BinaryField128;

    /// Each arity commits the tree p3 builds at that arity: a cap of `arity^c`
    /// roots, and pruned openings that verify and restore to `(arity - 1)`
    /// siblings per level below the cap.
    #[test]
    fn each_arity_commits_opens_and_restores_its_own_tree() {
        const LOG_HEIGHT: usize = 7;
        const CAP_HEIGHT: usize = 1;
        let rows = 1 << LOG_HEIGHT;
        let matrix = RowMajorMatrix::new(
            (0..rows * 3)
                .map(|i| F::from_u32(i as u32 * 7 + 1))
                .collect(),
            3,
        );
        let dimensions = [Dimensions {
            width: 3,
            height: rows,
        }];
        let indices = [0, 5, 77, rows - 1];
        for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
            for arity in [MerkleArity::Two, MerkleArity::Four] {
                let mmcs = NativeWhirMmcs::<F>::new(hash, arity, CAP_HEIGHT);
                assert_eq!(mmcs.compression_arity(), arity.digests());
                assert_eq!(ByteDigestMmcs::cap_height(&mmcs), CAP_HEIGHT);
                let (cap, data) = mmcs.commit_matrix(matrix.clone());
                assert_eq!(Some(cap.num_roots()), arity.cap_roots(CAP_HEIGHT));
                let (opened, proof) = mmcs.open_multi_batch(&indices, &data);
                mmcs.verify_multi_batch(&cap, &dimensions, &indices, &opened, &proof)
                    .unwrap();
                let views: Vec<Vec<&[F]>> = opened
                    .iter()
                    .map(|row| row.iter().map(Vec::as_slice).collect())
                    .collect();
                let paths = mmcs
                    .restore_paths(&dimensions, &indices, &views, &proof)
                    .unwrap();
                let siblings = arity.path_siblings(LOG_HEIGHT, CAP_HEIGHT).unwrap();
                assert!(paths.iter().all(|path| path.siblings.len() == siblings));
                let mut wrong = opened.clone();
                wrong[1][0][2] += F::ONE;
                assert!(
                    mmcs.verify_multi_batch(&cap, &dimensions, &indices, &wrong, &proof)
                        .is_err()
                );
            }
        }
    }

    /// The two arities commit different caps to the same rows.
    #[test]
    fn arities_commit_different_caps() {
        let matrix = RowMajorMatrix::new((0..64).map(F::from_u32).collect(), 2);
        let caps: Vec<_> = [MerkleArity::Two, MerkleArity::Four]
            .into_iter()
            .map(|arity| {
                NativeWhirMmcs::<F>::new(ByteHash::Keccak256, arity, 0)
                    .commit_matrix(matrix.clone())
                    .0
            })
            .collect();
        assert_eq!(caps[0].num_roots(), 1);
        assert_eq!(caps[1].num_roots(), 1);
        assert_ne!(caps[0], caps[1]);
    }
}
