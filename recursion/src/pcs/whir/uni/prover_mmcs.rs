//! Shared immutable commitment storage for WHIR's consuming opening API.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_matrix::{Dimensions, Matrix};

/// An MMCS with inexpensive prover-data clones.
///
/// WHIR consumes its opening state, while the univariate PCS retains commitments
/// for later proofs. Sharing the immutable Merkle tree avoids copying its entire
/// codeword and digest layers on every opening. Commitments and proofs are unchanged.
#[derive(Clone, Debug)]
pub struct SharedMmcs<MT>(pub(crate) MT);

impl<T: Send + Sync + Clone, MT: Mmcs<T>> Mmcs<T> for SharedMmcs<MT> {
    type ProverData<M> = Arc<MT::ProverData<M>>;
    type Commitment = MT::Commitment;
    type Proof = MT::Proof;
    type MultiProof = MT::MultiProof;
    type Error = MT::Error;

    fn commit<M: Matrix<T>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        let (commitment, data) = self.0.commit(inputs);
        (commitment, Arc::new(data))
    }

    fn open_batch<M: Matrix<T>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<T, Self> {
        let (values, proof) = self.0.open_batch(index, prover_data).unpack();
        BatchOpening::new(values, proof)
    }

    fn get_matrices<'a, M: Matrix<T>>(&self, prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        self.0.get_matrices(prover_data)
    }

    fn verify_batch(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, T, Self>,
    ) -> Result<(), Self::Error> {
        self.0.verify_batch(
            commitment,
            dimensions,
            index,
            BatchOpeningRef::new(opening.opened_values, opening.opening_proof),
        )
    }

    fn open_multi_batch<M: Matrix<T>>(
        &self,
        indices: &[usize],
        prover_data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<T>>>, Self::MultiProof) {
        self.0.open_multi_batch(indices, prover_data)
    }

    fn verify_multi_batch<R: AsRef<[T]> + PartialEq>(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.0
            .verify_multi_batch(commitment, dimensions, indices, values, proof)
    }
}
