//! Bounded import of opaque native grouped multiproofs through a closed recorder.

use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use p3_binary_pcs::transcript::BinaryPcsShape;
use p3_binary_pcs::{BinaryPcsProof, GroupedCodewordMmcs};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::bytes_to_limbs;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{ExtensionField, Field, PackedValue};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs, PrunedMerklePaths};
use p3_multilinear_util::point::Point;
use p3_sumcheck::OpeningBatch;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::grouped_pcs::{BinaryGroupedPcsInputShape, BinaryGroupedPcsVerifier};
use super::input::{NativeBinaryPcsInput, NativeOracle};
use super::verifier::batches;
use super::whir_plan::invalid;
use super::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

type Tree<F, H, C> = MerkleTreeMmcs<F, u8, H, C, 2, 32>;
type Grouped<F, H, C> = GroupedCodewordMmcs<Tree<F, H, C>>;

#[derive(Clone, Debug)]
struct NativeGroupedOpening {
    leaves: Vec<Vec<u128>>,
    paths: Vec<Vec<[u8; 32]>>,
}

/// Witness material, checked against a retained verifier shape. Circuit
/// constraints still authenticate the caps, all logical rows and supplements.
#[derive(Clone, Debug)]
pub struct NativeBinaryGroupedPcsInput {
    shape: BinaryGroupedPcsInputShape,
    opening: NativeBinaryPcsInput,
    oracles: Vec<NativeGroupedOpening>,
}

impl NativeBinaryGroupedPcsInput {
    pub fn shape(&self) -> &BinaryGroupedPcsInputShape {
        &self.shape
    }
    pub fn query_indices(&self) -> &[usize] {
        self.opening.query_indices()
    }

    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryGroupedPcsInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary grouped input belongs to a different verifier",
            ));
        }
        let mut values = self.opening.private_values(&expected.core)?;
        for oracle in &self.oracles {
            for &raw in oracle.leaves.iter().flatten() {
                values.extend((0..8).map(|i| EF::from_u16((raw >> (16 * i)) as u16)));
            }
            for digest in oracle.paths.iter().flatten() {
                values.extend(bytes_to_limbs(digest).into_iter().map(EF::from_u16));
            }
        }
        Ok(values)
    }
}

impl<F, E> BinaryGroupedPcsVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    pub(crate) fn check_native<H0, C0, H1, C1>(
        &self,
        base_tree: &Tree<F, H0, C0>,
        round_tree: &Tree<E, H1, C1>,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<E>],
        proof: &BinaryPcsProof<F, E, Grouped<F, H0, C0>, Grouped<E, H1, C1>>,
    ) -> Result<(), VerificationError>
    where
        F: PackedValue<Value = F>,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<F, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
    {
        let inner = &self.inner;
        let shape = BinaryPcsShape::new(&inner.config);
        let input_shape = self.input_shape();
        if base_tree.cap_height() != inner.cap_height
            || round_tree.cap_height() != inner.cap_height
            || commitment.roots().len() != 1usize << inner.cap_height
            || proof.sumcheck.polynomial_evaluations.len() != inner.config.num_variables()
            || !proof.sumcheck.pow_witnesses.is_empty()
            || proof.rounds.len() != shape.num_oracles
            || proof.final_codeword.as_slice().len() != shape.final_codeword_len
            || proof.evals.len() != inner.protocol.iter_openings().count()
            || points.len() != proof.evals.len()
        {
            return Err(invalid("binary grouped native proof shape mismatch"));
        }
        let tables = inner.protocol.table_shapes();
        for (i, (table, batch)) in inner.protocol.iter_openings().enumerate() {
            if points[i].num_variables() != tables[table].num_variables()
                || !batch.has_same_shape(&proof.evals[i])
            {
                return Err(invalid("binary grouped native opening shape mismatch"));
            }
        }
        for (i, &(count, _, _)) in input_shape.geometry.iter().enumerate() {
            if i == 0 {
                if proof.base_opened_values.len() != count
                    || proof.base_opened_values.iter().any(|r| r.len() != 1)
                {
                    return Err(invalid("binary grouped native base rows mismatch"));
                }
            } else {
                let round = &proof.rounds[i - 1];
                if round.commitment.roots().len() != 1usize << inner.cap_height
                    || round.opened_values.len() != count
                    || round.opened_values.iter().any(|r| r.len() != 1)
                {
                    return Err(invalid("binary grouped native round rows mismatch"));
                }
            }
        }
        Ok(())
    }

    /// Replays only bounded native sampling, then lets the released grouping
    /// implementation reconstruct complete leaves. The private recorder checks
    /// frontier and restoration budgets before retaining any native paths.
    /// Every failure leaves the caller's challenger unchanged.
    pub fn import_native<H0, C0, H1, C1, Ch>(
        &self,
        base_tree: &Tree<F, H0, C0>,
        round_tree: &Tree<E, H1, C1>,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<E>],
        proof: &BinaryPcsProof<F, E, Grouped<F, H0, C0>, Grouped<E, H1, C1>>,
        challenger: &mut Ch,
    ) -> Result<NativeBinaryGroupedPcsInput, VerificationError>
    where
        F: PackedValue<Value = F>,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<F, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: Clone
            + FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<E, [u8; 32]>>,
    {
        self.import_native_with_usage(
            base_tree,
            round_tree,
            commitment,
            points,
            proof,
            challenger,
            &RefCell::new(InputResourceUsage::default()),
        )
    }

    pub(crate) fn import_native_with_usage<H0, C0, H1, C1, Ch>(
        &self,
        base_tree: &Tree<F, H0, C0>,
        round_tree: &Tree<E, H1, C1>,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<E>],
        proof: &BinaryPcsProof<F, E, Grouped<F, H0, C0>, Grouped<E, H1, C1>>,
        challenger: &mut Ch,
        usage: &RefCell<InputResourceUsage>,
    ) -> Result<NativeBinaryGroupedPcsInput, VerificationError>
    where
        F: PackedValue<Value = F>,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<F, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: Clone
            + FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<E, [u8; 32]>>,
    {
        self.check_native(base_tree, round_tree, commitment, points, proof)?;
        let inner = &self.inner;
        let input_shape = self.input_shape();
        let mut staged = challenger.clone();
        let caps = proof
            .rounds
            .iter()
            .map(|r| r.commitment.clone())
            .collect::<Vec<_>>();
        let queries = inner.replay_native_queries(
            points,
            &proof.sumcheck,
            &proof.evals,
            &caps,
            proof.final_codeword.as_slice(),
            proof.pow_witness,
            &mut staged,
        )?;
        let log_domain = inner.config.num_variables() + inner.config.log_inv_rate();
        let mut oracles = Vec::new();
        for (batch, (start, arity)) in batches(&inner.config).enumerate() {
            let size = 1usize << arity;
            let indices = queries
                .iter()
                .flat_map(|&q| {
                    let first = ((q << inner.config.log_folding_factor()) >> start) & !(size - 1);
                    first..first + size
                })
                .collect::<Vec<_>>();
            let geometry = input_shape.geometry[batch];
            let opening = if batch == 0 {
                extract(
                    base_tree,
                    commitment,
                    log_domain,
                    geometry,
                    &indices,
                    &proof.base_opened_values,
                    &proof.base_multi_proof,
                    &inner.limits,
                    usage,
                )?
            } else {
                let round = &proof.rounds[batch - 1];
                extract(
                    round_tree,
                    &round.commitment,
                    log_domain - start,
                    geometry,
                    &indices,
                    &round.opened_values,
                    &round.multi_proof,
                    &inner.limits,
                    usage,
                )?
            };
            oracles.push(opening);
        }
        let opening = NativeBinaryPcsInput {
            shape: input_shape.core.clone(),
            sumcheck: proof
                .sumcheck
                .polynomial_evaluations
                .iter()
                .map(|m| m.map(E::raw_coordinates))
                .collect(),
            evals: proof
                .evals
                .iter()
                .map(|v| {
                    OpeningBatch::new(
                        v.current().iter().map(|v| v.raw_coordinates()).collect(),
                        v.next().iter().map(|v| v.raw_coordinates()).collect(),
                    )
                })
                .collect(),
            rounds: proof
                .rounds
                .iter()
                .map(|r| NativeOracle {
                    cap: r.commitment.roots().to_vec(),
                    rows: r
                        .opened_values
                        .iter()
                        .map(|r| r[0].raw_coordinates())
                        .collect(),
                    paths: vec![vec![]; r.opened_values.len()],
                })
                .collect(),
            base_rows: proof
                .base_opened_values
                .iter()
                .map(|r| r[0].raw_coordinates())
                .collect(),
            base_paths: vec![vec![]; proof.base_opened_values.len()],
            final_codeword: proof
                .final_codeword
                .as_slice()
                .iter()
                .map(|v| v.raw_coordinates())
                .collect(),
            pow_witness: proof.pow_witness.raw_coordinates(),
            queries,
        };
        *challenger = staged;
        Ok(NativeBinaryGroupedPcsInput {
            shape: input_shape,
            opening,
            oracles,
        })
    }
}

struct Captured<F> {
    indices: Vec<usize>,
    leaves: Vec<Vec<F>>,
    paths: Vec<Vec<[u8; 32]>>,
}

// The same associated native MultiProof type lets the released grouping
// implementation reveal its opaque supplements through this private inner
// MMCS. No caller-supplied verifier or callback participates in the relation.
struct Recorder<'a, F, H, C> {
    tree: &'a Tree<F, H, C>,
    dimensions: Dimensions,
    depth: usize,
    limits: &'a VerifierLimits,
    usage: &'a RefCell<InputResourceUsage>,
    captured: &'a RefCell<Option<Captured<F>>>,
    failure: &'a RefCell<Option<VerificationError>>,
}

impl<F, H, C> Clone for Recorder<'_, F, H, C> {
    fn clone(&self) -> Self {
        Self {
            tree: self.tree,
            dimensions: self.dimensions,
            depth: self.depth,
            limits: self.limits,
            usage: self.usage,
            captured: self.captured,
            failure: self.failure,
        }
    }
}

impl<F, H, C> Mmcs<F> for Recorder<'_, F, H, C>
where
    F: Field + PackedValue<Value = F>,
    H: CryptographicHasher<F, [u8; 32]> + Sync,
    C: PseudoCompressionFunction<[u8; 32], 2> + Sync,
{
    type ProverData<M> = <Tree<F, H, C> as Mmcs<F>>::ProverData<M>;
    type Commitment = MerkleCap<F, [u8; 32]>;
    type Proof = Vec<[u8; 32]>;
    type MultiProof = PrunedMerklePaths<u8, 32>;
    type Error = VerificationError;

    fn commit<M: Matrix<F>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        self.tree.commit(inputs)
    }
    fn open_batch<M: Matrix<F>>(
        &self,
        index: usize,
        data: &Self::ProverData<M>,
    ) -> BatchOpening<F, Self> {
        let (rows, proof) = self.tree.open_batch(index, data).unpack();
        BatchOpening::new(rows, proof)
    }
    fn get_matrices<'a, M: Matrix<F>>(&self, data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        self.tree.get_matrices(data)
    }
    fn verify_batch(
        &self,
        cap: &Self::Commitment,
        dims: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, F, Self>,
    ) -> Result<(), Self::Error> {
        self.tree
            .verify_batch(
                cap,
                dims,
                index,
                BatchOpeningRef::new(opening.opened_values, opening.opening_proof),
            )
            .map_err(|_| invalid("binary grouped batch verification failed"))
    }
    fn open_multi_batch<M: Matrix<F>>(
        &self,
        indices: &[usize],
        data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<F>>>, Self::MultiProof) {
        self.tree.open_multi_batch(indices, data)
    }
    fn verify_multi_batch<R: AsRef<[F]> + PartialEq>(
        &self,
        _cap: &Self::Commitment,
        dims: &[Dimensions],
        indices: &[usize],
        rows: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        let result = (|| {
            if self.captured.borrow().is_some()
                || dims != [self.dimensions]
                || indices.len() != rows.len()
                || indices.windows(2).any(|w| w[0] >= w[1])
                || rows
                    .iter()
                    .any(|r| r.len() != 1 || r[0].as_ref().len() != self.dimensions.width)
            {
                return Err(invalid("binary grouped extraction shape mismatch"));
            }
            let max = indices.len().checked_mul(self.depth).ok_or(
                VerificationError::ResourceArithmeticOverflow {
                    component: "binary grouped frontier",
                },
            )?;
            if proof.sibling_hashes.len() > max {
                return Err(invalid(
                    "binary grouped frontier exceeds its possible path count",
                ));
            }
            self.usage
                .borrow_mut()
                .add_compressed_frontier_hashes(self.limits, proof.sibling_hashes.len())?;
            let restored = self
                .tree
                .restore_and_recompute_paths(dims, indices, rows, proof)
                .map_err(|_| invalid("binary grouped multiproof restoration failed"))?;
            if restored.len() != indices.len()
                || restored
                    .iter()
                    .zip(indices)
                    .any(|(p, &i)| p.leaf_index != i || p.siblings.len() != self.depth)
            {
                return Err(invalid("binary grouped restored path mismatch"));
            }
            *self.captured.borrow_mut() = Some(Captured {
                indices: indices.to_vec(),
                leaves: rows.iter().map(|r| r[0].as_ref().to_vec()).collect(),
                paths: restored.into_iter().map(|p| p.siblings).collect(),
            });
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                *self.failure.borrow_mut() = Some(error);
                Err(invalid("binary grouped recorder rejected its opening"))
            }
        }
    }
}

fn extract<F, H, C>(
    tree: &Tree<F, H, C>,
    cap: &MerkleCap<F, [u8; 32]>,
    symbol_bits: usize,
    geometry: (usize, usize, usize),
    indices: &[usize],
    rows: &[Vec<F>],
    proof: &<Grouped<F, H, C> as Mmcs<F>>::MultiProof,
    limits: &VerifierLimits,
    usage: &RefCell<InputResourceUsage>,
) -> Result<NativeGroupedOpening, VerificationError>
where
    F: RecursiveBinaryTowerField + PackedValue<Value = F>,
    H: CryptographicHasher<F, [u8; 32]> + Sync,
    C: PseudoCompressionFunction<[u8; 32], 2> + Sync,
{
    let (_, width, depth) = geometry;
    let captured = RefCell::new(None);
    let failure = RefCell::new(None);
    let recorder = Recorder {
        tree,
        dimensions: Dimensions {
            width,
            height: (1usize << symbol_bits) / width,
        },
        depth,
        limits,
        usage,
        captured: &captured,
        failure: &failure,
    };
    let grouped = GroupedCodewordMmcs::new(recorder, width);
    let wrapped = rows.iter().map(|r| vec![r.as_slice()]).collect::<Vec<_>>();
    let result = grouped.verify_multi_batch(
        cap,
        &[Dimensions {
            width: 1,
            height: 1usize << symbol_bits,
        }],
        indices,
        &wrapped,
        proof,
    );
    if result.is_err() {
        return Err(failure
            .into_inner()
            .unwrap_or_else(|| invalid("binary grouped native extraction failed")));
    }
    let captured = captured
        .into_inner()
        .ok_or_else(|| invalid("binary grouped extraction omitted its inner opening"))?;
    let mut leaves = Vec::with_capacity(indices.len());
    let mut paths = Vec::with_capacity(indices.len());
    for &index in indices {
        let i = captured
            .indices
            .binary_search(&(index / width))
            .map_err(|_| invalid("binary grouped extraction omitted a queried leaf"))?;
        leaves.push(
            captured.leaves[i]
                .iter()
                .map(|v| v.raw_coordinates())
                .collect(),
        );
        paths.push(captured.paths[i].clone());
    }
    Ok(NativeGroupedOpening { leaves, paths })
}
