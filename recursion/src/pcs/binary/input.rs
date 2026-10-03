//! Bounded native proof import and proof-independent circuit input allocation.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_pcs::transcript::{BinaryPcsShape, BinaryPcsVerifierTranscript};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsProof};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash, bytes_to_limbs};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PackedValue, PrimeField64};
use p3_matrix::Dimensions;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs, PrunedMerklePaths};
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{Layout, SuffixProver, Verifier};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, SumcheckData};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::verifier::batches;
use super::{
    BinaryOracleOpeningTargets, BinaryPcs128ProofTargets, BinaryPcsVerifier,
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField,
};
use crate::verifier::{InputResourceUsage, VerificationError};

/// Pure structural input description. Query values, rejection patterns and
/// compressed frontier sizes are deliberately absent. Constructed only from a
/// resource-checked verifier, and reusable across native proofs of that verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPcsInputShape {
    config: BinaryPcsConfig,
    protocol: OpeningProtocol,
    hash: ByteHash,
    cap_height: usize,
    max_query_draws: usize,
}

impl BinaryPcsInputShape {
    /// Allocates only proof witnesses. The caller allocates and binds the
    /// commitment and prescribed points at their surrounding transcript sites.
    pub fn allocate_targets<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryPcs128ProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let shape = BinaryPcsShape::new(&self.config);
        let sumcheck = (0..self.config.num_variables())
            .map(|_| {
                Ok([
                    alloc_field::<BF, EF>(circuit)?,
                    alloc_field::<BF, EF>(circuit)?,
                ])
            })
            .collect::<Result<_, VerificationError>>()?;
        let evals = self
            .protocol
            .iter_openings()
            .map(|(_, batch)| {
                Ok(OpeningBatch::new(
                    (0..batch.current().len())
                        .map(|_| alloc_field::<BF, EF>(circuit))
                        .collect::<Result<_, _>>()?,
                    (0..batch.next().len())
                        .map(|_| alloc_field::<BF, EF>(circuit))
                        .collect::<Result<_, _>>()?,
                ))
            })
            .collect::<Result<_, VerificationError>>()?;
        let log_domain = self.config.num_variables() + self.config.log_inv_rate();
        let mut rounds = Vec::new();
        for (start, arity) in batches(&self.config).skip(1) {
            let cap = (0..1usize << self.cap_height)
                .map(|_| alloc_digest(circuit))
                .collect();
            let (rows, paths) = alloc_oracle::<BF, EF>(
                circuit,
                shape.num_pairs << arity,
                log_domain - start - self.cap_height,
            )?;
            rounds.push(BinaryOracleOpeningTargets { cap, rows, paths });
        }
        let (base_rows, base_paths) = alloc_oracle::<BF, EF>(
            circuit,
            shape.num_pairs << self.config.log_folding_factor(),
            log_domain - self.cap_height,
        )?;
        let final_codeword = (0..shape.final_codeword_len)
            .map(|_| alloc_field::<BF, EF>(circuit))
            .collect::<Result<_, _>>()?;
        let pow_witness = alloc_field::<BF, EF>(circuit)?;
        let query_indices = (0..shape.num_pairs)
            .map(|_| {
                (0..shape.pair_bits)
                    .map(|_| circuit.alloc_private_input("binary PCS query bit"))
                    .collect()
            })
            .collect();
        Ok(BinaryPcs128ProofTargets {
            sumcheck,
            evals,
            rounds,
            base_rows,
            base_paths,
            final_codeword,
            pow_witness,
            query_indices,
        })
    }
}

/// Shape-checked native input after bounded transcript replay and path
/// restoration. This is witness material, not a verification authority: the
/// circuit still authenticates every path and checks the complete PCS relation.
#[derive(Clone, Debug)]
pub struct NativeBinaryPcsInput {
    shape: BinaryPcsInputShape,
    sumcheck: Vec<[u128; 2]>,
    evals: Vec<OpeningBatch<u128>>,
    rounds: Vec<NativeOracle>,
    base_rows: Vec<u128>,
    base_paths: Vec<Vec<[u8; 32]>>,
    final_codeword: Vec<u128>,
    pow_witness: u128,
    queries: Vec<usize>,
}

#[derive(Clone, Debug)]
struct NativeOracle {
    cap: Vec<[u8; 32]>,
    rows: Vec<u128>,
    paths: Vec<Vec<[u8; 32]>>,
}

impl NativeBinaryPcsInput {
    pub fn shape(&self) -> &BinaryPcsInputShape {
        &self.shape
    }

    /// Unshifted sorted candidates, suitable for the circuit's query witnesses.
    pub fn query_indices(&self) -> &[usize] {
        &self.queries
    }

    /// Packs exactly the private input order of `shape().allocate_targets()`.
    /// A different verifier shape is rejected before packing.
    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryPcsInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary PCS imported input belongs to a different verifier",
            ));
        }
        let mut values = Vec::new();
        let push_field = |values: &mut Vec<EF>, raw: u128| {
            values.extend((0..8).map(|i| EF::from_u16((raw >> (16 * i)) as u16)));
        };
        let push_digest = |values: &mut Vec<EF>, digest: &[u8; 32]| {
            values.extend(bytes_to_limbs(digest).into_iter().map(EF::from_u16));
        };
        for &raw in self.sumcheck.iter().flatten() {
            push_field(&mut values, raw);
        }
        for evals in &self.evals {
            for &raw in evals.current().iter().chain(evals.next()) {
                push_field(&mut values, raw);
            }
        }
        for round in &self.rounds {
            for digest in &round.cap {
                push_digest(&mut values, digest);
            }
            for &raw in &round.rows {
                push_field(&mut values, raw);
            }
            for digest in round.paths.iter().flatten() {
                push_digest(&mut values, digest);
            }
        }
        for &raw in &self.base_rows {
            push_field(&mut values, raw);
        }
        for digest in self.base_paths.iter().flatten() {
            push_digest(&mut values, digest);
        }
        for &raw in &self.final_codeword {
            push_field(&mut values, raw);
        }
        push_field(&mut values, self.pow_witness);
        let bits = BinaryPcsShape::new(&self.shape.config).pair_bits;
        for &index in &self.queries {
            values.extend((0..bits).map(|b| EF::from_bool(index >> b & 1 == 1)));
        }
        Ok(values)
    }
}

impl<F, E> BinaryPcsVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    /// Inspects structural shape without reading a proof or replaying a transcript.
    pub fn input_shape(&self) -> BinaryPcsInputShape {
        BinaryPcsInputShape {
            config: self.config,
            protocol: self.protocol.clone(),
            hash: self.hash,
            cap_height: self.cap_height,
            max_query_draws: self.max_query_draws,
        }
    }

    pub(crate) fn check_native<H0, C0, H1, C1>(
        &self,
        base_mmcs: &MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<E>],
        proof: &BinaryPcsProof<
            F,
            E,
            MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
            MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        >,
    ) -> Result<(), VerificationError>
    where
        F: PackedValue<Value = F>,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<F, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
    {
        let shape = BinaryPcsShape::new(&self.config);
        if base_mmcs.cap_height() != self.cap_height
            || round_mmcs.cap_height() != self.cap_height
            || commitment.roots().len() != 1usize << self.cap_height
            || proof.sumcheck.polynomial_evaluations.len() != self.config.num_variables()
            || !proof.sumcheck.pow_witnesses.is_empty()
            || proof.rounds.len() != shape.num_oracles
            || proof.final_codeword.as_slice().len() != shape.final_codeword_len
            || proof.evals.len() != self.protocol.iter_openings().count()
            || points.len() != proof.evals.len()
        {
            return Err(invalid(
                "binary PCS native proof or commitment shape mismatch",
            ));
        }
        let shapes = self.protocol.table_shapes();
        for (i, (table, batch)) in self.protocol.iter_openings().enumerate() {
            if points[i].num_variables() != shapes[table].num_variables()
                || !batch.has_same_shape(&proof.evals[i])
            {
                return Err(invalid("binary PCS native opening shape mismatch"));
            }
        }
        let mut usage = InputResourceUsage::default();
        for (batch, (_, arity)) in batches(&self.config).enumerate() {
            let (rows, frontier) = if batch == 0 {
                (proof.base_opened_values.len(), &proof.base_multi_proof)
            } else {
                let oracle = &proof.rounds[batch - 1];
                if oracle.commitment.roots().len() != 1usize << self.cap_height
                    || oracle.opened_values.iter().any(|r| r.len() != 1)
                {
                    return Err(invalid("binary PCS native folded oracle shape mismatch"));
                }
                (oracle.opened_values.len(), &oracle.multi_proof)
            };
            if rows != shape.num_pairs << arity {
                return Err(invalid("binary PCS native opened row count mismatch"));
            }
            usage.add_compressed_frontier_hashes(&self.limits, frontier.sibling_hashes.len())?;
        }
        if proof.base_opened_values.iter().any(|r| r.len() != 1) {
            return Err(invalid("binary PCS native base row width mismatch"));
        }
        Ok(())
    }

    /// Imports released ordinary byte-tree proofs. `challenger` must be at the
    /// native `verify_at` entry, after commitment and prescribed-point binding.
    /// Stops exactly at native query completion within the explicit draw budget.
    /// Passing a mutable challenger reference preserves that native continuation
    /// for importing a following opening. No native unbounded sampler runs.
    pub fn import_native<H0, C0, H1, C1, Ch>(
        &self,
        base_mmcs: &MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<E>],
        proof: &BinaryPcsProof<
            F,
            E,
            MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
            MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        >,
        mut challenger: Ch,
    ) -> Result<NativeBinaryPcsInput, VerificationError>
    where
        F: PackedValue<Value = F>,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<F, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        Ch: FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<E, [u8; 32]>>,
    {
        self.check_native(base_mmcs, round_mmcs, commitment, points, proof)?;
        let shape = BinaryPcsShape::new(&self.config);
        let shapes = self.protocol.table_shapes();
        let mut layout = Verifier::<F, E>::new(&shapes, SuffixProver::<F, E>::strategy());
        for (i, (table, batch)) in self.protocol.iter_openings().enumerate() {
            layout
                .add_claim_at(table, batch, &points[i], &proof.evals[i], &mut challenger)
                .map_err(|_| invalid("binary PCS native layout replay failed"))?;
        }
        {
            let mut transcript =
                BinaryPcsVerifierTranscript::<F, E, _>::new(&mut challenger, shape);
            let replay = (|| {
                let alpha = transcript.fold_batch(|ch| layout.batching_challenge(ch));
                let mut claim = layout.sum(alpha);
                for (batch, (start, arity)) in batches(&self.config).enumerate() {
                    for r in start..start + arity {
                        let message = SumcheckData {
                            polynomial_evaluations: vec![proof.sumcheck.polynomial_evaluations[r]],
                            pow_witnesses: vec![],
                        };
                        let _ = transcript
                            .fold_batch(|ch| {
                                message.verify_rounds(ch, &mut claim, 1, 0, Basis::Evaluation)
                            })
                            .map_err(|_| invalid("binary PCS native sumcheck replay failed"))?;
                    }
                    if batch < shape.num_oracles {
                        transcript.oracle_commitment(proof.rounds[batch].commitment.clone());
                    }
                }
                transcript
                    .final_codeword(proof.final_codeword.as_slice())
                    .map_err(|_| invalid("binary PCS native final codeword replay failed"))?;
                transcript
                    .query_pow(proof.pow_witness)
                    .map_err(|_| invalid("binary PCS native query grinding failed"))?;
                Ok::<_, VerificationError>(())
            })();
            // The final described query step is implemented below with an
            // explicit bound; release the native driver's unfinished-step guard.
            transcript.abort();
            replay?;
        }
        let mut queries = Vec::with_capacity(shape.num_pairs);
        for _ in 0..self.max_query_draws {
            let candidate = challenger
                .sample_uniform_bits::<true>(shape.pair_bits)
                .map_err(|_| invalid("binary PCS native query sampling failed"))?;
            if candidate >= 1usize << shape.pair_bits {
                return Err(invalid(
                    "binary PCS native query sampler returned an out-of-range index",
                ));
            }
            if !queries.contains(&candidate) {
                queries.push(candidate);
            }
            if queries.len() == shape.num_pairs {
                break;
            }
        }
        if queries.len() != shape.num_pairs {
            return Err(invalid("binary PCS native query draw budget exhausted"));
        }
        queries.sort_unstable();
        let log_domain = self.config.num_variables() + self.config.log_inv_rate();
        let indices = |start: usize, arity: usize| {
            let size = 1usize << arity;
            queries
                .iter()
                .flat_map(|&query| {
                    let first =
                        ((query << self.config.log_folding_factor()) >> start) & !(size - 1);
                    first..first + size
                })
                .collect::<Vec<_>>()
        };
        let base_paths = restore(
            base_mmcs,
            log_domain,
            &indices(0, self.config.log_folding_factor()),
            &proof.base_opened_values,
            &proof.base_multi_proof,
            self.cap_height,
        )?;
        let rounds = batches(&self.config)
            .skip(1)
            .zip(&proof.rounds)
            .map(|((start, arity), oracle)| {
                Ok(NativeOracle {
                    cap: oracle.commitment.roots().to_vec(),
                    rows: oracle
                        .opened_values
                        .iter()
                        .map(|r| r[0].raw_coordinates())
                        .collect(),
                    paths: restore(
                        round_mmcs,
                        log_domain - start,
                        &indices(start, arity),
                        &oracle.opened_values,
                        &oracle.multi_proof,
                        self.cap_height,
                    )?,
                })
            })
            .collect::<Result<_, VerificationError>>()?;
        Ok(NativeBinaryPcsInput {
            shape: self.input_shape(),
            sumcheck: proof
                .sumcheck
                .polynomial_evaluations
                .iter()
                .map(|m| m.map(E::raw_coordinates))
                .collect(),
            evals: proof
                .evals
                .iter()
                .map(|e| {
                    OpeningBatch::new(
                        e.current()
                            .iter()
                            .copied()
                            .map(E::raw_coordinates)
                            .collect(),
                        e.next().iter().copied().map(E::raw_coordinates).collect(),
                    )
                })
                .collect(),
            rounds,
            base_rows: proof
                .base_opened_values
                .iter()
                .map(|r| r[0].raw_coordinates())
                .collect(),
            base_paths,
            final_codeword: proof
                .final_codeword
                .as_slice()
                .iter()
                .copied()
                .map(E::raw_coordinates)
                .collect(),
            pow_witness: proof.pow_witness.raw_coordinates(),
            queries,
        })
    }
}

fn restore<F, H, C>(
    mmcs: &MerkleTreeMmcs<F, u8, H, C, 2, 32>,
    log_height: usize,
    indices: &[usize],
    rows: &[Vec<F>],
    proof: &PrunedMerklePaths<u8, 32>,
    cap_height: usize,
) -> Result<Vec<Vec<[u8; 32]>>, VerificationError>
where
    F: Field + PackedValue<Value = F>,
    H: CryptographicHasher<F, [u8; 32]> + Sync,
    C: PseudoCompressionFunction<[u8; 32], 2> + Sync,
{
    let wrapped: Vec<_> = rows.iter().map(|row| vec![row.as_slice()]).collect();
    let paths = mmcs
        .restore_and_recompute_paths(
            &[Dimensions {
                width: 1,
                height: 1usize << log_height,
            }],
            indices,
            &wrapped,
            proof,
        )
        .map_err(|_| invalid("binary PCS native multiproof restoration failed"))?;
    if paths.len() != indices.len()
        || paths.iter().zip(indices).any(|(path, &index)| {
            path.leaf_index != index || path.siblings.len() != log_height - cap_height
        })
    {
        return Err(invalid("binary PCS restored path shape mismatch"));
    }
    Ok(paths.into_iter().map(|path| path.siblings).collect())
}

fn alloc_field<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
) -> Result<BinaryTower128Target, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let limbs = circuit.alloc_private_input_array::<8>("binary PCS field");
    Ok(circuit.binary128_from_limbs::<BF>(limbs)?)
}

fn alloc_digest<EF: Field + Eq + Hash>(circuit: &mut CircuitBuilder<EF>) -> Vec<ExprId> {
    circuit
        .alloc_private_input_array::<16>("binary PCS digest")
        .to_vec()
}

fn alloc_oracle<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    count: usize,
    depth: usize,
) -> Result<(Vec<BinaryTower128Target>, Vec<Vec<Vec<ExprId>>>), VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let rows = (0..count)
        .map(|_| alloc_field::<BF, EF>(circuit))
        .collect::<Result<_, _>>()?;
    let paths = (0..count)
        .map(|_| (0..depth).map(|_| alloc_digest(circuit)).collect())
        .collect();
    Ok((rows, paths))
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
