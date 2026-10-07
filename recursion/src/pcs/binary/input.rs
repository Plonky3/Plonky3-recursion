//! Bounded native proof import and proof-independent circuit input allocation.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::BinaryPcsConfig;
use p3_binary_pcs::transcript::{BinaryPcsShape, BinaryPcsVerifierTranscript};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryTower128Target, ByteHash, NativeTower128Target, bytes_to_limbs};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PackedValue, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Dimensions;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs, PrunedMerklePaths};
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{Layout, SuffixProver, Verifier};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, SumcheckData};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};

use super::verifier::{batches, coset_path_shape, coset_subtree_depth};
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
    pub(super) config: BinaryPcsConfig,
    protocol: OpeningProtocol,
    hash: ByteHash,
    cap_height: usize,
    max_query_draws: usize,
    pub(super) grouping: Option<[super::grouped_pcs::BinaryCodewordGrouping; 2]>,
}

impl BinaryPcsInputShape {
    pub(crate) fn native_decode_shape(&self) -> crate::artifact::binary_native::codec::PcsDecode {
        debug_assert!(
            self.grouping.is_none(),
            "closed native authority uses ordinary PCS"
        );
        self.native_scalar_geometry()
    }

    pub(super) fn native_scalar_geometry(
        &self,
    ) -> crate::artifact::binary_native::codec::PcsDecode {
        use crate::artifact::binary_native::codec::{OracleDecode, PcsDecode};
        let shape = BinaryPcsShape::new(&self.config);
        let log_domain = self.config.num_variables() + self.config.log_inv_rate();
        PcsDecode {
            cap_roots: 1usize << self.cap_height,
            sumcheck_rounds: self.config.num_variables(),
            eval_widths: self
                .protocol
                .iter_openings()
                .map(|(_, b)| (b.current().len(), b.next().len()))
                .collect(),
            rounds: batches(&self.config)
                .skip(1)
                .map(|(start, arity)| OracleDecode {
                    rows: shape.num_pairs << arity,
                    path_len: log_domain - start - self.cap_height,
                })
                .collect(),
            base: OracleDecode {
                rows: shape.num_pairs << self.config.log_folding_factor(),
                path_len: log_domain - self.cap_height,
            },
            final_codeword: shape.final_codeword_len,
        }
    }

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
        self.allocate_with(circuit, alloc_field::<BF, EF>)
    }

    /// Allocates proof witnesses as native Tower128 scalars, one private
    /// input per field value, in the order of [`Self::allocate_targets`].
    /// Grouped codewords and hashes the native host cannot evaluate are
    /// rejected before any input is allocated.
    pub fn allocate_native_targets(
        &self,
        circuit: &mut CircuitBuilder<BinaryField128>,
    ) -> Result<BinaryPcs128ProofTargets<NativeTower128Target>, VerificationError> {
        if self.grouping.is_some() {
            return Err(invalid(
                "native scalar binary PCS verifier does not support grouped codewords",
            ));
        }
        <NativeBinaryEncoding as BinaryCircuitHost<BinaryField128>>::check_hash(self.hash)?;
        self.allocate_with(circuit, |b| {
            let value = b.alloc_private_input("native binary PCS field");
            b.check_construction_limits()?;
            Ok(b.native_tower128_from_expr(value))
        })
    }

    /// Proof witness allocation order shared by every scalar representation.
    pub(super) fn allocate_with<T, CF>(
        &self,
        circuit: &mut CircuitBuilder<CF>,
        mut field: impl FnMut(&mut CircuitBuilder<CF>) -> Result<T, VerificationError>,
    ) -> Result<BinaryPcs128ProofTargets<T>, VerificationError>
    where
        CF: Field + Eq + Hash,
    {
        let shape = BinaryPcsShape::new(&self.config);
        let sumcheck = (0..self.config.num_variables())
            .map(|_| Ok([field(circuit)?, field(circuit)?]))
            .collect::<Result<_, VerificationError>>()?;
        let evals = self
            .protocol
            .iter_openings()
            .map(|(_, batch)| {
                Ok(OpeningBatch::new(
                    (0..batch.current().len())
                        .map(|_| field(circuit))
                        .collect::<Result<_, _>>()?,
                    (0..batch.next().len())
                        .map(|_| field(circuit))
                        .collect::<Result<_, _>>()?,
                ))
            })
            .collect::<Result<_, VerificationError>>()?;
        let path_shape = |start: usize, arity: usize| {
            let (per_query, depth) = coset_path_shape(
                &self.config,
                self.cap_height,
                self.grouping.is_some(),
                start,
                arity,
            );
            (shape.num_pairs * per_query, depth)
        };
        let mut rounds = Vec::new();
        for (start, arity) in batches(&self.config).skip(1) {
            let cap = (0..1usize << self.cap_height)
                .map(|_| alloc_digest(circuit))
                .collect();
            let (rows, paths) = alloc_oracle(
                circuit,
                shape.num_pairs << arity,
                path_shape(start, arity),
                &mut field,
            )?;
            rounds.push(BinaryOracleOpeningTargets { cap, rows, paths });
        }
        let (base_rows, base_paths) = alloc_oracle(
            circuit,
            shape.num_pairs << self.config.log_folding_factor(),
            path_shape(0, self.config.log_folding_factor()),
            &mut field,
        )?;
        let final_codeword = (0..shape.final_codeword_len)
            .map(|_| field(circuit))
            .collect::<Result<_, _>>()?;
        let pow_witness = field(circuit)?;
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
    pub(super) shape: BinaryPcsInputShape,
    pub(super) sumcheck: Vec<[u128; 2]>,
    pub(super) evals: Vec<OpeningBatch<u128>>,
    pub(super) rounds: Vec<NativeOracle>,
    pub(super) base_rows: Vec<u128>,
    pub(super) base_paths: Vec<Vec<[u8; 32]>>,
    pub(super) final_codeword: Vec<u128>,
    pub(super) pow_witness: u128,
    pub(super) queries: Vec<usize>,
}

#[derive(Clone, Debug)]
pub(super) struct NativeOracle {
    pub(super) cap: Vec<[u8; 32]>,
    pub(super) rows: Vec<u128>,
    pub(super) paths: Vec<Vec<[u8; 32]>>,
}

impl NativeBinaryPcsInput {
    pub const fn shape(&self) -> &BinaryPcsInputShape {
        &self.shape
    }

    /// Unshifted sorted candidates, suitable for the circuit's query witnesses.
    pub fn query_indices(&self) -> &[usize] {
        &self.queries
    }

    /// Path digests of the oracle at fold batch `(start, arity)` in circuit
    /// input order. A query coset authenticated as one Merkle subtree takes
    /// its offset-0 siblings above the subtree; otherwise every restored path.
    fn circuit_path_digests<'a>(
        &self,
        paths: &'a [Vec<[u8; 32]>],
        start: usize,
        arity: usize,
    ) -> Result<Vec<&'a [u8; 32]>, VerificationError> {
        if self.shape.grouping.is_some()
            || coset_subtree_depth(&self.shape.config, self.shape.cap_height, start, arity)
                .is_none()
        {
            return Ok(paths.iter().flatten().collect());
        }
        let mut digests = Vec::new();
        for coset in paths.chunks(1usize << arity) {
            digests.extend(
                coset[0]
                    .get(arity..)
                    .ok_or_else(|| invalid("binary PCS restored path is shorter than its coset"))?,
            );
        }
        Ok(digests)
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
        for (round, (start, arity)) in self.rounds.iter().zip(batches(&self.shape.config).skip(1)) {
            for digest in &round.cap {
                push_digest(&mut values, digest);
            }
            for &raw in &round.rows {
                push_field(&mut values, raw);
            }
            for digest in self.circuit_path_digests(&round.paths, start, arity)? {
                push_digest(&mut values, digest);
            }
        }
        for &raw in &self.base_rows {
            push_field(&mut values, raw);
        }
        let base_arity = self.shape.config.log_folding_factor();
        for digest in self.circuit_path_digests(&self.base_paths, 0, base_arity)? {
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

    /// Packs exactly the private input order of `shape().allocate_native_targets()`.
    /// A different verifier shape is rejected before packing.
    pub fn private_native_values(
        &self,
        expected: &BinaryPcsInputShape,
    ) -> Result<Vec<BinaryField128>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid(
                "binary PCS imported input belongs to a different verifier",
            ));
        }
        if expected.grouping.is_some() {
            return Err(invalid(
                "native scalar binary PCS verifier does not support grouped codewords",
            ));
        }
        let mut values = Vec::new();
        let push_digest = |values: &mut Vec<BinaryField128>,
                           digest: &[u8; 32]|
         -> Result<(), VerificationError> {
            for word in bytes_to_limbs(digest) {
                values.push(<NativeBinaryEncoding as BinaryCircuitEncoding<
                    BinaryField128,
                >>::encode_u16(word)?);
            }
            Ok(())
        };
        values.extend(
            self.sumcheck
                .iter()
                .flatten()
                .map(|&raw| BinaryField128::from_repr(raw)),
        );
        for evals in &self.evals {
            values.extend(
                evals
                    .current()
                    .iter()
                    .chain(evals.next())
                    .map(|&raw| BinaryField128::from_repr(raw)),
            );
        }
        for (round, (start, arity)) in self.rounds.iter().zip(batches(&self.shape.config).skip(1)) {
            for digest in &round.cap {
                push_digest(&mut values, digest)?;
            }
            values.extend(round.rows.iter().map(|&raw| BinaryField128::from_repr(raw)));
            for digest in self.circuit_path_digests(&round.paths, start, arity)? {
                push_digest(&mut values, digest)?;
            }
        }
        values.extend(
            self.base_rows
                .iter()
                .map(|&raw| BinaryField128::from_repr(raw)),
        );
        let base_arity = self.shape.config.log_folding_factor();
        for digest in self.circuit_path_digests(&self.base_paths, 0, base_arity)? {
            push_digest(&mut values, digest)?;
        }
        values.extend(
            self.final_codeword
                .iter()
                .map(|&raw| BinaryField128::from_repr(raw)),
        );
        values.push(BinaryField128::from_repr(self.pow_witness));
        let bits = BinaryPcsShape::new(&self.shape.config).pair_bits;
        for &index in &self.queries {
            values.extend((0..bits).map(|b| BinaryField128::from_bool(index >> b & 1 == 1)));
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
            grouping: self.grouping,
        }
    }

    pub(crate) fn check_native<H0, C0, H1, C1>(
        &self,
        base_mmcs: &MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<E>],
        proof: &super::ByteMerklePcsProof<F, E, H0, C0, H1, C1>,
    ) -> Result<(), VerificationError>
    where
        F: PackedValue<Value = F>,
        E: PackedValue<Value = E>,
        H0: CryptographicHasher<F, [u8; 32]> + Sync,
        H1: CryptographicHasher<E, [u8; 32]> + Sync,
        C0: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C1: PseudoCompressionFunction<[u8; 32], 2> + Sync,
    {
        self.check_native_with_usage(
            base_mmcs,
            round_mmcs,
            commitment,
            points,
            proof,
            &mut InputResourceUsage::default(),
        )
    }

    pub(crate) fn check_native_with_usage<H0, C0, H1, C1>(
        &self,
        base_mmcs: &MerkleTreeMmcs<F, u8, H0, C0, 2, 32>,
        round_mmcs: &MerkleTreeMmcs<E, u8, H1, C1, 2, 32>,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<E>],
        proof: &super::ByteMerklePcsProof<F, E, H0, C0, H1, C1>,
        usage: &mut InputResourceUsage,
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
        proof: &super::ByteMerklePcsProof<F, E, H0, C0, H1, C1>,
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
        let caps = proof
            .rounds
            .iter()
            .map(|r| r.commitment.clone())
            .collect::<Vec<_>>();
        let queries = self.replay_native_queries(
            points,
            &proof.sumcheck,
            &proof.evals,
            &caps,
            proof.final_codeword.as_slice(),
            proof.pow_witness,
            &mut challenger,
        )?;
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

    /// Transcript-only replay shared by ordinary and grouped byte-tree imports.
    /// Callers validate all retained counts before entering this bounded sampler.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub(super) fn replay_native_queries<Ch>(
        &self,
        points: &[Point<E>],
        sumcheck: &SumcheckData<F, E>,
        evals: &[OpeningBatch<E>],
        round_caps: &[MerkleCap<E, [u8; 32]>],
        final_codeword: &[E],
        pow_witness: F,
        challenger: &mut Ch,
    ) -> Result<Vec<usize>, VerificationError>
    where
        Ch: FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<E, [u8; 32]>>,
    {
        let shape = BinaryPcsShape::new(&self.config);
        let shapes = self.protocol.table_shapes();
        let mut layout = Verifier::<F, E>::new(&shapes, SuffixProver::<F, E>::strategy());
        for (i, (table, batch)) in self.protocol.iter_openings().enumerate() {
            layout
                .add_claim_at(table, batch, &points[i], &evals[i], &mut *challenger)
                .map_err(|_| invalid("binary PCS native layout replay failed"))?;
        }
        {
            let mut transcript =
                BinaryPcsVerifierTranscript::<F, E, _>::new(&mut *challenger, shape);
            let replay = (|| {
                let alpha = transcript.fold_batch(|ch| layout.batching_challenge(ch));
                let mut claim = layout.sum(alpha);
                for (batch, (start, arity)) in batches(&self.config).enumerate() {
                    for r in start..start + arity {
                        let message = SumcheckData {
                            polynomial_evaluations: vec![sumcheck.polynomial_evaluations[r]],
                            pow_witnesses: vec![],
                        };
                        let _ = transcript
                            .fold_batch(|ch| {
                                message.verify_rounds(ch, &mut claim, 1, 0, Basis::Evaluation)
                            })
                            .map_err(|_| invalid("binary PCS native sumcheck replay failed"))?;
                    }
                    if batch < shape.num_oracles {
                        transcript.oracle_commitment(round_caps[batch].clone());
                    }
                }
                transcript
                    .final_codeword(final_codeword)
                    .map_err(|_| invalid("binary PCS native final codeword replay failed"))?;
                transcript
                    .query_pow(pow_witness)
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
        Ok(queries)
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

pub(super) fn alloc_field<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
) -> Result<BinaryTower128Target, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let limbs = circuit.alloc_private_input_array::<8>("binary PCS field");
    Ok(circuit.binary128_from_limbs::<BF>(limbs)?)
}

pub(super) fn alloc_digest<EF: Field + Eq + Hash>(circuit: &mut CircuitBuilder<EF>) -> Vec<ExprId> {
    circuit
        .alloc_private_input_array::<16>("binary PCS digest")
        .to_vec()
}

fn alloc_oracle<T, CF: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<CF>,
    count: usize,
    (paths, depth): (usize, usize),
    field: &mut impl FnMut(&mut CircuitBuilder<CF>) -> Result<T, VerificationError>,
) -> Result<super::OracleOpeningTargets<T>, VerificationError> {
    let rows = (0..count)
        .map(|_| field(circuit))
        .collect::<Result<_, _>>()?;
    let paths = (0..paths)
        .map(|_| (0..depth).map(|_| alloc_digest(circuit)).collect())
        .collect();
    Ok((rows, paths))
}

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
