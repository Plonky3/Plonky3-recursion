//! Full opening relation for the released binary tower PCS and byte Merkle trees.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::BinaryPcsConfig;
use p3_binary_pcs::transcript::BinaryPcsShape;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{
    Layout, SuffixProver, Verifier, commitment_domain_separator, plan_stacked_layout,
};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::transcript::SumcheckShape;
use p3_sumcheck::{OpeningBatch, OpeningProtocol};

use super::{
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField, binary128_eq_eval,
    binary128_fold_pair, binary128_next_eval, binary128_reduce_sumcheck_claim,
    verify_binary_pcs_query_indices_with_continuation,
};
use crate::transcript::{SeedTap, domain_separator_seed};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// One authenticated folded oracle. Digests are sixteen natural-order u16
/// limbs. Rows and paths have native query order, including projected duplicates.
/// Each row contains one checked binary symbol and each path belongs to that row.
#[derive(Clone, Debug)]
pub struct BinaryOracleOpeningTargets {
    pub cap: Vec<Vec<ExprId>>,
    pub rows: Vec<BinaryTower128Target>,
    pub paths: Vec<Vec<Vec<ExprId>>>,
}

/// Native binary PCS witnesses widened into checked 128-bit tower targets.
/// The verifier constrains upper coordinates outside each native field to zero.
/// Pruned paths must be expanded before building this input; authentication is
/// performed in the circuit using the constrained query bits. The native
/// sumcheck PoW vector must be checked empty by a native proof importer.
#[derive(Clone, Debug)]
pub struct BinaryPcs128ProofTargets {
    pub sumcheck: Vec<[BinaryTower128Target; 2]>,
    pub evals: Vec<OpeningBatch<BinaryTower128Target>>,
    pub rounds: Vec<BinaryOracleOpeningTargets>,
    pub base_rows: Vec<BinaryTower128Target>,
    pub base_paths: Vec<Vec<Vec<ExprId>>>,
    pub final_codeword: Vec<BinaryTower128Target>,
    pub pow_witness: BinaryTower128Target,
    /// Sorted unshifted sampled pair indices, in little-endian bit order.
    /// Native `query_pairs()` returns even low-symbol positions; an importer
    /// converts those positions with `position >> 1` before populating this field.
    pub query_indices: Vec<Vec<ExprId>>,
}

/// Verifier-owned binary PCS geometry, transcript seeds, hash and query budget.
/// Supports the released byte-aligned tower alphabets and 64/128-bit challenges with
/// ordinary binary-arity Keccak-256 or BLAKE3 Merkle trees. This is an opening
/// relation; its caller owns the commitment and prescribed points' statement
/// binding, just as native `PrescribedPointPcs::verify_at` does.
#[derive(Clone, Debug)]
pub struct BinaryPcsVerifier<F, E> {
    pub(super) config: BinaryPcsConfig,
    pub(super) protocol: OpeningProtocol,
    pub(super) hash: ByteHash,
    pub(super) cap_height: usize,
    pub(super) max_query_draws: usize,
    pub(super) limits: VerifierLimits,
    pub(super) usage: InputResourceUsage,
    pub(super) grouping: Option<[super::grouped_pcs::BinaryCodewordGrouping; 2]>,
    opening_seeds: Vec<Vec<F>>,
    batching_seed: Vec<F>,
    challenge_field: PhantomData<E>,
}

/// Same-field 128-bit tower PCS verifier.
pub type BinaryPcs128Verifier = BinaryPcsVerifier<BinaryField128, BinaryField128>;

impl<F, E> BinaryPcsVerifier<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    /// Builds a verifier with finite default limits. The query draw budget is
    /// explicit and independent of the proof's rejection pattern.
    pub fn new(
        config: BinaryPcsConfig,
        protocol: OpeningProtocol,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(
            config,
            protocol,
            hash,
            cap_height,
            max_query_draws,
            &VerifierLimits::default(),
        )
    }

    /// Validates protocol geometry and operational bounds before allocating
    /// native layout state or capturing any transcript seed.
    pub fn with_limits(
        config: BinaryPcsConfig,
        protocol: OpeningProtocol,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        Self::with_grouping(
            config,
            protocol,
            hash,
            cap_height,
            max_query_draws,
            limits,
            None,
        )
    }

    pub(super) fn with_grouping(
        config: BinaryPcsConfig,
        protocol: OpeningProtocol,
        hash: ByteHash,
        cap_height: usize,
        max_query_draws: usize,
        limits: &VerifierLimits,
        grouping: Option<[super::grouped_pcs::BinaryCodewordGrouping; 2]>,
    ) -> Result<Self, VerificationError> {
        if config.committed_field_bits() != F::RAW_BITS
            || config.challenge_field_bits() != E::RAW_BITS
        {
            return Err(shape_error(
                "binary PCS configuration does not match its native tower alphabets",
            ));
        }
        let log_domain = config
            .num_variables()
            .checked_add(config.log_inv_rate())
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary PCS log domain",
            })?;
        limit(
            "binary PCS log domain",
            log_domain,
            limits.max_log_domain_or_degree,
        )?;
        if log_domain >= usize::BITS as usize || cap_height > log_domain {
            // Every committed word must support the configured native cap.
            return Err(shape_error("binary PCS domain or cap height is invalid"));
        }
        let cells =
            protocol
                .checked_num_cells()
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary PCS protocol cells",
                })?;
        if cells == 0 || p3_util::log2_ceil_usize(cells) != config.num_variables() {
            return Err(shape_error(
                "binary PCS protocol does not match the configured stacked arity",
            ));
        }
        let claims =
            protocol
                .checked_num_claims()
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary PCS opening claims",
                })?;
        if claims > config.max_opening_claims() {
            return Err(shape_error(
                "binary PCS opening claims exceed the native security budget",
            ));
        }
        let shape = BinaryPcsShape::new(&config);
        if max_query_draws < shape.num_pairs {
            return Err(shape_error(
                "binary PCS query draw budget is smaller than the query count",
            ));
        }
        limit(
            "binary PCS query draws",
            max_query_draws,
            limits.max_queries_per_round,
        )?;
        let shapes = protocol.table_shapes();
        let mut usage = InputResourceUsage::default();
        usage.add_instances(limits, shapes.len())?;
        usage.add_rounds(limits, config.num_variables())?;
        usage.add_metadata_entries(limits, claims)?;
        usage.add_final_poly_evaluations(limits, shape.final_codeword_len)?;
        let field_values = config
            .num_variables()
            .checked_mul(2)
            .and_then(|n| n.checked_add(claims))
            .and_then(|n| n.checked_add(shape.final_codeword_len))
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(8))
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary PCS scalar limbs",
            })?;
        usage.add_scalar_elements(limits, field_values)?;
        usage.add_scalar_elements(
            limits,
            shape.num_pairs.checked_mul(shape.pair_bits).ok_or(
                VerificationError::ResourceArithmeticOverflow {
                    component: "binary PCS query bits",
                },
            )?,
        )?;
        for table in &shapes {
            limit(
                "binary PCS table width",
                table.width(),
                limits.max_matrix_width,
            )?;
        }
        for (table, batch) in protocol.iter_openings() {
            if batch.is_empty()
                || batch
                    .current()
                    .iter()
                    .chain(batch.next())
                    .any(|&column| column >= shapes[table].width())
            {
                return Err(shape_error(
                    "binary PCS opening request is empty or outside its table",
                ));
            }
            usage.add_scalar_elements(
                limits,
                shapes[table].num_variables().checked_mul(8).ok_or(
                    VerificationError::ResourceArithmeticOverflow {
                        component: "binary PCS prescribed point limbs",
                    },
                )?,
            )?;
        }
        let cap_roots = 1usize << cap_height;
        for (batch, (start, arity)) in batches(&config).enumerate() {
            let group_size = grouping.map_or(Ok(1), |g| {
                g[usize::from(batch != 0)].effective(&config, log_domain - start)
            })?;
            limit(
                "binary grouped leaf width",
                group_size,
                limits.max_matrix_width,
            )?;
            let group_bits = group_size.ilog2() as usize;
            if cap_height > log_domain - start - group_bits {
                return Err(shape_error(
                    "binary PCS cap height exceeds a committed tree's depth",
                ));
            }
            let rows = shape.num_pairs.checked_mul(1usize << arity).ok_or(
                VerificationError::ResourceArithmeticOverflow {
                    component: "binary PCS opened rows",
                },
            )?;
            usage.add_query_round(limits, rows)?;
            usage.add_cap_roots(limits, cap_roots)?;
            usage.add_scalar_elements(
                limits,
                cap_roots
                    .checked_mul(16)
                    .ok_or(VerificationError::ResourceArithmeticOverflow {
                        component: "binary PCS cap limbs",
                    })?,
            )?;
            usage.add_scalar_elements(
                limits,
                rows.checked_mul(8)
                    .ok_or(VerificationError::ResourceArithmeticOverflow {
                        component: "binary PCS row limbs",
                    })?,
            )?;
            if grouping.is_some() {
                usage.add_scalar_elements(
                    limits,
                    rows.checked_mul(group_size)
                        .and_then(|n| n.checked_mul(8))
                        .ok_or(VerificationError::ResourceArithmeticOverflow {
                            component: "binary grouped leaf limbs",
                        })?,
                )?;
            }
            let depth = log_domain - start - group_bits - cap_height;
            let paths =
                rows.checked_mul(depth)
                    .ok_or(VerificationError::ResourceArithmeticOverflow {
                        component: "binary PCS restored paths",
                    })?;
            usage.add_restored_authentication_path_hashes(limits, rows, depth)?;
            usage.add_scalar_elements(
                limits,
                paths
                    .checked_mul(16)
                    .ok_or(VerificationError::ResourceArithmeticOverflow {
                        component: "binary PCS path limbs",
                    })?,
            )?;
        }
        // Public native calls capture private layout seeds without copying
        // upstream protocol descriptions. Values and prescribed points are
        // dummy zeros; only verifier-owned shapes enter these seeds.
        let mut layout = Verifier::<F, E>::new(&shapes, SuffixProver::<F, E>::strategy());
        let mut opening_seeds = Vec::new();
        for (table, batch) in protocol.iter_openings() {
            let point = Point::new(vec![E::ZERO; shapes[table].num_variables()]);
            let evals = OpeningBatch::new(
                vec![E::ZERO; batch.current().len()],
                vec![E::ZERO; batch.next().len()],
            );
            let mut tap = SeedTap::new();
            layout
                .add_claim_at(table, batch, &point, &evals, &mut tap)
                .map_err(|_| shape_error("invalid binary PCS opening protocol"))?;
            opening_seeds.push(tap.binary_seed());
        }
        let mut tap = SeedTap::new();
        let _ = layout.batching_challenge(&mut tap);
        Ok(Self {
            config,
            protocol,
            hash,
            cap_height,
            max_query_draws,
            limits: *limits,
            usage,
            grouping,
            opening_seeds,
            batching_seed: tap.binary_seed(),
            challenge_field: PhantomData,
        })
    }

    /// Absorbs the native commitment phase's seed followed by all cap roots.
    /// The caller must do this at the native transcript position before
    /// deriving opening points. All targets must use the same builder.
    pub fn observe_commitment<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_cap(cap)?;
        observe_seed::<F, BF, EF>(
            circuit,
            challenger,
            &domain_separator_seed(&commitment_domain_separator::<F>()),
        )?;
        observe_cap::<BF, EF>(circuit, challenger, cap)
    }

    pub const fn input_resource_usage(&self) -> InputResourceUsage {
        self.usage
    }

    /// Samples the configured native challenge width, zero-extended into the
    /// 128-bit tower gadget. This consumes exactly the bytes native extension
    /// sampling uses, including when the committed alphabet is narrower.
    pub fn sample_challenge<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: &mut BinaryTower128Challenger,
    ) -> Result<BinaryTower128Target, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let bytes = challenger.sample_bytes::<BF, EF>(circuit, E::RAW_BITS / 8)?;
        let mut bits = [ExprId::ZERO; 128];
        for (i, byte) in bytes.into_iter().enumerate() {
            let byte_bits = circuit.decompose_to_bits::<BF>(byte, 8)?;
            bits[8 * i..8 * i + 8].copy_from_slice(&byte_bits);
        }
        Ok(circuit.binary128_from_bits(bits)?)
    }

    /// Constrains the complete native prescribed-point opening relation and
    /// drops its query continuation. The caller binds the commitment and points
    /// to its statement. Use [`Self::verify_at_with_continuation`] when another
    /// nonempty observation follows this opening in the native transcript.
    pub fn verify_at<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryPcs128ProofTargets,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_at_with_continuation::<BF, EF>(circuit, challenger, cap, points, proof)
            .map(|_| ())
    }

    /// Returns the exact native query-completion digest after installing all
    /// opening and authentication constraints. It can only resume through the
    /// next nonempty native observation. All targets must share this builder.
    pub fn verify_at_with_continuation<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        challenger: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryPcs128ProofTargets,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_at_impl::<BF, EF>(circuit, challenger, cap, points, proof, false)
    }

    /// Verifies an opening immediately after another opening's bounded query
    /// phase. Absorbs this verifier's first native seed exactly once, including
    /// schedules with no opening batches, before exposing any sampling state.
    pub fn verify_at_after_queries<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        continuation: BinaryQueryContinuation,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryPcs128ProofTargets,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(cap, points, proof)?;
        let seed = self.opening_seeds.first().cloned().unwrap_or_else(|| {
            domain_separator_seed(&BinaryPcsShape::new(&self.config).domain_separator::<F, E>())
        });
        let bytes = seed_bytes_with_host::<F, PrimeBinaryEncoding<BF>, EF>(circuit, &seed)?;
        let challenger = continuation.resume_with_observation::<BF, EF>(circuit, &bytes)?;
        self.verify_at_impl::<BF, EF>(circuit, challenger, cap, points, proof, true)
    }

    fn verify_at_impl<BF, EF>(
        &self,
        circuit: &mut CircuitBuilder<EF>,
        mut challenger: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryPcs128ProofTargets,
        first_seed_observed: bool,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.check_targets(cap, points, proof)?;
        for value in points
            .iter()
            .flatten()
            .chain(proof.sumcheck.iter().flatten())
            .chain(
                proof
                    .evals
                    .iter()
                    .flat_map(|e| e.current().iter().chain(e.next())),
            )
            .chain(&proof.final_codeword)
            .chain(proof.rounds.iter().flat_map(|r| &r.rows))
        {
            constrain_width(circuit, value, E::RAW_BITS);
        }
        for value in proof
            .base_rows
            .iter()
            .chain(core::slice::from_ref(&proof.pow_witness))
        {
            constrain_width(circuit, value, F::RAW_BITS);
        }
        for (i, evals) in proof.evals.iter().enumerate() {
            if i != 0 || !first_seed_observed {
                observe_seed::<F, BF, EF>(circuit, &mut challenger, &self.opening_seeds[i])?;
            }
            observe_values::<BF, EF>(circuit, &mut challenger, &evals.to_vec(), E::RAW_BITS)?;
        }
        let shape = BinaryPcsShape::new(&self.config);
        if !first_seed_observed || !self.opening_seeds.is_empty() {
            observe_seed::<F, BF, EF>(
                circuit,
                &mut challenger,
                &domain_separator_seed(&shape.domain_separator::<F, E>()),
            )?;
        }
        observe_seed::<F, BF, EF>(circuit, &mut challenger, &self.batching_seed)?;
        let alpha = self.sample_challenge::<BF, EF>(circuit, &mut challenger)?;
        let shapes = self.protocol.table_shapes();
        let (_, placements) = plan_stacked_layout(&shapes);
        let one = circuit.binary128_constant(1)?;
        let mut power = one.clone();
        let mut claim = circuit.binary128_constant(0)?;
        // Native batching order is placements, then per-table claims, current, next.
        for placement in &placements {
            for (i, (table, _)) in self.protocol.iter_openings().enumerate() {
                if table != placement.idx() {
                    continue;
                }
                for eval in proof.evals[i].current().iter().chain(proof.evals[i].next()) {
                    let term = circuit.binary128_mul(&power, eval);
                    claim = circuit.binary128_add(&claim, &term);
                    power = circuit.binary128_mul(&power, &alpha);
                }
            }
        }
        let round_seed = domain_separator_seed(
            &SumcheckShape::new(1, 0, Basis::Evaluation).domain_separator::<F, E>(),
        );
        let mut betas = Vec::with_capacity(self.config.num_variables());
        for (batch, (start, arity)) in batches(&self.config).enumerate() {
            for message in &proof.sumcheck[start..start + arity] {
                observe_seed::<F, BF, EF>(circuit, &mut challenger, &round_seed)?;
                observe_values::<BF, EF>(circuit, &mut challenger, message, E::RAW_BITS)?;
                let beta = self.sample_challenge::<BF, EF>(circuit, &mut challenger)?;
                claim = binary128_reduce_sumcheck_claim(
                    circuit,
                    &claim,
                    &message[0],
                    &message[1],
                    &beta,
                )?;
                betas.push(beta);
            }
            if batch + 1 < self.config.num_fold_batches() {
                observe_cap::<BF, EF>(circuit, &mut challenger, &proof.rounds[batch].cap)?;
            }
        }
        let fold_point: Vec<_> = betas.iter().rev().cloned().collect();
        let mut weight = circuit.binary128_constant(0)?;
        power = one;
        for placement in &placements {
            for (i, (table, batch)) in self.protocol.iter_openings().enumerate() {
                if table != placement.idx() {
                    continue;
                }
                for (columns, successor) in [(batch.current(), false), (batch.next(), true)] {
                    for &column in columns {
                        let selector = placement.selectors()[column];
                        let selector_point: Vec<_> = selector
                            .point::<BinaryField128>()
                            .as_slice()
                            .iter()
                            .map(|x| circuit.binary128_constant(x.to_repr()))
                            .collect::<Result<_, _>>()?;
                        let selector_vars = selector.num_variables();
                        let local_weight = if successor {
                            binary128_next_eval(circuit, &points[i], &fold_point[selector_vars..])?
                        } else {
                            binary128_eq_eval(circuit, &points[i], &fold_point[selector_vars..])?
                        };
                        let selector_weight = binary128_eq_eval(
                            circuit,
                            &selector_point,
                            &fold_point[..selector_vars],
                        )?;
                        let selected_weight =
                            circuit.binary128_mul(&selector_weight, &local_weight);
                        let term = circuit.binary128_mul(&power, &selected_weight);
                        weight = circuit.binary128_add(&weight, &term);
                        power = circuit.binary128_mul(&power, &alpha);
                    }
                }
            }
        }
        let final_value = &proof.final_codeword[0];
        for value in &proof.final_codeword[1..] {
            assert_equal(circuit, value, final_value);
        }
        let expected_claim = circuit.binary128_mul(&weight, final_value);
        assert_equal(circuit, &claim, &expected_claim);
        observe_values::<BF, EF>(circuit, &mut challenger, &proof.final_codeword, E::RAW_BITS)?;
        if self.config.pow_bits() == 0 {
            let zero = circuit.binary128_constant(0)?;
            assert_equal(circuit, &proof.pow_witness, &zero);
        } else {
            observe_values::<BF, EF>(
                circuit,
                &mut challenger,
                core::slice::from_ref(&proof.pow_witness),
                F::RAW_BITS,
            )?;
            for bit in challenger.sample_bits::<BF, EF>(circuit, self.config.pow_bits())? {
                let difference = circuit.sub(ExprId::ZERO, bit);
                circuit.assert_zero(difference);
            }
        }
        let continuation = verify_binary_pcs_query_indices_with_continuation::<BF, EF>(
            circuit,
            challenger,
            &self.config,
            &proof.query_indices,
            self.max_query_draws,
        )?;
        let zero = circuit.define_const(EF::ZERO);
        let one = circuit.define_const(EF::ONE);
        let schedule: Vec<_> = batches(&self.config).collect();
        let log_domain = self.config.num_variables() + self.config.log_inv_rate();
        for (q, query) in proof.query_indices.iter().enumerate() {
            let mut index = vec![zero; self.config.log_folding_factor()];
            index.extend_from_slice(query);
            for (batch, &(start, arity)) in schedule.iter().enumerate() {
                let (rows, paths, cap) = if batch == 0 {
                    (&proof.base_rows, &proof.base_paths, cap)
                } else {
                    let oracle = &proof.rounds[batch - 1];
                    (&oracle.rows, &oracle.paths, oracle.cap.as_slice())
                };
                let size = 1usize << arity;
                let coset = &rows[q * size..(q + 1) * size];
                for (offset, row) in coset.iter().enumerate().filter(|_| self.grouping.is_none()) {
                    let mut leaf_index = index[start..].to_vec();
                    for (b, bit) in leaf_index[..arity].iter_mut().enumerate() {
                        *bit = if offset >> b & 1 == 1 { one } else { zero };
                    }
                    let width = if batch == 0 { F::RAW_BITS } else { E::RAW_BITS };
                    let bytes = tower_bytes::<BF, EF>(circuit, row, width)?;
                    // A fixed coset offset can send a sibling limb straight
                    // into the hash NPO. Range checks also give each private
                    // digest limb an ALU creator on the witness bus.
                    for &limb in paths[q * size + offset].iter().flatten() {
                        let _ = circuit.decompose_to_bits::<BF>(limb, 16)?;
                    }
                    circuit.verify_byte_hash_mmcs_opening_bytes::<BF>(
                        self.hash,
                        &[bytes],
                        &[1usize << (log_domain - start)],
                        &leaf_index,
                        &paths[q * size + offset],
                        cap,
                    )?;
                }
                let mut folded = coset.to_vec();
                for j in 0..arity {
                    let mut next = Vec::with_capacity(folded.len() / 2);
                    for (offset, pair) in folded.as_chunks::<2>().0.iter().enumerate() {
                        let mut pair_index = index[start + j + 1..].to_vec();
                        for (b, bit) in pair_index[..arity - j - 1].iter_mut().enumerate() {
                            *bit = if offset >> b & 1 == 1 { one } else { zero };
                        }
                        next.push(binary128_fold_pair(
                            circuit,
                            &pair_index,
                            &betas[start + j],
                            &pair[0],
                            &pair[1],
                        )?);
                    }
                    folded = next;
                }
                let expected = if let Some(&(_, next_arity)) = schedule.get(batch + 1) {
                    let size = 1usize << next_arity;
                    select_symbol(
                        circuit,
                        &proof.rounds[batch].rows[q * size..(q + 1) * size],
                        &index[start + arity..start + arity + next_arity],
                    )?
                } else {
                    // Uniformity already binds every final symbol to the first.
                    final_value.clone()
                };
                assert_equal(circuit, &folded[0], &expected);
            }
        }
        Ok(continuation)
    }

    fn check_cap(&self, cap: &[Vec<ExprId>]) -> Result<(), VerificationError> {
        if cap.len() != 1usize << self.cap_height || cap.iter().any(|d| d.len() != 16) {
            return Err(shape_error(
                "binary PCS cap does not match verifier geometry",
            ));
        }
        Ok(())
    }

    pub(crate) fn check_targets(
        &self,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryPcs128ProofTargets,
    ) -> Result<(), VerificationError> {
        self.check_cap(cap)?;
        let shape = BinaryPcsShape::new(&self.config);
        if proof.sumcheck.len() != self.config.num_variables()
            || proof.rounds.len() != shape.num_oracles
            || proof.final_codeword.len() != shape.final_codeword_len
            || proof.query_indices.len() != shape.num_pairs
            || proof
                .query_indices
                .iter()
                .any(|q| q.len() != shape.pair_bits)
        {
            return Err(shape_error(
                "binary PCS proof targets do not match the fold and query schedule",
            ));
        }
        if points.len() != self.opening_seeds.len() || proof.evals.len() != self.opening_seeds.len()
        {
            return Err(shape_error("binary PCS opening batch count mismatch"));
        }
        let shapes = self.protocol.table_shapes();
        for (i, (table, batch)) in self.protocol.iter_openings().enumerate() {
            if points[i].len() != shapes[table].num_variables()
                || !batch.has_same_shape(&proof.evals[i])
            {
                return Err(shape_error(
                    "binary PCS opening point or evaluation shape mismatch",
                ));
            }
        }
        let log_domain = self.config.num_variables() + self.config.log_inv_rate();
        for (batch, (start, arity)) in batches(&self.config).enumerate() {
            let (rows, paths) = if batch == 0 {
                (&proof.base_rows, &proof.base_paths)
            } else {
                self.check_cap(&proof.rounds[batch - 1].cap)?;
                (
                    &proof.rounds[batch - 1].rows,
                    &proof.rounds[batch - 1].paths,
                )
            };
            let count = shape.num_pairs << arity;
            let depth = if self.grouping.is_some() {
                0
            } else {
                log_domain - start - self.cap_height
            };
            if rows.len() != count
                || paths.len() != count
                || paths
                    .iter()
                    .any(|p| p.len() != depth || p.iter().any(|d| d.len() != 16))
            {
                return Err(shape_error(
                    "binary PCS authenticated row or path shape mismatch",
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn batches(config: &BinaryPcsConfig) -> impl Iterator<Item = (usize, usize)> + '_ {
    (0..config.num_variables())
        .step_by(config.log_folding_factor())
        .map(|start| {
            (
                start,
                config
                    .log_folding_factor()
                    .min(config.num_variables() - start),
            )
        })
}

pub(crate) fn observe_seed<F, BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut BinaryTower128Challenger,
    seed: &[F],
) -> Result<(), VerificationError>
where
    F: RecursiveBinaryTowerField,
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    observe_seed_with_host::<F, PrimeBinaryEncoding<BF>, EF>(circuit, challenger, seed)
}

pub(crate) fn observe_seed_with_host<F, H, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut BinaryTower128Challenger,
    seed: &[F],
) -> Result<(), VerificationError>
where
    F: RecursiveBinaryTowerField,
    H: BinaryCircuitHost<EF>,
    EF: Field + Eq + Hash,
{
    let bytes = seed_bytes_with_host::<F, H, EF>(circuit, seed)?;
    challenger.observe_bytes_with_host::<H, EF>(circuit, &bytes)?;
    Ok(())
}

pub(crate) fn seed_bytes_with_host<F, H, EF>(
    circuit: &mut CircuitBuilder<EF>,
    seed: &[F],
) -> Result<Vec<ExprId>, VerificationError>
where
    F: RecursiveBinaryTowerField,
    H: BinaryCircuitEncoding<EF>,
    EF: Field + Eq + Hash,
{
    H::check_carrier()?;
    seed.iter()
        .flat_map(|x| {
            x.raw_coordinates()
                .to_le_bytes()
                .into_iter()
                .take(F::RAW_BITS / 8)
        })
        .map(|byte| Ok(circuit.define_const(H::encode_u16(u16::from(byte))?)))
        .collect()
}

pub(crate) fn observe_cap<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut BinaryTower128Challenger,
    cap: &[Vec<ExprId>],
) -> Result<(), VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    observe_cap_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, challenger, cap)
}

pub(crate) fn observe_cap_with_host<H, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut BinaryTower128Challenger,
    cap: &[Vec<ExprId>],
) -> Result<(), VerificationError>
where
    H: BinaryCircuitHost<EF>,
    EF: Field + Eq + Hash,
{
    if cap.iter().any(|digest| digest.len() != 16) {
        return Err(shape_error("binary PCS digest width mismatch"));
    }
    for digest in cap {
        let digest = digest.as_slice().try_into().expect("checked digest width");
        challenger.observe_digest_with_host::<H, EF>(circuit, digest)?;
    }
    Ok(())
}

pub(super) fn tower_bytes<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    value: &BinaryTower128Target,
    width: usize,
) -> Result<Vec<ExprId>, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    tower_bytes_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, value, width)
}

pub(crate) fn tower_bytes_with_host<H, EF>(
    circuit: &mut CircuitBuilder<EF>,
    value: &BinaryTower128Target,
    width: usize,
) -> Result<Vec<ExprId>, VerificationError>
where
    H: BinaryCircuitEncoding<EF>,
    EF: Field + Eq + Hash,
{
    if width > 128 || !width.is_multiple_of(8) {
        return Err(shape_error("binary tower byte width mismatch"));
    }
    Ok(value.bits()[..width]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bits| H::recompose_word(circuit, bits))
        .collect::<Result<_, _>>()?)
}

pub(crate) fn observe_values<BF, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut BinaryTower128Challenger,
    values: &[BinaryTower128Target],
    width: usize,
) -> Result<(), VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    observe_values_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, challenger, values, width)
}

pub(crate) fn observe_values_with_host<H, EF>(
    circuit: &mut CircuitBuilder<EF>,
    challenger: &mut BinaryTower128Challenger,
    values: &[BinaryTower128Target],
    width: usize,
) -> Result<(), VerificationError>
where
    H: BinaryCircuitHost<EF>,
    EF: Field + Eq + Hash,
{
    if width > 128 || !width.is_multiple_of(8) {
        return Err(shape_error("binary tower byte width mismatch"));
    }
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend(tower_bytes_with_host::<H, EF>(circuit, value, width)?);
    }
    challenger.observe_bytes_with_host::<H, EF>(circuit, &bytes)?;
    Ok(())
}

pub(super) fn constrain_width<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    value: &BinaryTower128Target,
    width: usize,
) {
    for &bit in &value.bits()[width..] {
        let difference = circuit.sub(ExprId::ZERO, bit);
        circuit.assert_zero(difference);
    }
}

pub(crate) fn assert_equal<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    a: &BinaryTower128Target,
    b: &BinaryTower128Target,
) {
    for (&a, &b) in a.bits().iter().zip(b.bits()) {
        // Keep a genuine ALU equality when one side is zero. `a - 0`
        // simplifies to `a`; aliasing a decomposition hint's output directly
        // to zero can leave its original input slot without a producer.
        let difference = if b == ExprId::ZERO {
            circuit.sub(b, a)
        } else {
            circuit.sub(a, b)
        };
        circuit.assert_zero(difference);
    }
}

fn select_symbol<F: Field + Eq + Hash>(
    circuit: &mut CircuitBuilder<F>,
    symbols: &[BinaryTower128Target],
    index: &[ExprId],
) -> Result<BinaryTower128Target, VerificationError> {
    let mut layer = symbols.to_vec();
    for &bit in index {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let bits = core::array::from_fn(|i| {
                    circuit.select(bit, pair[1].bits()[i], pair[0].bits()[i])
                });
                circuit.binary128_from_bits(bits)
            })
            .collect::<Result<_, _>>()?;
    }
    Ok(layer
        .pop()
        .expect("verified binary symbol selector geometry"))
}

fn shape_error(message: &str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

const fn limit(
    component: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), VerificationError> {
    if actual > limit {
        Err(VerificationError::ResourceLimitExceeded {
            component,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod host_tests {
    use p3_binary_field::{BinaryChallenger, BinaryField32, Poly64};
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
    use p3_circuit::ops::binary_native::BinaryCoordinateField;
    use p3_field::BasedVectorSpace;
    use p3_keccak::Keccak256Hash;
    use p3_symmetric::Hash as Digest;

    use super::*;

    type H = NativeBinaryEncoding;

    fn transcript<CF: BinaryCoordinateField>() {
        let seed = [0x81234567, 0xfedcba98].map(BinaryField32::from_repr);
        let dense = BinaryField128::from_repr(0x8123456789abcdeffedcba9876543210);
        let digest: [u8; 32] = core::array::from_fn(|i| 129u8.wrapping_add(i as u8 * 3));
        let mut native = BinaryChallenger::<BinaryField32, _>::from_hasher(vec![], Keccak256Hash);
        let mut b = CircuitBuilder::<CF>::new();
        b.enable_native_keccak_f1600().unwrap();
        let mut ch = BinaryTower128Challenger::new(ByteHash::Keccak256);
        native.observe_slice(&seed);
        observe_seed_with_host::<BinaryField32, H, CF>(&mut b, &mut ch, &seed).unwrap();
        let first = ch.sample_with_host::<H, CF>(&mut b).unwrap();
        let expected_first = native.sample_algebra_element::<BinaryField128>();
        let cap = b.alloc_public_input_array::<16>("cap words");
        assert!(
            observe_cap_with_host::<H, CF>(&mut b, &mut ch, &[cap.to_vec(), cap[..15].to_vec()],)
                .is_err()
        );
        let target = b.binary128_constant(dense.to_repr()).unwrap();
        for width in [7, 129, 136] {
            assert!(tower_bytes_with_host::<H, CF>(&mut b, &target, width).is_err());
            assert!(observe_values_with_host::<H, CF>(&mut b, &mut ch, &[], width).is_err());
        }
        native.observe(Digest::<BinaryField32, u8, 32>::from(digest));
        observe_cap_with_host::<H, CF>(&mut b, &mut ch, &[cap.to_vec()]).unwrap();
        native.observe_slice(
            <BinaryField128 as BasedVectorSpace<BinaryField32>>::as_basis_coefficients_slice(
                &dense,
            ),
        );
        observe_values_with_host::<H, CF>(&mut b, &mut ch, &[target], 128).unwrap();
        let second = ch.sample_with_host::<H, CF>(&mut b).unwrap();
        let expected_second = native.sample_algebra_element::<BinaryField128>();
        let mut public: Vec<CF> = digest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|word| H::encode_u16(u16::from_le_bytes(*word)).unwrap())
            .collect();
        for (actual, expected) in [first, second]
            .iter()
            .zip([expected_first, expected_second])
        {
            let words = b.alloc_public_input_array::<8>("expected raw sample");
            for (i, word) in words.into_iter().enumerate() {
                let bits = H::decompose_word(&mut b, word, 16).unwrap();
                for (&actual, expected) in actual.bits()[16 * i..16 * i + 16].iter().zip(bits) {
                    b.connect(actual, expected);
                }
                public.push(H::encode_u16((expected.to_repr() >> (16 * i)) as u16).unwrap());
            }
        }
        let circuit = b.build().unwrap();
        let run = |public: &[CF]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        assert!(run(&public));
        for index in [0, 16, 24] {
            let mut wrong = public.clone();
            wrong[index] += CF::ONE;
            assert!(!run(&wrong));
        }
    }

    #[test]
    fn native_protocol_seeds_caps_and_observations_preserve_all_bytes() {
        transcript::<BinaryField128>();
        transcript::<Poly64>();
    }
}
