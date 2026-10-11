//! Full opening relation for the released binary tower PCS and byte Merkle trees.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::BinaryPcsConfig;
use p3_binary_pcs::transcript::BinaryPcsShape;
use p3_circuit::ops::binary_encoding::{
    BinaryCircuitEncoding, NativeBinaryEncoding, PrimeBinaryEncoding,
};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::{BinaryTower128Target, ByteHash, NativeTower128Target};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{
    Layout, SuffixProver, Verifier, commitment_domain_separator, plan_stacked_layout,
};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::transcript::SumcheckShape;
use p3_sumcheck::{OpeningBatch, OpeningProtocol};

use super::gadgets::{next_eval_using, reduce_sumcheck_using};
use super::{
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField,
    verify_binary_pcs_query_indices_with_host,
};
use crate::transcript::{SeedTap, domain_separator_seed};
use crate::verifier::binary_field_policy::{
    BinaryFoldPolicy, NativeTower128Relation, TowerRelation,
};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

/// One authenticated folded oracle. Digests are sixteen natural-order u16
/// limbs. Rows and paths have native query order, including projected duplicates.
/// Each row contains one checked binary symbol. A query coset below the cap
/// layer has one path, the siblings above its Merkle subtree; otherwise each
/// path belongs to one row.
#[derive(Clone, Debug)]
pub struct BinaryOracleOpeningTargets<T = BinaryTower128Target> {
    pub cap: Vec<Vec<ExprId>>,
    pub rows: Vec<T>,
    pub paths: Vec<Vec<Vec<ExprId>>>,
}

/// Native binary PCS witnesses widened into checked 128-bit tower targets.
/// The verifier constrains upper coordinates outside each native field to zero.
/// Pruned paths must be expanded before building this input; authentication is
/// performed in the circuit using the constrained query bits. The native
/// sumcheck PoW vector must be checked empty by a native proof importer.
#[derive(Clone, Debug)]
pub struct BinaryPcs128ProofTargets<T = BinaryTower128Target> {
    pub sumcheck: Vec<[T; 2]>,
    pub evals: Vec<OpeningBatch<T>>,
    pub rounds: Vec<BinaryOracleOpeningTargets<T>>,
    pub base_rows: Vec<T>,
    pub base_paths: Vec<Vec<Vec<ExprId>>>,
    pub final_codeword: Vec<T>,
    pub pow_witness: T,
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
        self.observe_commitment_with_host::<PrimeBinaryEncoding<BF>, EF>(circuit, challenger, cap)
    }

    /// Same commitment observation under an explicit circuit host.
    pub fn observe_commitment_with_host<H, CF>(
        &self,
        circuit: &mut CircuitBuilder<CF>,
        challenger: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
    {
        self.check_cap(cap)?;
        H::check_hash(self.hash)?;
        observe_seed_with_host::<F, H, CF>(
            circuit,
            challenger,
            &domain_separator_seed(&commitment_domain_separator::<F>()),
        )?;
        observe_cap_with_host::<H, CF>(circuit, challenger, cap)
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
        self.verify_at_using::<TowerRelation<F, E>, PrimeBinaryEncoding<BF>, EF>(
            circuit,
            challenger,
            cap,
            points,
            proof,
            false,
            self.ordinary_leaves(),
        )
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
        self.after_queries_using::<TowerRelation<F, E>, PrimeBinaryEncoding<BF>, EF>(
            circuit,
            continuation,
            cap,
            points,
            proof,
            self.ordinary_leaves(),
        )
    }

    /// Same post-query opening under an explicit scalar policy, circuit host
    /// and coset leaf mode.
    pub(crate) fn after_queries_using<P, H, CF>(
        &self,
        circuit: &mut CircuitBuilder<CF>,
        continuation: BinaryQueryContinuation,
        cap: &[Vec<ExprId>],
        points: &[Vec<P::ChallengeTarget>],
        proof: &BinaryPcs128ProofTargets<P::ChallengeTarget>,
        leaves: CosetLeaves,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryPcsMmcsHost<CF>,
        P: BinaryFoldPolicy<CF, Base = F, Challenge = E>,
    {
        self.check_targets_with(cap, points, proof, leaves)?;
        let seed = self.opening_seeds.first().cloned().unwrap_or_else(|| {
            domain_separator_seed(&BinaryPcsShape::new(&self.config).domain_separator::<F, E>())
        });
        let bytes = seed_bytes_with_host::<F, H, CF>(circuit, &seed)?;
        let challenger =
            continuation.resume_with_observation_with_host::<H, CF>(circuit, &bytes)?;
        self.verify_at_using::<P, H, CF>(circuit, challenger, cap, points, proof, true, leaves)
    }

    /// Same opening relation under an explicit scalar policy, circuit host
    /// and coset leaf mode.
    #[expect(
        clippy::too_many_arguments,
        reason = "The verifier keeps protocol inputs explicit."
    )]
    pub(crate) fn verify_at_using<P, H, CF>(
        &self,
        circuit: &mut CircuitBuilder<CF>,
        mut challenger: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<P::ChallengeTarget>],
        proof: &BinaryPcs128ProofTargets<P::ChallengeTarget>,
        first_seed_observed: bool,
        leaves: CosetLeaves,
    ) -> Result<BinaryQueryContinuation, VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryPcsMmcsHost<CF>,
        P: BinaryFoldPolicy<CF, Base = F, Challenge = E>,
    {
        self.check_targets_with(cap, points, proof, leaves)?;
        H::check_hash(self.hash)?;
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
            P::constrain_word(circuit, value, E::RAW_BITS)?;
        }
        for value in proof
            .base_rows
            .iter()
            .chain(core::slice::from_ref(&proof.pow_witness))
        {
            P::constrain_word(circuit, value, F::RAW_BITS)?;
        }
        for (i, evals) in proof.evals.iter().enumerate() {
            if i != 0 || !first_seed_observed {
                observe_seed_with_host::<F, H, CF>(
                    circuit,
                    &mut challenger,
                    &self.opening_seeds[i],
                )?;
            }
            P::observe::<H>(circuit, &mut challenger, &evals.to_vec())?;
        }
        let shape = BinaryPcsShape::new(&self.config);
        if !first_seed_observed || !self.opening_seeds.is_empty() {
            observe_seed_with_host::<F, H, CF>(
                circuit,
                &mut challenger,
                &domain_separator_seed(&shape.domain_separator::<F, E>()),
            )?;
        }
        observe_seed_with_host::<F, H, CF>(circuit, &mut challenger, &self.batching_seed)?;
        let alpha = P::sample::<H>(circuit, &mut challenger)?;
        let shapes = self.protocol.table_shapes();
        let (_, placements) = plan_stacked_layout(&shapes);
        let one = P::constant(circuit, 1)?;
        let mut power = one.clone();
        let mut claim = P::constant(circuit, 0)?;
        // Native batching order is placements, then per-table claims, current, next.
        for placement in &placements {
            for (i, (table, _)) in self.protocol.iter_openings().enumerate() {
                if table != placement.idx() {
                    continue;
                }
                for eval in proof.evals[i].current().iter().chain(proof.evals[i].next()) {
                    let term = P::mul(circuit, &power, eval);
                    claim = P::add(circuit, &claim, &term);
                    power = P::mul(circuit, &power, &alpha);
                }
            }
        }
        let round_seed = domain_separator_seed(
            &SumcheckShape::new(1, 0, Basis::Evaluation).domain_separator::<F, E>(),
        );
        let mut betas = Vec::with_capacity(self.config.num_variables());
        for (batch, (start, arity)) in batches(&self.config).enumerate() {
            for message in &proof.sumcheck[start..start + arity] {
                observe_seed_with_host::<F, H, CF>(circuit, &mut challenger, &round_seed)?;
                P::observe::<H>(circuit, &mut challenger, message)?;
                let beta = P::sample::<H>(circuit, &mut challenger)?;
                claim = reduce_sumcheck_using::<P, CF>(
                    circuit,
                    &claim,
                    &message[0],
                    &message[1],
                    &beta,
                )?;
                betas.push(beta);
            }
            if batch + 1 < self.config.num_fold_batches() {
                observe_cap_with_host::<H, CF>(circuit, &mut challenger, &proof.rounds[batch].cap)?;
            }
            circuit.check_construction_limits()?;
        }
        let fold_point: Vec<_> = betas.iter().rev().cloned().collect();
        let mut weight = P::constant(circuit, 0)?;
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
                            .map(|x| P::constant(circuit, x.to_repr()))
                            .collect::<Result<_, _>>()?;
                        let selector_vars = selector.num_variables();
                        let local_weight = if successor {
                            next_eval_using::<P, CF>(
                                circuit,
                                &points[i],
                                &fold_point[selector_vars..],
                            )?
                        } else {
                            P::eq_eval(circuit, &points[i], &fold_point[selector_vars..])?
                        };
                        let selector_weight =
                            P::eq_eval(circuit, &selector_point, &fold_point[..selector_vars])?;
                        let selected_weight = P::mul(circuit, &selector_weight, &local_weight);
                        let term = P::mul(circuit, &power, &selected_weight);
                        weight = P::add(circuit, &weight, &term);
                        power = P::mul(circuit, &power, &alpha);
                    }
                }
            }
        }
        let final_value = &proof.final_codeword[0];
        for value in &proof.final_codeword[1..] {
            P::assert_equal(circuit, value, final_value);
        }
        let expected_claim = P::mul(circuit, &weight, final_value);
        P::assert_equal(circuit, &claim, &expected_claim);
        P::observe::<H>(circuit, &mut challenger, &proof.final_codeword)?;
        if self.config.pow_bits() == 0 {
            let zero = P::constant(circuit, 0)?;
            P::assert_equal(circuit, &proof.pow_witness, &zero);
        } else {
            P::observe_word::<H>(circuit, &mut challenger, &proof.pow_witness, F::RAW_BITS)?;
            for bit in challenger.sample_bits_with_host::<H, CF>(circuit, self.config.pow_bits())? {
                let difference = circuit.sub(ExprId::ZERO, bit);
                circuit.assert_zero(difference);
            }
        }
        let continuation = verify_binary_pcs_query_indices_with_host::<H, CF>(
            circuit,
            challenger,
            &self.config,
            &proof.query_indices,
            self.max_query_draws,
        )?;
        let zero = circuit.define_const(CF::ZERO);
        let one = circuit.define_const(CF::ONE);
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
                let width = if batch == 0 { F::RAW_BITS } else { E::RAW_BITS };
                let subtree = coset_subtree_depth(&self.config, self.cap_height, start, arity);
                if leaves == CosetLeaves::Symbols && subtree.is_some() {
                    // Leaf `offset` sits at position `upper << arity | offset`,
                    // so the coset is the subtree at the query's upper bits.
                    let words = coset
                        .iter()
                        .map(|row| P::leaf_words(circuit, row, width))
                        .collect::<Result<Option<Vec<_>>, _>>()?;
                    if let Some(leaves) = words {
                        H::authenticate_subtree_words(
                            circuit,
                            self.hash,
                            &leaves,
                            1usize << (log_domain - start),
                            &index[start + arity..],
                            &paths[q],
                            cap,
                        )?;
                    } else {
                        let leaves = coset
                            .iter()
                            .map(|row| P::leaf_bytes::<H>(circuit, row, width))
                            .collect::<Result<Vec<_>, _>>()?;
                        H::authenticate_subtree(
                            circuit,
                            self.hash,
                            &leaves,
                            1usize << (log_domain - start),
                            &index[start + arity..],
                            &paths[q],
                            cap,
                        )?;
                    }
                }
                if leaves == CosetLeaves::Coset {
                    // The grouped leaf at `upper` holds the symbols at
                    // `upper << arity | offset` in ascending offset order.
                    let words = coset
                        .iter()
                        .map(|row| P::leaf_words(circuit, row, width))
                        .collect::<Result<Option<Vec<_>>, _>>()?;
                    let leaf = if let Some(words) = words {
                        words.concat()
                    } else {
                        // Narrow symbols straddle words, so the whole leaf's
                        // bytes are packed together.
                        let mut bytes = Vec::new();
                        for row in coset {
                            bytes.extend(P::leaf_bytes::<H>(circuit, row, width)?);
                        }
                        H::words_from_bytes(circuit, &bytes)?
                    };
                    H::authenticate_subtree_words(
                        circuit,
                        self.hash,
                        &[leaf],
                        1usize << (log_domain - start - arity),
                        &index[start + arity..],
                        &paths[q],
                        cap,
                    )?;
                }
                for (offset, row) in coset
                    .iter()
                    .enumerate()
                    .filter(|_| leaves == CosetLeaves::Symbols && subtree.is_none())
                {
                    let mut leaf_index = index[start..].to_vec();
                    for (b, bit) in leaf_index[..arity].iter_mut().enumerate() {
                        *bit = if offset >> b & 1 == 1 { one } else { zero };
                    }
                    if let Some(words) = P::leaf_words(circuit, row, width)? {
                        H::authenticate_subtree_words(
                            circuit,
                            self.hash,
                            &[words],
                            1usize << (log_domain - start),
                            &leaf_index,
                            &paths[q * size + offset],
                            cap,
                        )?;
                    } else {
                        let bytes = P::leaf_bytes::<H>(circuit, row, width)?;
                        H::authenticate_leaf(
                            circuit,
                            self.hash,
                            bytes,
                            1usize << (log_domain - start),
                            &leaf_index,
                            &paths[q * size + offset],
                            cap,
                        )?;
                    }
                }
                let mut folded = coset.to_vec();
                for j in 0..arity {
                    let mut next = Vec::with_capacity(folded.len() / 2);
                    for (offset, pair) in folded.as_chunks::<2>().0.iter().enumerate() {
                        let mut pair_index = index[start + j + 1..].to_vec();
                        for (b, bit) in pair_index[..arity - j - 1].iter_mut().enumerate() {
                            *bit = if offset >> b & 1 == 1 { one } else { zero };
                        }
                        next.push(P::fold_pair(
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
                    select_symbol::<P, CF>(
                        circuit,
                        &proof.rounds[batch].rows[q * size..(q + 1) * size],
                        &index[start + arity..start + arity + next_arity],
                    )?
                } else {
                    // Uniformity already binds every final symbol to the first.
                    final_value.clone()
                };
                P::assert_equal(circuit, &folded[0], &expected);
            }
            circuit.check_construction_limits()?;
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

    /// Leaf mode of every ordinary caller: grouped trees are authenticated by
    /// the caller's grouped openings, ungrouped trees one symbol per leaf.
    pub(super) const fn ordinary_leaves(&self) -> CosetLeaves {
        CosetLeaves::ordinary(self.grouping.is_some())
    }

    pub(crate) fn check_targets<T>(
        &self,
        cap: &[Vec<ExprId>],
        points: &[Vec<T>],
        proof: &BinaryPcs128ProofTargets<T>,
    ) -> Result<(), VerificationError> {
        self.check_targets_with(cap, points, proof, self.ordinary_leaves())
    }

    /// Target shapes for the authentication paths of `leaves`, which must
    /// match the committed trees.
    pub(super) fn check_targets_with<T>(
        &self,
        cap: &[Vec<ExprId>],
        points: &[Vec<T>],
        proof: &BinaryPcs128ProofTargets<T>,
        leaves: CosetLeaves,
    ) -> Result<(), VerificationError> {
        check_coset_leaves(&self.config, self.cap_height, self.grouping, leaves)?;
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
            let (per_query, depth) =
                coset_path_shape(&self.config, self.cap_height, leaves, start, arity);
            if rows.len() != count
                || paths.len() != shape.num_pairs * per_query
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

impl<F> BinaryPcsVerifier<F, BinaryField128>
where
    F: RecursiveBinaryTowerField,
    BinaryField128: ExtensionField<F>,
{
    /// Rejects grouped codewords and hashes the native host cannot evaluate.
    pub(crate) fn check_native_support(&self) -> Result<(), VerificationError> {
        if self.grouping.is_some() {
            return Err(shape_error(
                "native scalar binary PCS verifier does not support grouped codewords",
            ));
        }
        <NativeBinaryEncoding as BinaryCircuitHost<BinaryField128>>::check_hash(self.hash)?;
        Ok(())
    }

    /// Complete opening relation over native Tower128 scalars. The caller
    /// binds the commitment and prescribed points to its statement.
    pub fn verify_at_native(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<NativeTower128Target>],
        proof: &BinaryPcs128ProofTargets<NativeTower128Target>,
    ) -> Result<BinaryQueryContinuation, VerificationError> {
        self.check_native_support()?;
        self.verify_at_using::<NativeTower128Relation<F>, NativeBinaryEncoding, BinaryField128>(
            b,
            ch,
            cap,
            points,
            proof,
            false,
            CosetLeaves::Symbols,
        )
    }

    /// Native opening immediately after another opening's query phase.
    pub fn verify_at_native_after_queries(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        continuation: BinaryQueryContinuation,
        cap: &[Vec<ExprId>],
        points: &[Vec<NativeTower128Target>],
        proof: &BinaryPcs128ProofTargets<NativeTower128Target>,
    ) -> Result<BinaryQueryContinuation, VerificationError> {
        self.check_native_support()?;
        self.after_queries_using::<NativeTower128Relation<F>, NativeBinaryEncoding, BinaryField128>(
            b,
            continuation,
            cap,
            points,
            proof,
            CosetLeaves::Symbols,
        )
    }
}

/// Byte-tree authentication of serialized BaseFold symbols under a circuit host.
pub(crate) trait BinaryPcsMmcsHost<CF: Field + Eq + Hash>: BinaryCircuitHost<CF> {
    #[allow(clippy::too_many_arguments)]
    fn authenticate_leaf(
        b: &mut CircuitBuilder<CF>,
        hash: ByteHash,
        bytes: Vec<ExprId>,
        height: usize,
        index: &[ExprId],
        path: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>;

    /// Byte-tree authentication of the serialized symbols at positions
    /// `upper << k | i`, `i < 2^k = leaves.len()`, as one Merkle subtree;
    /// `index` holds the bits of `upper` and `path` the siblings above it.
    #[allow(clippy::too_many_arguments)]
    fn authenticate_subtree(
        b: &mut CircuitBuilder<CF>,
        hash: ByteHash,
        leaves: &[Vec<ExprId>],
        height: usize,
        index: &[ExprId],
        path: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>;

    /// [`Self::authenticate_subtree`] for leaves given as low-first sixteen-bit
    /// words, each standing for its two little-endian bytes. A single leaf is
    /// one symbol under its full index and path. Every word must already be
    /// bound to its symbol; this method range-checks it.
    #[allow(clippy::too_many_arguments)]
    fn authenticate_subtree_words(
        b: &mut CircuitBuilder<CF>,
        hash: ByteHash,
        leaves: &[Vec<ExprId>],
        height: usize,
        index: &[ExprId],
        path: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError> {
        let leaves = leaves
            .iter()
            .map(|words| Self::bytes_from_words(b, words))
            .collect::<Result<Vec<_>, _>>()?;
        Self::authenticate_subtree(b, hash, &leaves, height, index, path, cap)
    }
}

impl<BF, EF> BinaryPcsMmcsHost<EF> for PrimeBinaryEncoding<BF>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    fn authenticate_leaf(
        b: &mut CircuitBuilder<EF>,
        hash: ByteHash,
        bytes: Vec<ExprId>,
        height: usize,
        index: &[ExprId],
        path: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError> {
        // A fixed coset offset can send a sibling limb straight
        // into the hash NPO. Range checks also give each private
        // digest limb an ALU creator on the witness bus.
        for &limb in path.iter().flatten() {
            let _ = b.decompose_to_bits::<BF>(limb, 16)?;
        }
        b.verify_byte_hash_mmcs_opening_bytes::<BF>(hash, &[bytes], &[height], index, path, cap)?;
        Ok(())
    }

    fn authenticate_subtree(
        b: &mut CircuitBuilder<EF>,
        hash: ByteHash,
        leaves: &[Vec<ExprId>],
        height: usize,
        index: &[ExprId],
        path: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError> {
        // Range checks also give each private sibling limb an ALU creator on
        // the witness bus. Digests inside the subtree are hash outputs.
        for &limb in path.iter().flatten() {
            let _ = b.decompose_to_bits::<BF>(limb, 16)?;
        }
        b.verify_byte_hash_mmcs_subtree_bytes::<BF>(hash, leaves, height, index, path, cap)?;
        Ok(())
    }
}

impl BinaryPcsMmcsHost<BinaryField128> for NativeBinaryEncoding {
    fn authenticate_leaf(
        b: &mut CircuitBuilder<BinaryField128>,
        hash: ByteHash,
        bytes: Vec<ExprId>,
        height: usize,
        index: &[ExprId],
        path: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError> {
        for sibling in path {
            <Self as BinaryCircuitHost<BinaryField128>>::constrain_sibling(b, sibling)?;
        }
        b.verify_byte_hash_mmcs_opening_bytes_with_host::<Self>(
            hash,
            &[bytes],
            &[height],
            index,
            path,
            cap,
        )?;
        b.check_construction_limits()?;
        Ok(())
    }

    fn authenticate_subtree(
        b: &mut CircuitBuilder<BinaryField128>,
        hash: ByteHash,
        leaves: &[Vec<ExprId>],
        height: usize,
        index: &[ExprId],
        path: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError> {
        for sibling in path {
            <Self as BinaryCircuitHost<BinaryField128>>::constrain_sibling(b, sibling)?;
        }
        b.verify_byte_hash_mmcs_subtree_bytes_with_host::<Self>(
            hash, leaves, height, index, path, cap,
        )?;
        b.check_construction_limits()?;
        Ok(())
    }

    fn authenticate_subtree_words(
        b: &mut CircuitBuilder<BinaryField128>,
        hash: ByteHash,
        leaves: &[Vec<ExprId>],
        height: usize,
        index: &[ExprId],
        path: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError> {
        for sibling in path {
            <Self as BinaryCircuitHost<BinaryField128>>::constrain_sibling(b, sibling)?;
        }
        // Each leaf word is absorbed as a raw Keccak limb, which the native
        // Keccak AIR constrains to sixteen coordinates.
        b.verify_byte_hash_mmcs_subtree_words_with_host::<Self>(
            hash, leaves, height, index, path, cap,
        )?;
        b.check_construction_limits()?;
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

/// Siblings above the Merkle subtree of an ungrouped query coset at fold
/// batch `(start, arity)`, or `None` when its `2^arity` leaves reach into the
/// cap layer and each symbol is authenticated by its own full path.
pub(super) const fn coset_subtree_depth(
    config: &BinaryPcsConfig,
    cap_height: usize,
    start: usize,
    arity: usize,
) -> Option<usize> {
    (config.num_variables() + config.log_inv_rate() - start - cap_height).checked_sub(arity)
}

/// How the opening relation authenticates the rows of each query coset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CosetLeaves {
    /// Ungrouped trees: one leaf per symbol, so a coset below the cap layer
    /// is one Merkle subtree and otherwise each symbol has its own path.
    Symbols,
    /// Grouped trees authenticated by the caller's grouped openings; the
    /// ordinary paths are empty.
    External,
    /// Grouped trees whose leaf is exactly one fold coset: the coset rows,
    /// in offset order, hash as one leaf with one path per query.
    Coset,
}

impl CosetLeaves {
    pub(super) const fn ordinary(grouped: bool) -> Self {
        if grouped {
            Self::External
        } else {
            Self::Symbols
        }
    }
}

/// Rejects a leaf mode the committed trees do not support. `Coset` needs
/// grouped trees whose effective group size at every fold batch
/// `(start, arity)` is exactly `2^arity`, with the leaf layer at or below
/// the cap; the size is checked, not the grouping policy.
pub(super) fn check_coset_leaves(
    config: &BinaryPcsConfig,
    cap_height: usize,
    grouping: Option<[super::grouped_pcs::BinaryCodewordGrouping; 2]>,
    leaves: CosetLeaves,
) -> Result<(), VerificationError> {
    match (leaves, grouping) {
        (CosetLeaves::Symbols, None) | (CosetLeaves::External, Some(_)) => Ok(()),
        (CosetLeaves::Coset, Some(grouping)) => {
            let log_domain = config.num_variables() + config.log_inv_rate();
            for (batch, (start, arity)) in batches(config).enumerate() {
                let group =
                    grouping[usize::from(batch != 0)].effective(config, log_domain - start)?;
                if group != 1usize << arity
                    || coset_subtree_depth(config, cap_height, start, arity).is_none()
                {
                    return Err(shape_error(
                        "binary grouped leaf is not one fold coset below the cap",
                    ));
                }
            }
            Ok(())
        }
        (CosetLeaves::Symbols, Some(_)) | (CosetLeaves::External | CosetLeaves::Coset, None) => {
            Err(shape_error(
                "binary PCS coset leaf mode does not match the committed trees",
            ))
        }
    }
}

/// Authentication paths per query and siblings per path of the oracle at
/// fold batch `(start, arity)`. External grouped openings leave these paths
/// empty. A whole-coset leaf has one path per query, the siblings above that
/// grouped leaf; [`check_coset_leaves`] keeps the leaf layer below the cap.
pub(super) const fn coset_path_shape(
    config: &BinaryPcsConfig,
    cap_height: usize,
    leaves: CosetLeaves,
    start: usize,
    arity: usize,
) -> (usize, usize) {
    match (
        leaves,
        coset_subtree_depth(config, cap_height, start, arity),
    ) {
        (CosetLeaves::External, _) => (1 << arity, 0),
        (CosetLeaves::Symbols | CosetLeaves::Coset, Some(depth)) => (1, depth),
        (CosetLeaves::Symbols | CosetLeaves::Coset, None) => (
            1 << arity,
            config.num_variables() + config.log_inv_rate() - start - cap_height,
        ),
    }
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

/// Observes each cap digest as its sixteen natural-order little-endian limbs.
///
/// A host that hashes words whole observes the limbs as words: every
/// commitment is followed by a draw, whose refill range-checks each limb, as a
/// hash lane or, at an odd offset or in an odd-length input, as checked bytes.
/// Any other host range-checks each limb and splits it into bytes here.
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
    if H::hashes_words_whole(challenger.hash()) {
        challenger.observe_words_with_host::<H, EF>(circuit, &cap.concat())?;
        return Ok(());
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

fn select_symbol<P, CF>(
    circuit: &mut CircuitBuilder<CF>,
    symbols: &[P::ChallengeTarget],
    index: &[ExprId],
) -> Result<P::ChallengeTarget, VerificationError>
where
    CF: Field + Eq + Hash,
    P: BinaryFoldPolicy<CF>,
{
    let mut layer = symbols.to_vec();
    for &bit in index {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| P::select(circuit, bit, &pair[1], &pair[0]))
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
        // The cap limbs are observed as words for the next refill to absorb
        // as Keccak lanes, with no decomposition or other node here.
        let before = b.construction_usage().unwrap();
        observe_cap_with_host::<H, CF>(&mut b, &mut ch, &[cap.to_vec()]).unwrap();
        assert_eq!(b.construction_usage().unwrap(), before);
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
        // A cap word with coordinate 16 keeps its low sixteen coordinates, so
        // only the range check of its Keccak lane refuses it.
        let wide = CF::from_raw_coordinates(1 << 16).unwrap();
        for index in [0, 15] {
            let mut wrong = public.clone();
            wrong[index] += wide;
            assert!(!run(&wrong), "wide cap word {index}");
        }
    }

    #[test]
    fn native_protocol_seeds_caps_and_observations_preserve_all_bytes() {
        transcript::<BinaryField128>();
        transcript::<Poly64>();
    }
}
