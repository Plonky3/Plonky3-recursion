//! Trusted geometry and native separators for released additive WHIR pairs.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_binary_field::BinaryField128;
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::ByteHash;
use p3_field::{BasedVectorSpace, ExtensionField};
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{
    LayoutStrategy, TablePlacement, Verifier, commitment_domain_separator, plan_stacked_layout,
};
use p3_sumcheck::strategy::{Basis, VariableOrder};
use p3_sumcheck::transcript::SumcheckShape;
use p3_sumcheck::{OpeningBatch, OpeningProtocol};
use p3_whir::WhirConfig;
use p3_whir::transcript::WhirShape;

use super::BinaryWhirQueryPlan;
use super::fields::WhirFieldPair;
use crate::transcript::{SeedTap, domain_separator_seed};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FoldShape {
    pub rounds: usize,
    pub pow_bits: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OracleSite {
    pub variables: usize,
    pub width: usize,
    pub log_height: usize,
    pub query_pow_bits: usize,
    pub queries: BinaryWhirQueryPlan,
    pub ood: usize,
    pub fold: FoldShape,
}

#[derive(Clone, Debug)]
pub(super) struct WhirPlan<F, E = BinaryField128> {
    _challenge: PhantomData<E>,
    pub protocol: OpeningProtocol,
    pub order: VariableOrder,
    pub hash: ByteHash,
    pub cap_height: usize,
    pub limits: VerifierLimits,
    pub usage: InputResourceUsage,
    pub variables: usize,
    pub initial_ood: usize,
    pub initial_fold: FoldShape,
    pub sites: Vec<OracleSite>,
    pub final_len: usize,
    pub placements: Vec<TablePlacement>,
    pub commitment_seed: Vec<F>,
    pub virtual_seeds: Vec<Vec<F>>,
    pub opening_seeds: Vec<Vec<F>>,
    pub batching_seed: Vec<F>,
    pub engine_seed: Vec<F>,
    pub fold_seeds: Vec<Vec<F>>,
}

impl<F, E> WhirPlan<F, E>
where
    F: WhirFieldPair<E>,
    E: ExtensionField<F>,
{
    pub fn new<Ch>(
        config: &WhirConfig<E, F, Ch>,
        protocol: OpeningProtocol,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let variables = config.num_variables();
        // The released binary challenger searches a 64-bit counter with eight
        // bits of headroom, even when the base alphabet is wider than 64 bits.
        limit(
            "binary WHIR native grinding bits",
            config.max_pow_bits(),
            F::ALPHABET_BITS
                .min(64)
                .saturating_sub(8)
                .min(usize::BITS as usize - 1),
        )?;
        let log_domain = variables
            .checked_add(config.params().starting_log_inv_rate)
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary WHIR domain",
            })?;
        limit(
            "binary WHIR domain bits",
            log_domain,
            limits
                .max_log_domain_or_degree
                .min(usize::BITS as usize - 1),
        )?;
        limit("binary WHIR cap height", cap_height, log_domain)?;
        let cells =
            protocol
                .checked_num_cells()
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary WHIR protocol cells",
                })?;
        if cells == 0 || p3_util::log2_ceil_usize(cells) != variables {
            return Err(invalid(
                "binary WHIR protocol does not match the committed arity",
            ));
        }
        let claims =
            protocol
                .checked_num_claims()
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary WHIR claims",
                })?;
        let mut usage = InputResourceUsage::default();
        let shapes = protocol.table_shapes();
        usage.add_instances(limits, shapes.len())?;
        usage.add_rounds(limits, variables)?;
        usage.add_metadata_entries(limits, claims)?;
        for shape in &shapes {
            limit(
                "binary WHIR table width",
                shape.width(),
                limits.max_matrix_width,
            )?;
        }
        for (table, batch) in protocol.iter_openings() {
            if batch.is_empty()
                || batch
                    .current()
                    .iter()
                    .chain(batch.next())
                    .any(|&col| col >= shapes[table].width())
            {
                return Err(invalid("binary WHIR opening request is invalid"));
            }
            for columns in [batch.current(), batch.next()] {
                let mut seen = hashbrown::HashSet::new();
                if columns.iter().any(|&col| !seen.insert(col)) {
                    return Err(invalid("binary WHIR opening repeats a column"));
                }
            }
            usage.add_scalar_elements(
                limits,
                mul(shapes[table].num_variables(), F::CHALLENGE_INPUT_LIMBS)?,
            )?;
        }
        limit(
            "binary WHIR intermediate rounds",
            config.n_rounds(),
            limits.max_rounds,
        )?;
        let initial_ood = config.commitment_ood_samples();
        usage.add_metadata_entries(limits, initial_ood)?;
        let initial_claims = claims.checked_add(initial_ood).ok_or(
            VerificationError::ResourceArithmeticOverflow {
                component: "binary WHIR initial claims",
            },
        )?;
        config
            .validate_initial_claims(initial_claims)
            .map_err(|_| invalid("binary WHIR initial claim security budget exceeded"))?;
        let shape = WhirShape::new(config, protocol.num_openings());
        if shape.domain_id != F::DOMAIN_ID || !shape.stratified_queries || !config.check_pow_bits()
        {
            return Err(invalid(
                "binary WHIR configuration uses another domain or exceeds its grinding budget",
            ));
        }
        let initial_fold = FoldShape {
            rounds: shape.initial_sumcheck.rounds,
            pow_bits: shape.initial_sumcheck.pow_bits,
        };
        fold_usage::<F, E>(&mut usage, limits, &initial_fold)?;
        usage.add_scalar_elements(limits, mul(initial_claims, F::CHALLENGE_INPUT_LIMBS)?)?;
        let final_config = config.final_round_config();
        let mut sites = Vec::new();
        for (i, params) in config
            .round_parameters()
            .iter()
            .chain(core::iter::once(&final_config))
            .enumerate()
        {
            limit(
                "binary WHIR site domain bits",
                params.domain_size.ilog2() as usize,
                limits.max_log_domain_or_degree,
            )?;
            let (draws, bits, ood, fold) = if let Some(round) = shape.rounds.get(i) {
                (
                    round.query_draws,
                    round.index_bits,
                    round.ood_samples,
                    FoldShape {
                        rounds: round.sumcheck.rounds,
                        pow_bits: round.sumcheck.pow_bits,
                    },
                )
            } else {
                (
                    shape.final_query_draws,
                    shape.final_index_bits,
                    0,
                    FoldShape {
                        rounds: shape.final_sumcheck.rounds,
                        pow_bits: shape.final_sumcheck.pow_bits,
                    },
                )
            };
            if cap_height > bits || bits > F::ALPHABET_BITS {
                return Err(invalid(
                    "binary WHIR cap or query width exceeds its tree or alphabet",
                ));
            }
            let width = 1usize
                .checked_shl(
                    params
                        .folding_factor
                        .try_into()
                        .map_err(|_| invalid("binary WHIR fold width overflows"))?,
                )
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary WHIR row width",
                })?;
            limit("binary WHIR row width", width, limits.max_matrix_width)?;
            let physical_width = mul(
                width,
                if i == 0 {
                    1
                } else {
                    <E as BasedVectorSpace<F>>::DIMENSION
                },
            )?;
            limit(
                "binary WHIR native row width",
                physical_width,
                limits.max_matrix_width,
            )?;
            let queries = BinaryWhirQueryPlan::with_limits(bits, draws, limits)?;
            let q = queries.num_queries();
            usage.add_query_round(limits, q)?;
            usage.add_metadata_entries(limits, draws.count_ones() as usize)?;
            usage.add_scalar_elements(limits, mul(q, bits)?)?;
            usage.add_metadata_entries(limits, ood)?;
            usage.add_scalar_elements(
                limits,
                mul(ood, F::CHALLENGE_INPUT_LIMBS)?
                    .checked_add(F::BASE_INPUT_LIMBS)
                    .ok_or(VerificationError::ResourceArithmeticOverflow {
                        component: "binary WHIR OOD values",
                    })?,
            )?;
            usage.add_scalar_elements(
                limits,
                mul(
                    mul(q, width)?,
                    if i == 0 {
                        F::BASE_INPUT_LIMBS
                    } else {
                        F::CHALLENGE_INPUT_LIMBS
                    },
                )?,
            )?;
            let paths = mul(q, bits - cap_height)?;
            usage.add_restored_authentication_path_hashes(limits, q, bits - cap_height)?;
            usage.add_compressed_frontier_hashes(limits, paths)?;
            usage.add_scalar_elements(limits, mul(paths, 16)?)?;
            let roots = 1usize << cap_height;
            usage.add_cap_roots(limits, roots)?;
            usage.add_scalar_elements(limits, mul(roots, 16)?)?;
            fold_usage::<F, E>(&mut usage, limits, &fold)?;
            if params.pow_bits >= usize::BITS as usize {
                return Err(invalid("binary WHIR query grinding width is invalid"));
            }
            sites.push(OracleSite {
                variables: params.num_variables,
                width,
                log_height: bits,
                query_pow_bits: params.pow_bits,
                queries,
                ood,
                fold,
            });
        }
        usage.add_final_poly_evaluations(limits, shape.final_poly_len)?;
        usage.add_scalar_elements(limits, mul(shape.final_poly_len, F::CHALLENGE_INPUT_LIMBS)?)?;
        let strategy = LayoutStrategy::new(order == VariableOrder::Prefix, order);
        let (_, mut placements) = plan_stacked_layout(&shapes);
        if order == VariableOrder::Prefix {
            placements
                .iter_mut()
                .for_each(TablePlacement::reverse_selectors);
        }
        let mut native_layout = Verifier::<F, E>::new(&shapes, strategy);
        let mut virtual_seeds = Vec::new();
        for _ in 0..initial_ood {
            let mut tap = SeedTap::new();
            native_layout.add_virtual_eval(E::ZERO, &mut tap);
            virtual_seeds.push(tap.binary_seed());
        }
        let mut opening_seeds = Vec::new();
        for (table, batch) in protocol.iter_openings() {
            let point = Point::new(vec![E::ZERO; shapes[table].num_variables()]);
            let evals = OpeningBatch::new(
                vec![E::ZERO; batch.current().len()],
                vec![E::ZERO; batch.next().len()],
            );
            let mut tap = SeedTap::new();
            native_layout
                .add_claim_at(table, batch, &point, &evals, &mut tap)
                .map_err(|_| invalid("binary WHIR layout seed capture failed"))?;
            opening_seeds.push(tap.binary_seed());
        }
        let mut tap = SeedTap::new();
        let _ = native_layout.batching_challenge(&mut tap);
        let batching_seed = tap.binary_seed();
        let fold_seeds = core::iter::once(&initial_fold)
            .chain(sites.iter().map(|s| &s.fold))
            .map(|fold| {
                if fold.rounds == 0 {
                    vec![]
                } else {
                    domain_separator_seed(
                        &SumcheckShape::new(fold.rounds, fold.pow_bits, Basis::Evaluation)
                            .domain_separator::<F, E>(),
                    )
                }
            })
            .collect();
        Ok(Self {
            _challenge: PhantomData,
            protocol,
            order,
            hash,
            cap_height,
            limits: *limits,
            usage,
            variables,
            initial_ood,
            initial_fold,
            sites,
            final_len: shape.final_poly_len,
            placements,
            commitment_seed: domain_separator_seed(&commitment_domain_separator::<F>()),
            virtual_seeds,
            opening_seeds,
            batching_seed,
            engine_seed: domain_separator_seed(&shape.domain_separator::<F, E>()),
            fold_seeds,
        })
    }
}

fn fold_usage<F, E>(
    usage: &mut InputResourceUsage,
    limits: &VerifierLimits,
    fold: &FoldShape,
) -> Result<(), VerificationError>
where
    F: WhirFieldPair<E>,
    E: ExtensionField<F>,
{
    if fold.pow_bits >= usize::BITS as usize {
        return Err(invalid("binary WHIR folding grinding width is invalid"));
    }
    usage.add_scalar_elements(
        limits,
        mul(
            fold.rounds,
            2 * F::CHALLENGE_INPUT_LIMBS
                + if fold.pow_bits > 0 {
                    F::BASE_INPUT_LIMBS
                } else {
                    0
                },
        )?,
    )
}
fn mul(a: usize, b: usize) -> Result<usize, VerificationError> {
    a.checked_mul(b)
        .ok_or(VerificationError::ResourceArithmeticOverflow {
            component: "binary WHIR input sizes",
        })
}
pub(super) fn limit(
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
pub(super) fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
