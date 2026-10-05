//! Full released non-hiding additive WHIR relation for tower alphabets.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{
    BinaryTower128Target, ByteHash, NativeTower128Target,
    binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding},
    binary_host::BinaryCircuitHost,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{OpeningBatch, OpeningProtocol};
use p3_whir::WhirConfig;

use super::gadgets::{next_eval_using, reduce_sumcheck_using};
use super::verifier::{observe_cap_with_host, observe_seed_with_host};
use super::whir_gadgets::{eval_coefficients_using, eval_multilinear_using, select_eval_using};
use super::whir_plan::{FoldShape, OracleSite, WhirPlan, invalid};
use super::{BinaryWhirProofTargets, BinaryWhirSumcheckTargets, RecursiveBinaryWhirTowerField};
use crate::verifier::binary_field_policy::{
    BinaryTowerPolicy, NativeTower128Relation, TowerRelation,
};

use crate::BinaryTower128Challenger;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

/// Verifier-owned native domain, schedule, separators and finite input bounds.
/// Supports the released Tower32→Tower128 and Tower128→Tower128 additive
/// families with ordinary binary-arity byte Merkle trees. The caller binds
/// the commitment and prescribed opening points to its statement.
#[derive(Clone, Debug)]
pub struct BinaryWhirVerifier<F = BinaryField128> {
    pub(super) plan: WhirPlan<F>,
}

enum Weight<T> {
    Eq(Vec<T>),
    Next {
        selector: Vec<T>,
        point: Vec<T>,
        selector_last: bool,
    },
    Select(Vec<T>),
}
struct Term<T> {
    variables: usize,
    coefficient: T,
    weight: Weight<T>,
}
struct Authentication<'a, T> {
    site: &'a OracleSite,
    rows: &'a [Vec<T>],
    paths: &'a [Vec<Vec<ExprId>>],
    cap: Vec<Vec<ExprId>>,
    indices: Vec<Vec<ExprId>>,
    field_bits: usize,
}

impl<F> BinaryWhirVerifier<F>
where
    F: RecursiveBinaryWhirTowerField,
    BinaryField128: ExtensionField<F>,
{
    /// Conservative checked input counters retained by the trusted plan.
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.plan.usage
    }
    pub(crate) fn check_host<H, CF>(&self) -> Result<(), VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
    {
        H::check_hash(self.plan.hash)?;
        Ok(())
    }
    pub fn new<Ch>(
        config: &WhirConfig<BinaryField128, F, Ch>,
        protocol: OpeningProtocol,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        Self::with_limits(
            config,
            protocol,
            order,
            hash,
            cap_height,
            &VerifierLimits::default(),
        )
    }

    pub fn with_limits<Ch>(
        config: &WhirConfig<BinaryField128, F, Ch>,
        protocol: OpeningProtocol,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        Ok(Self {
            plan: WhirPlan::new(config, protocol, order, hash, cap_height, limits)?,
        })
    }

    pub fn observe_commitment<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.observe_commitment_with_host::<PrimeBinaryEncoding<BF>, EF>(b, ch, cap)
    }
    pub fn observe_commitment_with_host<H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        ch: &mut BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
    ) -> Result<(), VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
    {
        self.check_cap(cap)?;
        H::check_hash(self.plan.hash)?;
        observe_seed_with_host::<F, H, CF>(b, ch, &self.plan.commitment_seed)?;
        observe_cap_with_host::<H, CF>(b, ch, cap)
    }

    /// Replays the complete native PCS adapter and WHIR engine. Every query
    /// authenticates its full row, every sumcheck uses its phase separator,
    /// and the terminal constraint binds all opening, OOD and selector claims.
    /// The fixed stratified query schedule returns an exact ordinary challenger.
    pub fn verify_at<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryWhirProofTargets,
    ) -> Result<
        (
            Vec<OpeningBatch<BinaryTower128Target>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    >
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify_at_using::<TowerRelation<F, BinaryField128>, PrimeBinaryEncoding<BF>, EF>(
            b, ch, cap, points, proof,
        )
    }
    pub(crate) fn verify_at_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        mut ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<P::ChallengeTarget>],
        proof: &BinaryWhirProofTargets<P::ChallengeTarget>,
    ) -> Result<
        (
            Vec<OpeningBatch<P::ChallengeTarget>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    >
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryTowerPolicy<CF, Base = F, Challenge = BinaryField128>,
    {
        H::check_hash(self.plan.hash)?;
        self.check_targets(cap, points, proof)?;
        let p = &self.plan;
        let mut virtual_points = Vec::new();
        for (seed, answer) in p.virtual_seeds.iter().zip(&proof.initial_ood_answers) {
            observe_seed_with_host::<F, H, CF>(b, &mut ch, seed)?;
            let z = P::sample::<H>(b, &mut ch)?;
            virtual_points.push(expand::<P, CF>(b, &z, p.variables));
            P::observe::<H>(b, &mut ch, core::slice::from_ref(answer))?;
        }
        for (seed, evals) in p.opening_seeds.iter().zip(&proof.evals) {
            observe_seed_with_host::<F, H, CF>(b, &mut ch, seed)?;
            P::observe::<H>(b, &mut ch, evals.current())?;
            P::observe::<H>(b, &mut ch, evals.next())?;
        }
        observe_seed_with_host::<F, H, CF>(b, &mut ch, &p.engine_seed)?;
        observe_seed_with_host::<F, H, CF>(b, &mut ch, &p.batching_seed)?;
        let alpha = P::sample::<H>(b, &mut ch)?;
        let mut power = P::constant(b, 1)?;
        let mut claim = P::constant(b, 0)?;
        let mut terms = Vec::new();
        for placement in &p.placements {
            for (opening, (table, request)) in p
                .protocol
                .iter_openings()
                .enumerate()
                .filter(|(_, (table, _))| *table == placement.idx())
            {
                for (next, columns, evals) in [
                    (false, request.current(), proof.evals[opening].current()),
                    (true, request.next(), proof.evals[opening].next()),
                ] {
                    for (&column, eval) in columns.iter().zip(evals) {
                        let selector = placement.selectors()[column]
                            .point::<BinaryField128>()
                            .iter()
                            .map(|v| P::constant(b, v.to_repr()))
                            .collect::<Result<Vec<_>, _>>()?;
                        let point = points[opening].clone();
                        let weight = if next {
                            Weight::Next {
                                selector,
                                point,
                                selector_last: p.order == VariableOrder::Prefix,
                            }
                        } else {
                            let lifted = if p.order == VariableOrder::Prefix {
                                point.into_iter().chain(selector).collect()
                            } else {
                                selector.into_iter().chain(point).collect()
                            };
                            Weight::Eq(lifted)
                        };
                        let value = P::mul(b, &power, eval);
                        claim = P::add(b, &claim, &value);
                        terms.push(Term {
                            variables: p.variables,
                            coefficient: power.clone(),
                            weight,
                        });
                        power = P::mul(b, &power, &alpha);
                    }
                }
                // The table index determines placement order; the prescribed
                // point and values retain their protocol opening indices.
                let _ = table;
            }
        }
        for (point, answer) in virtual_points.into_iter().zip(&proof.initial_ood_answers) {
            let value = P::mul(b, &power, answer);
            claim = P::add(b, &claim, &value);
            terms.push(Term {
                variables: p.variables,
                coefficient: power.clone(),
                weight: Weight::Eq(point),
            });
            power = P::mul(b, &power, &alpha);
        }
        let (mut claim, mut last_r) = self.fold_using::<P, H, CF>(
            b,
            &mut ch,
            claim,
            &proof.initial_sumcheck,
            &p.initial_fold,
            &p.fold_seeds[0],
        )?;
        let mut all_r = last_r.clone();
        let mut previous_cap = cap.to_vec();
        let mut checks = Vec::new();
        for (i, (site, round)) in p.sites.iter().zip(&proof.rounds).enumerate() {
            observe_cap_with_host::<H, CF>(b, &mut ch, &round.cap)?;
            let mut ood_points = Vec::new();
            for answer in &round.ood_answers {
                let z = P::sample::<H>(b, &mut ch)?;
                ood_points.push(expand::<P, CF>(b, &z, site.variables));
                P::observe::<H>(b, &mut ch, core::slice::from_ref(answer))?;
            }
            self.pow_using::<P, H, CF>(b, &mut ch, site.query_pow_bits, &round.pow_witness)?;
            let indices = site.queries.sample_with_host::<H, CF>(b, &mut ch)?;
            let row_r = oriented(&last_r, p.order);
            let folds = round
                .rows
                .iter()
                .map(|row| eval_multilinear_using::<P, CF>(b, row, &row_r))
                .collect::<Result<Vec<_>, _>>()?;
            let query_points = indices
                .iter()
                .map(|index| P::query_point(b, index, site.variables))
                .collect::<Result<Vec<_>, _>>()?;
            checks.push(Authentication {
                site,
                rows: &round.rows,
                paths: &round.paths,
                cap: previous_cap,
                indices,
                field_bits: if i == 0 { F::RAW_BITS } else { 128 },
            });
            let gamma = P::sample::<H>(b, &mut ch)?;
            let mut power = gamma.clone();
            for ((point, value), select) in ood_points
                .into_iter()
                .zip(&round.ood_answers)
                .map(|pair| (pair, false))
                .chain(
                    query_points
                        .into_iter()
                        .zip(&folds)
                        .map(|pair| (pair, true)),
                )
            {
                let weighted = P::mul(b, &power, value);
                claim = P::add(b, &claim, &weighted);
                terms.push(Term {
                    variables: site.variables,
                    coefficient: power.clone(),
                    weight: if select {
                        Weight::Select(point)
                    } else {
                        Weight::Eq(point)
                    },
                });
                power = P::mul(b, &power, &gamma);
            }
            (claim, last_r) = self.fold_using::<P, H, CF>(
                b,
                &mut ch,
                claim,
                &round.sumcheck,
                &site.fold,
                &p.fold_seeds[i + 1],
            )?;
            all_r.extend_from_slice(&last_r);
            previous_cap = round.cap.clone();
        }
        P::observe::<H>(b, &mut ch, &proof.final_poly)?;
        let site = p.sites.last().expect("checked final site");
        self.pow_using::<P, H, CF>(b, &mut ch, site.query_pow_bits, &proof.final_pow_witness)?;
        let indices = site.queries.sample_with_host::<H, CF>(b, &mut ch)?;
        let row_r = oriented(&last_r, p.order);
        for (index, row) in indices.iter().zip(&proof.final_rows) {
            let folded = eval_multilinear_using::<P, CF>(b, row, &row_r)?;
            let point = P::query_point(b, index, site.variables)?;
            let expected = eval_coefficients_using::<P, CF>(b, &proof.final_poly, &point)?;
            P::assert_equal(b, &folded, &expected);
        }
        checks.push(Authentication {
            site,
            rows: &proof.final_rows,
            paths: &proof.final_paths,
            cap: previous_cap,
            indices,
            field_bits: if proof.rounds.is_empty() {
                F::RAW_BITS
            } else {
                128
            },
        });
        let (claim, closing_r) = self.fold_using::<P, H, CF>(
            b,
            &mut ch,
            claim,
            &proof.final_sumcheck,
            &site.fold,
            p.fold_seeds.last().expect("checked closing seed"),
        )?;
        all_r.extend_from_slice(&closing_r);
        if all_r.len() != p.variables {
            return Err(invalid(
                "binary WHIR trusted fold arities do not close the domain",
            ));
        }
        let mut weight = P::constant(b, 0)?;
        for term in terms {
            let row = oriented(&all_r[all_r.len() - term.variables..], p.order);
            let value = match term.weight {
                Weight::Eq(point) => P::eq_eval(b, &point, &row)?,
                Weight::Select(point) => select_eval_using::<P, CF>(b, &point, &row)?,
                Weight::Next {
                    selector,
                    point,
                    selector_last,
                } => {
                    let (selector_row, local_row) = if selector_last {
                        (&row[point.len()..], &row[..point.len()])
                    } else {
                        (&row[..selector.len()], &row[selector.len()..])
                    };
                    let selector_weight = P::eq_eval(b, &selector, selector_row)?;
                    let next_weight = next_eval_using::<P, CF>(b, &point, local_row)?;
                    P::mul(b, &selector_weight, &next_weight)
                }
            };
            let scaled = P::mul(b, &term.coefficient, &value);
            weight = P::add(b, &weight, &scaled);
        }
        let closing_r = oriented(&closing_r, p.order);
        let final_value = eval_multilinear_using::<P, CF>(b, &proof.final_poly, &closing_r)?;
        let expected = P::mul(b, &weight, &final_value);
        P::assert_equal(b, &claim, &expected);
        for check in checks {
            for ((row, path), index) in check.rows.iter().zip(check.paths).zip(&check.indices) {
                let mut bytes = Vec::new();
                for value in row {
                    bytes.extend(P::word_bytes::<H>(b, value, check.field_bits)?);
                }
                for &limb in path.iter().flatten() {
                    H::decompose_word(b, limb, 16)?;
                }
                b.verify_byte_hash_mmcs_opening_bytes_with_host::<H>(
                    p.hash,
                    &[bytes],
                    &[1usize << check.site.log_height],
                    index,
                    path,
                    &check.cap,
                )?;
            }
        }
        Ok((proof.evals.clone(), ch))
    }

    fn fold_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        ch: &mut BinaryTower128Challenger,
        mut claim: P::ChallengeTarget,
        proof: &BinaryWhirSumcheckTargets<P::ChallengeTarget>,
        shape: &FoldShape,
        seed: &[F],
    ) -> Result<(P::ChallengeTarget, Vec<P::ChallengeTarget>), VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryTowerPolicy<CF, Base = F, Challenge = BinaryField128>,
    {
        if shape.rounds == 0 {
            return Ok((claim, Vec::new()));
        }
        observe_seed_with_host::<F, H, CF>(b, ch, seed)?;
        let mut randomness = Vec::new();
        for (i, [h0, hinf]) in proof.messages.iter().enumerate() {
            P::observe::<H>(b, ch, &[h0.clone(), hinf.clone()])?;
            if shape.pow_bits > 0 {
                self.pow_using::<P, H, CF>(b, ch, shape.pow_bits, &proof.pow_witnesses[i])?;
            }
            let beta = P::sample::<H>(b, ch)?;
            claim = reduce_sumcheck_using::<P, CF>(b, &claim, h0, hinf, &beta)?;
            randomness.push(beta);
        }
        Ok((claim, randomness))
    }

    fn pow_using<P, H, CF>(
        &self,
        b: &mut CircuitBuilder<CF>,
        ch: &mut BinaryTower128Challenger,
        bits: usize,
        witness: &P::ChallengeTarget,
    ) -> Result<(), VerificationError>
    where
        CF: Field + Eq + Hash,
        H: BinaryCircuitHost<CF>,
        P: BinaryTowerPolicy<CF, Base = F, Challenge = BinaryField128>,
    {
        if bits == 0 {
            let zero = P::constant(b, 0)?;
            P::assert_equal(b, witness, &zero);
        } else {
            let bytes = P::word_bytes::<H>(b, witness, F::RAW_BITS)?;
            ch.observe_bytes_with_host::<H, CF>(b, &bytes)?;
            for bit in ch.sample_bits_with_host::<H, CF>(b, bits)? {
                let difference = b.sub(ExprId::ZERO, bit);
                b.assert_zero(difference);
            }
        }
        Ok(())
    }

    fn check_cap(&self, cap: &[Vec<ExprId>]) -> Result<(), VerificationError> {
        if cap.len() != 1usize << self.plan.cap_height
            || cap.iter().any(|digest| digest.len() != 16)
        {
            Err(invalid("binary WHIR cap shape mismatch"))
        } else {
            Ok(())
        }
    }
    pub(crate) fn check_targets<T>(
        &self,
        cap: &[Vec<ExprId>],
        points: &[Vec<T>],
        proof: &BinaryWhirProofTargets<T>,
    ) -> Result<(), VerificationError> {
        self.check_cap(cap)?;
        let p = &self.plan;
        let shapes = p.protocol.table_shapes();
        if points.len() != p.protocol.num_openings()
            || proof.evals.len() != points.len()
            || p.protocol
                .iter_openings()
                .enumerate()
                .any(|(i, (table, batch))| {
                    points[i].len() != shapes[table].num_variables()
                        || !batch.has_same_shape(&proof.evals[i])
                })
            || proof.initial_ood_answers.len() != p.initial_ood
            || proof.rounds.len() + 1 != p.sites.len()
            || proof.final_poly.len() != p.final_len
        {
            return Err(invalid(
                "binary WHIR target opening or proof shape mismatch",
            ));
        }
        check_fold(&proof.initial_sumcheck, &p.initial_fold)?;
        for (site, round) in p.sites.iter().zip(&proof.rounds) {
            self.check_cap(&round.cap)?;
            if round.ood_answers.len() != site.ood {
                return Err(invalid("binary WHIR target OOD shape mismatch"));
            }
            check_opening(site, p.cap_height, &round.rows, &round.paths)?;
            check_fold(&round.sumcheck, &site.fold)?;
        }
        let site = p.sites.last().expect("checked final site");
        check_opening(site, p.cap_height, &proof.final_rows, &proof.final_paths)?;
        check_fold(&proof.final_sumcheck, &site.fold)
    }
}

fn expand<P, CF>(
    b: &mut CircuitBuilder<CF>,
    z: &P::ChallengeTarget,
    n: usize,
) -> Vec<P::ChallengeTarget>
where
    CF: Field + Eq + Hash,
    P: BinaryTowerPolicy<CF>,
{
    let mut point = Vec::new();
    let mut power = z.clone();
    for _ in 0..n {
        point.push(power.clone());
        power = P::mul(b, &power, &power);
    }
    point.reverse();
    point
}
fn oriented<T: Clone>(point: &[T], order: VariableOrder) -> Vec<T> {
    if order == VariableOrder::Suffix {
        point.iter().rev().cloned().collect()
    } else {
        point.to_vec()
    }
}
fn check_fold<T>(
    proof: &BinaryWhirSumcheckTargets<T>,
    shape: &FoldShape,
) -> Result<(), VerificationError> {
    if proof.messages.len() != shape.rounds
        || proof.pow_witnesses.len() != if shape.pow_bits > 0 { shape.rounds } else { 0 }
    {
        Err(invalid("binary WHIR target sumcheck shape mismatch"))
    } else {
        Ok(())
    }
}
fn check_opening<T>(
    site: &OracleSite,
    cap: usize,
    rows: &[Vec<T>],
    paths: &[Vec<Vec<ExprId>>],
) -> Result<(), VerificationError> {
    if rows.len() != site.queries.num_queries()
        || rows.iter().any(|row| row.len() != site.width)
        || paths.len() != rows.len()
        || paths.iter().any(|path| {
            path.len() != site.log_height - cap || path.iter().any(|digest| digest.len() != 16)
        })
    {
        Err(invalid("binary WHIR target query opening shape mismatch"))
    } else {
        Ok(())
    }
}

impl BinaryWhirVerifier<BinaryField128> {
    /// Complete authenticated additive WHIR relation over native scalar cells.
    pub fn verify_at_native(
        &self,
        b: &mut CircuitBuilder<BinaryField128>,
        ch: BinaryTower128Challenger,
        cap: &[Vec<ExprId>],
        points: &[Vec<NativeTower128Target>],
        proof: &BinaryWhirProofTargets<NativeTower128Target>,
    ) -> Result<
        (
            Vec<OpeningBatch<NativeTower128Target>>,
            BinaryTower128Challenger,
        ),
        VerificationError,
    > {
        self.verify_at_using::<NativeTower128Relation, NativeBinaryEncoding, BinaryField128>(
            b, ch, cap, points, proof,
        )
    }
}
