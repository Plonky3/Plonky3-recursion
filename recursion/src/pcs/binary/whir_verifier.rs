//! Full released non-hiding additive WHIR relation for tower alphabets.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_sumcheck::OpeningBatch;
use p3_sumcheck::OpeningProtocol;
use p3_sumcheck::strategy::VariableOrder;
use p3_whir::WhirConfig;

use super::verifier::{
    assert_equal, constrain_width, observe_cap, observe_seed, observe_values, tower_bytes,
};
use super::whir_plan::{FoldShape, OracleSite, WhirPlan, invalid};
use super::{
    BinaryWhirProofTargets, BinaryWhirSumcheckTargets, RecursiveBinaryWhirTowerField,
    binary_whir_query_point, binary128_eq_eval, binary128_eval_coefficients,
    binary128_eval_multilinear, binary128_next_eval, binary128_reduce_sumcheck_claim,
    binary128_select_eval,
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

enum Weight {
    Eq(Vec<BinaryTower128Target>),
    Next {
        selector: Vec<BinaryTower128Target>,
        point: Vec<BinaryTower128Target>,
        selector_last: bool,
    },
    Select(Vec<BinaryTower128Target>),
}
struct Term {
    variables: usize,
    coefficient: BinaryTower128Target,
    weight: Weight,
}
struct Authentication<'a> {
    site: &'a OracleSite,
    rows: &'a [Vec<BinaryTower128Target>],
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
        self.check_cap(cap)?;
        observe_seed::<F, BF, EF>(b, ch, &self.plan.commitment_seed)?;
        observe_cap::<BF, EF>(b, ch, cap)
    }

    /// Replays the complete native PCS adapter and WHIR engine. Every query
    /// authenticates its full row, every sumcheck uses its phase separator,
    /// and the terminal constraint binds all opening, OOD and selector claims.
    /// The fixed stratified query schedule returns an exact ordinary challenger.
    pub fn verify_at<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        mut ch: BinaryTower128Challenger,
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
        self.check_targets(cap, points, proof)?;
        let p = &self.plan;
        let mut virtual_points = Vec::new();
        for (seed, answer) in p.virtual_seeds.iter().zip(&proof.initial_ood_answers) {
            observe_seed::<F, BF, EF>(b, &mut ch, seed)?;
            let z = ch.sample::<BF, EF>(b)?;
            virtual_points.push(expand(b, &z, p.variables));
            observe_values::<BF, EF>(b, &mut ch, core::slice::from_ref(answer), 128)?;
        }
        for (seed, evals) in p.opening_seeds.iter().zip(&proof.evals) {
            observe_seed::<F, BF, EF>(b, &mut ch, seed)?;
            observe_values::<BF, EF>(b, &mut ch, evals.current(), 128)?;
            observe_values::<BF, EF>(b, &mut ch, evals.next(), 128)?;
        }
        observe_seed::<F, BF, EF>(b, &mut ch, &p.engine_seed)?;
        observe_seed::<F, BF, EF>(b, &mut ch, &p.batching_seed)?;
        let alpha = ch.sample::<BF, EF>(b)?;
        let mut power = b.binary128_constant(1)?;
        let mut claim = b.binary128_constant(0)?;
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
                            .map(|v| b.binary128_constant(v.to_repr()))
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
                        let value = b.binary128_mul(&power, eval);
                        claim = b.binary128_add(&claim, &value);
                        terms.push(Term {
                            variables: p.variables,
                            coefficient: power.clone(),
                            weight,
                        });
                        power = b.binary128_mul(&power, &alpha);
                    }
                }
                // The table index determines placement order; the prescribed
                // point and values retain their protocol opening indices.
                let _ = table;
            }
        }
        for (point, answer) in virtual_points.into_iter().zip(&proof.initial_ood_answers) {
            let value = b.binary128_mul(&power, answer);
            claim = b.binary128_add(&claim, &value);
            terms.push(Term {
                variables: p.variables,
                coefficient: power.clone(),
                weight: Weight::Eq(point),
            });
            power = b.binary128_mul(&power, &alpha);
        }
        let (mut claim, mut last_r) = self.fold::<BF, EF>(
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
            observe_cap::<BF, EF>(b, &mut ch, &round.cap)?;
            let mut ood_points = Vec::new();
            for answer in &round.ood_answers {
                let z = ch.sample::<BF, EF>(b)?;
                ood_points.push(expand(b, &z, site.variables));
                observe_values::<BF, EF>(b, &mut ch, core::slice::from_ref(answer), 128)?;
            }
            self.pow::<BF, EF>(b, &mut ch, site.query_pow_bits, &round.pow_witness)?;
            let indices = site.queries.sample::<BF, EF>(b, &mut ch)?;
            let row_r = oriented(&last_r, p.order);
            let folds = round
                .rows
                .iter()
                .map(|row| binary128_eval_multilinear(b, row, &row_r))
                .collect::<Result<Vec<_>, _>>()?;
            let query_points = indices
                .iter()
                .map(|index| binary_whir_query_point::<F, EF>(b, index, site.variables))
                .collect::<Result<Vec<_>, _>>()?;
            checks.push(Authentication {
                site,
                rows: &round.rows,
                paths: &round.paths,
                cap: previous_cap,
                indices,
                field_bits: if i == 0 { F::RAW_BITS } else { 128 },
            });
            let gamma = ch.sample::<BF, EF>(b)?;
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
                let weighted = b.binary128_mul(&power, value);
                claim = b.binary128_add(&claim, &weighted);
                terms.push(Term {
                    variables: site.variables,
                    coefficient: power.clone(),
                    weight: if select {
                        Weight::Select(point)
                    } else {
                        Weight::Eq(point)
                    },
                });
                power = b.binary128_mul(&power, &gamma);
            }
            (claim, last_r) = self.fold::<BF, EF>(
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
        observe_values::<BF, EF>(b, &mut ch, &proof.final_poly, 128)?;
        let site = p.sites.last().expect("checked final site");
        self.pow::<BF, EF>(b, &mut ch, site.query_pow_bits, &proof.final_pow_witness)?;
        let indices = site.queries.sample::<BF, EF>(b, &mut ch)?;
        let row_r = oriented(&last_r, p.order);
        for (index, row) in indices.iter().zip(&proof.final_rows) {
            let folded = binary128_eval_multilinear(b, row, &row_r)?;
            let point = binary_whir_query_point::<F, EF>(b, index, site.variables)?;
            let expected = binary128_eval_coefficients(b, &proof.final_poly, &point)?;
            assert_equal(b, &folded, &expected);
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
        let (claim, closing_r) = self.fold::<BF, EF>(
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
        let mut weight = b.binary128_constant(0)?;
        for term in terms {
            let row = oriented(&all_r[all_r.len() - term.variables..], p.order);
            let value = match term.weight {
                Weight::Eq(point) => binary128_eq_eval(b, &point, &row)?,
                Weight::Select(point) => binary128_select_eval(b, &point, &row)?,
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
                    let selector_weight = binary128_eq_eval(b, &selector, selector_row)?;
                    let next_weight = binary128_next_eval(b, &point, local_row)?;
                    b.binary128_mul(&selector_weight, &next_weight)
                }
            };
            let scaled = b.binary128_mul(&term.coefficient, &value);
            weight = b.binary128_add(&weight, &scaled);
        }
        let closing_r = oriented(&closing_r, p.order);
        let final_value = binary128_eval_multilinear(b, &proof.final_poly, &closing_r)?;
        let expected = b.binary128_mul(&weight, &final_value);
        assert_equal(b, &claim, &expected);
        for check in checks {
            for ((row, path), index) in check.rows.iter().zip(check.paths).zip(&check.indices) {
                let mut bytes = Vec::new();
                for value in row {
                    constrain_width(b, value, check.field_bits);
                    bytes.extend(tower_bytes::<BF, EF>(b, value, check.field_bits)?);
                }
                for &limb in path.iter().flatten() {
                    b.decompose_to_bits::<BF>(limb, 16)?;
                }
                b.verify_byte_hash_mmcs_opening_bytes::<BF>(
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

    fn fold<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        mut claim: BinaryTower128Target,
        proof: &BinaryWhirSumcheckTargets,
        shape: &FoldShape,
        seed: &[F],
    ) -> Result<(BinaryTower128Target, Vec<BinaryTower128Target>), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        if shape.rounds == 0 {
            return Ok((claim, Vec::new()));
        }
        observe_seed::<F, BF, EF>(b, ch, seed)?;
        let mut randomness = Vec::new();
        for (i, [h0, hinf]) in proof.messages.iter().enumerate() {
            observe_values::<BF, EF>(b, ch, &[h0.clone(), hinf.clone()], 128)?;
            if shape.pow_bits > 0 {
                self.pow::<BF, EF>(b, ch, shape.pow_bits, &proof.pow_witnesses[i])?;
            }
            let beta = ch.sample::<BF, EF>(b)?;
            claim = binary128_reduce_sumcheck_claim(b, &claim, h0, hinf, &beta)?;
            randomness.push(beta);
        }
        Ok((claim, randomness))
    }

    fn pow<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        bits: usize,
        witness: &BinaryTower128Target,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        constrain_width(b, witness, F::RAW_BITS);
        if bits == 0 {
            let zero = b.binary128_constant(0)?;
            assert_equal(b, witness, &zero);
        } else {
            observe_values::<BF, EF>(b, ch, core::slice::from_ref(witness), F::RAW_BITS)?;
            for bit in ch.sample_bits::<BF, EF>(b, bits)? {
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
    pub(super) fn check_targets(
        &self,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryTower128Target>],
        proof: &BinaryWhirProofTargets,
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

fn expand<EF: Field + Eq + Hash>(
    b: &mut CircuitBuilder<EF>,
    z: &BinaryTower128Target,
    n: usize,
) -> Vec<BinaryTower128Target> {
    let mut point = Vec::new();
    let mut power = z.clone();
    for _ in 0..n {
        point.push(power.clone());
        power = b.binary128_square(&power);
    }
    point.reverse();
    point
}
fn oriented(point: &[BinaryTower128Target], order: VariableOrder) -> Vec<BinaryTower128Target> {
    if order == VariableOrder::Suffix {
        point.iter().rev().cloned().collect()
    } else {
        point.to_vec()
    }
}
fn check_fold(
    proof: &BinaryWhirSumcheckTargets,
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
fn check_opening(
    site: &OracleSite,
    cap: usize,
    rows: &[Vec<BinaryTower128Target>],
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
