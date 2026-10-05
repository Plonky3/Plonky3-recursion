//! Field-neutral released non-hiding additive WHIR relation.
use super::gadgets::{next_eval_using, reduce_sumcheck_using};
use super::verifier::observe_cap_with_host;
use super::whir_gadgets::{eval_coefficients_using, eval_multilinear_using, select_eval_using};
use super::whir_plan::{FoldShape, OracleSite, WhirPlan, invalid};
use super::{BinaryWhirProofTargets, BinaryWhirSumcheckTargets};
use crate::BinaryTower128Challenger;
use crate::verifier::VerificationError;
use crate::verifier::binary_field_policy::{BinaryOracleWord, BinaryWhirPolicy};
use alloc::vec::Vec;
use core::hash::Hash;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::Field;
use p3_sumcheck::{OpeningBatch, strategy::VariableOrder};
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
    mode: BinaryOracleWord,
}

pub(super) fn verify_using<P, H, CF>(
    p: &WhirPlan<P::Base, P::Challenge>,
    b: &mut CircuitBuilder<CF>,
    mut ch: BinaryTower128Challenger,
    cap: &[Vec<ExprId>],
    points: &[Vec<P::ChallengeTarget>],
    proof: &BinaryWhirProofTargets<P::ChallengeTarget, P::BaseTarget>,
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
    P: BinaryWhirPolicy<CF>,
{
    H::check_hash(p.hash)?;
    check_targets(p, cap, points, proof)?;
    b.check_construction_limits()?;
    let mut virtual_points = Vec::new();
    for (seed, answer) in p.virtual_seeds.iter().zip(&proof.initial_ood_answers) {
        P::observe_seed::<H>(b, &mut ch, seed)?;
        let z = P::sample::<H>(b, &mut ch)?;
        virtual_points.push(expand::<P, CF>(b, &z, p.variables)?);
        P::observe::<H>(b, &mut ch, core::slice::from_ref(answer))?;
    }
    for (seed, evals) in p.opening_seeds.iter().zip(&proof.evals) {
        P::observe_seed::<H>(b, &mut ch, seed)?;
        P::observe::<H>(b, &mut ch, evals.current())?;
        P::observe::<H>(b, &mut ch, evals.next())?;
    }
    P::observe_seed::<H>(b, &mut ch, &p.engine_seed)?;
    P::observe_seed::<H>(b, &mut ch, &p.batching_seed)?;
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
                    let selector = &placement.selectors()[column];
                    let selector = (0..selector.num_variables())
                        .rev()
                        .map(|bit| P::constant(b, ((selector.index() >> bit) & 1) as u128))
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
                    b.check_construction_limits()?;
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
        b.check_construction_limits()?;
    }
    let (mut claim, mut last_r) = fold_using::<P, H, CF>(
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
            ood_points.push(expand::<P, CF>(b, &z, site.variables)?);
            P::observe::<H>(b, &mut ch, core::slice::from_ref(answer))?;
        }
        pow_using::<P, H, CF>(b, &mut ch, site.query_pow_bits, &round.pow_witness)?;
        let indices = site.queries.sample_with_host::<H, CF>(b, &mut ch)?;
        let row_r = oriented(&last_r, p.order);
        let folds = round
            .rows
            .iter()
            .map(|row| eval_multilinear_using::<P, CF>(b, row, &row_r))
            .collect::<Result<Vec<_>, _>>()?;
        let query_points = indices
            .iter()
            .map(|index| {
                let point = P::query_point(b, index, site.variables)?;
                b.check_construction_limits()?;
                Ok::<_, VerificationError>(point)
            })
            .collect::<Result<Vec<_>, _>>()?;
        checks.push(Authentication {
            site,
            rows: &round.rows,
            paths: &round.paths,
            cap: previous_cap,
            indices,
            mode: if i == 0 {
                BinaryOracleWord::Base
            } else {
                BinaryOracleWord::Challenge
            },
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
            b.check_construction_limits()?;
        }
        (claim, last_r) = fold_using::<P, H, CF>(
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
    pow_using::<P, H, CF>(b, &mut ch, site.query_pow_bits, &proof.final_pow_witness)?;
    let indices = site.queries.sample_with_host::<H, CF>(b, &mut ch)?;
    let row_r = oriented(&last_r, p.order);
    for (index, row) in indices.iter().zip(&proof.final_rows) {
        let folded = eval_multilinear_using::<P, CF>(b, row, &row_r)?;
        let point = P::query_point(b, index, site.variables)?;
        let expected = eval_coefficients_using::<P, CF>(b, &proof.final_poly, &point)?;
        P::assert_equal(b, &folded, &expected);
        b.check_construction_limits()?;
    }
    checks.push(Authentication {
        site,
        rows: &proof.final_rows,
        paths: &proof.final_paths,
        cap: previous_cap,
        indices,
        mode: if proof.rounds.is_empty() {
            BinaryOracleWord::Base
        } else {
            BinaryOracleWord::Challenge
        },
    });
    let (claim, closing_r) = fold_using::<P, H, CF>(
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
        b.check_construction_limits()?;
    }
    let closing_r = oriented(&closing_r, p.order);
    let final_value = eval_multilinear_using::<P, CF>(b, &proof.final_poly, &closing_r)?;
    let expected = P::mul(b, &weight, &final_value);
    P::assert_equal(b, &claim, &expected);
    for check in checks {
        for ((row, path), index) in check.rows.iter().zip(check.paths).zip(&check.indices) {
            let mut bytes = Vec::new();
            for value in row {
                bytes.extend(P::oracle_bytes::<H>(b, value, check.mode)?);
                b.check_construction_limits()?;
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
            b.check_construction_limits()?;
        }
    }
    Ok((proof.evals.clone(), ch))
}

fn fold_using<P, H, CF>(
    b: &mut CircuitBuilder<CF>,
    ch: &mut BinaryTower128Challenger,
    mut claim: P::ChallengeTarget,
    proof: &BinaryWhirSumcheckTargets<P::ChallengeTarget, P::BaseTarget>,
    shape: &FoldShape,
    seed: &[P::Base],
) -> Result<(P::ChallengeTarget, Vec<P::ChallengeTarget>), VerificationError>
where
    CF: Field + Eq + Hash,
    H: BinaryCircuitHost<CF>,
    P: BinaryWhirPolicy<CF>,
{
    if shape.rounds == 0 {
        return Ok((claim, Vec::new()));
    }
    P::observe_seed::<H>(b, ch, seed)?;
    let mut randomness = Vec::new();
    for (i, [h0, hinf]) in proof.messages.iter().enumerate() {
        P::observe::<H>(b, ch, &[h0.clone(), hinf.clone()])?;
        if shape.pow_bits > 0 {
            pow_using::<P, H, CF>(b, ch, shape.pow_bits, &proof.pow_witnesses[i])?;
        }
        let beta = P::sample::<H>(b, ch)?;
        claim = reduce_sumcheck_using::<P, CF>(b, &claim, h0, hinf, &beta)?;
        randomness.push(beta);
        b.check_construction_limits()?;
    }
    Ok((claim, randomness))
}

fn pow_using<P, H, CF>(
    b: &mut CircuitBuilder<CF>,
    ch: &mut BinaryTower128Challenger,
    bits: usize,
    witness: &P::BaseTarget,
) -> Result<(), VerificationError>
where
    CF: Field + Eq + Hash,
    H: BinaryCircuitHost<CF>,
    P: BinaryWhirPolicy<CF>,
{
    let witness = P::lift(b, witness)?;
    if bits == 0 {
        let zero = P::constant(b, 0)?;
        P::assert_equal(b, &witness, &zero);
    } else {
        let bytes = P::oracle_bytes::<H>(b, &witness, BinaryOracleWord::Base)?;
        ch.observe_bytes_with_host::<H, CF>(b, &bytes)?;
        for bit in ch.sample_bits_with_host::<H, CF>(b, bits)? {
            let difference = b.sub(ExprId::ZERO, bit);
            b.assert_zero(difference);
        }
    }
    Ok(())
}

pub(super) fn check_cap(cap_height: usize, cap: &[Vec<ExprId>]) -> Result<(), VerificationError> {
    if cap.len() != 1usize << cap_height || cap.iter().any(|digest| digest.len() != 16) {
        Err(invalid("binary WHIR cap shape mismatch"))
    } else {
        Ok(())
    }
}
pub(super) fn check_targets<F, E, T, B>(
    p: &WhirPlan<F, E>,
    cap: &[Vec<ExprId>],
    points: &[Vec<T>],
    proof: &BinaryWhirProofTargets<T, B>,
) -> Result<(), VerificationError> {
    check_cap(p.cap_height, cap)?;
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
        check_cap(p.cap_height, &round.cap)?;
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
fn expand<P, CF>(
    b: &mut CircuitBuilder<CF>,
    z: &P::ChallengeTarget,
    n: usize,
) -> Result<Vec<P::ChallengeTarget>, VerificationError>
where
    CF: Field + Eq + Hash,
    P: BinaryWhirPolicy<CF>,
{
    let mut point = Vec::new();
    let mut power = z.clone();
    for _ in 0..n {
        point.push(power.clone());
        power = P::square(b, &power);
        b.check_construction_limits()?;
    }
    point.reverse();
    Ok(point)
}
fn oriented<T: Clone>(point: &[T], order: VariableOrder) -> Vec<T> {
    if order == VariableOrder::Suffix {
        point.iter().rev().cloned().collect()
    } else {
        point.to_vec()
    }
}
fn check_fold<T, B>(
    proof: &BinaryWhirSumcheckTargets<T, B>,
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
