//! Field-neutral released non-hiding additive WHIR relation.
use alloc::vec::Vec;
use core::hash::Hash;

use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::Field;
use p3_sumcheck::strategy::VariableOrder;
use p3_util::reverse_bits_len;

use super::gadgets::{next_eval_using, reduce_sumcheck_using};
use super::verifier::observe_cap_with_host;
use super::whir_gadgets::{
    Powers, eval_coefficients_using, eval_multilinear_using, eval_power_table_using,
    select_eval_using,
};
use super::whir_plan::{FoldShape, OracleSite, WhirPlan, invalid};
use super::{BinaryWhirProofTargets, BinaryWhirSumcheckTargets, MerkleArity};
use crate::BinaryTower128Challenger;
use crate::verifier::VerificationError;
use crate::verifier::binary_field_policy::{BinaryOracleWord, BinaryWhirPolicy};
enum Weight<T> {
    Eq(Vec<T>),
    Select(Vec<T>),
}
/// Terms of the initial claim that take consecutive powers of the batching
/// challenge `alpha`.
enum Batched<T> {
    /// Columns of one opening and kind. A column at selector slot `c` has
    /// weight `eq(c, r_sel) * w(point, r_x)`, with `w` the equality or the
    /// successor weight, so the group's weight is `w(point, r_x)` times the
    /// slot table of `alpha^k` at the `k`-th column's slot.
    Columns {
        point: Vec<T>,
        next: bool,
        selector_variables: usize,
        /// Each column's selector slot, bit-reversed under prefix order to
        /// match the reversed selector coordinates it is folded against.
        slots: Vec<usize>,
    },
    /// An initial out-of-domain point over every variable.
    Point(Vec<T>),
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
) -> Result<super::WhirVerificationOutput<P::ChallengeTarget>, VerificationError>
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
    let mut values = Vec::new();
    let mut batched = Vec::new();
    for placement in &p.placements {
        for (opening, (table, request)) in p
            .protocol
            .iter_openings()
            .enumerate()
            .filter(|(_, (table, _))| *table == placement.idx())
        {
            let point = &points[opening];
            let selector_variables = p.variables.checked_sub(point.len()).ok_or_else(|| {
                invalid("binary WHIR opening point exceeds the committed variables")
            })?;
            for (next, columns, evals) in [
                (false, request.current(), proof.evals[opening].current()),
                (true, request.next(), proof.evals[opening].next()),
            ] {
                let mut slots = Vec::with_capacity(columns.len());
                for (&column, eval) in columns.iter().zip(evals) {
                    let selector = &placement.selectors()[column];
                    if selector.num_variables() != selector_variables {
                        return Err(invalid(
                            "binary WHIR selector does not complete the opening point",
                        ));
                    }
                    // Prefix order stores bit-reversed slots; the reversed
                    // slot against the reversed selector coordinates is the
                    // same weight and keeps consecutive columns adjacent.
                    slots.push(if p.order == VariableOrder::Prefix {
                        reverse_bits_len(selector.index(), selector_variables)
                    } else {
                        selector.index()
                    });
                    values.push(eval.clone());
                }
                if !slots.is_empty() {
                    batched.push(Batched::Columns {
                        point: point.clone(),
                        next,
                        selector_variables,
                        slots,
                    });
                }
                b.check_construction_limits()?;
            }
            // The table index determines placement order; the prescribed
            // point and values retain their protocol opening indices.
            let _ = table;
        }
    }
    for (point, answer) in virtual_points.into_iter().zip(&proof.initial_ood_answers) {
        values.push(answer.clone());
        batched.push(Batched::Point(point));
    }
    let claim = horner_using::<P, CF>(b, &values, &alpha)?;
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
    let mut terms = Vec::new();
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
            claim = P::mul_add(b, &power, value, &claim);
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
    let mut weight = batched_weight_using::<P, CF>(b, p.order, batched, &all_r, &alpha)?;
    for term in terms {
        let row = oriented(&all_r[all_r.len() - term.variables..], p.order);
        let value = match term.weight {
            Weight::Eq(point) => P::eq_eval(b, &point, &row)?,
            Weight::Select(point) => select_eval_using::<P, CF>(b, &point, &row)?,
        };
        weight = P::mul_add(b, &term.coefficient, &value, &weight);
        b.check_construction_limits()?;
    }
    let closing_r = oriented(&closing_r, p.order);
    let final_value = eval_multilinear_using::<P, CF>(b, &proof.final_poly, &closing_r)?;
    let expected = P::mul(b, &weight, &final_value);
    P::assert_equal(b, &claim, &expected);
    for check in checks {
        for ((row, path), index) in check.rows.iter().zip(check.paths).zip(&check.indices) {
            // Every value of a row shares one width, so either all of them
            // split into words or none does.
            let words = row
                .iter()
                .map(|value| P::oracle_words(b, value, check.mode))
                .collect::<Result<Option<Vec<_>>, _>>()?;
            let mut bytes = Vec::new();
            if words.is_none() {
                for value in row {
                    bytes.extend(P::oracle_bytes::<H>(b, value, check.mode)?);
                    b.check_construction_limits()?;
                }
            }
            for sibling in path {
                H::constrain_sibling(b, sibling)?;
            }
            let heights = [1usize << check.site.log_height];
            let (hash, cap) = (p.hash, &check.cap);
            match (words, p.arity) {
                (Some(words), MerkleArity::Two) => b
                    .verify_byte_hash_mmcs_opening_words_with_host::<H>(
                        hash,
                        &[words.concat()],
                        &heights,
                        index,
                        path,
                        cap,
                    )?,
                (Some(words), MerkleArity::Four) => b
                    .verify_byte_hash_mmcs_opening_words_with_host_arity::<H, 4>(
                        hash,
                        &[words.concat()],
                        &heights,
                        index,
                        path,
                        cap,
                    )?,
                (None, MerkleArity::Two) => b.verify_byte_hash_mmcs_opening_bytes_with_host::<H>(
                    hash,
                    &[bytes],
                    &heights,
                    index,
                    path,
                    cap,
                )?,
                (None, MerkleArity::Four) => b
                    .verify_byte_hash_mmcs_opening_bytes_with_host_arity::<H, 4>(
                        hash,
                        &[bytes],
                        &heights,
                        index,
                        path,
                        cap,
                    )?,
            }
            b.check_construction_limits()?;
        }
    }
    Ok((proof.evals.clone(), ch))
}

/// `sum_i x^i * values[i]`, accumulated from the last value.
fn horner_using<P, CF>(
    b: &mut CircuitBuilder<CF>,
    values: &[P::ChallengeTarget],
    x: &P::ChallengeTarget,
) -> Result<P::ChallengeTarget, VerificationError>
where
    CF: Field + Eq + Hash,
    P: BinaryWhirPolicy<CF>,
{
    let mut values = values.iter().rev();
    let Some(last) = values.next() else {
        return Ok(P::constant(b, 0)?);
    };
    let mut sum = last.clone();
    for value in values {
        sum = P::mul_add(b, &sum, x, value);
        b.check_construction_limits()?;
    }
    Ok(sum)
}

/// The weight of the initial claim at the folded point `all_r`: every
/// batched item's weight times `alpha` to the number of columns before it,
/// accumulated from the last item.
fn batched_weight_using<P, CF>(
    b: &mut CircuitBuilder<CF>,
    order: VariableOrder,
    batched: Vec<Batched<P::ChallengeTarget>>,
    all_r: &[P::ChallengeTarget],
    alpha: &P::ChallengeTarget,
) -> Result<P::ChallengeTarget, VerificationError>
where
    CF: Field + Eq + Hash,
    P: BinaryWhirPolicy<CF>,
{
    let row = oriented(all_r, order);
    let mut powers = Powers::new::<P, CF>(b, alpha)?;
    let mut sum = None;
    for item in batched.into_iter().rev() {
        let (value, count) = match item {
            Batched::Columns {
                point,
                next,
                selector_variables,
                slots,
            } => {
                let (selector_row, local_row) = if order == VariableOrder::Prefix {
                    let (local, selector) = row.split_at(point.len());
                    (selector.iter().rev().cloned().collect::<Vec<_>>(), local)
                } else {
                    let (selector, local) = row.split_at(selector_variables);
                    (selector.to_vec(), local)
                };
                let local = if next {
                    next_eval_using::<P, CF>(b, &point, local_row)?
                } else {
                    P::eq_eval(b, &point, local_row)?
                };
                let selectors =
                    eval_power_table_using::<P, CF>(b, &slots, &selector_row, &mut powers)?;
                (P::mul(b, &selectors, &local), slots.len())
            }
            Batched::Point(point) => (P::eq_eval(b, &point, &row)?, 1),
        };
        sum = Some(match sum {
            None => value,
            Some(later) => {
                let shift = powers.get::<P, CF>(b, count);
                P::mul_add(b, &shift, &later, &value)
            }
        });
        b.check_construction_limits()?;
    }
    match sum {
        Some(sum) => Ok(sum),
        None => Ok(P::constant(b, 0)?),
    }
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
        // The refill of the draw that follows range-checks each word.
        let words = if H::hashes_words_whole(ch.hash()) {
            P::oracle_words(b, &witness, BinaryOracleWord::Base)?
        } else {
            None
        };
        if let Some(words) = words {
            ch.observe_words_with_host::<H, CF>(b, &words)?;
        } else {
            let bytes = P::oracle_bytes::<H>(b, &witness, BinaryOracleWord::Base)?;
            ch.observe_bytes_with_host::<H, CF>(b, &bytes)?;
        }
        for bit in ch.sample_bits_with_host::<H, CF>(b, bits)? {
            let difference = b.sub(ExprId::ZERO, bit);
            b.assert_zero(difference);
        }
    }
    Ok(())
}

pub(super) fn check_cap(roots: usize, cap: &[Vec<ExprId>]) -> Result<(), VerificationError> {
    if cap.len() != roots || cap.iter().any(|digest| digest.len() != 16) {
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
    check_cap(p.cap_roots, cap)?;
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
        check_cap(p.cap_roots, &round.cap)?;
        if round.ood_answers.len() != site.ood {
            return Err(invalid("binary WHIR target OOD shape mismatch"));
        }
        check_opening(site, &round.rows, &round.paths)?;
        check_fold(&round.sumcheck, &site.fold)?;
    }
    let site = p.sites.last().expect("checked final site");
    check_opening(site, &proof.final_rows, &proof.final_paths)?;
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
    rows: &[Vec<T>],
    paths: &[Vec<Vec<ExprId>>],
) -> Result<(), VerificationError> {
    if rows.len() != site.queries.num_queries()
        || rows.iter().any(|row| row.len() != site.width)
        || paths.len() != rows.len()
        || paths
            .iter()
            .any(|path| path.len() != site.path_len || path.iter().any(|digest| digest.len() != 16))
    {
        Err(invalid("binary WHIR target query opening shape mismatch"))
    } else {
        Ok(())
    }
}
