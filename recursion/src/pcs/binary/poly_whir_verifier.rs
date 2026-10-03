//! Complete released Poly64→Poly192 additive WHIR relation.

use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryPoly64Target, BinaryPoly192Target, ByteHash};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_sumcheck::OpeningBatch;
use p3_sumcheck::OpeningProtocol;
use p3_sumcheck::strategy::VariableOrder;
use p3_whir::WhirConfig;

use super::poly_whir_gadgets::{
    assert_equal, constrain_width, observe_seed, observe_values, poly_bytes, poly_whir_query_point,
    poly192_eq_eval, poly192_eval_coefficients, poly192_eval_multilinear, poly192_next_eval,
    poly192_reduce_sumcheck_claim, poly192_select_eval,
};
use super::verifier::observe_cap;
use super::whir_plan::{FoldShape, OracleSite, WhirPlan, invalid};
use super::{BinaryPolyWhirProofTargets, BinaryPolyWhirSumcheckTargets};
use crate::BinaryTower128Challenger;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

/// Verifier-owned native domain, schedule, separators and finite input bounds.
/// Supports the released Poly64→Poly192 polynomial-basis additive family
/// with ordinary binary-arity byte Merkle trees. The caller binds
/// the commitment and prescribed opening points to its statement.
#[derive(Clone, Debug)]
pub struct BinaryPolyWhirVerifier {
    pub(super) plan: WhirPlan<Poly64, Poly192>,
}

enum Weight {
    Eq(Vec<BinaryPoly192Target>),
    Next {
        selector: Vec<BinaryPoly192Target>,
        point: Vec<BinaryPoly192Target>,
        selector_last: bool,
    },
    Select(Vec<BinaryPoly192Target>),
}
struct Term {
    variables: usize,
    coefficient: BinaryPoly192Target,
    weight: Weight,
}
struct Authentication<'a> {
    site: &'a OracleSite,
    rows: &'a [Vec<BinaryPoly192Target>],
    paths: &'a [Vec<Vec<ExprId>>],
    cap: Vec<Vec<ExprId>>,
    indices: Vec<Vec<ExprId>>,
    field_bits: usize,
}

impl BinaryPolyWhirVerifier {
    /// Conservative checked input counters retained by the trusted plan.
    pub fn input_resource_usage(&self) -> InputResourceUsage {
        self.plan.usage
    }
    pub fn new<Ch>(
        config: &WhirConfig<Poly192, Poly64, Ch>,
        protocol: OpeningProtocol,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
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
        config: &WhirConfig<Poly192, Poly64, Ch>,
        protocol: OpeningProtocol,
        order: VariableOrder,
        hash: ByteHash,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError>
    where
        Ch: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
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
        observe_seed::<BF, EF>(b, ch, &self.plan.commitment_seed)?;
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
        points: &[Vec<BinaryPoly192Target>],
        proof: &BinaryPolyWhirProofTargets,
    ) -> Result<
        (
            Vec<OpeningBatch<BinaryPoly192Target>>,
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
            observe_seed::<BF, EF>(b, &mut ch, seed)?;
            let z = ch.sample_poly192::<BF, EF>(b)?;
            virtual_points.push(expand(b, &z, p.variables));
            observe_values::<BF, EF>(b, &mut ch, core::slice::from_ref(answer), 192)?;
        }
        for (seed, evals) in p.opening_seeds.iter().zip(&proof.evals) {
            observe_seed::<BF, EF>(b, &mut ch, seed)?;
            observe_values::<BF, EF>(b, &mut ch, evals.current(), 192)?;
            observe_values::<BF, EF>(b, &mut ch, evals.next(), 192)?;
        }
        observe_seed::<BF, EF>(b, &mut ch, &p.engine_seed)?;
        observe_seed::<BF, EF>(b, &mut ch, &p.batching_seed)?;
        let alpha = ch.sample_poly192::<BF, EF>(b)?;
        let mut power = b.binary_poly192_constant([1, 0, 0])?;
        let mut claim = b.binary_poly192_constant([0; 3])?;
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
                            .point::<Poly192>()
                            .iter()
                            .map(|v| {
                                b.binary_poly192_constant(v.coefficients().map(Poly64::to_bits))
                            })
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
                        let value = b.binary_poly192_mul(&power, eval);
                        claim = b.binary_poly192_add(&claim, &value);
                        terms.push(Term {
                            variables: p.variables,
                            coefficient: power.clone(),
                            weight,
                        });
                        power = b.binary_poly192_mul(&power, &alpha);
                    }
                }
                // The table index determines placement order; the prescribed
                // point and values retain their protocol opening indices.
                let _ = table;
            }
        }
        for (point, answer) in virtual_points.into_iter().zip(&proof.initial_ood_answers) {
            let value = b.binary_poly192_mul(&power, answer);
            claim = b.binary_poly192_add(&claim, &value);
            terms.push(Term {
                variables: p.variables,
                coefficient: power.clone(),
                weight: Weight::Eq(point),
            });
            power = b.binary_poly192_mul(&power, &alpha);
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
                let z = ch.sample_poly192::<BF, EF>(b)?;
                ood_points.push(expand(b, &z, site.variables));
                observe_values::<BF, EF>(b, &mut ch, core::slice::from_ref(answer), 192)?;
            }
            self.pow::<BF, EF>(b, &mut ch, site.query_pow_bits, &round.pow_witness)?;
            let indices = site.queries.sample::<BF, EF>(b, &mut ch)?;
            let row_r = oriented(&last_r, p.order);
            let folds = round
                .rows
                .iter()
                .map(|row| poly192_eval_multilinear(b, row, &row_r))
                .collect::<Result<Vec<_>, _>>()?;
            let query_points = indices
                .iter()
                .map(|index| poly_whir_query_point::<EF>(b, index, site.variables))
                .collect::<Result<Vec<_>, _>>()?;
            checks.push(Authentication {
                site,
                rows: &round.rows,
                paths: &round.paths,
                cap: previous_cap,
                indices,
                field_bits: if i == 0 { 64 } else { 192 },
            });
            let gamma = ch.sample_poly192::<BF, EF>(b)?;
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
                let weighted = b.binary_poly192_mul(&power, value);
                claim = b.binary_poly192_add(&claim, &weighted);
                terms.push(Term {
                    variables: site.variables,
                    coefficient: power.clone(),
                    weight: if select {
                        Weight::Select(point)
                    } else {
                        Weight::Eq(point)
                    },
                });
                power = b.binary_poly192_mul(&power, &gamma);
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
        observe_values::<BF, EF>(b, &mut ch, &proof.final_poly, 192)?;
        let site = p.sites.last().expect("checked final site");
        self.pow::<BF, EF>(b, &mut ch, site.query_pow_bits, &proof.final_pow_witness)?;
        let indices = site.queries.sample::<BF, EF>(b, &mut ch)?;
        let row_r = oriented(&last_r, p.order);
        for (index, row) in indices.iter().zip(&proof.final_rows) {
            let folded = poly192_eval_multilinear(b, row, &row_r)?;
            let point = poly_whir_query_point::<EF>(b, index, site.variables)?;
            let expected = poly192_eval_coefficients(b, &proof.final_poly, &point)?;
            assert_equal(b, &folded, &expected);
        }
        checks.push(Authentication {
            site,
            rows: &proof.final_rows,
            paths: &proof.final_paths,
            cap: previous_cap,
            indices,
            field_bits: if proof.rounds.is_empty() { 64 } else { 192 },
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
        let mut weight = b.binary_poly192_constant([0; 3])?;
        for term in terms {
            let row = oriented(&all_r[all_r.len() - term.variables..], p.order);
            let value = match term.weight {
                Weight::Eq(point) => poly192_eq_eval(b, &point, &row)?,
                Weight::Select(point) => poly192_select_eval(b, &point, &row)?,
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
                    let selector_weight = poly192_eq_eval(b, &selector, selector_row)?;
                    let next_weight = poly192_next_eval(b, &point, local_row)?;
                    b.binary_poly192_mul(&selector_weight, &next_weight)
                }
            };
            let scaled = b.binary_poly192_mul(&term.coefficient, &value);
            weight = b.binary_poly192_add(&weight, &scaled);
        }
        let closing_r = oriented(&closing_r, p.order);
        let final_value = poly192_eval_multilinear(b, &proof.final_poly, &closing_r)?;
        let expected = b.binary_poly192_mul(&weight, &final_value);
        assert_equal(b, &claim, &expected);
        for check in checks {
            for ((row, path), index) in check.rows.iter().zip(check.paths).zip(&check.indices) {
                let mut bytes = Vec::new();
                for value in row {
                    constrain_width(b, value, check.field_bits);
                    bytes.extend(poly_bytes::<BF, EF>(b, value, check.field_bits)?);
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
        mut claim: BinaryPoly192Target,
        proof: &BinaryPolyWhirSumcheckTargets,
        shape: &FoldShape,
        seed: &[Poly64],
    ) -> Result<(BinaryPoly192Target, Vec<BinaryPoly192Target>), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        if shape.rounds == 0 {
            return Ok((claim, Vec::new()));
        }
        observe_seed::<BF, EF>(b, ch, seed)?;
        let mut randomness = Vec::new();
        for (i, [h0, hinf]) in proof.messages.iter().enumerate() {
            observe_values::<BF, EF>(b, ch, &[h0.clone(), hinf.clone()], 192)?;
            if shape.pow_bits > 0 {
                self.pow::<BF, EF>(b, ch, shape.pow_bits, &proof.pow_witnesses[i])?;
            }
            let beta = ch.sample_poly192::<BF, EF>(b)?;
            claim = poly192_reduce_sumcheck_claim(b, &claim, h0, hinf, &beta)?;
            randomness.push(beta);
        }
        Ok((claim, randomness))
    }

    fn pow<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: &mut BinaryTower128Challenger,
        bits: usize,
        witness: &BinaryPoly64Target,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        if bits == 0 {
            for &bit in witness.bits() {
                let difference = b.sub(ExprId::ZERO, bit);
                b.assert_zero(difference);
            }
        } else {
            ch.observe_poly64::<BF, EF>(b, witness)?;
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
    pub(crate) fn check_targets(
        &self,
        cap: &[Vec<ExprId>],
        points: &[Vec<BinaryPoly192Target>],
        proof: &BinaryPolyWhirProofTargets,
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
    z: &BinaryPoly192Target,
    n: usize,
) -> Vec<BinaryPoly192Target> {
    let mut point = Vec::new();
    let mut power = z.clone();
    for _ in 0..n {
        point.push(power.clone());
        power = b.binary_poly192_square(&power);
    }
    point.reverse();
    point
}
fn oriented(point: &[BinaryPoly192Target], order: VariableOrder) -> Vec<BinaryPoly192Target> {
    if order == VariableOrder::Suffix {
        point.iter().rev().cloned().collect()
    } else {
        point.to_vec()
    }
}
fn check_fold(
    proof: &BinaryPolyWhirSumcheckTargets,
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
    rows: &[Vec<BinaryPoly192Target>],
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
