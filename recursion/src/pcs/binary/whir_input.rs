//! Fixed allocation and bounded public-API import of additive WHIR witnesses.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash, bytes_to_limbs};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, PackedValue, PrimeCharacteristicRing, PrimeField64,
};
use p3_matrix::Dimensions;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::{LayoutStrategy, Verifier};
use p3_sumcheck::strategy::{Basis, VariableOrder};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, SumcheckData};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use p3_whir::WhirConfig;
use p3_whir::pcs::proof::{PcsProof, QueryOpenings};
use p3_whir::transcript::{WhirShape, WhirVerifierTranscript};

use super::whir_plan::{FoldShape, OracleSite, invalid};
use super::{BinaryWhirVerifier, RecursiveBinaryWhirTowerField};
use crate::transcript::domain_separator_seed;
use crate::verifier::{InputResourceUsage, VerificationError};

#[derive(Clone, Debug)]
pub struct BinaryWhirSumcheckTargets {
    pub messages: Vec<[BinaryTower128Target; 2]>,
    pub pow_witnesses: Vec<BinaryTower128Target>,
}

#[derive(Clone, Debug)]
pub struct BinaryWhirRoundTargets {
    pub cap: Vec<Vec<ExprId>>,
    pub ood_answers: Vec<BinaryTower128Target>,
    pub pow_witness: BinaryTower128Target,
    pub rows: Vec<Vec<BinaryTower128Target>>,
    pub paths: Vec<Vec<Vec<ExprId>>>,
    pub sumcheck: BinaryWhirSumcheckTargets,
}

#[derive(Clone, Debug)]
pub struct BinaryWhirProofTargets {
    pub evals: Vec<OpeningBatch<BinaryTower128Target>>,
    pub initial_ood_answers: Vec<BinaryTower128Target>,
    pub initial_sumcheck: BinaryWhirSumcheckTargets,
    pub rounds: Vec<BinaryWhirRoundTargets>,
    pub final_poly: Vec<BinaryTower128Target>,
    pub final_pow_witness: BinaryTower128Target,
    pub final_rows: Vec<Vec<BinaryTower128Target>>,
    pub final_paths: Vec<Vec<Vec<ExprId>>>,
    pub final_sumcheck: BinaryWhirSumcheckTargets,
}

/// Exact trusted contract, including native configuration seed and the whole
/// opening schedule. Query indices are derived in-circuit, not allocated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryWhirInputShape<F> {
    contract: Vec<F>,
    protocol: OpeningProtocol,
    order: VariableOrder,
    hash: ByteHash,
    cap_height: usize,
    initial_ood: usize,
    initial_fold: FoldShape,
    sites: Vec<OracleSite>,
    final_len: usize,
}

impl<F: RecursiveBinaryWhirTowerField> BinaryWhirInputShape<F> {
    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryWhirProofTargets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        let evals = self
            .protocol
            .iter_openings()
            .map(|(_, batch)| {
                Ok(OpeningBatch::new(
                    fields::<BF, EF>(b, batch.current().len())?,
                    fields::<BF, EF>(b, batch.next().len())?,
                ))
            })
            .collect::<Result<_, VerificationError>>()?;
        let initial_ood_answers = fields::<BF, EF>(b, self.initial_ood)?;
        let initial_sumcheck = fold::<BF, EF>(b, &self.initial_fold)?;
        let mut rounds = Vec::new();
        for site in self.sites.iter().take(self.sites.len() - 1) {
            let cap = (0..1usize << self.cap_height)
                .map(|_| b.alloc_private_input_array::<16>("WHIR round cap").to_vec())
                .collect();
            let ood_answers = fields::<BF, EF>(b, site.ood)?;
            let pow_witness = field::<BF, EF>(b)?;
            let (rows, paths) = opening::<BF, EF>(b, site, self.cap_height)?;
            let sumcheck = fold::<BF, EF>(b, &site.fold)?;
            rounds.push(BinaryWhirRoundTargets {
                cap,
                ood_answers,
                pow_witness,
                rows,
                paths,
                sumcheck,
            });
        }
        let final_poly = fields::<BF, EF>(b, self.final_len)?;
        let final_pow_witness = field::<BF, EF>(b)?;
        let site = self
            .sites
            .last()
            .expect("a checked WHIR plan has a final query site");
        let (final_rows, final_paths) = opening::<BF, EF>(b, site, self.cap_height)?;
        let final_sumcheck = fold::<BF, EF>(b, &site.fold)?;
        Ok(BinaryWhirProofTargets {
            evals,
            initial_ood_answers,
            initial_sumcheck,
            rounds,
            final_poly,
            final_pow_witness,
            final_rows,
            final_paths,
            final_sumcheck,
        })
    }
}

/// Witness extraction alone is not verification. The recursive relation must
/// authenticate every restored row/path and close every sumcheck constraint.
#[derive(Clone, Debug)]
pub struct NativeBinaryWhirInput<F> {
    shape: BinaryWhirInputShape<F>,
    limbs: Vec<u16>,
}
impl<F: RecursiveBinaryWhirTowerField> NativeBinaryWhirInput<F> {
    pub fn shape(&self) -> &BinaryWhirInputShape<F> {
        &self.shape
    }
    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryWhirInputShape<F>,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary WHIR input belongs to a different verifier"));
        }
        Ok(self.limbs.iter().copied().map(EF::from_u16).collect())
    }
}

impl<F> BinaryWhirVerifier<F>
where
    F: RecursiveBinaryWhirTowerField,
    BinaryField128: ExtensionField<F>,
{
    pub fn input_shape(&self) -> BinaryWhirInputShape<F> {
        let p = &self.plan;
        BinaryWhirInputShape {
            contract: p.engine_seed.clone(),
            protocol: p.protocol.clone(),
            order: p.order,
            hash: p.hash,
            cap_height: p.cap_height,
            initial_ood: p.initial_ood,
            initial_fold: p.initial_fold.clone(),
            sites: p.sites.clone(),
            final_len: p.final_len,
        }
    }

    pub(super) fn check_native<C, H, Co>(
        &self,
        config: &WhirConfig<BinaryField128, F, C>,
        mmcs: &MerkleTreeMmcs<F, u8, H, Co, 2, 32>,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<BinaryField128>],
        proof: &PcsProof<F, BinaryField128, MerkleTreeMmcs<F, u8, H, Co, 2, 32>>,
    ) -> Result<(), VerificationError>
    where
        F: PackedValue<Value = F>,
        H: CryptographicHasher<F, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let p = &self.plan;
        let shape = WhirShape::new(config, p.protocol.num_openings());
        if domain_separator_seed(&shape.domain_separator::<F, BinaryField128>()) != p.engine_seed
            || mmcs.cap_height() != p.cap_height
            || commitment.roots().len() != 1usize << p.cap_height
            || proof.evals.len() != p.protocol.num_openings()
            || p.protocol.check_points(points).is_err()
            || p.protocol
                .iter_openings()
                .zip(&proof.evals)
                .any(|((_, batch), evals)| !batch.has_same_shape(evals))
            || proof.whir.initial_ood_answers.len() != p.initial_ood
            || proof.whir.rounds.len() + 1 != p.sites.len()
            || proof
                .whir
                .final_poly
                .as_ref()
                .is_none_or(|poly| poly.as_slice().len() != p.final_len)
        {
            return Err(invalid(
                "binary WHIR native proof, points or configuration shape mismatch",
            ));
        }
        check_fold(&proof.whir.initial_sumcheck, &p.initial_fold)?;
        let last = p.sites.last().expect("checked final site");
        if last.fold.rounds == 0 {
            if proof.whir.final_sumcheck.is_some() {
                return Err(invalid(
                    "binary WHIR zero-round closing proof must be absent",
                ));
            }
        } else {
            check_fold(
                proof
                    .whir
                    .final_sumcheck
                    .as_ref()
                    .ok_or_else(|| invalid("binary WHIR closing sumcheck is missing"))?,
                &last.fold,
            )?;
        }
        let mut usage = InputResourceUsage::default();
        for (i, site) in p.sites.iter().enumerate() {
            let (openings, pow) = if let Some(round) = proof.whir.rounds.get(i) {
                if round
                    .commitment
                    .as_ref()
                    .is_none_or(|cap| cap.roots().len() != 1usize << p.cap_height)
                    || round.ood_answers.len() != site.ood
                {
                    return Err(invalid(
                        "binary WHIR native round commitment or OOD shape mismatch",
                    ));
                }
                check_fold(&round.sumcheck, &site.fold)?;
                (&round.openings, round.pow_witness)
            } else {
                (&proof.whir.final_openings, proof.whir.final_pow_witness)
            };
            if site.query_pow_bits == 0 && pow != F::ZERO {
                return Err(invalid(
                    "binary WHIR disabled query PoW witness must be zero",
                ));
            }
            let frontier = match (openings, i == 0) {
                (QueryOpenings::Base(opening), true) => {
                    if opening.rows.len() != site.queries.num_queries()
                        || opening.rows.iter().any(|row| row.len() != site.width)
                    {
                        return Err(invalid("binary WHIR native base query rows mismatch"));
                    }
                    &opening.proof
                }
                (QueryOpenings::Extension(opening), false) => {
                    if opening.rows.len() != site.queries.num_queries()
                        || opening.rows.iter().any(|row| row.len() != site.width)
                    {
                        return Err(invalid("binary WHIR native extension query rows mismatch"));
                    }
                    &opening.proof
                }
                _ => return Err(invalid("binary WHIR native query field variant mismatch")),
            };
            usage.add_compressed_frontier_hashes(&p.limits, frontier.sibling_hashes.len())?;
        }
        Ok(())
    }

    /// Imports through public native layout, WHIR transcript and byte-tree
    /// restoration APIs. The commitment must already be observed. Passing a
    /// mutable challenger retains its exact native continuation. All visible
    /// shapes and frontier budgets are checked before transcript replay. A
    /// zero-round closing sumcheck must omit the native optional proof slot.
    pub fn import_native<C, Ch, H, Co>(
        &self,
        config: &WhirConfig<BinaryField128, F, C>,
        mmcs: &MerkleTreeMmcs<F, u8, H, Co, 2, 32>,
        commitment: &MerkleCap<F, [u8; 32]>,
        points: &[Point<BinaryField128>],
        proof: &PcsProof<F, BinaryField128, MerkleTreeMmcs<F, u8, H, Co, 2, 32>>,
        mut challenger: Ch,
    ) -> Result<NativeBinaryWhirInput<F>, VerificationError>
    where
        F: PackedValue<Value = F>,
        H: CryptographicHasher<F, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C: FieldChallenger<F> + GrindingChallenger<Witness = F>,
        Ch: FieldChallenger<F>
            + CanSampleUniformBits<F>
            + GrindingChallenger<Witness = F>
            + CanObserve<MerkleCap<F, [u8; 32]>>,
    {
        self.check_native(config, mmcs, commitment, points, proof)?;
        let p = &self.plan;
        let shape = WhirShape::new(config, p.protocol.num_openings());
        let last = p.sites.last().expect("checked final site");
        let strategy = LayoutStrategy::new(p.order == VariableOrder::Prefix, p.order);
        let mut layout = Verifier::<F, BinaryField128>::new(&p.protocol.table_shapes(), strategy);
        for &answer in &proof.whir.initial_ood_answers {
            layout.add_virtual_eval(answer, &mut challenger);
        }
        for (((table, batch), evals), point) in
            p.protocol.iter_openings().zip(&proof.evals).zip(points)
        {
            layout
                .add_claim_at(table, batch, point, evals, &mut challenger)
                .map_err(|_| invalid("binary WHIR native opening replay failed"))?;
        }
        let mut indices = Vec::new();
        let mut transcript =
            WhirVerifierTranscript::<_, F, BinaryField128>::new(&mut challenger, shape);
        let replay = (|| {
            let mut claim = BinaryField128::ZERO;
            let _ = transcript
                .delegate_initial_fold(|ch| {
                    let alpha = layout.batching_challenge(ch);
                    layout.constraint(alpha).combine_evals(&mut claim);
                    proof.whir.initial_sumcheck.verify_rounds(
                        ch,
                        &mut claim,
                        p.initial_fold.rounds,
                        p.initial_fold.pow_bits,
                        Basis::Evaluation,
                    )
                })
                .map_err(|_| invalid("binary WHIR native initial fold replay failed"))?;
            for (i, round) in proof.whir.rounds.iter().enumerate() {
                transcript.commitment(
                    round
                        .commitment
                        .as_ref()
                        .expect("preflight checked commitment")
                        .clone(),
                );
                for &answer in &round.ood_answers {
                    let _ = transcript.ood_point();
                    transcript.ood_answer(answer);
                }
                transcript
                    .query_pow(i, round.pow_witness)
                    .map_err(|_| invalid("binary WHIR native query PoW failed"))?;
                indices.push(transcript.query_indices(i));
                let _ = transcript.round_batching();
                let fold = &p.sites[i].fold;
                let _ = transcript
                    .delegate_round_fold(|ch| {
                        round.sumcheck.verify_rounds(
                            ch,
                            &mut claim,
                            fold.rounds,
                            fold.pow_bits,
                            Basis::Evaluation,
                        )
                    })
                    .map_err(|_| invalid("binary WHIR native round fold replay failed"))?;
            }
            transcript
                .final_poly(
                    proof
                        .whir
                        .final_poly
                        .as_ref()
                        .expect("preflight checked polynomial")
                        .as_slice(),
                )
                .map_err(|_| invalid("binary WHIR native polynomial replay failed"))?;
            transcript
                .query_pow(p.sites.len() - 1, proof.whir.final_pow_witness)
                .map_err(|_| invalid("binary WHIR native final PoW failed"))?;
            indices.push(transcript.query_indices(p.sites.len() - 1));
            if let Some(result) = transcript.delegate_final_fold(|ch| {
                proof
                    .whir
                    .final_sumcheck
                    .as_ref()
                    .expect("preflight checked closing proof")
                    .verify_rounds(
                        ch,
                        &mut claim,
                        last.fold.rounds,
                        last.fold.pow_bits,
                        Basis::Evaluation,
                    )
            }) {
                let _ =
                    result.map_err(|_| invalid("binary WHIR native closing fold replay failed"))?;
            }
            Ok::<_, VerificationError>(())
        })();
        if let Err(error) = replay {
            transcript.abort();
            return Err(error);
        }
        transcript.finish();
        let mut limbs = Vec::new();
        for evals in &proof.evals {
            for &v in evals.current().iter().chain(evals.next()) {
                push(&mut limbs, v.to_repr());
            }
        }
        for &v in &proof.whir.initial_ood_answers {
            push(&mut limbs, v.to_repr());
        }
        push_fold(&mut limbs, &proof.whir.initial_sumcheck);
        for (i, site) in p.sites.iter().enumerate() {
            let openings = if let Some(round) = proof.whir.rounds.get(i) {
                for digest in round
                    .commitment
                    .as_ref()
                    .expect("checked commitment")
                    .roots()
                {
                    limbs.extend(bytes_to_limbs(digest));
                }
                for &v in &round.ood_answers {
                    push(&mut limbs, v.to_repr());
                }
                push(&mut limbs, round.pow_witness.raw_coordinates());
                &round.openings
            } else {
                for &v in proof
                    .whir
                    .final_poly
                    .as_ref()
                    .expect("checked final polynomial")
                    .as_slice()
                {
                    push(&mut limbs, v.to_repr());
                }
                push(&mut limbs, proof.whir.final_pow_witness.raw_coordinates());
                &proof.whir.final_openings
            };
            let (rows, frontier, degree) = match openings {
                QueryOpenings::Base(opening) => {
                    for &v in opening.rows.iter().flatten() {
                        push(&mut limbs, v.raw_coordinates());
                    }
                    (opening.rows.clone(), &opening.proof, 1)
                }
                QueryOpenings::Extension(opening) => {
                    for &v in opening.rows.iter().flatten() {
                        push(&mut limbs, v.to_repr());
                    }
                    (
                        opening
                            .rows
                            .iter()
                            .map(|row| {
                                row.iter()
                                    .flat_map(|v| v.as_basis_coefficients_slice().iter().copied())
                                    .collect()
                            })
                            .collect(),
                        &opening.proof,
                        <BinaryField128 as BasedVectorSpace<F>>::DIMENSION,
                    )
                }
            };
            let dimensions = [Dimensions {
                width: site.width * degree,
                height: 1usize << site.log_height,
            }];
            let values = rows
                .iter()
                .map(|row| vec![row.as_slice()])
                .collect::<Vec<_>>();
            let paths = mmcs
                .restore_and_recompute_paths(&dimensions, &indices[i], &values, frontier)
                .map_err(|_| invalid("binary WHIR native path restoration failed"))?;
            if paths.len() != indices[i].len() {
                return Err(invalid("binary WHIR restored path count mismatch"));
            }
            for (path, &index) in paths.iter().zip(&indices[i]) {
                if path.leaf_index != index || path.siblings.len() != site.log_height - p.cap_height
                {
                    return Err(invalid("binary WHIR restored path geometry mismatch"));
                }
                for digest in &path.siblings {
                    limbs.extend(bytes_to_limbs(digest));
                }
            }
            if let Some(round) = proof.whir.rounds.get(i) {
                push_fold(&mut limbs, &round.sumcheck);
            } else if let Some(fold) = &proof.whir.final_sumcheck {
                push_fold(&mut limbs, fold);
            }
        }
        Ok(NativeBinaryWhirInput {
            shape: self.input_shape(),
            limbs,
        })
    }
}

fn field<BF, EF>(b: &mut CircuitBuilder<EF>) -> Result<BinaryTower128Target, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let limbs = b.alloc_private_input_array::<8>("binary WHIR field");
    Ok(b.binary128_from_limbs::<BF>(limbs)?)
}
fn fields<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    n: usize,
) -> Result<Vec<BinaryTower128Target>, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    (0..n).map(|_| field::<BF, EF>(b)).collect()
}
fn fold<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    shape: &FoldShape,
) -> Result<BinaryWhirSumcheckTargets, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let messages = (0..shape.rounds)
        .map(|_| Ok([field::<BF, EF>(b)?, field::<BF, EF>(b)?]))
        .collect::<Result<_, VerificationError>>()?;
    let pow_witnesses = fields::<BF, EF>(b, if shape.pow_bits == 0 { 0 } else { shape.rounds })?;
    Ok(BinaryWhirSumcheckTargets {
        messages,
        pow_witnesses,
    })
}
fn opening<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    site: &OracleSite,
    cap: usize,
) -> Result<(Vec<Vec<BinaryTower128Target>>, Vec<Vec<Vec<ExprId>>>), VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let rows = (0..site.queries.num_queries())
        .map(|_| fields::<BF, EF>(b, site.width))
        .collect::<Result<_, _>>()?;
    let paths = (0..site.queries.num_queries())
        .map(|_| {
            (0..site.log_height - cap)
                .map(|_| {
                    b.alloc_private_input_array::<16>("WHIR path digest")
                        .to_vec()
                })
                .collect()
        })
        .collect();
    Ok((rows, paths))
}
fn check_fold<F: Field>(
    proof: &SumcheckData<F, BinaryField128>,
    shape: &FoldShape,
) -> Result<(), VerificationError> {
    if proof.polynomial_evaluations.len() != shape.rounds
        || proof.pow_witnesses.len() != if shape.pow_bits == 0 { 0 } else { shape.rounds }
    {
        Err(invalid("binary WHIR native sumcheck shape mismatch"))
    } else {
        Ok(())
    }
}
fn push(values: &mut Vec<u16>, raw: u128) {
    values.extend((0..8).map(|i| (raw >> (16 * i)) as u16));
}
fn push_fold<F: RecursiveBinaryWhirTowerField>(
    values: &mut Vec<u16>,
    proof: &SumcheckData<F, BinaryField128>,
) {
    for &v in proof.polynomial_evaluations.iter().flatten() {
        push(values, v.to_repr());
    }
    for &v in &proof.pow_witnesses {
        push(values, v.raw_coordinates());
    }
}
