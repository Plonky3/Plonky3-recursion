//! Fixed allocation and bounded import of Poly64→Poly192 WHIR witnesses.

use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_binary_field::{Poly64, Poly192, TowerLevel};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryPoly64Target, BinaryPoly192Target, ByteHash, bytes_to_limbs};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
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

use super::BinaryPolyWhirVerifier;
use super::whir_plan::{FoldShape, OracleSite, invalid, limit};
use crate::transcript::domain_separator_seed;
use crate::verifier::{InputResourceUsage, VerificationError};

#[derive(Clone, Debug)]
pub struct BinaryPolyWhirSumcheckTargets {
    pub messages: Vec<[BinaryPoly192Target; 2]>,
    pub pow_witnesses: Vec<BinaryPoly64Target>,
}

#[derive(Clone, Debug)]
pub struct BinaryPolyWhirRoundTargets {
    pub cap: Vec<Vec<ExprId>>,
    pub ood_answers: Vec<BinaryPoly192Target>,
    pub pow_witness: BinaryPoly64Target,
    pub rows: Vec<Vec<BinaryPoly192Target>>,
    pub paths: Vec<Vec<Vec<ExprId>>>,
    pub sumcheck: BinaryPolyWhirSumcheckTargets,
}

#[derive(Clone, Debug)]
pub struct BinaryPolyWhirProofTargets {
    pub evals: Vec<OpeningBatch<BinaryPoly192Target>>,
    pub initial_ood_answers: Vec<BinaryPoly192Target>,
    pub initial_sumcheck: BinaryPolyWhirSumcheckTargets,
    pub rounds: Vec<BinaryPolyWhirRoundTargets>,
    pub final_poly: Vec<BinaryPoly192Target>,
    pub final_pow_witness: BinaryPoly64Target,
    pub final_rows: Vec<Vec<BinaryPoly192Target>>,
    pub final_paths: Vec<Vec<Vec<ExprId>>>,
    pub final_sumcheck: BinaryPolyWhirSumcheckTargets,
}

/// Exact trusted contract, including native configuration seed and the whole
/// opening schedule. Query indices are derived in-circuit, not allocated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPolyWhirInputShape {
    contract: Vec<Poly64>,
    protocol: OpeningProtocol,
    order: VariableOrder,
    hash: ByteHash,
    cap_height: usize,
    initial_ood: usize,
    initial_fold: FoldShape,
    sites: Vec<OracleSite>,
    final_len: usize,
}

impl BinaryPolyWhirInputShape {
    pub(crate) fn native_decode_shape(&self) -> crate::artifact::binary_native::codec::WhirDecode {
        use crate::artifact::binary_native::codec::{
            OracleDecode, WhirDecode, WhirFoldDecode, WhirSiteDecode,
        };
        let fold = |shape: &FoldShape| WhirFoldDecode {
            rounds: shape.rounds,
            pow_count: if shape.pow_bits > 0 { shape.rounds } else { 0 },
        };
        WhirDecode {
            eval_widths: self
                .protocol
                .iter_openings()
                .map(|(_, batch)| (batch.current().len(), batch.next().len()))
                .collect(),
            cap_roots: 1usize << self.cap_height,
            initial_ood: self.initial_ood,
            initial_fold: fold(&self.initial_fold),
            sites: self
                .sites
                .iter()
                .map(|site| WhirSiteDecode {
                    width: site.width,
                    oracle: OracleDecode {
                        rows: site.queries.num_queries(),
                        path_len: site.log_height - self.cap_height,
                    },
                    query_pow_bits: site.query_pow_bits,
                    ood: site.ood,
                    fold: fold(&site.fold),
                })
                .collect(),
            final_poly_len: self.final_len,
        }
    }

    pub(crate) fn write_identity(
        &self,
        w: &mut crate::artifact::wire::Writer,
    ) -> Result<(), crate::artifact::ArtifactError> {
        w.write_vec(
            "binary WHIR configuration seed",
            &self.contract,
            |w, value| w.write_bytes(&value.to_repr().to_le_bytes()),
        )?;
        w.write_u8(match self.order {
            VariableOrder::Prefix => 0,
            VariableOrder::Suffix => 1,
        })?;
        w.write_u8(match self.hash {
            ByteHash::Keccak256 => 0,
            ByteHash::Blake3 => 1,
        })?;
        w.write_count("binary WHIR cap height", self.cap_height)?;
        let shapes = self.protocol.table_shapes();
        w.write_vec("binary WHIR tables", &shapes, |w, shape| {
            w.write_count("binary WHIR table height", shape.num_variables())?;
            w.write_count("binary WHIR table width", shape.width())
        })?;
        w.write_count("binary WHIR openings", self.protocol.num_openings())?;
        for (table, batch) in self.protocol.iter_openings() {
            w.write_count("binary WHIR opening table", table)?;
            for columns in [batch.current(), batch.next()] {
                w.write_vec("binary WHIR opening columns", columns, |w, &column| {
                    w.write_count("binary WHIR opening column", column)
                })?;
            }
        }
        Ok(())
    }

    pub fn allocate_targets<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<BinaryPolyWhirProofTargets, VerificationError>
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
        for (i, site) in self.sites.iter().take(self.sites.len() - 1).enumerate() {
            let cap = (0..1usize << self.cap_height)
                .map(|_| b.alloc_private_input_array::<16>("WHIR round cap").to_vec())
                .collect();
            let ood_answers = fields::<BF, EF>(b, site.ood)?;
            let pow_witness = base_field::<BF, EF>(b)?;
            let (rows, paths) = opening::<BF, EF>(b, site, self.cap_height, i == 0)?;
            let sumcheck = fold::<BF, EF>(b, &site.fold)?;
            rounds.push(BinaryPolyWhirRoundTargets {
                cap,
                ood_answers,
                pow_witness,
                rows,
                paths,
                sumcheck,
            });
        }
        let final_poly = fields::<BF, EF>(b, self.final_len)?;
        let final_pow_witness = base_field::<BF, EF>(b)?;
        let site = self
            .sites
            .last()
            .expect("a checked WHIR plan has a final query site");
        let (final_rows, final_paths) =
            opening::<BF, EF>(b, site, self.cap_height, self.sites.len() == 1)?;
        let final_sumcheck = fold::<BF, EF>(b, &site.fold)?;
        Ok(BinaryPolyWhirProofTargets {
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
pub struct NativeBinaryPolyWhirInput {
    shape: BinaryPolyWhirInputShape,
    limbs: Vec<u16>,
}
impl NativeBinaryPolyWhirInput {
    pub fn shape(&self) -> &BinaryPolyWhirInputShape {
        &self.shape
    }
    pub fn private_values<EF: Field>(
        &self,
        expected: &BinaryPolyWhirInputShape,
    ) -> Result<Vec<EF>, VerificationError> {
        if &self.shape != expected {
            return Err(invalid("binary WHIR input belongs to a different verifier"));
        }
        Ok(self.limbs.iter().copied().map(EF::from_u16).collect())
    }
}

impl BinaryPolyWhirVerifier {
    pub fn input_shape(&self) -> BinaryPolyWhirInputShape {
        let p = &self.plan;
        BinaryPolyWhirInputShape {
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

    pub(crate) fn check_native_with_usage<C, H, Co>(
        &self,
        config: &WhirConfig<Poly192, Poly64, C>,
        mmcs: &MerkleTreeMmcs<Poly64, u8, H, Co, 2, 32>,
        commitment: &MerkleCap<Poly64, [u8; 32]>,
        points: &[Point<Poly192>],
        proof: &PcsProof<Poly64, Poly192, MerkleTreeMmcs<Poly64, u8, H, Co, 2, 32>>,
        usage: &mut InputResourceUsage,
    ) -> Result<(), VerificationError>
    where
        H: CryptographicHasher<Poly64, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
    {
        let p = &self.plan;
        let shape = WhirShape::new(config, p.protocol.num_openings());
        if domain_separator_seed(&shape.domain_separator::<Poly64, Poly192>()) != p.engine_seed
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
            if site.query_pow_bits == 0 && pow != Poly64::ZERO {
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
            let max_frontier = site
                .queries
                .num_queries()
                .checked_mul(site.log_height - p.cap_height)
                .ok_or(VerificationError::ResourceArithmeticOverflow {
                    component: "binary Poly WHIR frontier",
                })?;
            limit(
                "binary Poly WHIR frontier",
                frontier.sibling_hashes.len(),
                max_frontier,
            )?;
            usage.add_compressed_frontier_hashes(&p.limits, frontier.sibling_hashes.len())?;
        }
        Ok(())
    }

    /// Imports through public native layout, WHIR transcript and byte-tree
    /// restoration APIs. The commitment must already be observed. Passing a
    /// mutable challenger retains its exact native continuation. All visible
    /// shapes and frontier budgets are checked before transcript replay. The
    /// caller's challenger is unchanged on every error, including restoration
    /// failures after replay. A
    /// zero-round closing sumcheck must omit the native optional proof slot.
    pub fn import_native<C, Ch, H, Co>(
        &self,
        config: &WhirConfig<Poly192, Poly64, C>,
        mmcs: &MerkleTreeMmcs<Poly64, u8, H, Co, 2, 32>,
        commitment: &MerkleCap<Poly64, [u8; 32]>,
        points: &[Point<Poly192>],
        proof: &PcsProof<Poly64, Poly192, MerkleTreeMmcs<Poly64, u8, H, Co, 2, 32>>,
        target_challenger: &mut Ch,
    ) -> Result<NativeBinaryPolyWhirInput, VerificationError>
    where
        H: CryptographicHasher<Poly64, [u8; 32]> + Sync,
        Co: PseudoCompressionFunction<[u8; 32], 2> + Sync,
        C: FieldChallenger<Poly64> + GrindingChallenger<Witness = Poly64>,
        Ch: Clone
            + FieldChallenger<Poly64>
            + CanSampleUniformBits<Poly64>
            + GrindingChallenger<Witness = Poly64>
            + CanObserve<MerkleCap<Poly64, [u8; 32]>>,
    {
        self.check_native_with_usage(
            config,
            mmcs,
            commitment,
            points,
            proof,
            &mut InputResourceUsage::default(),
        )?;
        let mut challenger = target_challenger.clone();
        let p = &self.plan;
        let shape = WhirShape::new(config, p.protocol.num_openings());
        let last = p.sites.last().expect("checked final site");
        let strategy = LayoutStrategy::new(p.order == VariableOrder::Prefix, p.order);
        let mut layout = Verifier::<Poly64, Poly192>::new(&p.protocol.table_shapes(), strategy);
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
            WhirVerifierTranscript::<_, Poly64, Poly192>::new(&mut challenger, shape);
        let replay = (|| {
            let mut claim = Poly192::ZERO;
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
                push_extension(&mut limbs, v);
            }
        }
        for &v in &proof.whir.initial_ood_answers {
            push_extension(&mut limbs, v);
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
                    push_extension(&mut limbs, v);
                }
                push_base(&mut limbs, round.pow_witness);
                &round.openings
            } else {
                for &v in proof
                    .whir
                    .final_poly
                    .as_ref()
                    .expect("checked final polynomial")
                    .as_slice()
                {
                    push_extension(&mut limbs, v);
                }
                push_base(&mut limbs, proof.whir.final_pow_witness);
                &proof.whir.final_openings
            };
            let (rows, frontier, degree) = match openings {
                QueryOpenings::Base(opening) => {
                    for &v in opening.rows.iter().flatten() {
                        push_base(&mut limbs, v);
                    }
                    (opening.rows.clone(), &opening.proof, 1)
                }
                QueryOpenings::Extension(opening) => {
                    for &v in opening.rows.iter().flatten() {
                        push_extension(&mut limbs, v);
                    }
                    (
                        opening
                            .rows
                            .iter()
                            .map(|row| row.iter().flat_map(|v| v.coefficients()).collect())
                            .collect(),
                        &opening.proof,
                        <Poly192 as BasedVectorSpace<Poly64>>::DIMENSION,
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
        *target_challenger = challenger;
        Ok(NativeBinaryPolyWhirInput {
            shape: self.input_shape(),
            limbs,
        })
    }
}

fn field<BF, EF>(b: &mut CircuitBuilder<EF>) -> Result<BinaryPoly192Target, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let limbs = b.alloc_private_input_array::<12>("binary Poly WHIR challenge");
    Ok(b.binary_poly192_from_limbs::<BF>(limbs)?)
}
fn fields<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    n: usize,
) -> Result<Vec<BinaryPoly192Target>, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    (0..n).map(|_| field::<BF, EF>(b)).collect()
}
fn fold<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    shape: &FoldShape,
) -> Result<BinaryPolyWhirSumcheckTargets, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let messages = (0..shape.rounds)
        .map(|_| Ok([field::<BF, EF>(b)?, field::<BF, EF>(b)?]))
        .collect::<Result<_, VerificationError>>()?;
    let pow_witnesses = (0..if shape.pow_bits == 0 { 0 } else { shape.rounds })
        .map(|_| base_field::<BF, EF>(b))
        .collect::<Result<_, VerificationError>>()?;
    Ok(BinaryPolyWhirSumcheckTargets {
        messages,
        pow_witnesses,
    })
}
fn opening<BF, EF>(
    b: &mut CircuitBuilder<EF>,
    site: &OracleSite,
    cap: usize,
    base: bool,
) -> Result<(Vec<Vec<BinaryPoly192Target>>, Vec<Vec<Vec<ExprId>>>), VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let rows = (0..site.queries.num_queries())
        .map(|_| {
            (0..site.width)
                .map(|_| {
                    if base {
                        let coefficient = base_field::<BF, EF>(b)?;
                        let zero = b.binary_poly64_constant(0)?;
                        Ok(b.binary_poly192_from_coefficients([coefficient, zero.clone(), zero]))
                    } else {
                        field::<BF, EF>(b)
                    }
                })
                .collect::<Result<_, VerificationError>>()
        })
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
fn check_fold(
    proof: &SumcheckData<Poly64, Poly192>,
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
fn base_field<BF, EF>(b: &mut CircuitBuilder<EF>) -> Result<BinaryPoly64Target, VerificationError>
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let limbs = b.alloc_private_input_array::<4>("binary Poly WHIR base");
    Ok(b.binary_poly64_from_limbs::<BF>(limbs)?)
}
fn push_base(values: &mut Vec<u16>, value: Poly64) {
    values.extend((0..4).map(|i| (value.to_bits() >> (16 * i)) as u16));
}
fn push_extension(values: &mut Vec<u16>, value: Poly192) {
    for coefficient in value.coefficients() {
        push_base(values, coefficient);
    }
}
fn push_fold(values: &mut Vec<u16>, proof: &SumcheckData<Poly64, Poly192>) {
    for &v in proof.polynomial_evaluations.iter().flatten() {
        push_extension(values, v);
    }
    for &v in &proof.pow_witnesses {
        push_base(values, v);
    }
}
