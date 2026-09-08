//! Structural descriptors for recursive WHIR input allocation.

use alloc::format;
use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, ExtensionField, Field};
use p3_merkle_tree::MerkleCap;
use p3_sumcheck::SumcheckData;
use p3_whir::pcs::proof::QueryOpenings;

use super::MerkleCapShape;
use crate::pcs::whir::uni::pcs::WhirUniProof;
use crate::verifier::VerificationError;

/// Allocation-relevant structure of one sumcheck transcript.
#[derive(Clone, PartialEq, Eq)]
pub struct SumcheckShape {
    pub(crate) polynomial_evaluations: usize,
    pub(crate) pow_witnesses: usize,
}

/// Field variant and per-query row widths of WHIR openings.
#[derive(Clone, PartialEq, Eq)]
pub enum QueryOpeningsShape {
    Base { rows: Vec<usize> },
    Extension { rows: Vec<usize> },
}

/// Allocation-relevant structure of one intermediate WHIR step.
#[derive(Clone, PartialEq, Eq)]
pub struct WhirStepShape<C> {
    pub(crate) commitment: Option<C>,
    pub(crate) ood_answers: usize,
    pub(crate) openings: QueryOpeningsShape,
    pub(crate) sumcheck: SumcheckShape,
}

/// Complete allocation-relevant structure of one WHIR transcript.
#[derive(Clone, PartialEq, Eq)]
pub struct WhirShape<C> {
    pub(crate) initial_ood_answers: usize,
    pub(crate) initial_sumcheck: SumcheckShape,
    pub(crate) rounds: Vec<WhirStepShape<C>>,
    pub(crate) final_poly: Option<usize>,
    pub(crate) final_openings: QueryOpeningsShape,
    pub(crate) final_sumcheck: Option<SumcheckShape>,
}

/// Current/next partition of one PCS opening batch.
#[derive(Clone, PartialEq, Eq)]
pub struct OpeningBatchShape {
    pub(crate) current: usize,
    pub(crate) next: usize,
}

/// Allocation-relevant structure of one outer univariate PCS round.
#[derive(Clone, PartialEq, Eq)]
pub struct WhirPcsRoundShape<C> {
    pub(crate) evals: Vec<OpeningBatchShape>,
    pub(crate) whir: WhirShape<C>,
}

/// Complete allocation-relevant structure of a WHIR univariate opening proof.
#[derive(Clone, PartialEq, Eq)]
pub struct WhirUniShape<C> {
    pub(crate) rounds: Vec<WhirPcsRoundShape<C>>,
}

fn sumcheck_shape<F, EF>(input: &SumcheckData<F, EF>) -> SumcheckShape {
    SumcheckShape {
        polynomial_evaluations: input.polynomial_evaluations().len(),
        pow_witnesses: input.pow_witnesses.len(),
    }
}

fn query_shape<F, EF, P>(input: &QueryOpenings<F, EF, P>) -> QueryOpeningsShape {
    match input {
        QueryOpenings::Base(opening) => QueryOpeningsShape::Base {
            rows: opening.rows.iter().map(Vec::len).collect(),
        },
        QueryOpenings::Extension(opening) => QueryOpeningsShape::Extension {
            rows: opening.rows.iter().map(Vec::len).collect(),
        },
    }
}

fn validate_digest_packing(
    digest_elems: usize,
    extension_dimension: usize,
) -> Result<(), VerificationError> {
    if extension_dimension != 1 && !digest_elems.is_multiple_of(extension_dimension) {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR cap absorption requires EF::DIMENSION ({extension_dimension}) to be 1 or \
             evenly divide DIGEST_ELEMS ({digest_elems})"
        )));
    }
    Ok(())
}

/// Captures every native proof choice that changes WHIR target allocation.
pub(crate) fn capture_whir_uni_shape<F, EF, MT, const DIGEST_ELEMS: usize>(
    input: &WhirUniProof<F, EF, MT>,
) -> Result<WhirUniShape<MerkleCapShape>, VerificationError>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    MT: Mmcs<F, Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>>,
{
    validate_digest_packing(DIGEST_ELEMS, <EF as BasedVectorSpace<F>>::DIMENSION)?;

    let rounds = input
        .rounds
        .iter()
        .map(|round| {
            let evals = round
                .evals
                .iter()
                .map(|batch| {
                    if !batch.next().is_empty() {
                        return Err(VerificationError::InvalidProofShape(
                            "WHIR uni openings use no next group".into(),
                        ));
                    }
                    Ok(OpeningBatchShape {
                        current: batch.current().len(),
                        next: batch.next().len(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let whir = &round.whir;
            let rounds = whir
                .rounds
                .iter()
                .map(|step| {
                    let commitment = step.commitment.as_ref().ok_or_else(|| {
                        VerificationError::InvalidProofShape(
                            "WHIR proof missing intermediate round commitment".into(),
                        )
                    })?;
                    Ok(WhirStepShape {
                        commitment: Some(MerkleCapShape {
                            roots: commitment.num_roots(),
                        }),
                        ood_answers: step.ood_answers.len(),
                        openings: query_shape(&step.openings),
                        sumcheck: sumcheck_shape(&step.sumcheck),
                    })
                })
                .collect::<Result<Vec<_>, VerificationError>>()?;
            let final_poly = whir.final_poly.as_ref().ok_or_else(|| {
                VerificationError::InvalidProofShape("WHIR proof missing final polynomial".into())
            })?;

            Ok(WhirPcsRoundShape {
                evals,
                whir: WhirShape {
                    initial_ood_answers: whir.initial_ood_answers.len(),
                    initial_sumcheck: sumcheck_shape(&whir.initial_sumcheck),
                    rounds,
                    final_poly: Some(final_poly.num_evals()),
                    final_openings: query_shape(&whir.final_openings),
                    final_sumcheck: whir.final_sumcheck.as_ref().map(sumcheck_shape),
                },
            })
        })
        .collect::<Result<Vec<_>, VerificationError>>()?;

    Ok(WhirUniShape { rounds })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_merkle_tree::MerkleCap;
    use p3_sumcheck::OpeningBatch;
    use p3_whir::pcs::proof::{QueryOpenings, SharedProofOpening, WhirRoundProof};

    use super::validate_digest_packing;
    use crate::pcs::whir::uni::pcs::WhirUniProof;
    use crate::pcs::whir::uni::pcs::tests::{MyMmcs, open_two_matrices};
    use crate::pcs::whir::uni::targets::WhirUniProofTargets;
    use crate::traits::PreparedRecursive;
    use crate::verifier::VerificationError;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Targets = WhirUniProofTargets<F, EF, MyMmcs, 8>;

    fn whir_fixture() -> WhirUniProof<F, EF, MyMmcs> {
        let (_pcs, commitment, _coms, mut proof) = open_two_matrices();
        let whir = &mut proof.rounds[0].whir;
        whir.rounds.push(WhirRoundProof {
            commitment: Some(commitment),
            ood_answers: whir.initial_ood_answers.clone(),
            pow_witness: F::ZERO,
            openings: whir.final_openings.clone(),
            sumcheck: whir.initial_sumcheck.clone(),
        });
        proof
    }

    fn set_query_rows(
        openings: &mut QueryOpenings<F, EF, <MyMmcs as p3_commit::Mmcs<F>>::MultiProof>,
        widths: &[usize],
    ) {
        match openings {
            QueryOpenings::Base(opening) => {
                opening.rows = widths.iter().map(|&width| vec![F::ZERO; width]).collect();
            }
            QueryOpenings::Extension(opening) => {
                opening.rows = widths.iter().map(|&width| vec![EF::ZERO; width]).collect();
            }
        }
    }

    #[test]
    fn prepared_whir_current_next_partition_binds() {
        let mut native = whir_fixture();
        let batch = &mut native.rounds[0].evals[0];
        *batch = OpeningBatch::new(batch.current().to_vec(), vec![EF::ZERO]);

        assert!(matches!(
            Targets::input_shape(&native),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_whir_query_variant_binds() {
        let native = whir_fixture();
        let mut changed = native.clone();
        let openings = &mut changed.rounds[0].whir.rounds[0].openings;
        *openings = match openings {
            QueryOpenings::Base(opening) => QueryOpenings::Extension(SharedProofOpening {
                rows: opening
                    .rows
                    .iter()
                    .map(|row| row.iter().copied().map(EF::from).collect())
                    .collect(),
                proof: opening.proof.clone(),
            }),
            QueryOpenings::Extension(opening) => QueryOpenings::Base(SharedProofOpening {
                rows: opening
                    .rows
                    .iter()
                    .map(|row| row.iter().map(|_| F::ZERO).collect())
                    .collect(),
                proof: opening.proof.clone(),
            }),
        };

        assert!(Targets::input_shape(&native).unwrap() != Targets::input_shape(&changed).unwrap());
    }

    #[test]
    fn prepared_whir_equal_total_query_partition_differs() {
        let mut left = whir_fixture();
        let mut right = left.clone();
        set_query_rows(&mut left.rounds[0].whir.rounds[0].openings, &[1, 3]);
        set_query_rows(&mut right.rounds[0].whir.rounds[0].openings, &[2, 2]);

        assert!(Targets::input_shape(&left).unwrap() != Targets::input_shape(&right).unwrap());
    }

    #[test]
    fn prepared_whir_sumcheck_pow_count_binds() {
        let native = whir_fixture();
        let mut changed = native.clone();
        changed.rounds[0]
            .whir
            .initial_sumcheck
            .pow_witnesses
            .push(F::ZERO);

        assert!(Targets::input_shape(&native).unwrap() != Targets::input_shape(&changed).unwrap());
    }

    #[test]
    fn prepared_whir_missing_commitment_rejected() {
        let mut native = whir_fixture();
        native.rounds[0].whir.rounds[0].commitment = None;

        assert!(matches!(
            Targets::input_shape(&native),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_whir_missing_final_poly_rejected() {
        let mut native = whir_fixture();
        native.rounds[0].whir.final_poly = None;

        assert!(matches!(
            Targets::input_shape(&native),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_whir_final_sumcheck_option_binds() {
        let native = whir_fixture();
        assert!(native.rounds[0].whir.final_sumcheck.is_some());
        let mut changed = native.clone();
        changed.rounds[0].whir.final_sumcheck = None;

        assert!(Targets::input_shape(&native).unwrap() != Targets::input_shape(&changed).unwrap());
    }

    #[test]
    fn prepared_whir_outer_round_and_cap_counts_bind() {
        let native = whir_fixture();
        let mut extra_outer = native.clone();
        extra_outer.rounds.push(extra_outer.rounds[0].clone());
        assert!(
            Targets::input_shape(&native).unwrap() != Targets::input_shape(&extra_outer).unwrap()
        );

        let mut wider_cap = native.clone();
        let cap = wider_cap.rounds[0].whir.rounds[0]
            .commitment
            .as_mut()
            .unwrap();
        let root = cap.roots()[0];
        *cap = MerkleCap::new(vec![root; 2]);
        assert!(
            Targets::input_shape(&native).unwrap() != Targets::input_shape(&wider_cap).unwrap()
        );
    }

    #[test]
    fn prepared_whir_frontier_length_is_dynamic() {
        let native = whir_fixture();
        let mut changed = native.clone();
        match &mut changed.rounds[0].whir.final_openings {
            QueryOpenings::Base(opening) => opening.proof.sibling_hashes.push([F::ZERO; 8]),
            QueryOpenings::Extension(opening) => opening.proof.sibling_hashes.push([F::ZERO; 8]),
        }

        assert!(Targets::input_shape(&native).unwrap() == Targets::input_shape(&changed).unwrap());
    }

    #[test]
    fn prepared_whir_rejects_unsupported_digest_packing() {
        assert!(matches!(
            validate_digest_packing(8, 5),
            Err(VerificationError::InvalidProofShape(_))
        ));
        assert!(validate_digest_packing(8, 4).is_ok());
        assert!(validate_digest_packing(8, 1).is_ok());
    }
}
