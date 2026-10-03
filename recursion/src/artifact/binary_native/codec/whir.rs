//! Fixed retained geometry for public released additive WHIR proof fields.

use super::*;
use p3_binary_field::BinaryField128;
use p3_whir::pcs::proof::{PcsProof, QueryOpenings, SharedProofOpening, WhirProof, WhirRoundProof};

type NativeWhirProof<F> = PcsProof<F, BinaryField128, NativeMmcs<F>>;

pub(super) fn write_whir<F>(w: &mut Writer, p: &NativeWhirProof<F>) -> Result<(), ArtifactError>
where
    F: RecursiveBinaryTowerField + PackedValue<Value = F>,
{
    for batch in &p.evals {
        write_fields(w, batch.current())?;
        write_fields(w, batch.next())?;
    }
    write_fields(w, &p.whir.initial_ood_answers)?;
    write_fold(w, &p.whir.initial_sumcheck)?;
    for round in &p.whir.rounds {
        write_cap(
            w,
            round
                .commitment
                .as_ref()
                .ok_or_else(|| malformed("binary WHIR round cap"))?,
        )?;
        write_fields(w, &round.ood_answers)?;
        write_field(w, round.pow_witness)?;
        write_opening(w, &round.openings)?;
        write_fold(w, &round.sumcheck)?;
    }
    write_fields(
        w,
        p.whir
            .final_poly
            .as_ref()
            .ok_or_else(|| malformed("binary WHIR final polynomial"))?
            .as_slice(),
    )?;
    write_field(w, p.whir.final_pow_witness)?;
    write_opening(w, &p.whir.final_openings)?;
    if let Some(fold) = &p.whir.final_sumcheck {
        write_fold(w, fold)?;
    }
    Ok(())
}
fn write_fold<F: RecursiveBinaryTowerField>(
    w: &mut Writer,
    p: &SumcheckData<F, BinaryField128>,
) -> Result<(), ArtifactError> {
    for pair in &p.polynomial_evaluations {
        write_fields(w, pair)?;
    }
    write_fields(w, &p.pow_witnesses)
}
fn write_opening<F: RecursiveBinaryTowerField>(
    w: &mut Writer,
    p: &QueryOpenings<F, BinaryField128, PrunedMerklePaths<u8, 32>>,
) -> Result<(), ArtifactError> {
    match p {
        QueryOpenings::Base(o) => {
            for row in &o.rows {
                write_fields(w, row)?;
            }
            write_frontier(w, &o.proof)
        }
        QueryOpenings::Extension(o) => {
            for row in &o.rows {
                write_fields(w, row)?;
            }
            write_frontier(w, &o.proof)
        }
    }
}
fn read_fold<F: RecursiveBinaryTowerField>(
    r: &mut Reader<'_>,
    s: &WhirFoldDecode,
) -> Result<SumcheckData<F, BinaryField128>, ArtifactError> {
    Ok(SumcheckData {
        polynomial_evaluations: r.read_exact_items(
            "binary WHIR fold rounds",
            s.rounds,
            32,
            read_array::<BinaryField128, 2>,
        )?,
        pow_witnesses: read_fields(r, s.pow_count)?,
    })
}
fn read_opening<F: RecursiveBinaryTowerField>(
    r: &mut Reader<'_>,
    s: &WhirSiteDecode,
    base: bool,
    total: &mut usize,
) -> Result<QueryOpenings<F, BinaryField128, PrunedMerklePaths<u8, 32>>, ArtifactError> {
    fn rows<T: RecursiveBinaryTowerField>(
        r: &mut Reader<'_>,
        s: &WhirSiteDecode,
    ) -> Result<Vec<Vec<T>>, ArtifactError> {
        r.read_exact_items(
            "binary WHIR query rows",
            s.oracle.rows,
            checked_product(s.width, T::RAW_BITS / 8)?,
            |r| read_fields(r, s.width),
        )
    }
    if base {
        Ok(QueryOpenings::Base(SharedProofOpening {
            rows: rows(r, s)?,
            proof: read_frontier(r, &s.oracle, total)?,
        }))
    } else {
        Ok(QueryOpenings::Extension(SharedProofOpening {
            rows: rows(r, s)?,
            proof: read_frontier(r, &s.oracle, total)?,
        }))
    }
}
fn read_query_pow<F: RecursiveBinaryTowerField>(
    r: &mut Reader<'_>,
    site: &WhirSiteDecode,
) -> Result<F, ArtifactError> {
    let witness = read_field::<F>(r)?;
    if site.query_pow_bits == 0 && witness != F::ZERO {
        return Err(malformed("binary WHIR disabled query PoW witness"));
    }
    Ok(witness)
}
pub(super) fn read_whir<F>(
    r: &mut Reader<'_>,
    s: &WhirDecode,
    total: &mut usize,
) -> Result<NativeWhirProof<F>, ArtifactError>
where
    F: RecursiveBinaryTowerField + PackedValue<Value = F>,
{
    let evals = r.read_exact_items("binary WHIR opening batches", s.eval_widths.len(), 0, {
        let mut index = 0;
        move |r| {
            let (current, next) = s.eval_widths[index];
            index += 1;
            Ok(OpeningBatch::new(
                read_fields(r, current)?,
                read_fields(r, next)?,
            ))
        }
    })?;
    let initial_ood_answers = read_fields(r, s.initial_ood)?;
    let initial_sumcheck = read_fold(r, &s.initial_fold)?;
    let last = s
        .sites
        .last()
        .ok_or_else(|| malformed("binary WHIR query sites"))?;
    let round_total = &mut *total;
    let rounds = r.read_exact_items("binary WHIR intermediate rounds", s.sites.len() - 1, 0, {
        let mut index = 0;
        move |r| {
            let site = &s.sites[index];
            let base = index == 0;
            index += 1;
            Ok(WhirRoundProof {
                commitment: Some(read_cap(r, s.cap_roots)?),
                ood_answers: read_fields(r, site.ood)?,
                pow_witness: read_query_pow(r, site)?,
                openings: read_opening(r, site, base, round_total)?,
                sumcheck: read_fold(r, &site.fold)?,
            })
        }
    })?;
    let final_poly = Some(Poly::new(read_fields(r, s.final_poly_len)?));
    let final_pow_witness = read_query_pow(r, last)?;
    let final_openings = read_opening(r, last, s.sites.len() == 1, total)?;
    let final_sumcheck = if last.fold.rounds == 0 {
        None
    } else {
        Some(read_fold(r, &last.fold)?)
    };
    Ok(PcsProof {
        evals,
        whir: WhirProof {
            initial_ood_answers,
            initial_sumcheck,
            rounds,
            final_poly,
            final_pow_witness,
            final_openings,
            final_sumcheck,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
    use p3_field::PrimeCharacteristicRing;
    use p3_whir::pcs::proof::{PcsProof, QueryOpenings, SharedProofOpening, WhirProof};

    fn fixture() -> (
        WhirDecode,
        PcsProof<BinaryField32, BinaryField128, NativeMmcs<BinaryField32>>,
    ) {
        let shape = WhirDecode {
            eval_widths: vec![(1, 1)],
            cap_roots: 1,
            initial_ood: 1,
            initial_fold: WhirFoldDecode {
                rounds: 1,
                pow_count: 0,
            },
            sites: vec![WhirSiteDecode {
                width: 2,
                oracle: OracleDecode {
                    rows: 2,
                    path_len: 2,
                },
                query_pow_bits: 0,
                ood: 0,
                fold: WhirFoldDecode {
                    rounds: 0,
                    pow_count: 0,
                },
            }],
            final_poly_len: 2,
        };
        let proof = PcsProof {
            evals: vec![OpeningBatch::new(
                vec![BinaryField128::ONE],
                vec![BinaryField128::ZERO],
            )],
            whir: WhirProof {
                initial_ood_answers: vec![BinaryField128::ONE],
                initial_sumcheck: SumcheckData {
                    polynomial_evaluations: vec![[BinaryField128::ZERO, BinaryField128::ONE]],
                    pow_witnesses: vec![],
                },
                rounds: vec![],
                final_poly: Some(Poly::new(vec![BinaryField128::ZERO, BinaryField128::ONE])),
                final_pow_witness: BinaryField32::ZERO,
                final_openings: QueryOpenings::Base(SharedProofOpening {
                    // Repeated rows are retained rather than deduplicated.
                    rows: vec![vec![BinaryField32::ONE, BinaryField32::ZERO]; 2],
                    proof: PrunedMerklePaths {
                        sibling_hashes: vec![[7; 32], [9; 32]],
                    },
                }),
                final_sumcheck: None,
            },
        };
        (shape, proof)
    }

    #[test]
    fn fixed_whir_codec_retains_duplicate_rows_and_rejects_all_truncations() {
        let (shape, proof) = fixture();
        let limits = ArtifactLimits::default();
        let mut writer = Writer::new(limits.max_proof_bytes);
        write_whir(&mut writer, &proof).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = Reader::new(&bytes, &limits);
        let decoded = read_whir::<BinaryField32>(&mut reader, &shape, &mut 0).unwrap();
        reader.finish().unwrap();
        let QueryOpenings::Base(opening) = decoded.whir.final_openings else {
            panic!("wrong alphabet")
        };
        assert_eq!(
            opening.rows,
            vec![vec![BinaryField32::ONE, BinaryField32::ZERO]; 2]
        );
        assert_eq!(opening.proof.sibling_hashes, vec![[7; 32], [9; 32]]);
        assert!(decoded.whir.final_sumcheck.is_none());
        for length in 0..bytes.len() {
            assert!(
                read_whir::<BinaryField32>(
                    &mut Reader::new(&bytes[..length], &limits),
                    &shape,
                    &mut 0
                )
                .is_err()
            );
        }
    }

    #[test]
    fn consecutive_whir_openings_share_the_frontier_budget() {
        let (shape, proof) = fixture();
        let limits = ArtifactLimits {
            verifier: crate::verifier::VerifierLimits {
                max_compressed_frontier_hashes: 3,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut writer = Writer::new(limits.max_proof_bytes);
        write_whir(&mut writer, &proof).unwrap();
        write_whir(&mut writer, &proof).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = Reader::new(&bytes, &limits);
        let mut total = 0;
        read_whir::<BinaryField32>(&mut reader, &shape, &mut total).unwrap();
        assert_eq!(total, 2);
        assert!(matches!(
            read_whir::<BinaryField32>(&mut reader, &shape, &mut total),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "binary compressed frontier",
                actual: 2,
                limit: 1
            })
        ));
    }
    #[test]
    fn released_native_whir_proofs_roundtrip_both_alphabets_orders_and_hashes() {
        use crate::artifact::binary_native::{BinaryNativeChallenger, BinaryNativeHash};
        use crate::pcs::binary::BinaryWhirVerifier;
        use p3_binary_pcs::whir::BinaryWhirDomain;
        use p3_challenger::FieldChallenger;
        use p3_commit::MultilinearPcs;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_multilinear_util::point::Point;
        use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver, Table};
        use p3_sumcheck::{OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
        use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
        use p3_whir::{
            FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver,
        };
        macro_rules! check {
            ($field:ty, $layout:ident, $height:expr, $cap:expr) => {{
                type F = $field;
                type E = BinaryField128;
                type Ch = BinaryNativeChallenger<F>;
                type L = $layout<F, E>;
                for hash in [
                    p3_circuit::ops::ByteHash::Keccak256,
                    p3_circuit::ops::ByteHash::Blake3,
                ] {
                    let domain = BinaryWhirDomain::<F>::default();
                    let config = WhirConfig::<E, F, Ch>::new_with_domain(
                        $height,
                        ProtocolParameters {
                            security_level: 8,
                            pow_bits: 0,
                            round_log_inv_rates: vec![],
                            folding_factor: FoldingFactor::Constant(2),
                            soundness_type: SecurityAssumption::JohnsonBound,
                            starting_log_inv_rate: 1,
                        },
                        &domain,
                    )
                    .unwrap();
                    let mmcs = NativeMmcs::<F>::new(
                        SerializingHasher::new(BinaryNativeHash(hash)),
                        CompressionFunctionFromHasher::new(BinaryNativeHash(hash)),
                        $cap,
                    );
                    let pcs =
                        WhirProver::<E, F, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
                    let protocol = OpeningProtocol::new(vec![TableSpec::new(
                        TableShape::new($height, 1),
                        vec![OpeningBatch::new(vec![0], vec![0])],
                    )]);
                    let recursive = BinaryWhirVerifier::<F>::new(
                        &config,
                        protocol.clone(),
                        L::variable_order(),
                        hash,
                        $cap,
                    )
                    .unwrap();
                    let input_shape = recursive.input_shape();
                    let shape = input_shape.native_decode_shape();
                    let identity = |shape: &crate::pcs::binary::BinaryWhirInputShape<F>| {
                        let mut writer = Writer::new(1 << 20);
                        shape.write_identity(&mut writer).unwrap();
                        writer.finish().unwrap()
                    };
                    let other_order =
                        if L::variable_order() == p3_sumcheck::strategy::VariableOrder::Prefix {
                            p3_sumcheck::strategy::VariableOrder::Suffix
                        } else {
                            p3_sumcheck::strategy::VariableOrder::Prefix
                        };
                    let other = BinaryWhirVerifier::<F>::new(
                        &config,
                        protocol.clone(),
                        other_order,
                        hash,
                        $cap,
                    )
                    .unwrap();
                    assert_ne!(identity(&input_shape), identity(&other.input_shape()));
                    let tables = vec![Table::new(RowMajorMatrix::new(
                        (0..1usize << $height)
                            .map(|i| {
                                F::from_le_byte_iter(
                                    (i as u128 * 29 + 7)
                                        .to_le_bytes()
                                        .into_iter()
                                        .take(F::RAW_BITS / 8),
                                )
                            })
                            .collect(),
                        1usize << $height,
                    ))];
                    let witness = L::new_witness(tables, config.round_folding_factor(0));
                    let mut prover = Ch::fresh(vec![0, 19, 255], hash);
                    let (cap, data) = pcs.commit(witness, &mut prover).unwrap();
                    let points = vec![Point::new(
                        (0..$height)
                            .map(|i| {
                                E::from_le_byte_iter((i as u128 + 3).to_le_bytes().into_iter())
                            })
                            .collect(),
                    )];
                    let proof = pcs.open_at(data, &protocol, &points, &mut prover).unwrap();
                    let frontier_len = |q: &QueryOpenings<F, E, PrunedMerklePaths<u8, 32>>| match q
                    {
                        QueryOpenings::Base(o) => o.proof.sibling_hashes.len(),
                        QueryOpenings::Extension(o) => o.proof.sibling_hashes.len(),
                    };
                    let count = frontier_len(&proof.whir.final_openings)
                        + proof
                            .whir
                            .rounds
                            .iter()
                            .map(|r| frontier_len(&r.openings))
                            .sum::<usize>();
                    if count > 0 {
                        let mut usage = crate::verifier::InputResourceUsage {
                            compressed_frontier_hashes: crate::verifier::VerifierLimits::default()
                                .max_compressed_frontier_hashes
                                - count,
                            ..Default::default()
                        };
                        recursive
                            .check_native_with_usage(
                                &config, &mmcs, &cap, &points, &proof, &mut usage,
                            )
                            .unwrap();
                        assert!(matches!(
                            recursive.check_native_with_usage(
                                &config, &mmcs, &cap, &points, &proof, &mut usage
                            ),
                            Err(crate::verifier::VerificationError::ResourceLimitExceeded {
                                component: "compressed frontier hashes",
                                ..
                            })
                        ));
                    }

                    let limits = ArtifactLimits::default();
                    let mut writer = Writer::new(limits.max_proof_bytes);
                    write_whir(&mut writer, &proof).unwrap();
                    let bytes = writer.finish().unwrap();
                    let mut reader = Reader::new(&bytes, &limits);
                    let decoded = read_whir::<F>(&mut reader, &shape, &mut 0).unwrap();
                    reader.finish().unwrap();
                    let mut native = Ch::fresh(vec![0, 19, 255], hash);
                    pcs.observe_commitment(&cap, &mut native);
                    pcs.verify_at(&cap, &decoded, &protocol, &points, &mut native)
                        .unwrap();
                    assert_eq!(
                        native.sample_algebra_element::<E>(),
                        prover.sample_algebra_element::<E>()
                    );
                    assert_eq!(
                        decoded.whir.final_sumcheck.is_some(),
                        shape.sites.last().unwrap().fold.rounds > 0
                    );
                    assert_eq!(decoded.whir.rounds.len() + 1, shape.sites.len());
                }
            }};
        }
        check!(BinaryField32, PrefixProver, 9, 0);
        check!(BinaryField32, SuffixProver, 8, 1);
        check!(BinaryField128, PrefixProver, 9, 0);
        check!(BinaryField128, SuffixProver, 2, 1);
    }
    #[test]
    fn whir_codec_retains_base_pow_and_extension_rounds_without_wire_tags() {
        let (mut shape, mut proof) = fixture();
        shape.initial_fold.pow_count = 1;
        proof.whir.initial_sumcheck.pow_witnesses = vec![BinaryField32::ONE];
        let mut last = WhirSiteDecode {
            width: 2,
            oracle: OracleDecode {
                rows: 2,
                path_len: 2,
            },
            query_pow_bits: 3,
            ood: 0,
            fold: WhirFoldDecode {
                rounds: 1,
                pow_count: 1,
            },
        };
        let fold = SumcheckData {
            polynomial_evaluations: vec![[BinaryField128::ONE, BinaryField128::ZERO]],
            pow_witnesses: vec![BinaryField32::ONE],
        };
        proof.whir.rounds.push(WhirRoundProof {
            commitment: Some(MerkleCap::new(vec![[3; 32]])),
            ood_answers: vec![],
            pow_witness: BinaryField32::ZERO,
            openings: proof.whir.final_openings.clone(),
            sumcheck: SumcheckData::default(),
        });
        proof.whir.final_openings = QueryOpenings::Extension(SharedProofOpening {
            rows: vec![vec![BinaryField128::ONE; 2]; 2],
            proof: PrunedMerklePaths {
                sibling_hashes: vec![[11; 32]],
            },
        });
        proof.whir.final_pow_witness = BinaryField32::ONE;
        proof.whir.final_sumcheck = Some(fold);
        shape.sites.push(last);
        let limits = ArtifactLimits::default();
        let mut writer = Writer::new(limits.max_proof_bytes);
        write_whir(&mut writer, &proof).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = Reader::new(&bytes, &limits);
        let decoded = read_whir::<BinaryField32>(&mut reader, &shape, &mut 0).unwrap();
        reader.finish().unwrap();
        assert_eq!(
            decoded.whir.initial_sumcheck.pow_witnesses,
            vec![BinaryField32::ONE]
        );
        assert_eq!(
            decoded.whir.final_sumcheck.unwrap().pow_witnesses,
            vec![BinaryField32::ONE]
        );
        assert!(matches!(
            decoded.whir.final_openings,
            QueryOpenings::Extension(_)
        ));
        last = shape.sites.pop().unwrap();
        last.query_pow_bits = 0;
        shape.sites.push(last);
        assert!(matches!(
            read_whir::<BinaryField32>(&mut Reader::new(&bytes, &limits), &shape, &mut 0),
            Err(ArtifactError::MalformedProof {
                component: "binary WHIR disabled query PoW witness"
            })
        ));
    }
}
