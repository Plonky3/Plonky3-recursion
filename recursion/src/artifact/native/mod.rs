mod fri;
mod mmcs;
mod whir;

pub(crate) use fri::{
    read_fri_proof, read_hiding_fri_proof, write_fri_proof, write_hiding_fri_proof,
};
pub(crate) use mmcs::{
    MerkleMmcsCodec, MmcsCodec, SaltedMerkleMmcsCodec, read_salted_multi_proof,
    write_salted_multi_proof,
};
pub(crate) use whir::{read_option, read_optional_poly, read_whir_uni_proof, write_whir_uni_proof};

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
    use p3_fri::{BatchMultiOpening, FriProof};
    use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs, PrunedMerklePaths};
    use p3_multilinear_util::poly::Poly;
    use p3_sumcheck::{OpeningBatch, SumcheckData};
    use p3_symmetric::{MerkleCap, PaddingFreeSponge, TruncatedPermutation};
    use p3_whir::{PcsProof, QueryOpenings, SharedProofOpening, WhirProof, WhirRoundProof};
    use rand::rngs::StdRng;

    use crate::artifact::wire::{FieldEncoding, Reader, Writer};
    use crate::artifact::{ArtifactError, ArtifactLimits};
    use crate::pcs::whir::uni::WhirUniProof;

    use super::{
        MerkleMmcsCodec, SaltedMerkleMmcsCodec, read_fri_proof, read_hiding_fri_proof,
        read_salted_multi_proof, read_whir_uni_proof, write_fri_proof, write_hiding_fri_proof,
        write_salted_multi_proof, write_whir_uni_proof,
    };

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
    type PackedF = <F as Field>::Packing;
    type Mmcs = MerkleTreeMmcs<PackedF, PackedF, Hash, Compress, 2, 8>;
    type ChallengeMmcs = ExtensionMmcs<F, EF, Mmcs>;
    type SaltedMmcs = MerkleTreeHidingMmcs<PackedF, PackedF, Hash, Compress, StdRng, 2, 8, 4>;
    type SaltedChallengeMmcs = ExtensionMmcs<F, EF, SaltedMmcs>;

    fn f(value: u32) -> F {
        F::from_u32(value)
    }

    fn ef(values: [u32; 4]) -> EF {
        EF::from_basis_coefficients_fn(|i| f(values[i]))
    }

    fn cap(value: u32) -> MerkleCap<F, [F; 8]> {
        MerkleCap::new(vec![[f(value); 8]])
    }

    fn frontier(value: u32) -> PrunedMerklePaths<F, 8> {
        PrunedMerklePaths {
            sibling_hashes: vec![[f(value); 8]],
        }
    }

    fn ordinary_fri() -> FriProof<EF, ChallengeMmcs, F, Vec<BatchMultiOpening<F, Mmcs>>> {
        FriProof {
            commit_phase_commits: vec![cap(1)],
            commit_pow_witnesses: vec![f(2)],
            input_openings: vec![BatchMultiOpening {
                opened_values: vec![vec![vec![f(3), f(4)]]],
                opening_proof: frontier(5),
            }],
            commit_phase_openings: vec![p3_fri::CommitPhaseMultiStep {
                log_arity: 1,
                sibling_values: vec![vec![ef([6, 7, 8, 9])]],
                opening_proof: frontier(10),
            }],
            final_poly: vec![ef([11, 12, 13, 14])],
            query_pow_witness: f(15),
        }
    }

    fn roundtrip_fri<In, Ch>(
        proof: &FriProof<EF, Ch, F, Vec<BatchMultiOpening<F, In>>>,
        input_codec: &impl super::MmcsCodec<F, In>,
        challenge_codec: &impl super::MmcsCodec<EF, Ch>,
    ) -> FriProof<EF, Ch, F, Vec<BatchMultiOpening<F, In>>>
    where
        In: p3_commit::Mmcs<F>,
        Ch: p3_commit::Mmcs<EF>,
    {
        let limits = ArtifactLimits::default();
        let mut writer = Writer::new(limits.max_proof_bytes);
        write_fri_proof(
            &mut writer,
            proof,
            FieldEncoding::u32(),
            input_codec,
            challenge_codec,
        )
        .unwrap();
        let bytes = writer.finish().unwrap();

        let mut reader = Reader::new(&bytes, &limits);
        let decoded = read_fri_proof(
            &mut reader,
            FieldEncoding::u32(),
            input_codec,
            challenge_codec,
        )
        .unwrap();
        reader.finish().unwrap();

        let mut canonical = Writer::new(limits.max_proof_bytes);
        write_fri_proof(
            &mut canonical,
            &decoded,
            FieldEncoding::u32(),
            input_codec,
            challenge_codec,
        )
        .unwrap();
        assert_eq!(canonical.finish().unwrap(), bytes);
        decoded
    }

    #[test]
    fn ordinary_fri_and_random_codeword_tail_roundtrip_native_objects() {
        let codec = MerkleMmcsCodec::<F, 8>::new(FieldEncoding::u32());
        let proof = ordinary_fri();
        let decoded = roundtrip_fri(&proof, &codec, &codec);
        assert_eq!(decoded.commit_phase_commits[0].roots(), cap(1).roots());
        assert_eq!(decoded.final_poly[0], ef([11, 12, 13, 14]));

        let hiding = (vec![vec![vec![vec![ef([16, 17, 18, 19])]]]], proof);
        let limits = ArtifactLimits::default();
        let mut writer = Writer::new(limits.max_proof_bytes);
        write_hiding_fri_proof(&mut writer, &hiding, FieldEncoding::u32(), &codec, &codec).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = Reader::new(&bytes, &limits);
        let decoded = read_hiding_fri_proof::<F, EF, Mmcs, ChallengeMmcs, _, _>(
            &mut reader,
            FieldEncoding::u32(),
            &codec,
            &codec,
        )
        .unwrap();
        reader.finish().unwrap();
        assert_eq!(decoded.0[0][0][0][0], ef([16, 17, 18, 19]));
        assert_eq!(decoded.1.query_pow_witness, f(15));
    }

    #[test]
    fn salt4_mmcs_roundtrips_and_rejects_wrong_salt_length() {
        let limits = ArtifactLimits::default();
        let proof = (vec![vec![vec![f(1), f(2), f(3), f(4)]]], frontier(5));
        let mut writer = Writer::new(4096);
        write_salted_multi_proof::<F, 8, 4>(&mut writer, &proof, FieldEncoding::u32()).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = Reader::new(&bytes, &limits);
        let decoded =
            read_salted_multi_proof::<F, 8, 4>(&mut reader, FieldEncoding::u32()).unwrap();
        reader.finish().unwrap();
        assert_eq!(decoded.0[0][0], vec![f(1), f(2), f(3), f(4)]);
        assert_eq!(decoded.1.sibling_hashes.len(), 1);

        let malformed = (vec![vec![vec![f(1), f(2), f(3)]]], frontier(5));
        let mut writer = Writer::new(4096);
        assert_eq!(
            write_salted_multi_proof::<F, 8, 4>(&mut writer, &malformed, FieldEncoding::u32()),
            Err(ArtifactError::MalformedProof {
                component: "MMCS salt",
            })
        );

        let salted_codec = SaltedMerkleMmcsCodec::<F, 8, 4>::new(FieldEncoding::u32());
        let inner = ordinary_fri();
        let salted: FriProof<EF, SaltedChallengeMmcs, F, Vec<BatchMultiOpening<F, SaltedMmcs>>> =
            FriProof {
                commit_phase_commits: inner.commit_phase_commits,
                commit_pow_witnesses: inner.commit_pow_witnesses,
                input_openings: vec![BatchMultiOpening {
                    opened_values: vec![vec![vec![f(3)]]],
                    opening_proof: (vec![vec![vec![f(4); 4]]], frontier(5)),
                }],
                commit_phase_openings: vec![p3_fri::CommitPhaseMultiStep {
                    log_arity: 1,
                    sibling_values: inner.commit_phase_openings[0].sibling_values.clone(),
                    opening_proof: (vec![vec![vec![f(6); 4]]], frontier(7)),
                }],
                final_poly: inner.final_poly,
                query_pow_witness: inner.query_pow_witness,
            };
        let decoded = roundtrip_fri(&salted, &salted_codec, &salted_codec);
        assert_eq!(decoded.input_openings[0].opening_proof.0[0][0].len(), 4);
    }

    fn sumcheck(seed: u32) -> SumcheckData<F, EF> {
        SumcheckData {
            polynomial_evaluations: vec![[ef([seed, 0, 0, 0]), ef([seed + 1, 0, 0, 0])]],
            pow_witnesses: vec![f(seed + 2)],
        }
    }

    fn base_opening(seed: u32) -> QueryOpenings<F, EF, PrunedMerklePaths<F, 8>> {
        QueryOpenings::Base(SharedProofOpening {
            rows: vec![vec![f(seed), f(seed + 1)]],
            proof: frontier(seed + 2),
        })
    }

    #[test]
    fn whir_roundtrip_builds_native_options_batches_and_poly() {
        let proof = WhirUniProof::<F, EF, Mmcs> {
            rounds: vec![PcsProof {
                whir: WhirProof {
                    initial_ood_answers: vec![ef([1, 2, 3, 4])],
                    initial_sumcheck: sumcheck(5),
                    rounds: vec![WhirRoundProof {
                        commitment: Some(cap(8)),
                        ood_answers: vec![ef([9, 10, 11, 12])],
                        pow_witness: f(13),
                        openings: base_opening(14),
                        sumcheck: sumcheck(17),
                    }],
                    final_poly: Some(Poly::new(vec![ef([20, 0, 0, 0]), ef([21, 0, 0, 0])])),
                    final_pow_witness: f(22),
                    final_openings: QueryOpenings::Extension(SharedProofOpening {
                        rows: vec![vec![ef([23, 0, 0, 0])]],
                        proof: frontier(24),
                    }),
                    final_sumcheck: Some(sumcheck(25)),
                },
                evals: vec![OpeningBatch::new(
                    vec![ef([28, 0, 0, 0])],
                    vec![ef([29, 0, 0, 0])],
                )],
            }],
        };
        let limits = ArtifactLimits::default();
        let codec = MerkleMmcsCodec::<F, 8>::new(FieldEncoding::u32());
        let mut writer = Writer::new(limits.max_proof_bytes);
        write_whir_uni_proof(&mut writer, &proof, FieldEncoding::u32(), &codec).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = Reader::new(&bytes, &limits);
        let decoded =
            read_whir_uni_proof::<F, EF, Mmcs, _>(&mut reader, FieldEncoding::u32(), &codec)
                .unwrap();
        reader.finish().unwrap();
        assert_eq!(
            decoded.rounds[0]
                .whir
                .final_poly
                .as_ref()
                .unwrap()
                .num_evals(),
            2
        );
        assert_eq!(decoded.rounds[0].evals[0].current(), &[ef([28, 0, 0, 0])]);

        let mut canonical = Writer::new(limits.max_proof_bytes);
        write_whir_uni_proof(&mut canonical, &decoded, FieldEncoding::u32(), &codec).unwrap();
        assert_eq!(canonical.finish().unwrap(), bytes);
    }

    #[test]
    fn malformed_caps_polynomials_options_and_nested_counts_are_typed_errors() {
        let limits = ArtifactLimits::default();
        let codec = MerkleMmcsCodec::<F, 8>::new(FieldEncoding::u32());

        let mut zero_cap = Vec::new();
        zero_cap.extend_from_slice(&1_u32.to_le_bytes());
        zero_cap.extend_from_slice(&0_u32.to_le_bytes());
        let mut reader = Reader::new(&zero_cap, &limits);
        assert!(matches!(
            read_fri_proof::<F, EF, Mmcs, ChallengeMmcs, _, _>(
                &mut reader,
                FieldEncoding::u32(),
                &codec,
                &codec,
            ),
            Err(ArtifactError::MalformedProof {
                component: "Merkle cap",
            })
        ));

        let mut excessive = Vec::new();
        excessive.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut reader = Reader::new(&excessive, &limits);
        assert!(matches!(
            read_whir_uni_proof::<F, EF, Mmcs, _>(&mut reader, FieldEncoding::u32(), &codec,),
            Err(ArtifactError::DecodeLimitExceeded { .. }) | Err(ArtifactError::Truncated)
        ));

        let mut writer = Writer::new(32);
        writer.write_u8(2).unwrap();
        let option = writer.finish().unwrap();
        let mut reader = Reader::new(&option, &limits);
        assert_eq!(
            super::read_option(&mut reader, "final polynomial", |_| Ok::<_, ArtifactError>(
                ()
            )),
            Err(ArtifactError::InvalidTag {
                component: "final polynomial",
                tag: 2,
            })
        );

        let mut writer = Writer::new(64);
        writer.write_u8(1).unwrap();
        writer.write_u32(3).unwrap();
        for _ in 0..3 {
            writer
                .write_extension(FieldEncoding::<F>::u32(), &ef([1, 0, 0, 0]))
                .unwrap();
        }
        let malformed_poly = writer.finish().unwrap();
        let mut reader = Reader::new(&malformed_poly, &limits);
        assert_eq!(
            super::read_optional_poly::<F, EF>(&mut reader, FieldEncoding::u32()),
            Err(ArtifactError::MalformedProof {
                component: "WHIR final polynomial",
            })
        );

        let valid_salt = (vec![vec![vec![f(1), f(2), f(3), f(4)]]], frontier(5));
        let mut writer = Writer::new(4096);
        write_salted_multi_proof::<F, 8, 4>(&mut writer, &valid_salt, FieldEncoding::u32())
            .unwrap();
        let mut malformed_salt = writer.finish().unwrap();
        malformed_salt[8..12].copy_from_slice(&3_u32.to_le_bytes());
        let mut reader = Reader::new(&malformed_salt, &limits);
        assert!(matches!(
            read_salted_multi_proof::<F, 8, 4>(&mut reader, FieldEncoding::u32()),
            Err(ArtifactError::MalformedProof {
                component: "MMCS salt",
            })
        ));

        let mut excessive_frontier = Vec::new();
        excessive_frontier.extend_from_slice(&0_u32.to_le_bytes());
        excessive_frontier.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut reader = Reader::new(&excessive_frontier, &limits);
        assert!(matches!(
            read_salted_multi_proof::<F, 8, 4>(&mut reader, FieldEncoding::u32()),
            Err(ArtifactError::DecodeLimitExceeded {
                component: "compressed frontier hashes",
                ..
            })
        ));

        let empty_fri_final_poly = [0_u8; 20];
        let mut reader = Reader::new(&empty_fri_final_poly, &limits);
        assert_eq!(
            read_fri_proof::<F, EF, Mmcs, ChallengeMmcs, _, _>(
                &mut reader,
                FieldEncoding::u32(),
                &codec,
                &codec,
            )
            .err(),
            Some(ArtifactError::MalformedProof {
                component: "FRI final polynomial",
            })
        );

        let mut reader = Reader::new(&[2], &limits);
        assert!(matches!(
            super::whir::read_query_openings::<F, EF, Mmcs, _>(
                &mut reader,
                FieldEncoding::u32(),
                &codec,
            ),
            Err(ArtifactError::InvalidTag {
                component: "WHIR query field",
                tag: 2,
            })
        ));

        let mut empty_batch = Writer::new(128);
        empty_batch.write_u32(0).unwrap();
        empty_batch.write_u32(0).unwrap();
        empty_batch.write_u32(0).unwrap();
        empty_batch.write_u32(0).unwrap();
        empty_batch.write_u8(0).unwrap();
        empty_batch
            .write_field(FieldEncoding::<F>::u32(), f(0))
            .unwrap();
        empty_batch.write_u8(0).unwrap();
        empty_batch.write_u32(0).unwrap();
        empty_batch.write_u32(0).unwrap();
        empty_batch.write_u8(0).unwrap();
        empty_batch.write_u32(1).unwrap();
        empty_batch.write_u32(0).unwrap();
        empty_batch.write_u32(0).unwrap();
        let empty_batch = empty_batch.finish().unwrap();
        let mut reader = Reader::new(&empty_batch, &limits);
        assert!(matches!(
            super::whir::read_whir_pcs_proof::<F, EF, Mmcs, _>(
                &mut reader,
                FieldEncoding::u32(),
                &codec,
            ),
            Err(ArtifactError::MalformedProof {
                component: "WHIR opening batch",
            })
        ));
    }
}
