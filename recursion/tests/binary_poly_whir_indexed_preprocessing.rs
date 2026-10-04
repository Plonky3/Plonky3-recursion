//! Indexed provider columns authenticated through independent preprocessing WHIR.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_challenger::FieldChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::ByteHash;
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::IndexedLookupBuilder;
use p3_lookup::indexed::TraceWindow;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::verifier::{
    BinaryPolyWhirMultiStarkPreprocessing, BinaryPolyWhirMultiStarkVerifier, VerifierLimits,
};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Witness};
use p3_test_utils::binary_field_params::blake3;
use p3_whir::pcs::WhirProverData;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

struct IndexedPreprocessingAir;
impl BaseAir<Poly64> for IndexedPreprocessingAir {
    fn width(&self) -> usize {
        3
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        2
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Poly64>> {
        Some(RowMajorMatrix::new(
            (0..8)
                .flat_map(|i| {
                    let x = Poly64::new(0x1234_abcd_7654_ef90u64 ^ (i * 0x2317_9bad_fedcu64));
                    [x, x * x]
                })
                .collect(),
            2,
        ))
    }
}
impl<AB: AirBuilder<F = Poly64> + IndexedLookupBuilder + BusInteractionBuilder> Air<AB>
    for IndexedPreprocessingAir
{
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let provider = b.preprocessed().current_slice()[0];
        let pulled = main.current_slice()[1];
        let public = b.public_values()[0];
        b.when_first_row().assert_eq(pulled, public);
        b.assert_eq(main.current_slice()[2], pulled * pulled);
        b.push_indexed_table("preprocessed", TraceWindow::Preprocessed, [1, 0]);
        b.push_indexed_read("preprocessed", 0, [2, 1]);
        b.push_bus_interaction(
            BusName::new("values"),
            BusDirection::Push,
            [provider],
            BusActivation::Always,
        );
        b.push_bus_interaction(
            BusName::new("values"),
            BusDirection::Pull,
            [pulled],
            BusActivation::Always,
        );
    }
}

type PpCh = blake3::LevelChallenger<Poly64>;
type PpTree = blake3::LevelMmcs<Poly64>;
type PpLayout = SuffixProver<Poly64, Poly192>;
type PpPcs = WhirProver<Poly192, Poly64, BinaryWhirDomain<Poly64>, PpTree, PpCh, PpLayout>;
struct PpConfig {
    main: PpPcs,
    pp: PpPcs,
}
impl MultiStarkConfig for PpConfig {
    type Val = Poly64;
    type Challenge = Poly192;
    type Challenger = PpCh;
    type Pcs = PpPcs;
    fn pcs(&self) -> &PpPcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &PpPcs {
        &self.pp
    }
    fn min_num_variables(&self) -> usize {
        self.main.round_folding_factor(0)
    }
    fn build_witness(&self, tables: Vec<Table<Poly64>>) -> Witness<Poly64> {
        PpLayout::new_witness(tables, self.main.round_folding_factor(0))
    }
    fn committed_table<'a>(
        &self,
        data: &'a WhirProverData<Poly64, Poly192, PpTree, PpLayout>,
        index: usize,
    ) -> &'a Table<Poly64> {
        data.table(index)
    }
}

#[test]
fn indexed_columns_and_bus_claims_close_through_independent_preprocessing() {
    let domain = BinaryWhirDomain::<Poly64>::default();
    let parameters = |variables, rate| {
        WhirConfig::<Poly192, Poly64, PpCh>::new_with_domain(
            variables,
            ProtocolParameters {
                security_level: 8,
                pow_bits: 0,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: rate,
            },
            &domain,
        )
        .unwrap()
    };
    let main_cfg = parameters(5, 1);
    let pp_cfg = parameters(4, 2);
    let tree = |height| {
        PpTree::new(
            blake3::FieldHash::new(blake3::byte_hash()),
            blake3::Compress::new(blake3::byte_hash()),
            height,
        )
    };
    let main_tree = tree(0);
    let pp_tree = tree(1);
    let native = PpConfig {
        main: PpPcs::new(main_cfg.clone(), domain.clone(), main_tree.clone()),
        pp: PpPcs::new(pp_cfg.clone(), domain, pp_tree.clone()),
    };
    let make = || PpCh::from_hasher(vec![7, 19, 13], blake3::byte_hash());
    let air = IndexedPreprocessingAir;
    let (pk, vk) = setup(&native, &[&air], &mut make()).unwrap();
    let rows = air.preprocessed_trace().unwrap();
    let public = vec![vec![rows.values[14]]];
    let permutation = [7, 2, 5, 0, 6, 3, 1, 4];
    let trace = permutation
        .into_iter()
        .flat_map(|position| {
            [
                Poly64::new(position as u64),
                rows.values[2 * position],
                rows.values[2 * position + 1],
            ]
        })
        .collect();
    let table = Table::new(RowMajorMatrix::new(trace, 3).transpose());
    let pp_table = Table::new(rows.transpose());
    let (pp_cap, _) = native
        .pp
        .commit(PpLayout::new_witness(vec![pp_table], 1), &mut make())
        .unwrap();
    let build = |limits: &VerifierLimits| {
        BinaryPolyWhirMultiStarkVerifier::with_preprocessing(
            &[&air],
            &[3],
            &main_cfg,
            PpLayout::variable_order(),
            ByteHash::Blake3,
            0,
            0,
            8,
            BinaryPolyWhirMultiStarkPreprocessing {
                config: pp_cfg.clone(),
                order: PpLayout::variable_order(),
                hash: ByteHash::Blake3,
                cap_height: 1,
                commitment: pp_cap.clone(),
            },
            limits,
        )
    };
    let recursive = build(&VerifierLimits::default()).unwrap();
    let below = VerifierLimits {
        max_compressed_frontier_hashes: recursive.input_resource_usage().compressed_frontier_hashes
            - 1,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        build(&below),
        Err(
            p3_recursion::verifier::VerificationError::ResourceLimitExceeded {
                component: "compressed frontier hashes",
                ..
            }
        )
    ));
    assert_eq!(recursive.input_resource_usage().instances, 1);
    assert!(
        build(&VerifierLimits {
            max_instances: 1,
            ..VerifierLimits::default()
        })
        .is_ok()
    );
    assert!(
        build(&VerifierLimits {
            max_instances: 0,
            ..VerifierLimits::default()
        })
        .is_err()
    );
    let mut proof = prove(
        &native,
        ProverInstances::new(vec![ProverInstance::new(&air, table, &pk, &public[0])]),
        0,
        &mut make(),
    )
    .unwrap();
    let saved_openings = proof
        .preprocessed_opening
        .as_ref()
        .unwrap()
        .whir
        .final_openings
        .clone();
    use p3_whir::pcs::proof::QueryOpenings;
    for late in [false, true] {
        let openings = &mut proof
            .preprocessed_opening
            .as_mut()
            .unwrap()
            .whir
            .final_openings;
        if late {
            let hashes = match openings {
                QueryOpenings::Base(o) => &mut o.proof.sibling_hashes,
                QueryOpenings::Extension(o) => &mut o.proof.sibling_hashes,
            };
            hashes
                .pop()
                .expect("fixture has a nonempty preprocessing frontier");
        } else {
            match openings {
                QueryOpenings::Base(o) => {
                    o.rows.pop();
                }
                QueryOpenings::Extension(o) => {
                    o.rows.pop();
                }
            }
        }
        let mut unchanged = make();
        let result = recursive.import_native_with_preprocessing::<PpConfig, _, _, _>(
            &main_cfg,
            &main_tree,
            Some((&pp_cfg, &pp_tree)),
            &public,
            &proof,
            &mut unchanged,
        );
        if late {
            assert!(matches!(result,
                Err(p3_recursion::verifier::VerificationError::InvalidProofShape(message))
                if message == "binary WHIR native path restoration failed"));
        } else {
            assert!(result.is_err());
        }
        assert_eq!(
            unchanged.sample_algebra_element::<Poly192>(),
            make().sample_algebra_element::<Poly192>()
        );
        proof
            .preprocessed_opening
            .as_mut()
            .unwrap()
            .whir
            .final_openings = saved_openings.clone();
    }
    let original_indexed = proof.indexed.clone();
    let mut columns = proof.indexed.as_mut().unwrap().reduction.column_claims[0][0].coefficients();
    columns[2] += Poly64::ONE;
    proof.indexed.as_mut().unwrap().reduction.column_claims[0][0] = Poly192::new(columns);
    let mut failed = make();
    assert!(
        recursive
            .import_native_with_preprocessing::<PpConfig, _, _, _>(
                &main_cfg,
                &main_tree,
                Some((&pp_cfg, &pp_tree)),
                &public,
                &proof,
                &mut failed
            )
            .is_err()
    );
    assert_eq!(
        failed.sample_algebra_element::<Poly192>(),
        make().sample_algebra_element::<Poly192>()
    );
    proof.indexed = original_indexed;
    let mut expected = make();
    verify(
        &native,
        VerifierInstances::new(vec![VerifierInstance::new(&air, &vk, 3, &public[0])]),
        &proof,
        0,
        &mut expected,
    )
    .unwrap();
    let mut imported_ch = make();
    let input = recursive
        .import_native_with_preprocessing::<PpConfig, _, _, _>(
            &main_cfg,
            &main_tree,
            Some((&pp_cfg, &pp_tree)),
            &public,
            &proof,
            &mut imported_ch,
        )
        .unwrap();
    let next = expected.sample_algebra_element::<Poly192>();
    assert_eq!(next, imported_ch.sample_algebra_element::<Poly192>());
    let shape = recursive.input_shape();
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_blake3_compress::<BabyBear>();
    let public_limbs = core::array::from_fn(|_| b.public_input());
    let public_target = b
        .binary_poly64_from_limbs::<BabyBear>(public_limbs)
        .unwrap();
    let targets = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let initial = [7, 19, 13].map(|v| b.define_const(BabyBear::from_u8(v)));
    let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
        &mut b,
        ByteHash::Blake3,
        &initial,
    )
    .unwrap();
    let mut ch = recursive
        .verify::<BabyBear, BabyBear>(&mut b, ch, &[vec![public_target]], &targets)
        .unwrap();
    let actual = ch.sample_poly192::<BabyBear, BabyBear>(&mut b).unwrap();
    let limbs = b.alloc_private_input_array::<12>("preprocessed Poly continuation");
    let compared = b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap();
    for (a, e) in actual.coefficients().iter().zip(compared.coefficients()) {
        for (&a, &e) in a.bits().iter().zip(e.bits()) {
            let diff = b.sub(a, e);
            b.assert_zero(diff);
        }
    }
    let circuit = b.build().unwrap();
    let pack = |raw: u64| (0..4).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
    let mut private = input.private_values::<BabyBear>(&shape).unwrap();
    private.extend(
        next.coefficients()
            .into_iter()
            .flat_map(|c| pack(c.to_bits())),
    );
    let public_limbs = pack(public[0][0].to_bits()).collect::<Vec<_>>();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&private).unwrap();
    runner.set_public_inputs(&public_limbs).unwrap();
    runner.run().unwrap();
}

#[test]
fn checked_indexed_preprocessing_owner_binds_independent_hashes_and_caps() {
    use p3_recursion::artifact::{
        BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters, BinaryNativeVerifierSpec,
        CanonicalBinaryStatement, ExpectedVerifierArtifact,
    };
    let params = |n, hash, cap| {
        BinaryNativePolyWhirPcsParameters::new(
            n,
            ProtocolParameters {
                security_level: 24,
                pow_bits: 0,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 2,
            },
            hash,
            cap,
        )
        .unwrap()
    };
    let spec = BinaryNativeVerifierSpec {
        main: params(5, ByteHash::Keccak256, 0),
        preprocessed: Some(params(4, ByteHash::Blake3, 1)),
        transcript_hash: ByteHash::Blake3,
        initial_bytes: vec![7, 19, 13],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 8,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        vec![IndexedPreprocessingAir],
        vec![3],
        spec,
        &VerifierLimits {
            max_instances: 1,
            ..VerifierLimits::default()
        },
    )
    .unwrap();
    let rows = IndexedPreprocessingAir.preprocessed_trace().unwrap();
    let public = vec![vec![rows.values[14]]];
    let trace = [7, 2, 5, 0, 6, 3, 1, 4]
        .into_iter()
        .flat_map(|position| {
            [
                Poly64::new(position as u64),
                rows.values[2 * position],
                rows.values[2 * position + 1],
            ]
        })
        .collect();
    let mut proof = prover
        .prove(&public, vec![RowMajorMatrix::new(trace, 3)])
        .unwrap();
    let bytes = authority.encode_native_proof(&proof, &public).unwrap();
    let statement = authority.encode_statement(&public).unwrap();
    let identity = authority.canonical_verifier_bytes();
    let decode = |bytes: &[u8]| {
        authority.decode_and_verify(
            identity,
            ExpectedVerifierArtifact::from_trusted_bytes(identity),
            bytes,
            CanonicalBinaryStatement::new(&statement, 1),
        )
    };
    decode(&bytes)
        .unwrap()
        .native_input()
        .private_values::<BabyBear>(&authority.recursive_verifier().input_shape())
        .unwrap();
    for length in [0, bytes.len() / 2, bytes.len() - 1] {
        assert!(decode(&bytes[..length]).is_err());
    }
    let mut coefficients =
        proof.indexed.as_ref().unwrap().reduction.column_claims[0][0].coefficients();
    coefficients[2] += Poly64::ONE;
    proof.indexed.as_mut().unwrap().reduction.column_claims[0][0] = Poly192::new(coefficients);
    assert!(authority.verify_native(&proof, &public).is_err());
    proof.indexed = None;
    assert!(authority.encode_native_proof(&proof, &public).is_err());
}
