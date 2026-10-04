//! Poly192 indexed payloads and optional bus claims closed through WHIR.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_bus::{BusActivation, BusBoundary, BusDirection, BusInteractionBuilder, BusName};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{CircuitBuilder, StatementExport};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::IndexedLookupBuilder;
use p3_lookup::indexed::TraceWindow;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::config::MultiStarkConfig;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::verifier::{BinaryPolyWhirMultiStarkVerifier, VerifierLimits};
use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver, Table, Witness};
use p3_test_utils::binary_field_params::{blake3, keccak};
use p3_whir::pcs::WhirProverData;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

struct IndexedPermutationAir {
    activation_mode: u8,
}
impl<F> BaseAir<F> for IndexedPermutationAir {
    fn width(&self) -> usize {
        4
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder<F = Poly64> + BusInteractionBuilder + IndexedLookupBuilder> Air<AB>
    for IndexedPermutationAir
{
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let [_, provider, pulled, square] = main.current_slice().try_into().unwrap();
        let public = b.public_values()[0];
        b.assert_eq(square, pulled * pulled);
        b.when_first_row().assert_eq(provider, public);
        if self.activation_mode == 3 {
            return;
        }
        b.push_indexed_table("permutation-table", TraceWindow::Main, [1]);
        b.push_indexed_read("permutation-table", 0, [2]);
        if self.activation_mode == 0 {
            return;
        }
        b.push_bus_interaction(
            BusName::new("permutation"),
            BusDirection::Push,
            [provider.into(), public.into()],
            BusActivation::Always,
        );
        b.push_bus_interaction(
            BusName::new("permutation"),
            BusDirection::Pull,
            [pulled.into(), public.into()],
            BusActivation::Always,
        );
        if self.activation_mode != 0 {
            let push = if self.activation_mode == 1 {
                BusActivation::Boundary(BusBoundary::First)
            } else {
                BusActivation::Boolean(b.is_first_row())
            };
            let pull = if self.activation_mode == 1 {
                BusActivation::Boundary(BusBoundary::Last)
            } else {
                BusActivation::Boolean(b.is_last_row())
            };
            b.push_bus_interaction(
                BusName::new("endpoints"),
                BusDirection::Push,
                [provider],
                push,
            );
            b.push_bus_interaction(
                BusName::new("endpoints"),
                BusDirection::Pull,
                [pulled],
                pull,
            );
        }
    }
}
macro_rules! check {
    ($params:ident, $layout:ident, $hash:expr, $heights:expr, $variables:expr, $mode:expr) => {{
        type F = Poly64;
        type E = Poly192;
        type Ch = $params::LevelChallenger<F>;
        type M = $params::LevelMmcs<F>;
        type L = $layout<F, E>;
        type P = WhirProver<E, F, BinaryWhirDomain<F>, M, Ch, L>;
        struct Config {
            pcs: P,
        }
        impl MultiStarkConfig for Config {
            type Val = F;
            type Challenge = E;
            type Challenger = Ch;
            type Pcs = P;
            fn pcs(&self) -> &P {
                &self.pcs
            }
            fn min_num_variables(&self) -> usize {
                self.pcs.round_folding_factor(0)
            }
            fn build_witness(&self, tables: Vec<Table<F>>) -> Witness<F> {
                L::new_witness(tables, self.pcs.round_folding_factor(0))
            }
            fn committed_table<'a>(
                &self,
                data: &'a WhirProverData<F, E, M, L>,
                index: usize,
            ) -> &'a Table<F> {
                data.table(index)
            }
        }
        let heights = $heights;
        let domain = BinaryWhirDomain::<F>::default();
        let config = WhirConfig::<E, F, Ch>::new_with_domain(
            $variables,
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
        let mmcs = M::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let native = Config {
            pcs: P::new(config.clone(), domain, mmcs.clone()),
        };
        let air = IndexedPermutationAir {
            activation_mode: $mode,
        };
        let refs = vec![&air; heights.len()];
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let (pk, vk) = setup(&native, &refs, &mut make()).unwrap();
        let recursive = BinaryPolyWhirMultiStarkVerifier::new(
            &refs,
            &heights,
            &config,
            L::variable_order(),
            $hash,
            0,
            0,
            8,
        )
        .unwrap();
        assert_eq!(recursive.input_resource_usage().instances, heights.len());
        let air_limit = VerifierLimits {
            max_instances: heights.len(),
            ..VerifierLimits::default()
        };
        BinaryPolyWhirMultiStarkVerifier::with_limits(
            &refs,
            &heights,
            &config,
            L::variable_order(),
            $hash,
            0,
            0,
            8,
            &air_limit,
        )
        .unwrap();
        let shape = recursive.input_shape();
        let mut builder = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
        }
        let mut exports = vec![];
        let public_targets = heights
            .iter()
            .map(|_| {
                (0..1)
                    .map(|_| {
                        let limbs = core::array::from_fn(|_| builder.public_input());
                        exports.extend(limbs.map(StatementExport::Base));
                        builder.binary_poly64_from_limbs::<BabyBear>(limbs).unwrap()
                    })
                    .collect()
            })
            .collect::<Vec<_>>();
        let targets = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut builder)
            .unwrap();
        let initial = [7, 19, 13].map(|v| builder.define_const(BabyBear::from_u8(v)));
        let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut builder,
            $hash,
            &initial,
        )
        .unwrap();
        let plain_air = IndexedPermutationAir { activation_mode: 3 };
        let plain_refs = vec![&plain_air; heights.len()];
        let plain = BinaryPolyWhirMultiStarkVerifier::new(
            &plain_refs,
            &heights,
            &config,
            L::variable_order(),
            $hash,
            0,
            0,
            8,
        )
        .unwrap();
        assert!(
            plain
                .verify::<BabyBear, BabyBear>(&mut builder, ch.clone(), &public_targets, &targets)
                .is_err()
        );
        let mut missing = targets.clone();
        missing.indexed = None;
        assert!(
            recursive
                .verify::<BabyBear, BabyBear>(&mut builder, ch.clone(), &public_targets, &missing)
                .is_err()
        );
        let mut ch = recursive
            .verify::<BabyBear, BabyBear>(&mut builder, ch, &public_targets, &targets)
            .unwrap();
        for _ in 0..2 {
            let actual = ch
                .sample_poly192::<BabyBear, BabyBear>(&mut builder)
                .unwrap();
            let expected_limbs =
                builder.alloc_private_input_array::<12>("native Poly192 continuation");
            let expected = builder
                .binary_poly192_from_limbs::<BabyBear>(expected_limbs)
                .unwrap();
            for (a, e) in actual.coefficients().iter().zip(expected.coefficients()) {
                for (&a, &e) in a.bits().iter().zip(e.bits()) {
                    let difference = builder.sub(a, e);
                    builder.assert_zero(difference);
                }
            }
        }
        let observation = Poly64::new(0x91ab_cdef_0123_4567);
        let observed = builder
            .binary_poly64_constant(observation.to_bits())
            .unwrap();
        ch.observe_poly64::<BabyBear, BabyBear>(&mut builder, &observed)
            .unwrap();
        let actual = ch
            .sample_poly192::<BabyBear, BabyBear>(&mut builder)
            .unwrap();
        let limbs =
            builder.alloc_private_input_array::<12>("continuation after Poly64 observation");
        let expected = builder
            .binary_poly192_from_limbs::<BabyBear>(limbs)
            .unwrap();
        for (a, e) in actual.coefficients().iter().zip(expected.coefficients()) {
            for (&a, &e) in a.bits().iter().zip(e.bits()) {
                let difference = builder.sub(a, e);
                builder.assert_zero(difference);
            }
        }
        builder.set_statement_exports::<BabyBear>(&exports).unwrap();
        let circuit = builder.build().unwrap();
        let mut last = None;
        for seed in [0x2134_5678_91ab_cdefu64, 0xbcde_f012_3456_789a] {
            let mut publics = vec![];
            let mut tables = vec![];
            for (i, &height) in heights.iter().enumerate() {
                let count = 1usize << height;
                let table_values: Vec<_> = (0..count)
                    .map(|j| F::new(seed.wrapping_add(0x2173_85a9_4fcb * (j + 1 + i) as u64)))
                    .collect();
                let permutation: Vec<_> = if height == 2 {
                    vec![2, 3, 1, 0]
                } else {
                    (0..count).rev().collect()
                };
                let values = (0..count)
                    .flat_map(|row| {
                        let position = permutation[row];
                        let pulled = table_values[position];
                        [
                            F::new(position as u64),
                            table_values[row],
                            pulled,
                            pulled * pulled,
                        ]
                    })
                    .collect();
                publics.push(vec![table_values[0]]);
                tables.push(Table::new(RowMajorMatrix::new(values, 4).transpose()));
            }
            let public = publics;
            let instances = tables
                .into_iter()
                .zip(&public)
                .map(|(table, public)| ProverInstance::new(&air, table, &pk, public))
                .collect();
            let mut proof =
                prove(&native, ProverInstances::new(instances), 0, &mut make()).unwrap();
            assert!(proof.indexed.is_some());
            assert_eq!(proof.bus.is_some(), $mode != 0);
            let mut native_ch = make();
            verify(
                &native,
                VerifierInstances::new(
                    heights
                        .iter()
                        .zip(&public)
                        .map(|(&h, p)| VerifierInstance::new(&air, &vk, h, p))
                        .collect(),
                ),
                &proof,
                0,
                &mut native_ch,
            )
            .unwrap();
            let mut extra_ch = make();
            assert!(
                plain
                    .import_native(&config, &mmcs, &public, &proof, &mut extra_ch)
                    .is_err()
            );
            assert_eq!(
                extra_ch.sample_algebra_element::<E>(),
                make().sample_algebra_element::<E>()
            );
            let original_indexed = proof.indexed.clone();
            for tamper in 0..4 {
                if tamper == 0 {
                    proof.indexed = None;
                } else {
                    let indexed = proof.indexed.as_mut().unwrap();
                    let claim = match tamper {
                        1 => &mut indexed.reader_claims[0][0],
                        2 => &mut indexed.reduction.position_claims[0],
                        _ => &mut indexed.reduction.column_claims[0][0],
                    };
                    let mut coefficients = claim.coefficients();
                    coefficients[2] += F::ONE;
                    *claim = E::new(coefficients);
                }
                let mut failed = make();
                assert!(
                    recursive
                        .import_native(&config, &mmcs, &public, &proof, &mut failed)
                        .is_err()
                );
                assert_eq!(
                    failed.sample_algebra_element::<E>(),
                    make().sample_algebra_element::<E>()
                );
                proof.indexed = original_indexed.clone();
            }
            let mut imported_ch = make();
            let imported = recursive
                .import_native(&config, &mmcs, &public, &proof, &mut imported_ch)
                .unwrap();
            let pack = |raw: u64| (0..4).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
            let mut private = imported.private_values::<BabyBear>(&shape).unwrap();
            for _ in 0..2 {
                let next = native_ch.sample_algebra_element::<E>();
                assert_eq!(next, imported_ch.sample_algebra_element::<E>());
                private.extend(
                    next.coefficients()
                        .into_iter()
                        .flat_map(|c| pack(c.to_bits())),
                );
            }
            native_ch.observe(observation);
            imported_ch.observe(observation);
            let next = native_ch.sample_algebra_element::<E>();
            assert_eq!(next, imported_ch.sample_algebra_element::<E>());
            private.extend(
                next.coefficients()
                    .into_iter()
                    .flat_map(|c| pack(c.to_bits())),
            );
            let public_limbs: Vec<_> = public
                .iter()
                .flatten()
                .flat_map(|v| pack(v.to_bits()))
                .collect();
            let mut runner = circuit.runner();
            runner.set_private_inputs(&private).unwrap();
            runner.set_public_inputs(&public_limbs).unwrap();
            runner.run().unwrap();
            let mut wrong = public_limbs.clone();
            wrong[0] += BabyBear::ONE;
            let mut runner = circuit.runner();
            runner.set_private_inputs(&private).unwrap();
            runner.set_public_inputs(&wrong).unwrap();
            assert!(runner.run().is_err());
            for at in [0, 16 + 12 + 8, private.len() - 4] {
                let mut wrong = private.clone();
                wrong[at] += BabyBear::ONE;
                let mut runner = circuit.runner();
                if runner.set_private_inputs(&wrong).is_ok() {
                    runner.set_public_inputs(&public_limbs).unwrap();
                    assert!(runner.run().is_err());
                }
            }
            last = Some((private, public_limbs));
        }
        let (private, public) = last.unwrap();
        (circuit, private, public)
    }};
}
#[test]
fn poly_indexed_payloads_close_for_both_layouts_and_hashes() {
    check!(keccak, SuffixProver, ByteHash::Keccak256, vec![2], 4, 0);
    check!(blake3, PrefixProver, ByteHash::Blake3, vec![2], 4, 0);
}

#[test]
fn poly_bus_and_indexed_claims_share_the_exact_transcript() {
    check!(blake3, SuffixProver, ByteHash::Blake3, vec![2], 4, 1);
    check!(keccak, PrefixProver, ByteHash::Keccak256, vec![2], 4, 2);
}

#[test]
fn a_composed_poly_indexed_bus_relation_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver, StatementAirBuilder, StatementPreprocessor, StatementProver,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, private, public) = check!(blake3, SuffixProver, ByteHash::Blake3, vec![2], 4, 1);
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(Blake3CompressProver::<1>));
    let schema = circuit.statement_schema().unwrap().clone();
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema.clone())));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &[
                Box::new(Blake3CompressPreprocessor),
                Box::new(StatementPreprocessor::new(schema.clone())),
            ],
            &[
                Box::new(Blake3CompressAirBuilder::<1>),
                Box::new(StatementAirBuilder::<1>::new(schema)),
            ],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&private).unwrap();
    runner.set_public_inputs(&public).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &public).unwrap();
}

#[test]
fn checked_poly_indexed_owner_decodes_and_rejects_full_width_tampering() {
    use p3_recursion::artifact::{
        BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters, BinaryNativeVerifierSpec,
        CanonicalBinaryStatement, ExpectedVerifierArtifact,
    };
    for hash in [ByteHash::Blake3, ByteHash::Keccak256] {
        let spec = BinaryNativeVerifierSpec {
            main: BinaryNativePolyWhirPcsParameters::new(
                4,
                ProtocolParameters {
                    security_level: 24,
                    pow_bits: 0,
                    round_log_inv_rates: vec![],
                    folding_factor: FoldingFactor::Constant(2),
                    soundness_type: SecurityAssumption::JohnsonBound,
                    starting_log_inv_rate: 2,
                },
                hash,
                0,
            )
            .unwrap(),
            preprocessed: None,
            transcript_hash: hash,
            initial_bytes: vec![7, 19, 13],
            sumcheck_pow_bits: 0,
            max_tau_draws: 8,
            security_bits: 8,
        };
        let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
            vec![IndexedPermutationAir { activation_mode: 0 }],
            vec![2],
            spec,
            &VerifierLimits::default(),
        )
        .unwrap();
        let values = [
            0xfedc_ba98_7654_3210u64,
            0x9173_2548_efca_bd60,
            0x1234_5678_9abc_def0,
            0x8426_7301_bfac_de95,
        ]
        .map(Poly64::new);
        let public = vec![vec![values[0]]];
        let trace = (0..4)
            .flat_map(|row| {
                let position = [2, 3, 1, 0][row];
                let pulled = values[position];
                [
                    Poly64::new(position as u64),
                    values[row],
                    pulled,
                    pulled * pulled,
                ]
            })
            .collect();
        let mut proof = prover
            .prove(&public, vec![RowMajorMatrix::new(trace, 4)])
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
        let checked = decode(&bytes).unwrap();
        checked
            .native_input()
            .private_values::<BabyBear>(&authority.recursive_verifier().input_shape())
            .unwrap();
        for length in 0..bytes.len() {
            assert!(decode(&bytes[..length]).is_err());
        }
        let root = &mut proof.indexed.as_mut().unwrap().reduction.position_claims[0];
        let mut coefficients = root.coefficients();
        coefficients[2] += Poly64::ONE;
        *root = Poly192::new(coefficients);
        assert!(authority.verify_native(&proof, &public).is_err());
        proof.indexed = None;
        assert!(authority.encode_native_proof(&proof, &public).is_err());
    }
}
