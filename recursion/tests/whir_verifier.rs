//! Field/config matrix for the WHIR recursive verifier.
//!
//! Exercises `verify_whir_circuit` under configurations beyond the unit-test
//! baseline (BabyBear D4, 1 round):
//!   - BabyBear D4, 2 rounds — tests the generic multi-round loop and
//!     the Extension-leaf query path that only appears in rounds ≥ 1.
//!   - KoalaBear D4, 1 round — verifies the generic field typing.

use std::collections::VecDeque;

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_commit::MultilinearPcs;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Dimensions;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_poseidon2_circuit_air::{BabyBearD4Width16, KoalaBearD4Width16};
use p3_recursion::Target;
use p3_recursion::pcs::whir::{
    ConstraintWeightData, WhirProofTargets, WhirVerifierParams, verify_whir_circuit,
};
use p3_recursion::pcs::{
    convert_merkle_proof_to_siblings, restore_whir_query_paths, set_whir_mmcs_private_data,
};
use p3_recursion::traits::RecursiveChallenger;
use p3_sumcheck::constraints::{Constraint, Statements};
use p3_sumcheck::layout::{Layout, PrefixProver, Table, Verifier, observe_commitment};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir::pcs::proof::QueryOpenings;
use p3_whir::pcs::prover::WhirProver;
use p3_whir::transcript::{WhirShape, WhirVerifierTranscript};
use rand::SeedableRng;
use rand::rngs::SmallRng;

/// Replay the WHIR Fiat–Shamir transcript over a native `DuplexChallenger` and
/// collect the extension / base samples the `MockChallenger` must return.
///
/// Generic over any number of WHIR rounds; works for both BabyBear and KoalaBear.
macro_rules! whir_arithmetic_test {
    (
        $modname:ident,
        $BF:ty,
        $make_perm:expr,
        $Perm:ty,
        $EF:ty,
        $poseidon_air:ty,
        $poseidon_cfg:expr,
        $num_vars:expr,
        $folding:expr,
        $round_log_inv_rates:expr
    ) => {
        mod $modname {
            use super::*;

            type BF = $BF;
            type EF = $EF;
            type Perm = $Perm;
            type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
            type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
            type PackedBF = <BF as Field>::Packing;
            type MyMmcs = MerkleTreeMmcs<PackedBF, PackedBF, MyHash, MyCompress, 2, 8>;
            type MyDft = Radix2DFTSmallBatch<BF>;
            type MyChallenger = DuplexChallenger<BF, Perm, 16, 8>;
            type TestPcs = WhirProver<EF, BF, MyDft, MyMmcs, MyChallenger, PrefixProver<BF, EF>>;

            fn make_perm() -> Perm {
                ($make_perm)()
            }
            fn make_challenger() -> MyChallenger {
                MyChallenger::new(make_perm())
            }

            struct MockChallenger {
                ext_samples: VecDeque<EF>,
                base_samples: VecDeque<BF>,
            }

            impl RecursiveChallenger<BF, EF> for MockChallenger {
                fn observe(&mut self, _: &mut CircuitBuilder<EF>, _: Target) {}
                fn observe_ext(&mut self, _: &mut CircuitBuilder<EF>, _: Target) {}

                fn sample(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
                    let v = self.base_samples.pop_front().expect("base exhausted");
                    circuit.define_const(EF::from(v))
                }

                fn sample_ext(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
                    let v = self.ext_samples.pop_front().expect("ext exhausted");
                    circuit.define_const(v)
                }

                fn sample_bits(
                    &mut self,
                    circuit: &mut CircuitBuilder<EF>,
                    k: usize,
                ) -> Result<Vec<Target>, CircuitBuilderError> {
                    let raw = self.base_samples.pop_front().expect("base exhausted");
                    let raw_target = circuit.define_const(EF::from(raw));
                    let bits = circuit.decompose_to_bits::<BF>(raw_target, BF::bits())?;
                    Ok(bits[..k].to_vec())
                }

                fn check_pow_witness(
                    &mut self,
                    _: &mut CircuitBuilder<EF>,
                    _: usize,
                    _: Target,
                ) -> Result<(), CircuitBuilderError> {
                    Ok(())
                }

                fn clear(&mut self, _: &mut CircuitBuilder<EF>) {}
            }

            /// Builds the single-column `Table` the test protocol commits to.
            ///
            /// `Table` stores one polynomial per matrix row, so a single polynomial is a
            /// one-row matrix whose width is its hypercube size.
            fn single_poly_table(poly: &Poly<BF>) -> Table<BF> {
                let values = poly.as_slice();
                Table::new(RowMajorMatrix::new(values.to_vec(), values.len()))
            }

            /// Returns the batching challenge `γ` that weights the constraint's statements.
            ///
            /// `challenge_powers(shift)` yields `γ^shift, γ^{shift+1}, …`, so the first
            /// element at `shift = 1` is `γ` itself.
            fn constraint_challenge(constraint: &Constraint<BF, EF>) -> EF {
                constraint
                    .challenge_powers(1)
                    .next()
                    .expect("challenge_powers is an infinite sequence")
            }

            /// Collects the constraint's equality points in batching-power order.
            ///
            /// The native combiner walks the statement groups in order and advances the
            /// challenge exponent by each group's constraint count, so flattening every
            /// `Eq` group's points reproduces the `γ^0, γ^1, …` assignment that
            /// `ConstraintWeightData` applies to `eq_points`. That alignment only holds
            /// while every group is an `Eq` group; a `Next` or `Select` group would consume
            /// powers this flattening cannot see, and neither has an in-circuit weight
            /// gadget.
            fn constraint_eq_points(constraint: &Constraint<BF, EF>) -> Vec<&Point<EF>> {
                constraint
                    .statements()
                    .iter()
                    .flat_map(|statement| {
                        let Statements::Eq(eq_statement) = statement else {
                            panic!("WHIR initial constraint must hold only equality statements");
                        };
                        eq_statement.iter().map(|(point, _eval)| point)
                    })
                    .collect()
            }

            /// Appends one round's opened leaf rows to the circuit's private inputs, in
            /// query order.
            ///
            /// `is_base_round` mirrors the pairing the native `verify_merkle_proof`
            /// enforces: round 0 opens the base-field initial commitment, every later round
            /// opens an extension-field folded commitment. `WhirProofTargets::alloc`
            /// allocates its leaf targets from the same rule, and both variants allocate the
            /// same number of targets, so a variant that disagrees with the round would
            /// authenticate the rows under the wrong leaf encoding instead of being caught
            /// by an input-count check.
            fn push_opening_rows<P>(
                openings: &QueryOpenings<BF, EF, P>,
                is_base_round: bool,
                out: &mut Vec<EF>,
            ) {
                match (openings, is_base_round) {
                    (QueryOpenings::Base(opening), true) => {
                        for row in &opening.rows {
                            out.extend(row.iter().map(|&v| EF::from(v)));
                        }
                    }
                    (QueryOpenings::Extension(opening), false) => {
                        for row in &opening.rows {
                            out.extend(row.iter().copied());
                        }
                    }
                    _ => panic!("query openings field does not match the round"),
                }
            }

            fn digest_to_ext(digest: &[BF; 8]) -> Vec<EF> {
                convert_merkle_proof_to_siblings::<BF, EF, 8>(core::slice::from_ref(digest))
                    .into_iter()
                    .next()
                    .expect("one digest produces one packed entry")
            }

            #[test]
            fn full_mmcs_passes() {
                const NUM_VARIABLES: usize = $num_vars;
                const FOLDING: usize = $folding;

                let perm = make_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm);
                let mmcs = MyMmcs::new(hash, compress, 0);
                let dft = MyDft::default();

                let spec = TableSpec::new(
                    TableShape::new(NUM_VARIABLES, 1),
                    vec![OpeningBatch::new(vec![0], Vec::new())],
                );
                let protocol = OpeningProtocol::new(vec![spec]).pad_to_min_num_variables(FOLDING);
                let poly = Poly::<BF>::rand(&mut SmallRng::seed_from_u64(42), NUM_VARIABLES);
                let witness =
                    PrefixProver::<BF, EF>::new_witness(vec![single_poly_table(&poly)], FOLDING);

                let whir_params = ProtocolParameters {
                    security_level: 32,
                    pow_bits: 0,
                    round_log_inv_rates: $round_log_inv_rates,
                    folding_factor: FoldingFactor::Constant(FOLDING),
                    soundness_type: SecurityAssumption::CapacityBound,
                    starting_log_inv_rate: 1,
                };
                let config =
                    WhirConfig::<EF, BF, MyChallenger>::new(NUM_VARIABLES, whir_params).unwrap();
                let pcs = TestPcs::new(config.clone(), dft, mmcs.clone());

                let (commitment, proof) = {
                    let mut ch = make_challenger();
                    let (commitment, prover_data) =
                        <TestPcs as MultilinearPcs<EF, MyChallenger>>::commit(
                            &pcs, witness, &mut ch,
                        )
                        .unwrap();
                    let proof = <TestPcs as MultilinearPcs<EF, MyChallenger>>::open(
                        &pcs,
                        prover_data,
                        protocol.clone(),
                        &mut ch,
                    )
                    .unwrap();
                    (commitment, proof)
                };

                // Replay the native verifier through p3-whir's own typed transcript, recording
                // every sample the in-circuit verifier draws after the initial constraint.
                let mut ch = make_challenger();
                observe_commitment::<BF, _, _>(&mut ch, commitment.clone());
                let mut lv = Verifier::<BF, EF>::new(
                    &protocol.table_shapes(),
                    PrefixProver::<BF, EF>::strategy(),
                );
                for &eval in &proof.whir.initial_ood_answers {
                    lv.add_virtual_eval(eval, &mut ch);
                }
                for ((table_idx, polys), evals) in protocol.iter_openings().zip(&proof.evals) {
                    lv.add_claim(table_idx, polys, evals, &mut ch)
                        .expect("proof evaluations match the opening schedule shape");
                }

                let mut ext_samples: Vec<EF> = Vec::new();
                let mut base_samples: Vec<BF> = Vec::new();
                let mut round_indices = Vec::new();

                let shape = WhirShape::new(&config, protocol.num_openings());
                let mut vt = WhirVerifierTranscript::<MyChallenger, BF, EF>::new(&mut ch, shape);
                let (initial_constraint, initial_claimed_eval, initial_r) = vt
                    .delegate_initial_fold(|challenger| {
                        let alpha = lv.batching_challenge(challenger);
                        let constraint = lv.constraint(alpha);
                        let mut claimed_eval = EF::ZERO;
                        constraint.combine_evals(&mut claimed_eval);
                        let mut running = claimed_eval;
                        let r = proof.whir.initial_sumcheck.verify_rounds(
                            challenger,
                            &mut running,
                            config.round_folding_factor(0),
                            config.starting_folding_pow_bits(),
                            Basis::Evaluation,
                        );
                        (constraint, claimed_eval, r)
                    });
                ext_samples.extend(initial_r.expect("initial sumcheck replays").as_slice());
                let mut dummy = EF::ZERO;
                for (round_index, (rproof, rp)) in proof
                    .whir
                    .rounds
                    .iter()
                    .zip(config.round_parameters())
                    .enumerate()
                {
                    vt.commitment(
                        rproof
                            .commitment
                            .as_ref()
                            .expect("round commitment")
                            .clone(),
                    );
                    for &answer in &rproof.ood_answers {
                        ext_samples.push(vt.ood_point());
                        vt.ood_answer(answer);
                    }
                    vt.query_pow(round_index, rproof.pow_witness).unwrap();
                    let indices = vt.query_indices(round_index);
                    base_samples.extend(indices.iter().map(|&idx| BF::from_u64(idx as u64)));
                    round_indices.push(indices);
                    ext_samples.push(vt.round_batching());
                    let r = vt
                        .delegate_round_fold(|challenger| {
                            rproof.sumcheck.verify_rounds(
                                challenger,
                                &mut dummy,
                                config.round_folding_factor(round_index + 1),
                                rp.folding_pow_bits,
                                Basis::Evaluation,
                            )
                        })
                        .expect("round sumcheck replays");
                    ext_samples.extend(r.as_slice());
                }
                let n_rounds = proof.whir.rounds.len();
                let fp = proof.whir.final_poly.as_ref().expect("final_poly");
                vt.final_poly(fp.as_slice()).unwrap();
                vt.query_pow(n_rounds, proof.whir.final_pow_witness)
                    .unwrap();
                let final_indices = vt.query_indices(n_rounds);
                base_samples.extend(final_indices.iter().map(|&idx| BF::from_u64(idx as u64)));
                if let Some(r) = vt.delegate_final_fold(|challenger| {
                    p3_sumcheck::verify_final_sumcheck_rounds(
                        proof.whir.final_sumcheck.as_ref(),
                        challenger,
                        &mut dummy,
                        config.final_sumcheck_rounds(),
                        config.final_folding_pow_bits(),
                        Basis::Evaluation,
                    )
                }) {
                    ext_samples.extend(r.expect("final sumcheck replays").as_slice());
                }
                vt.finish();

                let vp = WhirVerifierParams::<BF>::from_config::<EF, MyChallenger>(
                    &config,
                    PrefixProver::<BF, EF>::variable_order(),
                    $poseidon_cfg,
                )
                .expect("non-saturating STIR query counts at this arity");

                let mut circuit = CircuitBuilder::<EF>::new();
                circuit.enable_poseidon2_perm::<$poseidon_air, _>(
                    generate_poseidon2_trace::<EF, $poseidon_air>,
                    make_perm(),
                );
                circuit.enable_recompose::<BF>(generate_recompose_trace::<BF, EF>);
                let proof_targets = WhirProofTargets::alloc::<BF, EF>(&mut circuit, &vp, 1, 2);
                let initial_cap: Vec<Vec<Target>> = commitment
                    .roots()
                    .iter()
                    .map(|digest| {
                        digest_to_ext(digest)
                            .into_iter()
                            .map(|value| circuit.define_const(value))
                            .collect()
                    })
                    .collect();
                let gamma_target = circuit.define_const(constraint_challenge(&initial_constraint));
                let eq_points: Vec<Vec<Target>> = constraint_eq_points(&initial_constraint)
                    .into_iter()
                    .map(|pt| {
                        pt.as_slice()
                            .iter()
                            .map(|&e| circuit.define_const(e))
                            .collect()
                    })
                    .collect();
                let circuit_constraint = ConstraintWeightData {
                    num_variables: initial_constraint.num_variables(),
                    eq_points,
                    sel_scalars: vec![],
                    gamma: gamma_target,
                    initial_power: 0,
                };
                let initial_claimed_eval_target = circuit.define_const(initial_claimed_eval);

                let mut mock = MockChallenger {
                    ext_samples: ext_samples.into_iter().collect(),
                    base_samples: base_samples.into_iter().collect(),
                };
                let op_ids = verify_whir_circuit::<BF, EF, MockChallenger>(
                    &mut circuit,
                    &mut mock,
                    &vp,
                    &proof_targets,
                    &initial_cap,
                    circuit_constraint,
                    initial_claimed_eval_target,
                )
                .expect("verify_whir_circuit failed");

                assert!(
                    mock.ext_samples.is_empty(),
                    "unused ext_samples: {}",
                    mock.ext_samples.len()
                );
                assert!(
                    mock.base_samples.is_empty(),
                    "unused base_samples: {}",
                    mock.base_samples.len()
                );

                let circuit = circuit.build().expect("circuit build failed");

                // Assemble public inputs: loop generically over all rounds.
                let mut public_inputs: Vec<EF> = Vec::new();
                for &v in &proof.whir.initial_ood_answers {
                    public_inputs.push(v);
                }
                for &[c0, cinf] in proof.whir.initial_sumcheck.polynomial_evaluations() {
                    public_inputs.push(c0);
                    public_inputs.push(cinf);
                }
                for r in &proof.whir.rounds {
                    for digest in r.commitment.as_ref().expect("round commitment").roots() {
                        public_inputs.extend(digest_to_ext(digest));
                    }
                    for &v in &r.ood_answers {
                        public_inputs.push(v);
                    }
                    public_inputs.push(EF::from(r.pow_witness));
                    for &[c0, cinf] in r.sumcheck.polynomial_evaluations() {
                        public_inputs.push(c0);
                        public_inputs.push(cinf);
                    }
                }
                for &v in proof.whir.final_poly.as_ref().unwrap().as_slice() {
                    public_inputs.push(v);
                }
                public_inputs.push(EF::from(proof.whir.final_pow_witness));
                if let Some(ref fsc) = proof.whir.final_sumcheck {
                    for &[c0, cinf] in fsc.polynomial_evaluations() {
                        public_inputs.push(c0);
                        public_inputs.push(cinf);
                    }
                }

                // Private inputs: query leaf values across all rounds.
                let mut private_inputs: Vec<EF> = Vec::new();
                for (round_index, r) in proof.whir.rounds.iter().enumerate() {
                    push_opening_rows(&r.openings, round_index == 0, &mut private_inputs);
                }
                // The final openings sit one round past the last round, so they are
                // base-field only when the protocol has no intermediate rounds at all.
                push_opening_rows(
                    &proof.whir.final_openings,
                    proof.whir.rounds.is_empty(),
                    &mut private_inputs,
                );

                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&public_inputs)
                    .expect("set_public_inputs");
                runner
                    .set_private_inputs(&private_inputs)
                    .expect("set_private_inputs");
                let restored_rounds: Vec<_> = proof
                    .whir
                    .rounds
                    .iter()
                    .zip(config.round_parameters())
                    .zip(&round_indices)
                    .map(|((round, params), indices)| {
                        restore_whir_query_paths::<PackedBF, PackedBF, EF, _, _, 2, 8>(
                            &mmcs,
                            &round.openings,
                            &[Dimensions {
                                height: params.domain_size >> params.folding_factor,
                                width: 1 << params.folding_factor,
                            }],
                            indices,
                        )
                        .expect("intermediate WHIR paths restore")
                    })
                    .collect();
                let final_config = config.final_round_config();
                let restored_final =
                    restore_whir_query_paths::<PackedBF, PackedBF, EF, _, _, 2, 8>(
                        &mmcs,
                        &proof.whir.final_openings,
                        &[Dimensions {
                            height: final_config.domain_size >> final_config.folding_factor,
                            width: 1 << final_config.folding_factor,
                        }],
                        &final_indices,
                    )
                    .expect("final WHIR paths restore");
                set_whir_mmcs_private_data::<BF, EF, 8>(
                    &mut runner,
                    &op_ids,
                    &restored_rounds,
                    &restored_final,
                    $poseidon_cfg,
                )
                .expect("WHIR MMCS private data matches circuit operations");
                runner.run().expect("circuit run failed");
            }
        }
    };
}

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_koala_bear::default_koalabear_poseidon2_16;

whir_arithmetic_test!(
    babybear_d4_2rounds,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    16,
    4,
    vec![4usize, 4]
);

whir_arithmetic_test!(
    koalabear_d4_1round,
    KoalaBear,
    default_koalabear_poseidon2_16,
    Poseidon2KoalaBear<16>,
    BinomialExtensionField<KoalaBear, 4>,
    KoalaBearD4Width16,
    p3_circuit::ops::Poseidon2Config::KOALA_BEAR_D4_W16,
    12,
    4,
    vec![4usize]
);
