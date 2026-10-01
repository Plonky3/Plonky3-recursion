//! Field/config matrix for the WHIR recursive verifier.
//!
//! Exercises `verify_whir_circuit` under configurations beyond the unit-test
//! baseline (BabyBear D4, 1 round):
//!   - BabyBear D4, 2 rounds — tests the generic multi-round loop and
//!     the Extension-leaf query path that only appears in rounds ≥ 1.
//!   - KoalaBear D4, 1 round — verifies the generic field typing.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, DuplexChallenger, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_circuit::ops::{Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitError};
use p3_commit::MultilinearPcs;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Dimensions;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_poseidon2_circuit_air::{BabyBearD4Width16, KoalaBearD4Width16};
use p3_recursion::pcs::whir::{
    ConstraintWeightData, WhirProofTargets, WhirVerifierParams, verify_whir_circuit,
};
use p3_recursion::pcs::{
    convert_merkle_proof_to_siblings, restore_whir_query_paths, set_whir_mmcs_private_data,
};
use p3_recursion::traits::RecursiveChallenger;
use p3_recursion::{CircuitChallenger, Target};
use p3_sumcheck::constraints::{Constraint, Statements};
use p3_sumcheck::layout::{
    Layout, PrefixProver, SuffixProver, Table, Verifier, observe_commitment,
};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_symmetric::{MerkleCap, PaddingFreeSponge, TruncatedPermutation};
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir::pcs::proof::QueryOpenings;
use p3_whir::pcs::prover::WhirProver;
use p3_whir::transcript::{WhirShape, WhirVerifierTranscript};
use rand::SeedableRng;
use rand::rngs::SmallRng;

/// Compare WHIR's native Fiat–Shamir transcript with a real circuit challenger.
///
/// Generic over any number of WHIR rounds; works for both BabyBear and KoalaBear.
macro_rules! whir_arithmetic_test {
    (
        $modname:ident,
        $Layout:ident,
        $BF:ty,
        $make_perm:expr,
        $Perm:ty,
        $EF:ty,
        $poseidon_air:ty,
        $poseidon_cfg:expr,
        $num_vars:expr,
        $folding:expr,
        $folding_strategy:expr,
        $expected_schedule:expr,
        $security:expr,
        $round_log_inv_rates:expr,
        $soundness:expr,
        $expected_round_saturation:expr,
        $expected_final_saturation:expr
    ) => {
        mod $modname {
            use super::*;

            type BF = $BF;
            type EF = $EF;
            type TestLayout = $Layout<BF, EF>;
            type Perm = $Perm;
            type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
            type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
            type PackedBF = <BF as Field>::Packing;
            type MyMmcs = MerkleTreeMmcs<PackedBF, PackedBF, MyHash, MyCompress, 2, 8>;
            type MyDft = Radix2DFTSmallBatch<BF>;
            type NativeDuplex = DuplexChallenger<BF, Perm, 16, 8>;
            type MyChallenger = RecordingNativeChallenger;
            type TestPcs = WhirProver<EF, BF, MyDft, MyMmcs, MyChallenger, TestLayout>;

            fn make_perm() -> Perm {
                ($make_perm)()
            }
            fn make_challenger() -> MyChallenger {
                MyChallenger {
                    inner: NativeDuplex::new(make_perm()),
                    events: Vec::new(),
                    bit_calls: 0,
                    uniform_widths: Vec::new(),
                }
            }

            #[derive(Clone, Copy)]
            enum NativeEvent {
                Observe(BF),
                Sample(BF),
            }

            #[derive(Clone)]
            struct RecordingNativeChallenger {
                inner: NativeDuplex,
                events: Vec<NativeEvent>,
                bit_calls: usize,
                uniform_widths: Vec<usize>,
            }

            impl CanObserve<BF> for RecordingNativeChallenger {
                fn observe(&mut self, value: BF) {
                    self.events.push(NativeEvent::Observe(value));
                    self.inner.observe(value);
                }
            }

            impl CanObserve<MerkleCap<BF, [BF; 8]>> for RecordingNativeChallenger {
                fn observe(&mut self, cap: MerkleCap<BF, [BF; 8]>) {
                    for digest in cap.roots() {
                        for &value in digest {
                            <Self as CanObserve<BF>>::observe(self, value);
                        }
                    }
                }
            }

            impl CanSample<BF> for RecordingNativeChallenger {
                fn sample(&mut self) -> BF {
                    let value = self.inner.sample();
                    self.events.push(NativeEvent::Sample(value));
                    value
                }
            }

            impl CanSampleBits<usize> for RecordingNativeChallenger {
                fn sample_bits(&mut self, bits: usize) -> usize {
                    self.bit_calls += 1;
                    self.inner.sample_bits(bits)
                }
            }

            impl CanSampleUniformBits<BF> for RecordingNativeChallenger {
                fn sample_uniform_bits<const RESAMPLE: bool>(
                    &mut self,
                    bits: usize,
                ) -> Result<usize, ResamplingError> {
                    self.uniform_widths.push(bits);
                    self.inner.sample_uniform_bits::<RESAMPLE>(bits)
                }
            }

            impl FieldChallenger<BF> for RecordingNativeChallenger {}

            impl GrindingChallenger for RecordingNativeChallenger {
                type Witness = BF;

                fn grind(&mut self, bits: usize) -> BF {
                    assert_eq!(bits, 0, "the transcript oracle requires zero PoW");
                    self.inner.grind(bits)
                }
            }

            struct RecordingCircuitChallenger {
                inner: CircuitChallenger<16, 8, Poseidon2Config>,
                bit_widths: Vec<usize>,
            }

            impl RecursiveChallenger<BF, EF> for RecordingCircuitChallenger {
                fn observe(&mut self, circuit: &mut CircuitBuilder<EF>, value: Target) {
                    RecursiveChallenger::<BF, EF>::observe(&mut self.inner, circuit, value);
                }

                fn observe_ext(&mut self, circuit: &mut CircuitBuilder<EF>, value: Target) {
                    RecursiveChallenger::<BF, EF>::observe_ext(&mut self.inner, circuit, value);
                }

                fn sample(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
                    RecursiveChallenger::<BF, EF>::sample(&mut self.inner, circuit)
                }

                fn sample_ext(&mut self, circuit: &mut CircuitBuilder<EF>) -> Target {
                    RecursiveChallenger::<BF, EF>::sample_ext(&mut self.inner, circuit)
                }

                fn sample_bits(
                    &mut self,
                    circuit: &mut CircuitBuilder<EF>,
                    k: usize,
                ) -> Result<Vec<Target>, CircuitBuilderError> {
                    self.bit_widths.push(k);
                    RecursiveChallenger::<BF, EF>::sample_bits(&mut self.inner, circuit, k)
                }

                fn check_pow_witness(
                    &mut self,
                    circuit: &mut CircuitBuilder<EF>,
                    bits: usize,
                    witness: Target,
                ) -> Result<(), CircuitBuilderError> {
                    RecursiveChallenger::<BF, EF>::check_pow_witness(
                        &mut self.inner,
                        circuit,
                        bits,
                        witness,
                    )
                }

                fn clear(&mut self, circuit: &mut CircuitBuilder<EF>) {
                    RecursiveChallenger::<BF, EF>::clear(&mut self.inner, circuit);
                }
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

            fn opening_row_widths<P>(openings: &QueryOpenings<BF, EF, P>) -> Vec<usize> {
                match openings {
                    QueryOpenings::Base(opening) => opening.rows.iter().map(Vec::len).collect(),
                    QueryOpenings::Extension(opening) => {
                        opening.rows.iter().map(Vec::len).collect()
                    }
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
                let witness = TestLayout::new_witness(vec![single_poly_table(&poly)], FOLDING);

                let whir_params = ProtocolParameters {
                    security_level: $security,
                    pow_bits: 0,
                    round_log_inv_rates: $round_log_inv_rates,
                    folding_factor: $folding_strategy,
                    soundness_type: $soundness,
                    starting_log_inv_rate: 1,
                };
                let config =
                    WhirConfig::<EF, BF, MyChallenger>::new(NUM_VARIABLES, whir_params).unwrap();
                assert_eq!(config.params().pow_bits, 0);
                assert_eq!(config.starting_folding_pow_bits(), 0);
                assert_eq!(config.final_folding_pow_bits(), 0);
                assert_eq!(config.terminal().pow_bits, 0);
                for round in config.round_parameters() {
                    assert_eq!(round.pow_bits, 0);
                    assert_eq!(round.folding_pow_bits, 0);
                }
                assert!(
                    3 * <EF as BasedVectorSpace<BF>>::DIMENSION > 8,
                    "three EF draws must cross the sponge rate"
                );
                assert_eq!(config.folding_schedule(), $expected_schedule);
                assert_eq!(config.folding_schedule()[0], FOLDING);
                assert_eq!(
                    config
                        .round_parameters()
                        .iter()
                        .map(|round| round.num_queries >= round.domain_size >> round.folding_factor)
                        .collect::<Vec<_>>(),
                    $expected_round_saturation,
                    "derived intermediate saturation differs from fixture"
                );
                let final_config = config.final_round_config();
                assert_eq!(
                    final_config.num_queries
                        >= final_config.domain_size >> final_config.folding_factor,
                    $expected_final_saturation,
                    "derived final saturation differs from fixture"
                );
                if NUM_VARIABLES == 4 && FOLDING == 4 {
                    assert_eq!(final_config.num_queries, 35);
                    assert_eq!(final_config.domain_size >> final_config.folding_factor, 2);
                    assert_eq!(config.final_sumcheck_rounds(), 0);
                }
                if NUM_VARIABLES == 11 && $security == 32 {
                    assert_eq!(config.round_parameters()[0].num_queries, 35);
                    assert_eq!(
                        config.round_parameters()[0].domain_size
                            >> config.round_parameters()[0].folding_factor,
                        256
                    );
                    assert_eq!(final_config.num_queries, 35);
                    assert_eq!(final_config.domain_size >> final_config.folding_factor, 16);
                }
                if NUM_VARIABLES == 11 && $security == 106 {
                    assert_eq!(config.round_parameters()[0].num_queries, 256);
                    assert_eq!(
                        config.round_parameters()[0].domain_size
                            >> config.round_parameters()[0].folding_factor,
                        256
                    );
                    assert_eq!(final_config.num_queries, 256);
                    assert_eq!(final_config.domain_size >> final_config.folding_factor, 16);
                }
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

                // The official PCS verifier checks the proof and supplies the end-state oracle.
                let mut official = make_challenger();
                <TestPcs as MultilinearPcs<EF, MyChallenger>>::verify(
                    &pcs,
                    &commitment,
                    &proof,
                    &mut official,
                    protocol.clone(),
                )
                .expect("official native PCS verification failed");
                assert_eq!(official.bit_calls, 0);
                let official_widths = official.uniform_widths.clone();
                let official_tail: [EF; 3] =
                    core::array::from_fn(|_| official.sample_algebra_element());

                // The typed native replay exposes the exact adapter-to-engine checkpoint
                // and query indices needed to restore authenticated paths.
                let mut ch = make_challenger();
                observe_commitment::<BF, _, _>(&mut ch, commitment.clone());
                let mut lv =
                    Verifier::<BF, EF>::new(&protocol.table_shapes(), TestLayout::strategy());
                for &eval in &proof.whir.initial_ood_answers {
                    lv.add_virtual_eval(eval, &mut ch);
                }
                for ((table_idx, polys), evals) in protocol.iter_openings().zip(&proof.evals) {
                    lv.add_claim(table_idx, polys, evals, &mut ch)
                        .expect("proof evaluations match the opening schedule shape");
                }

                let mut initial_events = None;
                let mut expected_bit_widths = Vec::new();
                let mut round_indices = Vec::new();

                let shape = WhirShape::new(&config, protocol.num_openings());
                let mut vt = WhirVerifierTranscript::<MyChallenger, BF, EF>::new(&mut ch, shape);
                let (initial_constraint, initial_claimed_eval, initial_r) = vt
                    .delegate_initial_fold(|challenger| {
                        let alpha = lv.batching_challenge(challenger);
                        let constraint = lv.constraint(alpha);
                        let mut claimed_eval = EF::ZERO;
                        constraint.combine_evals(&mut claimed_eval);
                        assert_eq!(challenger.bit_calls, 0);
                        assert!(challenger.uniform_widths.is_empty());
                        initial_events = Some(challenger.events.clone());
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
                let _ = initial_r.expect("initial sumcheck replays");
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
                        let _ = vt.ood_point();
                        vt.ood_answer(answer);
                    }
                    vt.query_pow(round_index, rproof.pow_witness).unwrap();
                    let indices = vt.query_indices(round_index);
                    let folded_domain_size = rp.domain_size >> rp.folding_factor;
                    if rp.num_queries >= folded_domain_size {
                        assert_eq!(indices, (0..folded_domain_size).collect::<Vec<_>>());
                    } else {
                        expected_bit_widths.extend(core::iter::repeat_n(
                            folded_domain_size.ilog2() as usize,
                            indices.len(),
                        ));
                    }
                    round_indices.push(indices);
                    let _ = vt.round_batching();
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
                    let _ = r;
                }
                let n_rounds = proof.whir.rounds.len();
                let fp = proof.whir.final_poly.as_ref().expect("final_poly");
                vt.final_poly(fp.as_slice()).unwrap();
                vt.query_pow(n_rounds, proof.whir.final_pow_witness)
                    .unwrap();
                let final_indices = vt.query_indices(n_rounds);
                let final_config = config.final_round_config();
                let final_folded_domain_size =
                    final_config.domain_size >> final_config.folding_factor;
                if final_config.num_queries >= final_folded_domain_size {
                    assert_eq!(
                        final_indices,
                        (0..final_folded_domain_size).collect::<Vec<_>>()
                    );
                } else {
                    expected_bit_widths.extend(core::iter::repeat_n(
                        final_folded_domain_size.ilog2() as usize,
                        final_indices.len(),
                    ));
                }
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
                    let _ = r.expect("final sumcheck replays");
                }
                vt.finish();
                assert_eq!(ch.bit_calls, 0);
                assert_eq!(ch.uniform_widths, expected_bit_widths);
                assert_eq!(ch.uniform_widths, official_widths);
                let manual_tail: [EF; 3] = core::array::from_fn(|_| ch.sample_algebra_element());
                assert_eq!(
                    manual_tail, official_tail,
                    "typed replay ended in a different state"
                );

                let vp = WhirVerifierParams::<BF>::from_config::<EF, MyChallenger>(
                    &config,
                    TestLayout::variable_order(),
                    $poseidon_cfg,
                )
                .expect("canonical WHIR query counts at this arity");

                let mut circuit = CircuitBuilder::<EF>::new();
                circuit.enable_poseidon2_perm::<$poseidon_air, _>(
                    generate_poseidon2_trace::<EF, $poseidon_air>,
                    make_perm(),
                );
                circuit.enable_recompose::<BF>(generate_recompose_trace::<BF, EF>);
                let proof_targets = WhirProofTargets::alloc::<BF, EF>(&mut circuit, &vp, 1, 2);
                assert_eq!(proof_targets.rounds.len(), proof.whir.rounds.len());
                for (target_round, native_round) in
                    proof_targets.rounds.iter().zip(&proof.whir.rounds)
                {
                    assert_eq!(
                        target_round.sumcheck.round_polys.len(),
                        native_round.sumcheck.polynomial_evaluations().len()
                    );
                    assert_eq!(
                        target_round.sumcheck.pow_witnesses.len(),
                        native_round.sumcheck.pow_witnesses.len()
                    );
                    assert_eq!(
                        target_round
                            .queries
                            .iter()
                            .map(|query| query.leaf_values().len())
                            .collect::<Vec<_>>(),
                        opening_row_widths(&native_round.openings)
                    );
                }
                assert_eq!(
                    proof_targets
                        .final_queries
                        .iter()
                        .map(|query| query.leaf_values().len())
                        .collect::<Vec<_>>(),
                    opening_row_widths(&proof.whir.final_openings)
                );
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

                let mut circuit_challenger = RecordingCircuitChallenger {
                    inner: CircuitChallenger::new($poseidon_cfg),
                    bit_widths: Vec::new(),
                };
                for event in initial_events.expect("initial transcript checkpoint was captured") {
                    match event {
                        NativeEvent::Observe(value) => {
                            let target = circuit.define_const(EF::from(value));
                            circuit_challenger.observe(&mut circuit, target);
                        }
                        NativeEvent::Sample(value) => {
                            let actual = circuit_challenger.sample(&mut circuit);
                            let expected = circuit.define_const(EF::from(value));
                            circuit.connect(actual, expected);
                        }
                    }
                }
                let op_ids = verify_whir_circuit::<BF, EF, RecordingCircuitChallenger>(
                    &mut circuit,
                    &mut circuit_challenger,
                    &vp,
                    &proof_targets,
                    &initial_cap,
                    circuit_constraint,
                    initial_claimed_eval_target,
                )
                .expect("verify_whir_circuit failed");

                assert_eq!(circuit_challenger.bit_widths, official_widths);
                for expected in official_tail {
                    let actual = circuit_challenger.sample_ext(&mut circuit);
                    let expected = circuit.define_const(expected);
                    circuit.connect(actual, expected);
                }

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

                let rejects = |values: &[EF], paths: &[Vec<[BF; 8]>]| {
                    let mut tampered = circuit.runner();
                    tampered.set_public_inputs(&public_inputs).unwrap();
                    tampered.set_private_inputs(values).unwrap();
                    set_whir_mmcs_private_data::<BF, EF, 8>(
                        &mut tampered,
                        &op_ids,
                        &restored_rounds,
                        paths,
                        $poseidon_cfg,
                    )
                    .unwrap();
                    matches!(tampered.run(), Err(CircuitError::WitnessConflict { .. }))
                };

                if NUM_VARIABLES == 4 && FOLDING == 4 {
                    // The final polynomial is constant, so its two whole-domain
                    // rows coincide. Corrupt values and paths individually.
                    assert_eq!(private_inputs.len(), 32);
                    assert_eq!(restored_final.len(), 2);
                    assert!(restored_final.iter().all(|path| path.len() == 1));
                    for index in [0, 31] {
                        let mut bad_leaf = private_inputs.clone();
                        bad_leaf[index] += EF::ONE;
                        assert!(rejects(&bad_leaf, &restored_final));
                    }
                    for index in [0, 1] {
                        let mut bad_paths = restored_final.clone();
                        bad_paths[index][0][0] += BF::ONE;
                        assert!(rejects(&private_inputs, &bad_paths));
                    }
                }
                if NUM_VARIABLES == 11 && $security == 32 {
                    // The mixed fixture has a nonconstant final codeword;
                    // swapping adjacent whole-domain rows must fail MMCS binding.
                    let width = 1usize << final_config.folding_factor;
                    let final_start = private_inputs.len() - final_indices.len() * width;
                    let mut reordered = private_inputs.clone();
                    reordered[final_start..final_start + 2 * width].rotate_left(width);
                    assert_ne!(reordered, private_inputs);
                    assert!(rejects(&reordered, &restored_final));
                }
            }
        }
    };
}

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_koala_bear::default_koalabear_poseidon2_16;

whir_arithmetic_test!(
    babybear_d4_2rounds,
    PrefixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    16,
    4,
    FoldingFactor::Constant(4),
    &[4, 4, 4],
    32,
    vec![4usize, 4],
    SecurityAssumption::CapacityBound,
    vec![false, false],
    false
);

whir_arithmetic_test!(
    koalabear_d4_1round,
    PrefixProver,
    KoalaBear,
    default_koalabear_poseidon2_16,
    Poseidon2KoalaBear<16>,
    BinomialExtensionField<KoalaBear, 4>,
    KoalaBearD4Width16,
    p3_circuit::ops::Poseidon2Config::KOALA_BEAR_D4_W16,
    12,
    4,
    FoldingFactor::Constant(4),
    &[4, 4],
    32,
    vec![4usize],
    SecurityAssumption::CapacityBound,
    vec![false],
    false
);

whir_arithmetic_test!(
    babybear_d4_saturated_final,
    PrefixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    4,
    4,
    FoldingFactor::Constant(4),
    &[4],
    32,
    vec![],
    SecurityAssumption::CapacityBound,
    vec![],
    true
);

whir_arithmetic_test!(
    babybear_d4_mixed_saturation,
    PrefixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    11,
    4,
    FoldingFactor::Constant(4),
    &[4, 4],
    32,
    vec![1usize],
    SecurityAssumption::CapacityBound,
    vec![false],
    true
);

whir_arithmetic_test!(
    babybear_d4_both_saturated,
    PrefixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    11,
    4,
    FoldingFactor::Constant(4),
    &[4, 4],
    106,
    vec![1usize],
    SecurityAssumption::UniqueDecoding,
    vec![true],
    true
);

whir_arithmetic_test!(
    babybear_d4_partial_final_fold,
    PrefixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    15,
    8,
    FoldingFactor::Constant(8),
    &[8, 7],
    32,
    vec![1usize],
    SecurityAssumption::CapacityBound,
    vec![false],
    true
);

whir_arithmetic_test!(
    babybear_d4_per_round_fold,
    PrefixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    12,
    2,
    FoldingFactor::PerRound(vec![2, 3, 1]),
    &[2, 3, 1],
    32,
    vec![1usize, 1],
    SecurityAssumption::CapacityBound,
    vec![false, false],
    false
);

whir_arithmetic_test!(
    babybear_d4_suffix_unsaturated,
    SuffixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    12,
    4,
    FoldingFactor::Constant(4),
    &[4, 4],
    32,
    vec![4usize],
    SecurityAssumption::CapacityBound,
    vec![false],
    false
);

whir_arithmetic_test!(
    babybear_d4_suffix_per_round_fold,
    SuffixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    12,
    2,
    FoldingFactor::PerRound(vec![2, 3, 1]),
    &[2, 3, 1],
    32,
    vec![1usize, 1],
    SecurityAssumption::CapacityBound,
    vec![false, false],
    false
);

whir_arithmetic_test!(
    babybear_d4_suffix_saturated_final,
    SuffixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    4,
    4,
    FoldingFactor::Constant(4),
    &[4],
    32,
    vec![],
    SecurityAssumption::CapacityBound,
    vec![],
    true
);

whir_arithmetic_test!(
    babybear_d4_suffix_mixed_saturation,
    SuffixProver,
    BabyBear,
    default_babybear_poseidon2_16,
    Poseidon2BabyBear<16>,
    BinomialExtensionField<BabyBear, 4>,
    BabyBearD4Width16,
    p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
    11,
    4,
    FoldingFactor::Constant(4),
    &[4, 4],
    32,
    vec![1usize],
    SecurityAssumption::CapacityBound,
    vec![false],
    true
);
