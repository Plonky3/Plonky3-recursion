//! Independent native-verifier versus transcript-replay assurance.

mod common;

use std::sync::{Arc, Mutex};

use common::transcript_snapshot::{DuplexSnapshot, RecordingDuplexChallenger};
use common::whir_config::{
    BbDft, BbEF, BbF, BbMmcs, BbPerm, bb_whir_mmcs, bb_whir_perm, bb_whir_protocol_params,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{
    BatchProof, CommonData, ProverData, StarkInstance, prove_batch, verify_batch,
};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, DuplexChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_koala_bear::{Poseidon2KoalaBear, default_koalabear_poseidon2_32};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::pcs::fri::{FriVerifierParams, MerkleCapTargets};
use p3_recursion::pcs::whir::uni::WhirUniPcs;
use p3_recursion::pcs::{restore_fri_query_paths, set_fri_mmcs_private_data};
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, OpeningTranscript, Poseidon2Config, observe_opened_values,
    replay_batch_stark_transcript, replay_uni_stark_transcript, verify_batch_circuit,
};
use p3_sumcheck::layout::PrefixProver;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_test_utils::corpus::{CaseRng, CorpusSpec, derive_family_seed, for_each_case};
use p3_test_utils::koala_bear_params::{
    Challenge, ChallengeMmcs, DIGEST_ELEMS, Dft, F, MyCompress, MyHash, MyMmcs, MyPcs, Perm, RATE,
    WIDTH, default_koalabear_poseidon2_16, make_test_config, test_fri_instance,
};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::StdRng;

const MAX_PROOF_CASES: u32 = 8;

type RecordingChallenger = RecordingDuplexChallenger<F, Perm, WIDTH, RATE>;
type RecordingConfig = StarkConfig<MyPcs, Challenge, RecordingChallenger>;
type HidingPcs = HidingFriPcs<F, Dft, MyMmcs, ChallengeMmcs, StdRng>;
type RecordingHidingConfig = StarkConfig<HidingPcs, Challenge, RecordingChallenger>;
type WidePerm = Poseidon2KoalaBear<32>;
type WideHash = PaddingFreeSponge<WidePerm, 32, 24, DIGEST_ELEMS>;
type QuaternaryCompress = TruncatedPermutation<WidePerm, 4, DIGEST_ELEMS, 32>;
type QuaternaryMmcs = MerkleTreeMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    WideHash,
    QuaternaryCompress,
    4,
    DIGEST_ELEMS,
>;
type QuaternaryChallengeMmcs = ExtensionMmcs<F, Challenge, QuaternaryMmcs>;
type QuaternaryPcs = TwoAdicFriPcs<F, Dft, QuaternaryMmcs, QuaternaryChallengeMmcs>;
type RecordingQuaternaryConfig = StarkConfig<QuaternaryPcs, Challenge, RecordingChallenger>;
type RecordingBbChallenger = RecordingDuplexChallenger<BbF, BbPerm, 16, 8>;
type RecordingWhirPcs =
    WhirUniPcs<BbEF, BbF, BbDft, BbMmcs, RecordingBbChallenger, PrefixProver<BbF, BbEF>>;
type RecordingWhirConfig = StarkConfig<RecordingWhirPcs, BbEF, RecordingBbChallenger>;

#[derive(Clone, Copy)]
struct SeededAddAir;

impl<Val: Field> BaseAir<Val> for SeededAddAir {
    fn width(&self) -> usize {
        3
    }
}

impl<AB: AirBuilder> Air<AB> for SeededAddAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        builder.assert_zero(row[0] + row[1] - row[2]);
    }
}

fn seeded_add_trace(seed: u64) -> RowMajorMatrix<F> {
    let mut rng = CaseRng::new(seed);
    let mut values = F::zero_vec((1 << 5) * 3);
    for row in values.as_chunks_mut::<3>().0 {
        row[0] = F::from_u64(rng.next_u64());
        row[1] = F::from_u64(rng.next_u64());
        row[2] = row[0] + row[1];
    }
    RowMajorMatrix::new(values, 3)
}

fn recording_config(
    branch: &'static str,
    sink: Arc<Mutex<Vec<DuplexSnapshot<F, WIDTH>>>>,
) -> RecordingConfig {
    let retained = make_test_config();
    StarkConfig::new(
        retained.pcs().clone(),
        RecordingChallenger::new(
            DuplexChallenger::new(default_koalabear_poseidon2_16()),
            sink,
            branch,
        ),
    )
}

fn assert_same_duplex_state<FN, const W: usize>(
    family: &'static str,
    seed: u64,
    native: &DuplexSnapshot<FN, W>,
    replay: &DuplexSnapshot<FN, W>,
) where
    FN: std::fmt::Debug + PartialEq,
{
    assert_eq!(
        native.sponge_state, replay.sponge_state,
        "family={family} seed={seed} checkpoint=post-pcs component=sponge-state"
    );
    assert_eq!(
        native.input_buffer, replay.input_buffer,
        "family={family} seed={seed} checkpoint=post-pcs component=input-buffer"
    );
    assert_eq!(
        native.output_buffer, replay.output_buffer,
        "family={family} seed={seed} checkpoint=post-pcs component=output-buffer"
    );
}

fn run_binary_fri_d4_case(seed: u64) {
    let family = "binary-fri-d4";
    let air = SeededAddAir;
    let trace = seeded_add_trace(seed);
    let public_values = vec![vec![]];
    let native_sink = Arc::new(Mutex::new(Vec::new()));
    let native_config = recording_config("native-verifier", Arc::clone(&native_sink));
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: vec![],
    }];
    let prover_data = ProverData::from_instances(&native_config, &instances);
    let proof = prove_batch(&native_config, &instances, &prover_data);

    native_sink
        .lock()
        .expect("native snapshot sink is not poisoned")
        .clear();
    verify_batch(
        &native_config,
        &[air],
        &proof,
        &public_values,
        &prover_data.common,
    )
    .unwrap_or_else(|error| {
        panic!("family={family} seed={seed} branch=native expected=accept error={error:?}")
    });
    let native_final = native_sink
        .lock()
        .expect("native snapshot sink is not poisoned")
        .last()
        .cloned()
        .expect("native verifier must exercise the recording challenger");

    let replay_sink = Arc::new(Mutex::new(Vec::new()));
    let replay_config = StarkConfig::new(
        native_config.pcs().clone(),
        RecordingChallenger::new(
            DuplexChallenger::new(default_koalabear_poseidon2_16()),
            Arc::clone(&replay_sink),
            "replay-plus-pcs",
        ),
    );
    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay_batch_stark_transcript(
        &[air],
        &replay_config,
        &proof,
        &public_values,
        &prover_data.common,
        &LogUpGadget::new(),
    )
    .unwrap_or_else(|error| {
        panic!("family={family} seed={seed} branch=replay expected=replay error={error:?}")
    })
    .0;
    replay_config
        .pcs()
        .verify(
            commitments_with_opening_points,
            &proof.opening_proof,
            &mut challenger,
        )
        .unwrap_or_else(|error| {
            panic!(
                "family={family} seed={seed} branch=replay-plus-pcs expected=accept error={error:?}"
            )
        });
    let replay_final = challenger.snapshot("replay-plus-pcs-final");

    assert_eq!(native_final.branch, "native-verifier");
    assert_eq!(replay_final.branch, "replay-plus-pcs");
    assert_same_duplex_state(family, seed, &native_final, &replay_final);
    run_binary_fri_d4_recursive_acceptance(
        seed,
        &air,
        &replay_config,
        &proof,
        &public_values,
        &prover_data.common,
    );
}

fn run_random_codeword_hiding_fri_case(seed: u64) {
    let family = "random-codeword-hiding-fri-d4";
    let air = SeededAddAir;
    let trace = seeded_add_trace(seed);
    let public_values = vec![vec![]];
    let perm = default_koalabear_poseidon2_16();
    let val_mmcs = MyMmcs::new(MyHash::new(perm.clone()), MyCompress::new(perm.clone()), 0);
    let fri_params = FriParameters::new_testing(ChallengeMmcs::new(val_mmcs.clone()), 0);
    let pcs = HidingPcs::new(
        Dft::default(),
        val_mmcs,
        fri_params,
        2,
        StdRng::seed_from_u64(seed),
    );
    let native_sink = Arc::new(Mutex::new(Vec::new()));
    let native_config = RecordingHidingConfig::new(
        pcs,
        RecordingChallenger::new(
            DuplexChallenger::new(perm.clone()),
            Arc::clone(&native_sink),
            "native-verifier",
        ),
    );
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: vec![],
    }];
    let prover_data = ProverData::from_instances(&native_config, &instances);
    let proof = prove_batch(&native_config, &instances, &prover_data);
    native_sink
        .lock()
        .expect("native snapshot sink is not poisoned")
        .clear();
    verify_batch(
        &native_config,
        &[air],
        &proof,
        &public_values,
        &prover_data.common,
    )
    .unwrap_or_else(|error| {
        panic!("family={family} seed={seed} branch=native expected=accept error={error:?}")
    });
    let native_final = native_sink
        .lock()
        .expect("native snapshot sink is not poisoned")
        .last()
        .cloned()
        .expect("native verifier must exercise the recording challenger");

    let replay_sink = Arc::new(Mutex::new(Vec::new()));
    let replay_config = RecordingHidingConfig::new(
        native_config.pcs().clone(),
        RecordingChallenger::new(DuplexChallenger::new(perm), replay_sink, "replay-plus-pcs"),
    );
    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay_batch_stark_transcript(
        &[air],
        &replay_config,
        &proof,
        &public_values,
        &prover_data.common,
        &LogUpGadget::new(),
    )
    .unwrap_or_else(|error| {
        panic!("family={family} seed={seed} branch=replay expected=replay error={error:?}")
    })
    .0;
    replay_config
        .pcs()
        .verify(
            commitments_with_opening_points,
            &proof.opening_proof,
            &mut challenger,
        )
        .unwrap_or_else(|error| {
            panic!(
                "family={family} seed={seed} branch=replay-plus-pcs expected=accept error={error:?}"
            )
        });
    let replay_final = challenger.snapshot("replay-plus-pcs-final");
    assert_same_duplex_state(family, seed, &native_final, &replay_final);
}

fn run_quaternary_wide_mmcs_case(seed: u64) {
    let family = "quaternary-wide-mmcs-narrow-challenger";
    let air = SeededAddAir;
    let trace = seeded_add_trace(seed);
    let public_values = vec![vec![]];
    let wide_perm = default_koalabear_poseidon2_32();
    let val_mmcs = QuaternaryMmcs::new(
        WideHash::new(wide_perm.clone()),
        QuaternaryCompress::new(wide_perm),
        0,
    );
    let fri_params = FriParameters::new_testing(QuaternaryChallengeMmcs::new(val_mmcs.clone()), 0);
    let pcs = QuaternaryPcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger_perm = default_koalabear_poseidon2_16();
    let native_sink = Arc::new(Mutex::new(Vec::new()));
    let native_config = RecordingQuaternaryConfig::new(
        pcs,
        RecordingChallenger::new(
            DuplexChallenger::new(challenger_perm.clone()),
            Arc::clone(&native_sink),
            "native-verifier",
        ),
    );
    let instances = [StarkInstance {
        air: &air,
        trace: &trace,
        public_values: vec![],
    }];
    let prover_data = ProverData::from_instances(&native_config, &instances);
    let proof = prove_batch(&native_config, &instances, &prover_data);
    native_sink
        .lock()
        .expect("native snapshot sink is not poisoned")
        .clear();
    verify_batch(
        &native_config,
        &[air],
        &proof,
        &public_values,
        &prover_data.common,
    )
    .unwrap_or_else(|error| {
        panic!("family={family} seed={seed} branch=native expected=accept error={error:?}")
    });
    let native_final = native_sink
        .lock()
        .expect("native snapshot sink is not poisoned")
        .last()
        .cloned()
        .expect("native verifier must exercise the recording challenger");

    let replay_sink = Arc::new(Mutex::new(Vec::new()));
    let replay_config = RecordingQuaternaryConfig::new(
        native_config.pcs().clone(),
        RecordingChallenger::new(
            DuplexChallenger::new(challenger_perm),
            replay_sink,
            "replay-plus-pcs",
        ),
    );
    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay_batch_stark_transcript(
        &[air],
        &replay_config,
        &proof,
        &public_values,
        &prover_data.common,
        &LogUpGadget::new(),
    )
    .unwrap_or_else(|error| {
        panic!("family={family} seed={seed} branch=replay expected=replay error={error:?}")
    })
    .0;
    replay_config
        .pcs()
        .verify(
            commitments_with_opening_points,
            &proof.opening_proof,
            &mut challenger,
        )
        .unwrap_or_else(|error| {
            panic!(
                "family={family} seed={seed} branch=replay-plus-pcs expected=accept error={error:?}"
            )
        });
    let replay_final = challenger.snapshot("replay-plus-pcs-final");
    assert_same_duplex_state(family, seed, &native_final, &replay_final);
}

fn run_non_zk_whir_d4_case(seed: u64) {
    let family = "non-zk-whir-d4";
    let log_n = 10;
    let n = 1 << log_n;
    let air = FibonacciAir {};
    let mut rng = CaseRng::new(seed);
    let start_a = rng.next_u64() % 1_000;
    let start_b = rng.next_u64() % 1_000;
    let trace = generate_trace_rows::<BbF>(start_a, start_b, n);
    let mut a = BbF::from_u64(start_a);
    let mut b = BbF::from_u64(start_b);
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    let public_values = vec![BbF::from_u64(start_a), BbF::from_u64(start_b), b];
    let perm = bb_whir_perm();
    let native_sink = Arc::new(Mutex::new(Vec::new()));
    let native_challenger = RecordingBbChallenger::new(
        DuplexChallenger::new(perm.clone()),
        Arc::clone(&native_sink),
        "native-verifier",
    );
    let pcs = RecordingWhirPcs::new(
        bb_whir_protocol_params(vec![4]),
        BbDft::default(),
        bb_whir_mmcs(),
        native_challenger.clone(),
        20,
    );
    let native_config = RecordingWhirConfig::new(pcs, native_challenger);
    let proof = prove(&native_config, &air, trace, &public_values);
    native_sink
        .lock()
        .expect("native snapshot sink is not poisoned")
        .clear();
    verify(&native_config, &air, &proof, &public_values).unwrap_or_else(|error| {
        panic!("family={family} seed={seed} branch=native expected=accept error={error:?}")
    });
    let native_final = native_sink
        .lock()
        .expect("native snapshot sink is not poisoned")
        .last()
        .cloned()
        .expect("native verifier must exercise the recording challenger");

    let replay_sink = Arc::new(Mutex::new(Vec::new()));
    let replay_challenger =
        RecordingBbChallenger::new(DuplexChallenger::new(perm), replay_sink, "replay-plus-pcs");
    let replay_config = RecordingWhirConfig::new(native_config.pcs().clone(), replay_challenger);
    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay_uni_stark_transcript(&replay_config, &air, &proof, &public_values, None)
        .unwrap_or_else(|error| {
            panic!("family={family} seed={seed} branch=replay expected=replay error={error:?}")
        });
    replay_config
        .pcs()
        .verify(
            commitments_with_opening_points,
            &proof.opening_proof,
            &mut challenger,
        )
        .unwrap_or_else(|error| {
            panic!(
                "family={family} seed={seed} branch=replay-plus-pcs expected=accept error={error:?}"
            )
        });
    let replay_final = challenger.snapshot("replay-plus-pcs-final");
    assert_same_duplex_state(family, seed, &native_final, &replay_final);
}

fn run_binary_fri_d4_recursive_acceptance(
    seed: u64,
    air: &SeededAddAir,
    config: &RecordingConfig,
    proof: &BatchProof<RecordingConfig>,
    public_values: &[Vec<F>],
    common: &CommonData<RecordingConfig>,
) {
    type InnerFri = common::InnerFriGeneric<RecordingConfig, MyHash, MyCompress, DIGEST_ELEMS>;

    let (val_mmcs, fri_params) = test_fri_instance();
    let verifier_params = FriVerifierParams::with_mmcs(
        fri_params.log_blowup,
        fri_params.log_final_poly_len,
        fri_params.commit_proof_of_work_bits,
        fri_params.query_proof_of_work_bits,
        fri_params.num_queries,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    );
    let mut builder = CircuitBuilder::new();
    let perm = default_koalabear_poseidon2_16();
    builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
        perm,
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let inputs = BatchStarkVerifierInputsBuilder::<
        RecordingConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(&mut builder, proof, common, &[0])
    .unwrap_or_else(|error| {
        panic!("family=binary-fri-d4 seed={seed} branch=circuit expected=allocate error={error:?}")
    });
    let op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        config,
        &[*air],
        &mut builder,
        &inputs.proof_targets,
        &inputs.air_public_targets,
        &verifier_params,
        &inputs.common_data,
        &LogUpGadget::new(),
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
    .unwrap_or_else(|error| {
        panic!("family=binary-fri-d4 seed={seed} branch=circuit expected=build error={error:?}")
    });
    let circuit = builder.build().unwrap_or_else(|error| {
        panic!("family=binary-fri-d4 seed={seed} branch=circuit expected=lower error={error:?}")
    });
    let (packed_public, packed_private) = inputs.pack_values(public_values, proof, common);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&packed_public).unwrap();
    runner.set_private_inputs(&packed_private).unwrap();

    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay_batch_stark_transcript(
        &[*air],
        config,
        proof,
        public_values,
        common,
        &LogUpGadget::new(),
    )
    .expect("the honest binary FRI transcript replays")
    .0;
    observe_opened_values::<RecordingConfig>(&mut challenger, &commitments_with_opening_points);
    let paths = restore_fri_query_paths(
        &fri_params,
        &val_mmcs,
        &val_mmcs,
        &proof.opening_proof,
        &mut challenger,
        &commitments_with_opening_points,
    )
    .expect("the honest binary FRI paths restore");
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut runner,
        &op_ids,
        &paths,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
    .expect("the honest binary FRI paths populate private data");
    runner.run().unwrap_or_else(|error| {
        panic!("family=binary-fri-d4 seed={seed} branch=circuit expected=accept error={error:?}")
    });
}

fn parse_proof_cases(value: Option<&str>) -> Result<u32, String> {
    let cases = match value {
        None => 1,
        Some(raw) => raw.parse::<u32>().map_err(|_| {
            format!("P3_ASSURANCE_PROOF_CASES must be a u32 in 1..={MAX_PROOF_CASES}, got {raw:?}")
        })?,
    };
    if !(1..=MAX_PROOF_CASES).contains(&cases) {
        return Err(format!(
            "P3_ASSURANCE_PROOF_CASES must be in 1..={MAX_PROOF_CASES}, got {cases}"
        ));
    }
    Ok(cases)
}

fn proof_corpus_from_env() -> CorpusSpec {
    let start_seed = std::env::var("P3_ASSURANCE_START_SEED")
        .ok()
        .map_or(Ok(0), |raw| {
            raw.parse::<u64>()
                .map_err(|_| format!("P3_ASSURANCE_START_SEED must be a u64, got {raw:?}"))
        })
        .unwrap_or_else(|error| panic!("{error}"));
    let cases = parse_proof_cases(std::env::var("P3_ASSURANCE_PROOF_CASES").ok().as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    CorpusSpec { start_seed, cases }
}

#[test]
fn assurance_recording_challenger_preserves_duplex_behavior() {
    let perm = default_koalabear_poseidon2_16();
    let mut direct = DuplexChallenger::<F, Perm, WIDTH, RATE>::new(perm.clone());
    let sink = Arc::new(Mutex::new(Vec::<DuplexSnapshot<F, WIDTH>>::new()));
    let mut recorded: RecordingDuplexChallenger<F, Perm, WIDTH, RATE> =
        RecordingDuplexChallenger::new(
            DuplexChallenger::<F, Perm, WIDTH, RATE>::new(perm),
            Arc::clone(&sink),
            "wrapped-control",
        );

    for value in [F::ONE, F::TWO, F::from_u8(9)] {
        direct.observe(value);
        recorded.observe(value);
    }
    let direct_sample: F = direct.sample();
    let recorded_sample: F = recorded.sample();
    assert_eq!(direct_sample, recorded_sample);
    assert_eq!(direct.sample_bits(7), recorded.sample_bits(7));

    let snapshot = recorded.snapshot("wrapped-control-final");
    assert_eq!(snapshot.sponge_state, direct.sponge_state);
    assert_eq!(snapshot.input_buffer, direct.input_buffer);
    assert_eq!(snapshot.output_buffer, direct.output_buffer);
    assert!(
        sink.lock()
            .expect("snapshot sink is not poisoned")
            .iter()
            .all(|entry| entry.branch == "wrapped-control")
    );
}

#[test]
fn assurance_proof_case_override_policy() {
    assert_eq!(parse_proof_cases(None), Ok(1));
    assert_eq!(parse_proof_cases(Some("4")), Ok(4));
    assert_eq!(parse_proof_cases(Some("8")), Ok(MAX_PROOF_CASES));
    for invalid in ["", "zero", "0", "9", "4294967296"] {
        assert!(
            parse_proof_cases(Some(invalid)).is_err(),
            "invalid proof-case override {invalid:?} must reject"
        );
    }
}

#[test]
fn assurance_native_replay_binary_fri_d4() {
    for_each_case(proof_corpus_from_env(), |case_seed| {
        run_binary_fri_d4_case(derive_family_seed(case_seed, 0x4249_4e41_5259_4434));
    });
}

#[test]
fn assurance_native_replay_random_codeword_hiding_fri_d4() {
    for_each_case(proof_corpus_from_env(), |case_seed| {
        run_random_codeword_hiding_fri_case(derive_family_seed(case_seed, 0x4849_4449_4e47_4434));
    });
}

#[test]
fn assurance_native_replay_quaternary_wide_mmcs_narrow_challenger() {
    for_each_case(proof_corpus_from_env(), |case_seed| {
        run_quaternary_wide_mmcs_case(derive_family_seed(case_seed, 0x5155_4154_4552_4e34));
    });
}

#[test]
fn assurance_native_replay_non_zk_whir_d4() {
    for_each_case(proof_corpus_from_env(), |case_seed| {
        run_non_zk_whir_d4_case(derive_family_seed(case_seed, 0x5748_4952_5f44_3400));
    });
}
