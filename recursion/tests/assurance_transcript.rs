//! Bounded deterministic native-versus-circuit challenger schedule assurance.

use p3_challenger::{CanObserve, CanSample, CanSampleBits, DuplexChallenger, FieldChallenger};
use p3_circuit::ops::poseidon1_perm::{
    GoldilocksD2Width8 as P1GoldilocksD2Width8, KoalaBearD1Width16 as P1KoalaBearD1Width16,
};
use p3_circuit::ops::{
    GoldilocksD2Width8, KoalaBearD1Width16, generate_poseidon1_trace, generate_poseidon2_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, Traces};
use p3_field::{ExtensionField, PrimeField64};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::challenger::CircuitChallenger;
use p3_recursion::{ChallengerPermConfig, RecursiveChallenger};
use p3_symmetric::CryptographicPermutation;
use p3_test_utils::baby_bear_params::{
    BabyBear, BinomialExtensionField, default_babybear_poseidon2_16,
};
use p3_test_utils::corpus::{
    CaseRng, CorpusSpec, DEFAULT_CASES, MAX_CASES, derive_family_seed, for_each_case,
};
use p3_test_utils::koala_bear_quintic_params::{
    LiftKoalaPermForQuintic, QuinticTrinomialExtensionField,
};
use rand::SeedableRng;
use rand::rngs::SmallRng;

const MAX_SCHEDULE_OPS: usize = 64;

fn corpus_spec_from_env() -> CorpusSpec {
    let start_seed = std::env::var("P3_ASSURANCE_START_SEED")
        .ok()
        .map_or(0, |value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("P3_ASSURANCE_START_SEED must be a u64, got {value:?}"))
        });
    let cases = std::env::var("P3_ASSURANCE_CASES")
        .ok()
        .map_or(DEFAULT_CASES, |value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("P3_ASSURANCE_CASES must be a u32, got {value:?}"))
        });
    assert!(
        (1..=MAX_CASES).contains(&cases),
        "P3_ASSURANCE_CASES must be in 1..={MAX_CASES}, got {cases}"
    );
    CorpusSpec { start_seed, cases }
}

fn full_nonzero_extension<F, EF>(rng: &mut CaseRng) -> EF
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    let mut coefficients = Vec::with_capacity(EF::DIMENSION);
    for index in 0..EF::DIMENSION {
        let mut coefficient = F::from_u64(rng.next_u64());
        if coefficient == F::ZERO {
            coefficient = F::from_usize(index + 1);
        }
        coefficients.push(coefficient);
    }
    EF::from_basis_coefficients_slice(&coefficients).unwrap()
}

fn run_schedule<
    F,
    EF,
    P,
    C,
    MakePerm,
    MakeCircuit,
    MakeChallenger,
    const WIDTH: usize,
    const RATE: usize,
>(
    family_tag: u64,
    field_label: &'static str,
    make_perm: MakePerm,
    make_circuit: MakeCircuit,
    make_challenger: MakeChallenger,
) where
    F: PrimeField64,
    EF: ExtensionField<F>,
    P: CryptographicPermutation<[F; WIDTH]> + Clone,
    C: ChallengerPermConfig,
    MakePerm: Fn() -> P,
    MakeCircuit: Fn() -> CircuitBuilder<EF>,
    MakeChallenger: Fn() -> CircuitChallenger<WIDTH, RATE, C>,
{
    for_each_case(corpus_spec_from_env(), |case_seed| {
        let mut rng = CaseRng::new(derive_family_seed(case_seed, family_tag));
        let mut native = DuplexChallenger::<F, P, WIDTH, RATE>::new(make_perm());
        let mut circuit = make_circuit();
        let mut recursive = make_challenger();
        let mut op = 0usize;

        macro_rules! observe_base {
            ($value:expr) => {{
                let value = $value;
                native.observe(value);
                let target = circuit.define_const(EF::from(value));
                RecursiveChallenger::<F, EF>::observe(&mut recursive, &mut circuit, target);
                op += 1;
            }};
        }
        macro_rules! observe_ext {
            ($value:expr) => {{
                let value = $value;
                native.observe_algebra_element(value);
                let target = circuit.define_const(value);
                RecursiveChallenger::<F, EF>::observe_ext(&mut recursive, &mut circuit, target);
                op += 1;
            }};
        }
        macro_rules! sample_base {
            () => {{
                let operation = op;
                let expected: F = native.sample();
                let actual = RecursiveChallenger::<F, EF>::sample(&mut recursive, &mut circuit);
                circuit
                    .tag(
                        actual,
                        format!("assurance-transcript-{field_label}-{case_seed}-{operation}"),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "family=challenger-schedule field={field_label} seed={case_seed} op={operation} mutation=none expected-stage=tag-base-sample error={error:?}"
                        )
                    });
                let expected = circuit.define_const(EF::from(expected));
                // Generated schedules may compare targets with distinct, valid coefficient
                // provenance, so enforce equality without aliasing their witness slots.
                let difference = circuit.sub(actual, expected);
                circuit.assert_zero(difference);
                op += 1;
            }};
        }
        macro_rules! sample_ext {
            () => {{
                let operation = op;
                let expected: EF = native.sample_algebra_element();
                let actual = RecursiveChallenger::<F, EF>::sample_ext(&mut recursive, &mut circuit);
                circuit
                    .tag(
                        actual,
                        format!("assurance-transcript-ext-{field_label}-{case_seed}-{operation}"),
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "family=challenger-schedule field={field_label} seed={case_seed} op={operation} mutation=none expected-stage=tag-extension-sample error={error:?}"
                        )
                    });
                let expected = circuit.define_const(expected);
                // Keep each side's coefficient provenance while constraining the values equal.
                let difference = circuit.sub(actual, expected);
                circuit.assert_zero(difference);
                op += 1;
            }};
        }
        macro_rules! clear {
            () => {{
                native = DuplexChallenger::<F, P, WIDTH, RATE>::new(make_perm());
                RecursiveChallenger::<F, EF>::clear(&mut recursive, &mut circuit);
                op += 1;
            }};
        }

        // Fixed prefixes hit every absorption boundary, including an empty squeeze.
        for (prefix_index, prefix_len) in [0, RATE - 1, RATE, RATE + 1].into_iter().enumerate() {
            if prefix_index != 0 {
                clear!();
            }
            for _ in 0..prefix_len {
                observe_base!(F::from_u64(rng.next_u64()));
            }
            sample_base!();
        }

        // Exactly drain, then over-drain, one complete output buffer.
        clear!();
        for _ in 0..RATE {
            observe_base!(F::from_u64(rng.next_u64()));
        }
        for _ in 0..=RATE {
            sample_base!();
        }

        // A genuine extension value keeps every coefficient, including high limbs, nonzero.
        let extension = full_nonzero_extension::<F, EF>(&mut rng);
        observe_ext!(extension);
        sample_ext!();

        // Exercise zero, unit, small and maximum supported bit requests.
        let max_supported_bits = (F::bits() - 1).min(usize::BITS as usize - 1);
        for num_bits in [0, 1, 5usize.min(max_supported_bits), max_supported_bits] {
            let operation = op;
            let expected = native.sample_bits(num_bits);
            let actual =
                RecursiveChallenger::<F, EF>::sample_bits(&mut recursive, &mut circuit, num_bits)
                    .unwrap_or_else(|error| {
                        panic!(
                            "family=challenger-schedule field={field_label} seed={case_seed} op={operation} mutation=none expected-stage=sample-bits-build error={error:?}"
                        )
                    });
            assert_eq!(
                actual.len(),
                num_bits,
                "family=challenger-schedule field={field_label} seed={case_seed} op={operation} mutation=none expected-stage=sample-bits-width"
            );
            for (bit, target) in actual.into_iter().enumerate() {
                let expected_bit = F::from_u64(((expected >> bit) & 1) as u64);
                let expected_target = circuit.define_const(EF::from(expected_bit));
                let difference = circuit.sub(target, expected_target);
                circuit.assert_zero(difference);
            }
            op += 1;
        }

        // Zero-bit PoW is a no-op; the immediately following sample proves state parity.
        let ignored_witness = circuit.define_const(EF::from(F::from_u64(rng.next_u64())));
        RecursiveChallenger::<F, EF>::check_pow_witness(
            &mut recursive,
            &mut circuit,
            0,
            ignored_witness,
        )
        .unwrap_or_else(|error| {
            panic!(
                "family=challenger-schedule field={field_label} seed={case_seed} op={op} mutation=none expected-stage=zero-pow-noop error={error:?}"
            )
        });
        op += 1;
        sample_base!();

        // Find a deterministic small valid PoW witness on a cloned native challenger.
        let pow_bits = 2;
        let witness = (0..=256u64)
            .find(|candidate| {
                let mut probe = native.clone();
                probe.observe(F::from_u64(*candidate));
                probe.sample_bits(pow_bits) == 0
            })
            .unwrap_or_else(|| {
                panic!(
                    "family=challenger-schedule field={field_label} seed={case_seed} op={op} mutation=pow-search expected-stage=valid-small-pow"
                )
            });
        let witness = F::from_u64(witness);
        native.observe(witness);
        assert_eq!(
            native.sample_bits(pow_bits),
            0,
            "family=challenger-schedule field={field_label} seed={case_seed} op={op} mutation=none expected-stage=native-pow-control"
        );
        let witness_target = circuit.define_const(EF::from(witness));
        RecursiveChallenger::<F, EF>::check_pow_witness(
            &mut recursive,
            &mut circuit,
            pow_bits,
            witness_target,
        )
        .unwrap_or_else(|error| {
            panic!(
                "family=challenger-schedule field={field_label} seed={case_seed} op={op} mutation=none expected-stage=valid-small-pow error={error:?}"
            )
        });
        op += 1;

        // Fill the remaining bounded schedule with deterministic mixed events.
        while op < MAX_SCHEDULE_OPS {
            match rng.next_u64() % 6 {
                0 | 1 => observe_base!(F::from_u64(rng.next_u64())),
                2 => sample_base!(),
                3 => observe_ext!(full_nonzero_extension::<F, EF>(&mut rng)),
                4 => sample_ext!(),
                _ => clear!(),
            }
        }
        assert_eq!(
            op, MAX_SCHEDULE_OPS,
            "family=challenger-schedule field={field_label} seed={case_seed} op={op} mutation=none expected-stage=schedule-bound"
        );

        let built = circuit.build().unwrap_or_else(|error| {
            panic!(
                "family=challenger-schedule field={field_label} seed={case_seed} op=build mutation=none expected-stage=build-success error={error:?}"
            )
        });
        let traces: Traces<EF> = built.runner().run().unwrap_or_else(|error| {
            panic!(
                "family=challenger-schedule field={field_label} seed={case_seed} op=0..{MAX_SCHEDULE_OPS} mutation=none expected-stage=native-circuit-equality error={error:?}"
            )
        });
        assert!(
            traces.witness_trace.num_rows() > 0,
            "family=challenger-schedule field={field_label} seed={case_seed} op=run mutation=none expected-stage=nonempty-trace"
        );
    });
}

fn goldilocks_poseidon2_perm() -> p3_test_utils::goldilocks_params::Perm {
    p3_test_utils::goldilocks_params::Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1))
}

fn setup_goldilocks_poseidon2()
-> CircuitBuilder<BinomialExtensionField<p3_test_utils::goldilocks_params::Goldilocks, 2>> {
    use p3_test_utils::goldilocks_params::Goldilocks;
    type EF = BinomialExtensionField<Goldilocks, 2>;
    let mut circuit = CircuitBuilder::<EF>::new();
    circuit.enable_poseidon2_perm_width_8::<GoldilocksD2Width8, _>(
        generate_poseidon2_trace::<EF, GoldilocksD2Width8>,
        goldilocks_poseidon2_perm(),
    );
    circuit.enable_recompose::<Goldilocks>(generate_recompose_trace::<Goldilocks, EF>);
    circuit.set_recompose_coeff_ctl_for_decompose_links(true);
    circuit
}

fn goldilocks_poseidon1_perm() -> p3_goldilocks::poseidon1::Poseidon1Goldilocks<8> {
    p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8()
}

fn setup_goldilocks_poseidon1()
-> CircuitBuilder<BinomialExtensionField<p3_test_utils::goldilocks_params::Goldilocks, 2>> {
    use p3_test_utils::goldilocks_params::Goldilocks;
    type EF = BinomialExtensionField<Goldilocks, 2>;
    let mut circuit = CircuitBuilder::<EF>::new();
    circuit.enable_poseidon1_perm_width_8::<P1GoldilocksD2Width8, _>(
        generate_poseidon1_trace::<EF, P1GoldilocksD2Width8>,
        goldilocks_poseidon1_perm(),
    );
    circuit.enable_recompose::<Goldilocks>(generate_recompose_trace::<Goldilocks, EF>);
    circuit.set_recompose_coeff_ctl_for_decompose_links(true);
    circuit
}

fn run_koalabear_d1_poseidon2() {
    use p3_test_utils::koala_bear_params::{
        KoalaBear, RATE, WIDTH, default_koalabear_poseidon2_16,
    };
    run_schedule::<KoalaBear, KoalaBear, _, _, _, _, _, WIDTH, RATE>(
        0x5452_4b42_4431_5032,
        "KoalaBear/D1/Poseidon2",
        default_koalabear_poseidon2_16,
        || {
            let mut circuit = CircuitBuilder::<KoalaBear>::new();
            circuit.enable_poseidon2_perm_base::<KoalaBearD1Width16, _>(
                generate_poseidon2_trace::<KoalaBear, KoalaBearD1Width16>,
                default_koalabear_poseidon2_16(),
            );
            circuit.enable_recompose::<KoalaBear>(generate_recompose_trace::<KoalaBear, KoalaBear>);
            circuit
        },
        CircuitChallenger::new_koalabear_base,
    );
}

fn run_goldilocks_d2_poseidon2() {
    use p3_test_utils::goldilocks_params::{Goldilocks, RATE, WIDTH};
    type EF = BinomialExtensionField<Goldilocks, 2>;
    run_schedule::<Goldilocks, EF, _, _, _, _, _, WIDTH, RATE>(
        0x5452_474c_4432_5032,
        "Goldilocks/D2/Poseidon2",
        goldilocks_poseidon2_perm,
        setup_goldilocks_poseidon2,
        CircuitChallenger::new_goldilocks,
    );
}

fn run_babybear_d4_poseidon2() {
    use p3_test_utils::baby_bear_params::{RATE, WIDTH};
    type EF = BinomialExtensionField<BabyBear, 4>;
    run_schedule::<BabyBear, EF, _, _, _, _, _, WIDTH, RATE>(
        0x5452_4242_4434_5032,
        "BabyBear/D4/Poseidon2",
        default_babybear_poseidon2_16,
        || {
            let mut circuit = CircuitBuilder::<EF>::new();
            circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
                generate_poseidon2_trace::<EF, BabyBearD4Width16>,
                default_babybear_poseidon2_16(),
            );
            circuit.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, EF>);
            circuit.set_recompose_coeff_ctl_for_decompose_links(true);
            circuit
        },
        CircuitChallenger::new_babybear,
    );
}

fn run_koalabear_d5_poseidon2() {
    use p3_test_utils::koala_bear_quintic_params::{
        F, RATE, WIDTH, default_koalabear_poseidon2_16,
    };
    type EF = QuinticTrinomialExtensionField<F>;
    run_schedule::<F, EF, _, _, _, _, _, WIDTH, RATE>(
        0x5452_4b42_4435_5032,
        "KoalaBear/D5/Poseidon2",
        default_koalabear_poseidon2_16,
        || {
            let mut circuit = CircuitBuilder::<EF>::new();
            circuit.enable_poseidon2_perm_base::<KoalaBearD1Width16, _>(
                generate_poseidon2_trace::<EF, KoalaBearD1Width16>,
                LiftKoalaPermForQuintic::new(default_koalabear_poseidon2_16()),
            );
            circuit.enable_recompose::<F>(generate_recompose_trace::<F, EF>);
            circuit.set_recompose_coeff_ctl_for_decompose_links(true);
            circuit
        },
        CircuitChallenger::new_koalabear_base,
    );
}

fn run_koalabear_d1_poseidon1() {
    use p3_koala_bear::default_koalabear_poseidon1_16;
    use p3_test_utils::koala_bear_params::{KoalaBear, RATE, WIDTH};
    run_schedule::<KoalaBear, KoalaBear, _, _, _, _, _, WIDTH, RATE>(
        0x5452_4b42_4431_5031,
        "KoalaBear/D1/Poseidon1",
        default_koalabear_poseidon1_16,
        || {
            let mut circuit = CircuitBuilder::<KoalaBear>::new();
            circuit.enable_poseidon1_perm_base::<P1KoalaBearD1Width16, _>(
                generate_poseidon1_trace::<KoalaBear, P1KoalaBearD1Width16>,
                default_koalabear_poseidon1_16(),
            );
            circuit.enable_recompose::<KoalaBear>(generate_recompose_trace::<KoalaBear, KoalaBear>);
            circuit
        },
        CircuitChallenger::new_koalabear_poseidon1_base,
    );
}

fn run_goldilocks_d2_poseidon1() {
    use p3_test_utils::goldilocks_params::{Goldilocks, RATE, WIDTH};
    type EF = BinomialExtensionField<Goldilocks, 2>;
    run_schedule::<Goldilocks, EF, _, _, _, _, _, WIDTH, RATE>(
        0x5452_474c_4432_5031,
        "Goldilocks/D2/Poseidon1",
        goldilocks_poseidon1_perm,
        setup_goldilocks_poseidon1,
        CircuitChallenger::new_goldilocks_poseidon1,
    );
}

#[test]
fn assurance_challenger_schedules_koalabear_d1_poseidon2() {
    run_koalabear_d1_poseidon2();
}

#[test]
fn assurance_challenger_schedules_goldilocks_d2_poseidon2() {
    run_goldilocks_d2_poseidon2();
}

#[test]
fn assurance_challenger_schedules_babybear_d4_poseidon2() {
    run_babybear_d4_poseidon2();
}

#[test]
fn assurance_challenger_schedules_koalabear_d5_poseidon2() {
    run_koalabear_d5_poseidon2();
}

#[test]
fn assurance_challenger_schedules_koalabear_d1_poseidon1_control() {
    run_koalabear_d1_poseidon1();
}

#[test]
fn assurance_challenger_schedules_goldilocks_d2_poseidon1_control() {
    run_goldilocks_d2_poseidon1();
}
