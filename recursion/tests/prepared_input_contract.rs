mod common;

use std::borrow::Cow;

use p3_circuit::CircuitBuilder;
use p3_circuit::symbolic::ColumnsTargets;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::Lookup;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::backend::fri::{FriRecursionBackendD5, FriRecursionBackendForExt};
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionBackendForExt};
use p3_recursion::prepared::{PreparedInput, PreparedPcsRecursionBackend, PreparedSource};
use p3_recursion::recursion::BatchOnly;
use p3_recursion::traits::{LookupMetadata, RecursiveAir};
use p3_recursion::{Poseidon2Config, RecursiveLagrangeSelectors, Target, VerificationError};
use p3_uni_stark::{Val, prove};

type Backend = common::KoalaBearD4Backend;
type Config = common::KoalaBearD4RecursionConfig;
type Contract = <Backend as PreparedPcsRecursionBackend<Config, BatchOnly, 4>>::InputContract;
type Challenge = <Config as p3_uni_stark::StarkGenericConfig>::Challenge;

struct UnknownArityAir;

impl RecursiveAir<Val<Config>, Challenge, LogUpGadget> for UnknownArityAir {
    fn width(&self) -> usize {
        panic!("prepared capture must not query width")
    }
    fn num_periodic_columns(&self) -> usize {
        panic!("prepared capture must not query periodic columns")
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val<Config>>]> {
        panic!("prepared capture must not query periodic columns")
    }
    fn eval_folded_circuit(
        &self,
        _builder: &mut CircuitBuilder<Challenge>,
        _sels: &RecursiveLagrangeSelectors,
        _alpha: &Target,
        _lookup_metadata: &LookupMetadata<'_, Val<Config>>,
        _columns: ColumnsTargets<'_>,
        _lookup_gadget: &LogUpGadget,
    ) -> Target {
        panic!("prepared capture must not evaluate the AIR")
    }
    fn get_log_num_quotient_chunks(
        &self,
        _preprocessed_width: usize,
        _trace_len: usize,
        _contexts: &[Lookup<Val<Config>>],
        _is_zk: usize,
        _lookup_gadget: &LogUpGadget,
    ) -> usize {
        panic!("prepared capture must not query quotient chunks")
    }
    fn declares_interactions(&self, _preprocessed_width: usize) -> bool {
        panic!("prepared capture must not query interactions")
    }
    fn opens_trace_next(&self) -> bool {
        panic!("prepared capture must not query openings")
    }
}

struct ExplicitArityAir<const N: usize>;

impl<const N: usize> RecursiveAir<Val<Config>, Challenge, LogUpGadget> for ExplicitArityAir<N> {
    fn expected_public_input_count(&self) -> Option<usize> {
        Some(N)
    }
    fn width(&self) -> usize {
        panic!("prepared capture must not query width")
    }
    fn num_periodic_columns(&self) -> usize {
        panic!("prepared capture must not query periodic columns")
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Val<Config>>]> {
        panic!("prepared capture must not query periodic columns")
    }
    fn eval_folded_circuit(
        &self,
        _builder: &mut CircuitBuilder<Challenge>,
        _sels: &RecursiveLagrangeSelectors,
        _alpha: &Target,
        _lookup_metadata: &LookupMetadata<'_, Val<Config>>,
        _columns: ColumnsTargets<'_>,
        _lookup_gadget: &LogUpGadget,
    ) -> Target {
        panic!("prepared capture must not evaluate the AIR")
    }
    fn get_log_num_quotient_chunks(
        &self,
        _preprocessed_width: usize,
        _trace_len: usize,
        _contexts: &[Lookup<Val<Config>>],
        _is_zk: usize,
        _lookup_gadget: &LogUpGadget,
    ) -> usize {
        panic!("prepared capture must not query quotient chunks")
    }
    fn declares_interactions(&self, _preprocessed_width: usize) -> bool {
        panic!("prepared capture must not query interactions")
    }
    fn opens_trace_next(&self) -> bool {
        panic!("prepared capture must not query openings")
    }
}

#[test]
fn built_in_backends_explicitly_opt_in_for_uni_and_batch_inputs() {
    fn assert_prepared<B, SC, A, const D: usize>()
    where
        SC: p3_uni_stark::StarkGenericConfig,
        A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
        B: PreparedPcsRecursionBackend<SC, A, D>,
    {
    }

    use p3_circuit::test_utils::FibonacciAir;
    assert_prepared::<FriRecursionBackendForExt<4>, Config, FibonacciAir, 4>();
    assert_prepared::<FriRecursionBackendForExt<4>, Config, BatchOnly, 4>();
    assert_prepared::<FriRecursionBackendD5<16, 8, Poseidon2Config>, Config, FibonacciAir, 5>();
    assert_prepared::<FriRecursionBackendD5<16, 8, Poseidon2Config>, Config, BatchOnly, 5>();
    assert_prepared::<
        WhirRecursionBackendForExt<4>,
        common::whir_config::BbWhirConfig,
        FibonacciAir,
        4,
    >();
    assert_prepared::<WhirRecursionBackendForExt<4>, common::whir_config::BbWhirConfig, BatchOnly, 4>(
    );
}

fn validate(
    fixture: &common::KoalaBearD4FirstLayerFixture,
    contract: &Contract,
    table_public_inputs: &[Vec<Val<Config>>],
) -> Result<(), VerificationError> {
    let input = PreparedInput::BatchStark {
        proof: &fixture.base_proof,
        common_data: &fixture.base_proof.stark_common,
        table_public_inputs,
    };
    <Backend as PreparedPcsRecursionBackend<Config, BatchOnly, 4>>::validate_prepared_input(
        &fixture.backend,
        &fixture.layer_config,
        contract,
        &input,
    )
}

#[test]
fn fri_uni_reference_enforces_exact_air_arity_but_values_stay_dynamic() {
    use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};

    let fixture = common::build_koala_bear_d4_first_layer_input();
    let n = 8;
    let trace = generate_trace_rows::<Val<Config>>(0, 1, n);
    let mut a = Val::<Config>::ZERO;
    let mut b = Val::<Config>::ONE;
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    let air = FibonacciAir {};
    let public_inputs = vec![Val::<Config>::ZERO, Val::<Config>::ONE, b];
    let proof = prove(&fixture.layer_config, &air, trace, &public_inputs);

    let reference = p3_recursion::RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs: public_inputs.clone(),
        preprocessed_commit: None,
    };
    let contract = fixture
        .backend
        .capture_input_contract(&fixture.layer_config, &reference)
        .expect("the blanket AIR hook reports Fibonacci's exact arity");

    for wrong in [public_inputs[..2].to_vec(), {
        let mut long = public_inputs.clone();
        long.push(Val::<Config>::ZERO);
        long
    }] {
        let source = p3_recursion::RecursionInput::UniStark {
            proof: &proof,
            air: &air,
            public_inputs: wrong,
            preprocessed_commit: None,
        };
        assert!(matches!(
            fixture
                .backend
                .capture_input_contract(&fixture.layer_config, &source),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    let mut changed_values = public_inputs;
    changed_values[2] += Val::<Config>::ONE;
    let input = PreparedInput::UniStark {
        proof: &proof,
        public_inputs: &changed_values,
        preprocessed_commit: None,
    };
    <Backend as PreparedPcsRecursionBackend<Config, FibonacciAir, 4>>::validate_prepared_input(
        &fixture.backend,
        &fixture.layer_config,
        &contract,
        &input,
    )
    .expect("same-length public values are dynamic witnesses");
}

#[test]
fn custom_uni_arity_is_fail_closed_and_explicitly_extensible() {
    use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};

    let fixture = common::build_koala_bear_d4_first_layer_input();
    let n = 8;
    let trace = generate_trace_rows::<Val<Config>>(0, 1, n);
    let mut a = Val::<Config>::ZERO;
    let mut b = Val::<Config>::ONE;
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    let public_inputs = vec![Val::<Config>::ZERO, Val::<Config>::ONE, b];
    let proof = prove(
        &fixture.layer_config,
        &FibonacciAir {},
        trace,
        &public_inputs,
    );

    let unknown = UnknownArityAir;
    let source = p3_recursion::RecursionInput::UniStark {
        proof: &proof,
        air: &unknown,
        public_inputs: public_inputs.clone(),
        preprocessed_commit: None,
    };
    assert!(matches!(
        <Backend as PreparedPcsRecursionBackend<Config, UnknownArityAir, 4>>::capture_input_contract(
            &fixture.backend,
            &fixture.layer_config,
            &source,
        ),
        Err(VerificationError::InvalidProofShape(_))
    ));

    let explicit = ExplicitArityAir::<3>;
    let source = p3_recursion::RecursionInput::UniStark {
        proof: &proof,
        air: &explicit,
        public_inputs,
        preprocessed_commit: None,
    };
    <Backend as PreparedPcsRecursionBackend<Config, ExplicitArityAir<3>, 4>>::capture_input_contract(
        &fixture.backend,
        &fixture.layer_config,
        &source,
    )
    .expect("a direct custom AIR can explicitly declare its exact arity");

    let zero = ExplicitArityAir::<0>;
    let source = p3_recursion::RecursionInput::UniStark {
        proof: &proof,
        air: &zero,
        public_inputs: vec![],
        preprocessed_commit: None,
    };
    <Backend as PreparedPcsRecursionBackend<Config, ExplicitArityAir<0>, 4>>::capture_input_contract(
        &fixture.backend,
        &fixture.layer_config,
        &source,
    )
    .expect("zero is a known exact public-input count");

    let source = p3_recursion::RecursionInput::<Config, BatchOnly>::UniStark {
        proof: &proof,
        air: &BatchOnly,
        public_inputs: vec![],
        preprocessed_commit: None,
    };
    <Backend as PreparedPcsRecursionBackend<Config, BatchOnly, 4>>::capture_input_contract(
        &fixture.backend,
        &fixture.layer_config,
        &source,
    )
    .expect("BatchOnly explicitly declares a known zero public-input count");
}

#[test]
fn batch_reference_never_queries_the_placeholder_air_arity() {
    let fixture = common::build_koala_bear_d4_first_layer_input();
    let table_public_inputs = vec![vec![]; fixture.base_proof.proof.opened_values.instances.len()];
    let source = p3_recursion::RecursionInput::<Config, UnknownArityAir>::BatchStark {
        proof: &fixture.base_proof,
        common_data: &fixture.base_proof.stark_common,
        table_public_inputs,
    };

    <Backend as PreparedPcsRecursionBackend<Config, UnknownArityAir, 4>>::capture_input_contract(
        &fixture.backend,
        &fixture.layer_config,
        &source,
    )
    .expect("batch capture derives every arity from reconstructed table AIRs");
}

#[test]
fn whir_uni_backend_captures_and_compares_the_native_contract() {
    use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
    use p3_recursion::recursion::RecursionInput;

    type WhirConfig = common::whir_config::BbWhirConfig;
    type WhirBackend = WhirRecursionBackendForExt<4>;

    let config = common::whir_config::bb_whir_config(vec![]);
    let n = 1 << 10;
    let trace = generate_trace_rows::<Val<WhirConfig>>(0, 1, n);
    let mut a = Val::<WhirConfig>::ZERO;
    let mut b = Val::<WhirConfig>::ONE;
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    let air = FibonacciAir {};
    let public_inputs = vec![Val::<WhirConfig>::ZERO, Val::<WhirConfig>::ONE, b];
    let mut proof = prove(&config, &air, trace, &public_inputs);
    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let source = RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs: public_inputs.clone(),
        preprocessed_commit: None,
    };
    let contract = backend
        .capture_input_contract(&config, &source)
        .expect("the honest WHIR proof has a valid native contract");
    drop(source);

    proof.opened_values.quotient_chunks.push(Vec::new());
    let input = PreparedInput::UniStark {
        proof: &proof,
        public_inputs: &public_inputs,
        preprocessed_commit: None,
    };
    assert!(matches!(
        <WhirBackend as PreparedPcsRecursionBackend<WhirConfig, FibonacciAir, 4>>::validate_prepared_input(
            &backend,
            &config,
            &contract,
            &input,
        ),
        Err(VerificationError::PreparedInputMismatch {
            component: "input.opened_values"
        })
    ));
}

#[test]
fn fri_batch_source_captures_and_accepts_its_native_contract() {
    let fixture = common::build_koala_bear_d4_first_layer_input();
    let table_public_inputs = vec![vec![]; fixture.base_proof.proof.opened_values.instances.len()];
    let source = PreparedSource::<_, BatchOnly>::batch(
        &fixture.base_proof,
        &fixture.base_proof.stark_common,
        &table_public_inputs,
    );
    let legacy = fixture.recursion_input();
    let contract = fixture
        .backend
        .capture_input_contract(&fixture.layer_config, &legacy)
        .expect("the trusted reference contract is valid");
    validate(&fixture, &contract, &table_public_inputs)
        .expect("the same native input satisfies its prepared contract");

    let _ = source;
}

#[test]
fn fri_batch_contract_rejects_compile_metadata_before_reconstruction() {
    let mut fixture = common::build_koala_bear_d4_first_layer_input();
    let table_public_inputs = vec![vec![]; fixture.base_proof.proof.opened_values.instances.len()];
    let legacy = fixture.recursion_input();
    let contract = fixture
        .backend
        .capture_input_contract(&fixture.layer_config, &legacy)
        .unwrap();
    drop(legacy);

    fixture.base_proof.proof.degree_bits[0] += 1;
    assert!(matches!(
        validate(&fixture, &contract, &table_public_inputs),
        Err(VerificationError::PreparedInputMismatch {
            component: "input.degree_bits"
        })
    ));
    fixture.base_proof.proof.degree_bits[0] -= 1;

    fixture.base_proof.table_packing = fixture
        .base_proof
        .table_packing
        .clone()
        .with_min_trace_height(2);
    assert!(matches!(
        validate(&fixture, &contract, &table_public_inputs),
        Err(VerificationError::PreparedInputMismatch {
            component: "input.metadata"
        })
    ));
}

#[test]
fn fri_batch_contract_binds_opening_partitions_and_optional_values() {
    let mut fixture = common::build_koala_bear_d4_first_layer_input();
    let table_public_inputs = vec![vec![]; fixture.base_proof.proof.opened_values.instances.len()];
    let legacy = fixture.recursion_input();
    let contract = fixture
        .backend
        .capture_input_contract(&fixture.layer_config, &legacy)
        .unwrap();
    drop(legacy);

    let opened = &mut fixture.base_proof.proof.opened_values.instances[0].base_opened_values;
    if opened.trace_local.len() > 1 {
        let value = opened.trace_local.pop().unwrap();
        opened.trace_next.get_or_insert_default().push(value);
    } else {
        opened.preprocessed_local = Some(Vec::new());
    }
    assert!(matches!(
        validate(&fixture, &contract, &table_public_inputs),
        Err(VerificationError::PreparedInputMismatch {
            component: "input.opened_values"
        })
    ));
}

#[test]
fn fri_batch_contract_rejects_changed_public_input_partition() {
    let fixture = common::build_koala_bear_d4_first_layer_input();
    let mut table_public_inputs =
        vec![vec![]; fixture.base_proof.proof.opened_values.instances.len()];
    let legacy = fixture.recursion_input();
    let contract = fixture
        .backend
        .capture_input_contract(&fixture.layer_config, &legacy)
        .unwrap();

    table_public_inputs[0].push(Val::<Config>::default());
    assert!(matches!(
        validate(&fixture, &contract, &table_public_inputs),
        Err(VerificationError::PreparedInputMismatch {
            component: "input.public_inputs"
        })
    ));
}

#[test]
fn fri_batch_contract_keeps_opening_and_commitment_scalars_dynamic() {
    let mut fixture = common::build_koala_bear_d4_first_layer_input();
    let table_public_inputs = vec![vec![]; fixture.base_proof.proof.opened_values.instances.len()];
    let legacy = fixture.recursion_input();
    let contract = fixture
        .backend
        .capture_input_contract(&fixture.layer_config, &legacy)
        .unwrap();
    drop(legacy);

    fixture.base_proof.proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += Challenge::ONE;
    let mut roots = fixture.base_proof.proof.commitments.main.as_ref().to_vec();
    roots[0][0] += Val::<Config>::ONE;
    fixture.base_proof.proof.commitments.main = roots.into();

    validate(&fixture, &contract, &table_public_inputs)
        .expect("fixed-shape opening and commitment scalars remain witness values");
}
