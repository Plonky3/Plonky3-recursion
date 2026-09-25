use std::fmt;

use p3_batch_stark::ProverData;
use p3_circuit::ops::poseidon1_perm::{
    KoalaBearD1Width16 as Poseidon1KoalaD1, Poseidon1PermCallBase,
};
use p3_circuit::ops::poseidon2_perm::{
    KoalaBearD1Width16 as Poseidon2KoalaD1, Poseidon2PermCallBase,
};
use p3_circuit::ops::{
    NpoTypeId, Poseidon1Config, Poseidon2Config, generate_poseidon1_trace, generate_poseidon2_trace,
};
use p3_circuit::{CircuitBuilder, Traces};
use p3_circuit_prover::batch_stark_prover::{
    BatchTableInstance, DynamicAirEntry, NonPrimitiveTableEntry, Poseidon1Prover, Poseidon2Prover,
    TableProver, poseidon1_air_builders_d5, poseidon2_air_builders_d5,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::{self, KoalaBearConfig};
use p3_circuit_prover::{
    BatchStarkProver, BatchStarkProverError, CircuitProverData, ConstraintProfile,
    Poseidon1Preprocessor, Poseidon2Preprocessor, TablePacking,
};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon1_16, default_koalabear_poseidon2_16};
use p3_symmetric::Permutation;
use p3_test_utils::LiftPermToQuintic;
#[cfg(debug_assertions)]
use p3_test_utils::rejection_oracle::{DebugRejectionKind, classify_debug_diagnostic};

const MUTATED_ROW: usize = 0;
const FIRST_FULL_ROUND_POST_0: usize = 16;
type EF = QuinticTrinomialExtensionField<KoalaBear>;

const fn lift(value: KoalaBear) -> EF {
    EF::new([
        value,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
    ])
}

#[derive(Debug)]
enum ProofCheckError {
    Prove(BatchStarkProverError),
    Verify(BatchStarkProverError),
    #[cfg(debug_assertions)]
    DebugPanic(DebugRejectionKind),
}

impl fmt::Display for ProofCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prove(error) => write!(f, "prover error: {error}"),
            Self::Verify(error) => write!(f, "verifier error: {error}"),
            #[cfg(debug_assertions)]
            Self::DebugPanic(kind) => write!(f, "debug rejection: {kind:?}"),
        }
    }
}

#[cfg(debug_assertions)]
fn run_with_strict_debug_oracle<T>(f: impl FnOnce() -> T) -> Result<T, DebugRejectionKind> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied());
            message
                .and_then(classify_debug_diagnostic)
                .map_or_else(|| std::panic::resume_unwind(payload), Err)
        }
    }
}

fn assert_constraint_rejection(result: &Result<(), ProofCheckError>, context: &str) {
    #[cfg(debug_assertions)]
    assert!(
        matches!(
            result,
            Err(ProofCheckError::DebugPanic(DebugRejectionKind::Constraint))
        ),
        "{context}: expected exact constraint diagnostic, got {result:?}"
    );
    #[cfg(not(debug_assertions))]
    assert!(
        matches!(
            result,
            Err(ProofCheckError::Verify(BatchStarkProverError::Verify(_)))
        ),
        "{context}: forged trace must prove and reach verifier rejection, got {result:?}"
    );
}

struct PostStateMutatingProver {
    inner: Box<dyn TableProver<KoalaBearConfig>>,
}

impl PostStateMutatingProver {
    fn new(inner: Box<dyn TableProver<KoalaBearConfig>>) -> Self {
        Self { inner }
    }

    fn mutate(&self, instance: &mut BatchTableInstance<KoalaBearConfig>) {
        assert!(
            instance.rows > 0,
            "selected Poseidon table must be nonempty"
        );
        assert!(
            instance.trace.width > FIRST_FULL_ROUND_POST_0,
            "selected internal Poseidon coordinate must exist"
        );
        let coordinate = MUTATED_ROW * instance.trace.width + FIRST_FULL_ROUND_POST_0;
        instance.trace.values[coordinate] += KoalaBear::ONE;
    }
}

impl TableProver<KoalaBearConfig> for PostStateMutatingProver {
    fn op_type(&self) -> NpoTypeId {
        self.inner.op_type()
    }

    fn batch_instance_d1(
        &self,
        config: &KoalaBearConfig,
        packing: &TablePacking,
        traces: &Traces<KoalaBear>,
    ) -> Option<BatchTableInstance<KoalaBearConfig>> {
        self.inner.batch_instance_d1(config, packing, traces)
    }

    fn batch_instance_d2(
        &self,
        config: &KoalaBearConfig,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<KoalaBear, 2>>,
    ) -> Option<BatchTableInstance<KoalaBearConfig>> {
        self.inner.batch_instance_d2(config, packing, traces)
    }

    fn batch_instance_d4(
        &self,
        config: &KoalaBearConfig,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<KoalaBear, 4>>,
    ) -> Option<BatchTableInstance<KoalaBearConfig>> {
        self.inner.batch_instance_d4(config, packing, traces)
    }

    fn batch_instance_d5(
        &self,
        config: &KoalaBearConfig,
        packing: &TablePacking,
        traces: &Traces<QuinticTrinomialExtensionField<KoalaBear>>,
    ) -> Option<BatchTableInstance<KoalaBearConfig>> {
        let mut instance = self.inner.batch_instance_d5(config, packing, traces)?;
        self.mutate(&mut instance);
        Some(instance)
    }

    fn batch_instance_d6(
        &self,
        config: &KoalaBearConfig,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<KoalaBear, 6>>,
    ) -> Option<BatchTableInstance<KoalaBearConfig>> {
        self.inner.batch_instance_d6(config, packing, traces)
    }

    fn batch_instance_d8(
        &self,
        config: &KoalaBearConfig,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<KoalaBear, 8>>,
    ) -> Option<BatchTableInstance<KoalaBearConfig>> {
        self.inner.batch_instance_d8(config, packing, traces)
    }

    fn batch_air_from_table_entry(
        &self,
        config: &KoalaBearConfig,
        degree: usize,
        circuit_extension_degree: u32,
        table_entry: &NonPrimitiveTableEntry<KoalaBearConfig>,
    ) -> Result<DynamicAirEntry<KoalaBearConfig>, String> {
        self.inner
            .batch_air_from_table_entry(config, degree, circuit_extension_degree, table_entry)
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<KoalaBear>,
        min_height: usize,
        lanes: usize,
        circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<KoalaBearConfig>> {
        self.inner.air_with_committed_preprocessed(
            committed_prep,
            min_height,
            lanes,
            circuit_extension_degree,
        )
    }
}

fn prove_forged_and_verify(
    prover: &BatchStarkProver<KoalaBearConfig>,
    traces: &Traces<EF>,
    data: &CircuitProverData<KoalaBearConfig>,
) -> Result<(), ProofCheckError> {
    #[cfg(debug_assertions)]
    return match run_with_strict_debug_oracle(|| {
        let proof = prover
            .prove_all_tables(traces, data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<EF>(&proof)
            .map_err(ProofCheckError::Verify)
    }) {
        Ok(result) => result,
        Err(kind) => Err(ProofCheckError::DebugPanic(kind)),
    };

    #[cfg(not(debug_assertions))]
    {
        let proof = prover
            .prove_all_tables(traces, data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<EF>(&proof)
            .map_err(ProofCheckError::Verify)
    }
}

#[test]
fn assurance_poseidon1_rejects_first_full_round_post_state_mutation() {
    let native = default_koalabear_poseidon1_16();
    let mut input = [KoalaBear::ZERO; 16];
    input[0] = KoalaBear::from_u32(11);
    input[1] = KoalaBear::from_u32(13);
    let output = native.permute(input);

    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_poseidon1_perm_base::<Poseidon1KoalaD1, _>(
        generate_poseidon1_trace::<EF, Poseidon1KoalaD1>,
        LiftPermToQuintic::new(native),
    );
    let in0 = builder.public_input();
    let in1 = builder.public_input();
    let mut inputs = [None; 16];
    inputs[0] = Some(in0);
    inputs[1] = Some(in1);
    let mut out_ctl = [false; 8];
    out_ctl[0] = true;
    out_ctl[1] = true;
    let (_, outputs) = builder
        .add_poseidon1_perm_base(&Poseidon1PermCallBase {
            config: Poseidon1Config::KOALA_BEAR_D1_W16,
            new_start: true,
            inputs,
            out_ctl,
            return_all_outputs: false,
            absorb_len: 0,
        })
        .unwrap();
    let expected0 = builder.public_input();
    let expected1 = builder.public_input();
    builder.connect(outputs[0].unwrap(), expected0);
    builder.connect(outputs[1].unwrap(), expected1);
    let circuit = builder.build().unwrap();

    let cfg = config::koala_bear();
    let prep: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> = vec![Box::new(Poseidon1Preprocessor)];
    let air_builders: Vec<Box<dyn NpoAirBuilder<KoalaBearConfig, 5>>> =
        poseidon1_air_builders_d5::<KoalaBearConfig>();
    let (airs_degrees, primitive, non_primitive) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 5>(
            &circuit,
            &TablePacking::default(),
            &prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let op_type = NpoTypeId::poseidon1_perm(Poseidon1Config::KOALA_BEAR_D1_W16);
    let fixed_prep = non_primitive.get(&op_type).unwrap().clone();
    assert!(
        !fixed_prep.is_empty(),
        "Poseidon1 preprocessing must be nonempty"
    );
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let data = CircuitProverData::new(
        ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap(),
        primitive,
        non_primitive,
    );
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[
            lift(input[0]),
            lift(input[1]),
            lift(output[0]),
            lift(output[1]),
        ])
        .unwrap();
    let traces = runner.run().unwrap();
    assert_eq!(traces.non_primitive_traces[&op_type].rows(), 1);

    let mut honest = BatchStarkProver::new(config::koala_bear());
    honest.register_poseidon1_table::<5>(Poseidon1Config::KOALA_BEAR_D1_W16);
    let proof = honest.prove_all_tables(&traces, &data).unwrap();
    honest.verify_all_tables::<EF>(&proof).unwrap();

    let mut forged = BatchStarkProver::new(config::koala_bear());
    forged.register_table_prover(Box::new(PostStateMutatingProver::new(Box::new(
        Poseidon1Prover::new(
            Poseidon1Config::KOALA_BEAR_D1_W16,
            ConstraintProfile::Standard,
        ),
    ))));
    let result = prove_forged_and_verify(&forged, &traces, &data);
    assert_eq!(data.non_primitive_columns[&op_type], fixed_prep);
    assert_constraint_rejection(
        &result,
        "Poseidon1 row 0 first-full-round post[0] column 16 incremented by one",
    );
}

#[test]
fn assurance_poseidon2_rejects_first_full_round_post_state_mutation() {
    let native = default_koalabear_poseidon2_16();
    let mut input = [KoalaBear::ZERO; 16];
    input[0] = KoalaBear::from_u32(17);
    input[1] = KoalaBear::from_u32(19);
    let output = native.permute(input);

    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_poseidon2_perm_base::<Poseidon2KoalaD1, _>(
        generate_poseidon2_trace::<EF, Poseidon2KoalaD1>,
        LiftPermToQuintic::new(native),
    );
    let in0 = builder.public_input();
    let in1 = builder.public_input();
    let mut inputs = [None; 16];
    inputs[0] = Some(in0);
    inputs[1] = Some(in1);
    let mut out_ctl = [false; 8];
    out_ctl[0] = true;
    out_ctl[1] = true;
    let (_, outputs) = builder
        .add_poseidon2_perm_base(&Poseidon2PermCallBase {
            config: Poseidon2Config::KOALA_BEAR_D1_W16,
            new_start: true,
            inputs,
            out_ctl,
            return_all_outputs: false,
            absorb_len: 0,
        })
        .unwrap();
    let expected0 = builder.public_input();
    let expected1 = builder.public_input();
    builder.connect(outputs[0].unwrap(), expected0);
    builder.connect(outputs[1].unwrap(), expected1);
    let circuit = builder.build().unwrap();

    let cfg = config::koala_bear();
    let prep: Vec<Box<dyn NpoPreprocessor<KoalaBear>>> = vec![Box::new(Poseidon2Preprocessor)];
    let air_builders: Vec<Box<dyn NpoAirBuilder<KoalaBearConfig, 5>>> =
        poseidon2_air_builders_d5::<KoalaBearConfig>();
    let (airs_degrees, primitive, non_primitive) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 5>(
            &circuit,
            &TablePacking::default(),
            &prep,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let op_type = NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D1_W16);
    let fixed_prep = non_primitive.get(&op_type).unwrap().clone();
    assert!(
        !fixed_prep.is_empty(),
        "Poseidon2 preprocessing must be nonempty"
    );
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let data = CircuitProverData::new(
        ProverData::from_airs_and_degrees(&cfg, &airs, &degrees).unwrap(),
        primitive,
        non_primitive,
    );
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[
            lift(input[0]),
            lift(input[1]),
            lift(output[0]),
            lift(output[1]),
        ])
        .unwrap();
    let traces = runner.run().unwrap();
    assert_eq!(traces.non_primitive_traces[&op_type].rows(), 1);

    let mut honest = BatchStarkProver::new(config::koala_bear());
    honest.register_poseidon2_table::<5>(Poseidon2Config::KOALA_BEAR_D1_W16);
    let proof = honest.prove_all_tables(&traces, &data).unwrap();
    honest.verify_all_tables::<EF>(&proof).unwrap();

    let mut forged = BatchStarkProver::new(config::koala_bear());
    forged.register_table_prover(Box::new(PostStateMutatingProver::new(Box::new(
        Poseidon2Prover::new(
            Poseidon2Config::KOALA_BEAR_D1_W16,
            ConstraintProfile::Standard,
        ),
    ))));
    let result = prove_forged_and_verify(&forged, &traces, &data);
    assert_eq!(data.non_primitive_columns[&op_type], fixed_prep);
    assert_constraint_rejection(
        &result,
        "Poseidon2 row 0 first-full-round post[0] column 16 incremented by one",
    );
}
