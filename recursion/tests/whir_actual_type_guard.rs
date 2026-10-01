//! Honest WHIR proofs with inconsistent recursive type declarations.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[allow(dead_code)]
#[path = "common/goldilocks_whir_config.rs"]
mod goldilocks_whir_config;
#[allow(dead_code)]
#[path = "common/poseidon1_whir_config.rs"]
mod poseidon1_whir_config;

use goldilocks_whir_config::{
    GoldChallenger, GoldDft, GoldF, GoldMmcs, gold_whir_mmcs, gold_whir_protocol_params,
};
use p3_circuit::ops::Poseidon1Config;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionConfig};
use p3_recursion::builtin_config::fixed_goldilocks_poseidon2_8;
use p3_recursion::generation::OpeningTranscript;
use p3_recursion::pcs::fri::MerkleCapTargets;
use p3_recursion::pcs::set_whir_mmcs_private_data;
use p3_recursion::pcs::whir::uni::{
    WhirUniPcs, WhirUniProof, WhirUniProofTargets, WhirUniVerifierParams,
    restore_whir_recursion_paths, whir_round_paths_op_count,
};
use p3_recursion::recursion::RecursionInput;
use p3_recursion::traits::RecursiveAir;
use p3_recursion::{
    PcsRecursionBackend, Poseidon2Config, PreparedInput, PreparedPcsRecursionBackend,
    VerificationError, build_next_layer_circuit,
};
use p3_sumcheck::layout::{Layout, PrefixProver};
use p3_uni_stark::{StarkGenericConfig, prove, verify};
use poseidon1_whir_config::{
    BABY_DIGEST_ELEMS, BabyChallenger, BabyEF, BabyF, BabyP1WhirConfig, baby_mmcs,
    baby_p1_whir_config, protocol_params,
};

const N: usize = 1 << 10;

fn fib_output<F: PrimeCharacteristicRing + Copy>(a: F, b: F) -> F {
    let (mut a, mut b) = (a, b);
    for _ in 1..N {
        (a, b) = (b, a + b);
    }
    b
}

#[derive(Clone)]
struct BabyWrongField {
    inner: BabyP1WhirConfig,
    params: WhirUniVerifierParams<BabyF>,
    prepare_calls: Arc<AtomicUsize>,
}

impl BabyWrongField {
    fn new(permutation: Poseidon1Config) -> Self {
        Self {
            inner: baby_p1_whir_config(),
            params: WhirUniVerifierParams::new(
                protocol_params(),
                PrefixProver::<BabyF, BabyEF>::variable_order(),
                permutation,
            )
            .unwrap(),
            prepare_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl StarkGenericConfig for BabyWrongField {
    type Pcs = <BabyP1WhirConfig as StarkGenericConfig>::Pcs;
    type Challenge = BabyEF;
    type Challenger = BabyChallenger;

    fn pcs(&self) -> &Self::Pcs {
        self.inner.pcs()
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.inner.initialise_challenger()
    }
}

impl WhirRecursionConfig for BabyWrongField {
    type Commitment = <BabyP1WhirConfig as WhirRecursionConfig>::Commitment;
    type InputProof = ();
    type OpeningProof = <BabyP1WhirConfig as WhirRecursionConfig>::OpeningProof;
    type RawOpeningProof = <BabyP1WhirConfig as WhirRecursionConfig>::RawOpeningProof;

    fn with_whir_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<BabyF, BabyEF, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        _circuit: &mut CircuitBuilder<BabyEF>,
    ) -> Result<(), VerificationError> {
        self.prepare_calls.fetch_add(1, Ordering::SeqCst);
        Err(VerificationError::InvalidProofShape(
            "prepare sentinel".into(),
        ))
    }

    fn pcs_verifier_params(&self) -> &WhirUniVerifierParams<BabyF> {
        &self.params
    }

    fn set_whir_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, BabyEF>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, BABY_DIGEST_ELEMS>(
            &baby_mmcs(),
            transcript,
            opening_proof,
            config.params.protocol_params(),
            config.params.folding(),
            config.params.variable_order(),
        )
        .map_err(|_| "BabyBear WHIR path restoration failed")?;
        let mut offset = 0;
        for round_paths in &paths {
            let count = whir_round_paths_op_count(round_paths);
            let ids = op_ids
                .get(offset..offset + count)
                .ok_or("missing WHIR path ops")?;
            set_whir_mmcs_private_data::<BabyF, BabyEF, BABY_DIGEST_ELEMS>(
                runner,
                ids,
                &round_paths.rounds,
                &round_paths.final_paths,
                Poseidon1Config::BABY_BEAR_D4_W16,
            )?;
            offset += count;
        }
        if offset != op_ids.len() {
            return Err("WHIR path op count mismatch");
        }
        Ok(())
    }
}

type GoldBasePcs =
    WhirUniPcs<GoldF, GoldF, GoldDft, GoldMmcs, GoldChallenger, PrefixProver<GoldF, GoldF>>;

#[derive(Clone)]
struct GoldBaseChallenge {
    pcs: GoldBasePcs,
    challenger: GoldChallenger,
    params: WhirUniVerifierParams<GoldF>,
    prepare_calls: Arc<AtomicUsize>,
}

impl GoldBaseChallenge {
    fn new() -> Self {
        let protocol = gold_whir_protocol_params();
        let challenger = GoldChallenger::new(fixed_goldilocks_poseidon2_8());
        Self {
            pcs: GoldBasePcs::new(
                protocol.clone(),
                GoldDft::default(),
                gold_whir_mmcs(),
                challenger.clone(),
                20,
            ),
            challenger,
            params: WhirUniVerifierParams::new(
                protocol,
                PrefixProver::<GoldF, GoldF>::variable_order(),
                Poseidon2Config::GOLDILOCKS_D2_W8,
            )
            .unwrap(),
            prepare_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl StarkGenericConfig for GoldBaseChallenge {
    type Pcs = GoldBasePcs;
    type Challenge = GoldF;
    type Challenger = GoldChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}

impl WhirRecursionConfig for GoldBaseChallenge {
    type Commitment = MerkleCapTargets<GoldF, 4>;
    type InputProof = ();
    type OpeningProof = WhirUniProofTargets<GoldF, GoldF, GoldMmcs, 4>;
    type RawOpeningProof = WhirUniProof<GoldF, GoldF, GoldMmcs>;

    fn with_whir_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<GoldF, GoldF, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        _circuit: &mut CircuitBuilder<GoldF>,
    ) -> Result<(), VerificationError> {
        self.prepare_calls.fetch_add(1, Ordering::SeqCst);
        Err(VerificationError::InvalidProofShape(
            "prepare sentinel".into(),
        ))
    }

    fn pcs_verifier_params(&self) -> &WhirUniVerifierParams<GoldF> {
        &self.params
    }

    fn set_whir_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, GoldF>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, 4>(
            &gold_whir_mmcs(),
            transcript,
            opening_proof,
            config.params.protocol_params(),
            config.params.folding(),
            config.params.variable_order(),
        )
        .map_err(|_| "Goldilocks WHIR path restoration failed")?;
        let mut offset = 0;
        for round_paths in &paths {
            let count = whir_round_paths_op_count(round_paths);
            let ids = op_ids
                .get(offset..offset + count)
                .ok_or("missing WHIR path ops")?;
            set_whir_mmcs_private_data::<GoldF, GoldF, 4>(
                runner,
                ids,
                &round_paths.rounds,
                &round_paths.final_paths,
                Poseidon2Config::GOLDILOCKS_D2_W8,
            )?;
            offset += count;
        }
        if offset != op_ids.len() {
            return Err("WHIR path op count mismatch");
        }
        Ok(())
    }
}

#[test]
fn honest_babybear_proof_rejects_koalabear_recursive_declaration() {
    let config = BabyWrongField::new(Poseidon1Config::KOALA_BEAR_D4_W16);
    let backend = WhirRecursionBackend::<16, 8, _>::new(Poseidon1Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let air = FibonacciAir {};
    let statement = vec![BabyF::ZERO, BabyF::ONE, fib_output(BabyF::ZERO, BabyF::ONE)];
    let proof = prove(
        &config,
        &air,
        generate_trace_rows::<BabyF>(0, 1, N),
        &statement,
    )
    .unwrap();
    verify(&config, &air, &proof, &statement).expect("honest BabyBear proof verifies natively");
    let input = RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs: statement.clone(),
        preprocessed_commit: None,
    };
    let result = <_ as PcsRecursionBackend<BabyWrongField, FibonacciAir, 4>>::validate_input(
        &backend, &config, &input,
    );
    assert!(
        matches!(result, Err(VerificationError::InvalidProofShape(ref message))
        if message == "WHIR input permutation field does not match the input base field")
    );
    assert!(matches!(
        build_next_layer_circuit::<BabyWrongField, _, _, 4>(&input, &config, &backend),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR input permutation field does not match the input base field"
    ));
    let mut builder = CircuitBuilder::<BabyEF>::new();
    assert!(matches!(
        <_ as PcsRecursionBackend<BabyWrongField, FibonacciAir, 4>>::build_verifier_circuit(
            &backend, &input, &config, &mut builder,
        ),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR input permutation field does not match the input base field"
    ));
    let empty = builder.build().unwrap();
    let baseline = CircuitBuilder::<BabyEF>::new().build().unwrap();
    assert_eq!(empty.ops.len(), baseline.ops.len());
    assert_eq!(empty.witness_count, baseline.witness_count);
    let mut prepare_builder = CircuitBuilder::<BabyEF>::new();
    assert!(matches!(
        <_ as PcsRecursionBackend<BabyWrongField, FibonacciAir, 4>>::prepare_circuit(
            &backend, &config, &mut prepare_builder,
        ),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR input permutation field does not match the input base field"
    ));
    let coherent_config = BabyWrongField::new(Poseidon1Config::BABY_BEAR_D4_W16);
    let coherent_backend = WhirRecursionBackend::<16, 8, _>::new(Poseidon1Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let contract = <_ as PreparedPcsRecursionBackend<BabyWrongField, FibonacciAir, 4>>::
        capture_input_contract(&coherent_backend, &coherent_config, &input).unwrap();
    assert!(matches!(
        <_ as PreparedPcsRecursionBackend<BabyWrongField, FibonacciAir, 4>>::
            capture_input_contract(&backend, &config, &input),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR input permutation field does not match the input base field"
    ));
    let prepared = PreparedInput::UniStark {
        proof: &proof,
        public_inputs: &statement,
        preprocessed_commit: None,
    };
    assert!(matches!(
        <_ as PreparedPcsRecursionBackend<BabyWrongField, FibonacciAir, 4>>::
            validate_prepared_input(&backend, &config, &contract, &prepared),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR input permutation field does not match the input base field"
    ));
    assert!(matches!(
        <_ as PreparedPcsRecursionBackend<BabyWrongField, FibonacciAir, 4>>::
            preflight_input(&backend, &config, &prepared),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR input permutation field does not match the input base field"
    ));
    assert_eq!(config.prepare_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn honest_goldilocks_base_challenge_rejects_d2_backend() {
    let config = GoldBaseChallenge::new();
    let backend = WhirRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>();
    let air = FibonacciAir {};
    let statement = vec![GoldF::ZERO, GoldF::ONE, fib_output(GoldF::ZERO, GoldF::ONE)];
    let proof = prove(
        &config,
        &air,
        generate_trace_rows::<GoldF>(0, 1, N),
        &statement,
    )
    .unwrap();
    verify(&config, &air, &proof, &statement)
        .expect("honest base-challenge Goldilocks proof verifies natively");
    let input = RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs: statement,
        preprocessed_commit: None,
    };
    let result = <_ as PcsRecursionBackend<GoldBaseChallenge, FibonacciAir, 2>>::validate_input(
        &backend, &config, &input,
    );
    assert!(
        matches!(result, Err(VerificationError::InvalidProofShape(ref message))
        if message == "WHIR backend challenge degree expected 2, got 1")
    );
    assert!(matches!(
        build_next_layer_circuit::<GoldBaseChallenge, _, _, 2>(&input, &config, &backend),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR backend challenge degree expected 2, got 1"
    ));
    let mut builder = CircuitBuilder::<GoldF>::new();
    assert!(matches!(
        <_ as PcsRecursionBackend<GoldBaseChallenge, FibonacciAir, 2>>::build_verifier_circuit(
            &backend, &input, &config, &mut builder,
        ),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR backend challenge degree expected 2, got 1"
    ));
    let empty = builder.build().unwrap();
    let baseline = CircuitBuilder::<GoldF>::new().build().unwrap();
    assert_eq!(empty.ops.len(), baseline.ops.len());
    assert_eq!(empty.witness_count, baseline.witness_count);
    let mut prepare_builder = CircuitBuilder::<GoldF>::new();
    assert!(matches!(
        <_ as PcsRecursionBackend<GoldBaseChallenge, FibonacciAir, 2>>::prepare_circuit(
            &backend, &config, &mut prepare_builder,
        ),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR backend challenge degree expected 2, got 1"
    ));
    assert!(matches!(
        <_ as PreparedPcsRecursionBackend<GoldBaseChallenge, FibonacciAir, 2>>::
            capture_input_contract(&backend, &config, &input),
        Err(VerificationError::InvalidProofShape(ref message))
            if message == "WHIR backend challenge degree expected 2, got 1"
    ));
    assert_eq!(config.prepare_calls.load(Ordering::SeqCst), 0);
}
