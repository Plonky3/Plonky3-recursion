use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::hash::CircuitPermutation;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::fri::{
    FriProofTargets, FriVerifierParams, HashTargets, InputProofTargets, RecExtensionValMmcs,
    RecValMmcs, Witness,
};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{VerificationError, generate_challenges, verify_circuit};
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

type F = BabyBear;
const D: usize = 4;
const RATE: usize = 8;
const EXT_RATE: usize = RATE / D;
const BASE_WIDTH: usize = 16;
type Challenge = BinomialExtensionField<F, D>;
type Dft = Radix2DitParallel<F>;
type Perm = Poseidon2BabyBear<BASE_WIDTH>;
type MyHash = PaddingFreeSponge<Perm, BASE_WIDTH, RATE, RATE>;
type MyCompress = TruncatedPermutation<Perm, 2, RATE, BASE_WIDTH>;
type ValMmcs = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm, BASE_WIDTH, RATE>;
type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}

struct MyPerm(Perm);

impl CircuitPermutation<Challenge> for MyPerm {
    fn permute(&self, state: &[Challenge]) -> Vec<Challenge> {
        let base_elems: Vec<F> = Challenge::flatten_to_base(state.to_vec());
        let base_array = base_elems.try_into().expect("invalid state length");
        let result_base = self.0.permute(base_array).to_vec();
        Challenge::reconstitute_from_base(result_base)
    }

    fn width(&self) -> usize {
        BASE_WIDTH / D
    }
}

#[test]
fn test_fibonacci_verifier() -> Result<(), VerificationError> {
    init_logger();
    let mut rng = SmallRng::seed_from_u64(1);
    let n = 1 << 3;
    let x = 21;

    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let trace = generate_trace_rows::<F>(0, 1, n);
    let log_final_poly_len = 0;
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let pow_bits = fri_params.proof_of_work_bits;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm.clone());

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![BabyBear::ZERO, BabyBear::ONE, BabyBear::from_u64(x)];

    let air = FibonacciAir {};
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());

    const DIGEST_ELEMS: usize = 8;

    // Type of the `OpeningProof` used in the circuit for a `TwoAdicFriPcs`.
    type InnerFri = FriProofTargets<
        Val<MyConfig>,
        <MyConfig as StarkGenericConfig>::Challenge,
        RecExtensionValMmcs<
            Val<MyConfig>,
            <MyConfig as StarkGenericConfig>::Challenge,
            DIGEST_ELEMS,
            RecValMmcs<Val<MyConfig>, DIGEST_ELEMS, MyHash, MyCompress>,
        >,
        InputProofTargets<
            Val<MyConfig>,
            <MyConfig as StarkGenericConfig>::Challenge,
            RecValMmcs<Val<MyConfig>, DIGEST_ELEMS, MyHash, MyCompress>,
        >,
        Witness<Val<MyConfig>>,
    >;

    let mut circuit_builder = CircuitBuilder::new();

    // Allocate all targets
    let verifier_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(&mut circuit_builder, &proof, None, pis.len());

    // Add the verification circuit to the builder.
    verify_circuit::<
        FibonacciAir,
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        EXT_RATE,
    >(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &fri_verifier_params,
    )?;

    circuit_builder.dump_allocation_log();

    // Build the circuit.
    let (circuit, _) = circuit_builder.build()?;

    let circuit_perm = MyPerm(perm.clone());
    let circuit_perm_width = circuit_perm.width();
    let mut runner = circuit.runner_with_permutation(Box::new(circuit_perm), circuit_perm_width);

    // Generate all the challenge values.
    let all_challenges = generate_challenges(
        &air,
        &config,
        &proof,
        &pis,
        Some(&[pow_bits, log_height_max]),
    )?;

    // Pack values using the same builder
    let num_queries = proof.opening_proof.query_proofs.len();
    let public_inputs =
        verifier_inputs.pack_values(&pis, &proof, &None, &all_challenges, num_queries);

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
