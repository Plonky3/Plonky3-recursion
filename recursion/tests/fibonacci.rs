use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::circuit_verifier::{VerificationError, verify_circuit};
use p3_recursion::recursive_generation::generate_challenges;
use p3_recursion::recursive_pcs::{
    FriProofTargets, HashTargets, InputProofTargets, RecExtensionValMmcs, RecValMmcs, Witness,
};
use p3_recursion::recursive_traits::{ProofTargets, Recursive};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

type F = BabyBear;
const D: usize = 4;
type Challenge = BinomialExtensionField<F, D>;
type Dft = Radix2DitParallel<F>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm, 16, 8>;
type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

#[test]
fn test_fibonacci_verifier() -> Result<(), VerificationError> {
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
    let fri_params = create_test_fri_params(challenge_mmcs, 1);
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![BabyBear::ZERO, BabyBear::ONE, BabyBear::from_u64(x)];

    let air = FibonacciAir {};
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());

    const DIGEST_ELEMS: usize = 8;

    // Initialize the circuit builder.
    let mut circuit_builder = CircuitBuilder::<Challenge>::new();

    let public_values = (0..pis.len())
        .map(|_| circuit_builder.add_public_input())
        .collect::<Vec<_>>();

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

    // Determine the lengths of all the vectors within the proof.
    let mut all_lens =
        ProofTargets::<MyConfig, HashTargets<F, DIGEST_ELEMS>, InnerFri>::lens(&proof);

    // Add the targets for the proof.
    let proof_targets = ProofTargets::<MyConfig, HashTargets<F, DIGEST_ELEMS>, InnerFri>::new(
        &mut circuit_builder,
        &mut all_lens,
        proof.degree_bits,
    );

    let all_proof_values =
        ProofTargets::<MyConfig, HashTargets<F, DIGEST_ELEMS>, InnerFri>::get_values(&proof);

    // Generate all the challenge values.
    let all_challenges = generate_challenges(&air, &config, &proof, &pis, Some(&[log_height_max]))?;

    // Add the verification circuit to the builder.
    verify_circuit::<
        FibonacciAir,
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
    >(
        &config,
        &air,
        &mut circuit_builder,
        &proof_targets,
        &public_values,
    )?;

    // Build the circuit.
    let circuit = circuit_builder.build()?;
    let mut runner = circuit.runner();

    // Construct the public input values.
    let public_values = pis
        .iter()
        .map(|pi| Challenge::from(*pi))
        .chain(all_proof_values)
        .chain(all_challenges)
        .collect::<Vec<_>>();

    // Set the public inputs and run the verification circuit.
    runner
        .set_public_inputs(&public_values)
        .map_err(VerificationError::CircuitError)?;

    let _traces = runner.run().map_err(VerificationError::CircuitError)?;

    Ok(())
}
