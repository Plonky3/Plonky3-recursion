use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit::{CircuitBuilder, CircuitError};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::recursive_pcs::{
    FriProofTargets, HashTargets, InputProofTargets, RecExtensionValMmcs, RecValMmcs, Witness,
};
use p3_recursion::recursive_traits::{ProofTargets, Recursive};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};
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
fn test_fibonacci_verifier() -> Result<(), CircuitError> {
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
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![BabyBear::ZERO, BabyBear::ONE, BabyBear::from_u64(x)];

    let proof = prove(&config, &FibonacciAir {}, trace, &pis);
    assert!(verify(&config, &FibonacciAir {}, &proof, &pis).is_ok());

    const DIGEST_ELEMS: usize = 8;

    // Initialize the circuit builder.
    let mut circuit_builder = CircuitBuilder::<Challenge>::new();

    // Determine the lengths of all the vectors within the proof.
    let mut all_lens = ProofTargets::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        FriProofTargets<
            F,
            Challenge,
            RecExtensionValMmcs<
                F,
                Challenge,
                DIGEST_ELEMS,
                RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
            >,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            Witness<F>,
        >,
    >::lens(&proof);

    // Add the targets for the proof.
    let proof_circuit = ProofTargets::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        FriProofTargets<
            F,
            Challenge,
            RecExtensionValMmcs<
                F,
                Challenge,
                DIGEST_ELEMS,
                RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
            >,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            Witness<F>,
        >,
    >::new(&mut circuit_builder, &mut all_lens, proof.degree_bits);

    let all_proof_values = ProofTargets::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        FriProofTargets<
            F,
            Challenge,
            RecExtensionValMmcs<
                F,
                Challenge,
                DIGEST_ELEMS,
                RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
            >,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            Witness<F>,
        >,
    >::get_values(&proof);

    println!(
        "proof targets: {:?}",
        proof_circuit.commitments_targets.trace_targets.hash_targets
    );
    let circuit = circuit_builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&all_proof_values)
}
