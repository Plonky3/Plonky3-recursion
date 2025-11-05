use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_batch_stark::{StarkInstance, prove_batch, verify_batch};
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::fri::{
    FriProofTargets, FriVerifierParams, HashTargets, InputProofTargets, RecExtensionValMmcs,
    RecValMmcs, Witness,
};
use p3_recursion::public_inputs::BatchStarkVerifierInputsBuilder;
use p3_recursion::{VerificationError, generate_batch_challenges, verify_batch_circuit};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val};
use rand::SeedableRng;
use rand::rngs::SmallRng;

type F = BabyBear;
const D: usize = 4;
const RATE: usize = 8;
type Challenge = BinomialExtensionField<F, D>;
type Dft = Radix2DitParallel<F>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, RATE, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm, 16, RATE>;
type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

#[test]
fn test_fibonacci_batch_stark_prover_builds() -> Result<(), VerificationError> {
    let mut rng = SmallRng::seed_from_u64(2);

    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let pow_bits = fri_params.proof_of_work_bits;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    let config = MyConfig::new(pcs, challenger);

    // Prepare two Fibonacci instances with different lengths.
    let airs = vec![FibonacciAir {}, FibonacciAir {}];
    let traces = [
        generate_trace_rows::<F>(0, 1, 1 << 3),
        generate_trace_rows::<F>(1, 1, 1 << 4),
    ];

    let fib_target = |a: F, b: F, steps: usize| -> F {
        let mut prev = a;
        let mut cur = b;
        if steps == 0 {
            return prev;
        }
        for _ in 1..steps {
            let next = prev + cur;
            prev = cur;
            cur = next;
        }
        cur
    };

    let pis = vec![
        vec![F::ZERO, F::ONE, fib_target(F::ZERO, F::ONE, 1 << 3)],
        vec![F::ONE, F::ONE, fib_target(F::ONE, F::ONE, 1 << 4)],
    ];

    let instances = vec![
        StarkInstance {
            air: &airs[0],
            trace: traces[0].clone(),
            public_values: pis[0].clone(),
        },
        StarkInstance {
            air: &airs[1],
            trace: traces[1].clone(),
            public_values: pis[1].clone(),
        },
    ];

    let proof = prove_batch(&config, instances);
    verify_batch(&config, airs.as_slice(), &proof, &pis).unwrap();

    const DIGEST_ELEMS: usize = 8;
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
    let public_counts: Vec<_> = pis.iter().map(Vec::len).collect();
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(&mut circuit_builder, &proof, &public_counts);

    verify_batch_circuit::<
        FibonacciAir,
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        RATE,
    >(
        &config,
        airs.as_slice(),
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &fri_verifier_params,
    )?;

    let circuit = circuit_builder.build()?;

    let challenges = generate_batch_challenges(
        airs.as_slice(),
        &config,
        &proof,
        &pis,
        Some(&[pow_bits, log_height_max]),
    )?;
    let num_queries = proof.opening_proof.query_proofs.len();

    let public_inputs = verifier_inputs.pack_values(&pis, &proof, &challenges, num_queries);

    assert_eq!(public_inputs.len(), circuit.public_flat_len);
    assert!(!public_inputs.is_empty());

    // Actually RUN the circuit to verify it executes correctly
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public_inputs)?;
    let _traces = runner.run()?;

    Ok(())
}
