use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_circuit::ops::MmcsVerifyConfig;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit::{
    CircuitBuilder, MmcsPrivateData, NonPrimitiveOpPrivateData, NonPrimitiveOpType, Op,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::circuit_verifier::{VerificationError, verify_circuit};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::recursive_generation::generate_challenges;
use p3_recursion::recursive_pcs::{
    FriProofTargets, FriVerifierParams, HashTargets, InputProofTargets, RecExtensionValMmcs,
    RecValMmcs, Witness,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val, prove, verify};
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
    let mmcs_config = MmcsVerifyConfig::babybear_quartic_extension_default();
    circuit_builder.enable_mmcs(&mmcs_config);

    // Allocate all targets
    let verifier_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(&mut circuit_builder, &proof, pis.len());

    // Add the verification circuit to the builder.
    verify_circuit::<
        FibonacciAir,
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        RATE,
    >(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &fri_verifier_params,
    )?;

    // Build the circuit.
    let circuit = circuit_builder.build()?;

    let mut runner = circuit.runner();

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
    let public_inputs = verifier_inputs.pack_values(&pis, &proof, &all_challenges, num_queries);

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    // TODO: This block of code should be the implementation of Recursive::set_private_data function.
    let compress = MyCompress::new(perm.clone());
    let mut non_primitive_ops_iter =
        runner
            .all_non_primitive_ops()
            .into_iter()
            .filter(|(_, op)| {
                if let Op::NonPrimitiveOpWithExecutor { executor, .. } = op {
                    matches!(executor.op_type(), NonPrimitiveOpType::MmcsVerify)
                } else {
                    false
                }
            });
    for query in proof.opening_proof.query_proofs.iter() {
        // For each batch in the input proof there must be one MmcsVerify op
        for batch in query.input_proof.iter() {
            let x = non_primitive_ops_iter.next();
            match x {
                Some((op_id, _)) => {
                    let siblings = batch
                        .opening_proof
                        .iter()
                        .map(|digest| {
                            digest
                                .iter()
                                .map(|x| Challenge::from(*x))
                                .collect::<Vec<Challenge>>()
                        })
                        .collect::<Vec<Vec<Challenge>>>();

                    let private_data = NonPrimitiveOpPrivateData::MmcsVerify(
                        MmcsPrivateData::new::<F, _, _>(&mmcs_config, &siblings, compress.clone()),
                    );
                    runner
                        .set_non_primitive_op_private_data(op_id, private_data)
                        .unwrap();
                }
                _ => panic!("Expected MmcsVerify op"),
            };
        }
    }

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
