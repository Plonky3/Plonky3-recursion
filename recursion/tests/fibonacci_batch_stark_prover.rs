mod common;

use p3_air::{Air, BaseAir, PairBuilder};
use p3_batch_stark::CommonData;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
use p3_circuit_prover::batch_stark_prover::PrimitiveTable;
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProver, TablePacking};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::create_test_fri_params;
use p3_recursion::generation::generate_batch_challenges;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::verifier::verify_p3_recursion_proof_circuit;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::common::baby_bear_params::*;

/// Wrapper enum for heterogeneous circuit table AIRs
enum CircuitTableAir<F: Field, const D: usize> {
    Witness(WitnessAir<F, D>),
    Const(ConstAir<F, D>),
    Public(PublicAir<F, D>),
    Add(AddAir<F, D>),
    Mul(MulAir<F, D>),
}

impl<F: Field, const D: usize> BaseAir<F> for CircuitTableAir<F, D> {
    fn width(&self) -> usize {
        match self {
            Self::Witness(a) => a.width(),
            Self::Const(a) => a.width(),
            Self::Public(a) => a.width(),
            Self::Add(a) => a.width(),
            Self::Mul(a) => a.width(),
        }
    }
}

impl<AB, const D: usize> Air<AB> for CircuitTableAir<AB::F, D>
where
    AB: PairBuilder,
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Witness(a) => a.eval(builder),
            Self::Const(a) => a.eval(builder),
            Self::Public(a) => a.eval(builder),
            Self::Add(a) => a.eval(builder),
            Self::Mul(a) => a.eval(builder),
        }
    }
}

#[test]
fn test_fibonacci_batch_verifier() {
    let n: usize = 100;

    let mut builder = CircuitBuilder::new();

    // Public input: expected F(n)
    let expected_result = builder.alloc_public_input("expected_result");

    // Compute F(n) iteratively
    let mut a = builder.alloc_const(F::ZERO, "F(0)");
    let mut b = builder.alloc_const(F::ONE, "F(1)");

    for _i in 2..=n {
        let next = builder.add(a, b);
        a = b;
        b = next;
    }

    // Assert computed F(n) equals expected result
    builder.connect(b, expected_result);

    builder.dump_allocation_log();

    let table_packing = TablePacking::new(1, 4, 1);

    let circuit = builder.build().unwrap();
    let airs_degrees =
        get_airs_and_degrees_with_prep::<_, _, 1>(&circuit, table_packing, None).unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    // Set public input
    let expected_fib = compute_fibonacci_classical(n);
    runner.set_public_inputs(&[expected_fib]).unwrap();

    let traces = runner.run().unwrap();

    // Use a seeded RNG for deterministic permutations
    let mut rng = SmallRng::seed_from_u64(42);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    // Create test FRI params with log_final_poly_len = 0
    let fri_params = create_test_fri_params(challenge_mmcs, 0);

    // Create config for proving
    let pcs_proving = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger_proving = Challenger::new(perm);
    let config_proving = MyConfig::new(pcs_proving, challenger_proving);

    // Create common data for proving and verifying.
    let common = CommonData::from_airs_and_degrees(&config_proving, &airs, &degrees);

    let prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);
    let batch_stark_proof = prover.prove_all_tables(&traces, &common).unwrap();
    prover
        .verify_all_tables(&batch_stark_proof, &common)
        .unwrap();

    // Now verify the batch STARK proof recursively
    let dft2 = Dft::default();
    let mut rng2 = SmallRng::seed_from_u64(42);
    let perm2 = Perm::new_from_rng_128(&mut rng2);
    let hash2 = MyHash::new(perm2.clone());
    let compress2 = MyCompress::new(perm2.clone());
    let val_mmcs2 = ValMmcs::new(hash2, compress2);
    let challenge_mmcs2 = ChallengeMmcs::new(val_mmcs2.clone());
    let fri_params2 = create_test_fri_params(challenge_mmcs2, 0);
    let fri_verifier_params = FriVerifierParams::from(&fri_params2);
    let pow_bits = fri_params2.proof_of_work_bits;
    let log_height_max = fri_params2.log_final_poly_len + fri_params2.log_blowup;
    let pcs_verif = MyPcs::new(dft2, val_mmcs2, fri_params2);
    let challenger_verif = Challenger::new(perm2);
    let config = MyConfig::new(pcs_verif, challenger_verif);

    // Extract proof components
    let batch_proof = &batch_stark_proof.proof;
    let rows = batch_stark_proof.rows;
    let packing = batch_stark_proof.table_packing;

    const TRACE_D: usize = 1; // Proof traces are in base field

    // Base field AIRs for native challenge generation
    let native_airs = vec![
        CircuitTableAir::Witness(WitnessAir::<F, TRACE_D>::new(
            rows[PrimitiveTable::Witness],
            packing.witness_lanes(),
        )),
        CircuitTableAir::Const(ConstAir::<F, TRACE_D>::new(rows[PrimitiveTable::Const])),
        CircuitTableAir::Public(PublicAir::<F, TRACE_D>::new(rows[PrimitiveTable::Public])),
        CircuitTableAir::Add(AddAir::<F, TRACE_D>::new(
            rows[PrimitiveTable::Add],
            packing.add_lanes(),
        )),
        CircuitTableAir::Mul(MulAir::<F, TRACE_D>::new(
            rows[PrimitiveTable::Mul],
            packing.mul_lanes(),
        )),
    ];

    // Public values (empty for all 5 circuit tables, using base field)
    let pis: Vec<Vec<F>> = vec![vec![]; 5];

    // Build the recursive verification circuit
    let mut circuit_builder = CircuitBuilder::new();

    // Attach verifier without manually building circuit_airs
    let verifier_inputs = verify_p3_recursion_proof_circuit::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        RATE,
        TRACE_D,
    >(
        &config,
        &mut circuit_builder,
        &batch_stark_proof,
        &fri_verifier_params,
        &common,
    )
    .unwrap();

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Generate all the challenge values for batch proof (uses base field AIRs)
    let all_challenges = generate_batch_challenges(
        &native_airs,
        &config,
        batch_proof,
        &pis,
        Some(&[pow_bits, log_height_max]),
        &common,
    )
    .unwrap();

    // Pack values using the builder
    let public_inputs = verifier_inputs.pack_values(&pis, batch_proof, &common, &all_challenges);

    assert_eq!(public_inputs.len(), expected_public_input_len);
    assert!(!public_inputs.is_empty());

    // Actually run the circuit to ensure constraints are satisfiable
    let mut runner = verification_circuit.runner();
    runner.set_public_inputs(&public_inputs).unwrap();
    let _traces = runner.run().unwrap();
}

fn compute_fibonacci_classical(n: usize) -> F {
    if n == 0 {
        return F::ZERO;
    }
    if n == 1 {
        return F::ONE;
    }

    let mut a = F::ZERO;
    let mut b = F::ONE;

    for _i in 2..=n {
        let next = a + b;
        a = b;
        b = next;
    }

    b
}
