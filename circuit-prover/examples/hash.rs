use core::array;
use std::env;

/// Hash verification circuit: prove the correct computation of a hash.
/// Public inputs: inputs, output
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_circuit::builder::{CircuitBuilder, CircuitHash, CircuitPerm};
use p3_circuit::{Challenger, FakeMerklePrivateData, NonPrimitiveOpPrivateData};
use p3_circuit_prover::MultiTableProver;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

type F = BabyBear;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = CircuitPerm::new_from_rng_128(&mut rng);

    let mut builder = CircuitBuilder::<F>::new();

    let mut challenger = Challenger::new();

    // Public inputs: hash inputs and hash output
    let inputs: [_; 16] = array::from_fn(|_| builder.add_public_input());
    let outputs: [_; 8] = array::from_fn(|_| builder.add_public_input());

    // Add hash operations
    challenger.add_inputs(&inputs);
    challenger.squeeze(&mut builder, &outputs);

    let circuit = builder.build();
    let mut runner = circuit.runner();

    // Generate random inputs
    let input_values: [_; 16] = array::from_fn(|_| rng.random::<F>());

    // Set public inputs
    let hasher = CircuitHash::new(perm.clone());
    let output_values = hasher.hash_iter(input_values);
    let public_inputs = input_values
        .into_iter()
        .chain(output_values.into_iter())
        .collect::<Vec<_>>();
    runner.set_public_inputs(&public_inputs)?;

    let traces = runner.run_with_hash(perm)?;
    let multi_prover = MultiTableProver::new();
    let proof = multi_prover.prove_all_tables(&traces)?;
    multi_prover.verify_all_tables(&proof)?;

    println!("✅ Verified hash({:?}) = {:?}", input_values, output_values);

    Ok(())
}
