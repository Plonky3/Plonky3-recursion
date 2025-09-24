use core::array;

/// Hash verification circuit: prove the correct computation of a hash.
/// Public inputs: inputs, output
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_circuit::Challenger;
use p3_circuit::builder::CircuitBuilder;
use p3_circuit_prover::MultiTableProver;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

type F = BabyBear;

const HASH_RATE: usize = 8;
const HASH_CAPACITY: usize = 8;
const HASH_STATE_SIZE: usize = HASH_RATE + HASH_CAPACITY;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Poseidon2BabyBear::<HASH_STATE_SIZE>::new_from_rng_128(&mut rng);

    let mut builder = CircuitBuilder::<F>::new();

    let mut challenger = Challenger::new();

    // Public inputs: hash inputs and hash output
    let inputs: [_; HASH_STATE_SIZE] = array::from_fn(|_| builder.add_public_input());
    let outputs: [_; HASH_RATE] = array::from_fn(|_| builder.add_public_input());

    // Add hash operations
    challenger.add_inputs(&inputs);
    challenger.squeeze(&mut builder, &outputs);

    let circuit = builder.build();
    let mut runner = circuit.runner();

    // Generate random inputs
    let input_values: [_; 16] = array::from_fn(|_| rng.random::<F>());

    // Set public inputs
    let hasher = PaddingFreeSponge::<_, HASH_STATE_SIZE, HASH_RATE, HASH_RATE>::new(perm.clone());
    let output_values = hasher.hash_iter(input_values);
    let public_inputs = input_values
        .into_iter()
        .chain(output_values.into_iter())
        .collect::<Vec<_>>();
    runner.set_public_inputs(&public_inputs)?;

    let traces = runner.run::<_, HASH_STATE_SIZE, HASH_RATE, HASH_CAPACITY>(perm)?;
    let config = build_standard_config_babybear();
    let table_packing = TablePacking::from_counts(4, 1);
    let multi_prover = MultiTableProver::new(config).with_table_packing(table_packing);
    let proof = multi_prover.prove_all_tables(&traces)?;
    multi_prover.verify_all_tables(&proof)?;

    println!("✅ Verified hash({:?}) = {:?}", input_values, output_values);

    Ok(())
}
