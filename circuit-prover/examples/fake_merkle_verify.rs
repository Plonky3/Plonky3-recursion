use std::env;

/// Fake Merkle verification circuit: Prove knowledge of a leaf in a Merkle tree
/// Public inputs: leaf_hash, expected_root
/// Private inputs: merkle path (siblings + directions)
use p3_baby_bear::BabyBear;
use p3_circuit::builder::CircuitBuilder;
use p3_circuit::{FakeMerklePrivateData, MerkleOps, NonPrimitiveOpPrivateData};
use p3_circuit_prover::MultiTableProver;
use p3_circuit_prover::config::babybear_config::build_standard_config_babybear;
use p3_circuit_prover::prover::ProverError;
use p3_field::PrimeCharacteristicRing;

type F = BabyBear;

fn main() -> Result<(), ProverError> {
    let depth = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);

    // Enable Merkle non-primitive op via policy
    let mut builder = CircuitBuilder::<F>::with_allow_all();

    // Public inputs: leaf hash and expected root hash
    let leaf_hash = builder.add_public_input();
    let expected_root = builder.add_public_input();

    // Add fake Merkle verification operation
    // This declares that leaf_hash and expected_root are connected to witness bus
    // The AIR constraints will verify the Merkle path is valid
    let merkle_op_id = builder.add_fake_merkle_verify(leaf_hash, expected_root)?;

    let circuit = builder.build()?;
    let mut runner = circuit.runner();

    // Create private Merkle path data and compute expected root with same mock hash
    let leaf_value = F::from_u64(42); // Our leaf value
    let private_data = create_merkle_path_data(leaf_value, depth);
    let expected_root_value = compute_merkle_root_from_private(leaf_value, &private_data);
    // Set public inputs
    runner.set_public_inputs(&[leaf_value, expected_root_value])?;
    runner.set_non_primitive_op_private_data(
        merkle_op_id,
        NonPrimitiveOpPrivateData::FakeMerkleVerify(private_data),
    )?;

    let traces = runner.run()?;
    let config = build_standard_config_babybear();
    let multi_prover = MultiTableProver::new(config);
    let proof = multi_prover.prove_all_tables(&traces)?;
    multi_prover.verify_all_tables(&proof)
}

/// Compute the expected root using the same mock hash as the circuit runner
fn compute_merkle_root_from_private(leaf: F, private: &FakeMerklePrivateData<F>) -> F {
    let mut current = leaf;
    for (sibling, &dir) in private
        .path_siblings
        .iter()
        .zip(private.path_directions.iter())
    {
        // Mock hash: left + right + (direction ? 1 : 0)
        current = current + *sibling + if dir { F::ONE } else { F::ZERO };
    }
    current
}

/// Create mock private Merkle path data
fn create_merkle_path_data(_leaf: F, depth: usize) -> FakeMerklePrivateData<F> {
    let mut path_siblings = Vec::new();
    let mut path_directions = Vec::new();

    for i in 0..depth {
        // Mock sibling (single field element)
        let sibling = F::from_u64((i + 1) as u64 * 10);
        path_siblings.push(sibling);

        // Alternate directions for demo
        path_directions.push(i % 2 == 0);
    }

    FakeMerklePrivateData {
        path_siblings,
        path_directions,
    }
}
