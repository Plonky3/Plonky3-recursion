use std::env;

/// Fake Merkle verification circuit: Prove knowledge of a leaf in a Merkle tree
/// Public inputs: leaf_hash, expected_root
/// Private inputs: merkle path (siblings + directions)
use p3_baby_bear::BabyBear;
use p3_circuit::builder::CircuitBuilder;
use p3_circuit::{FakeMerklePrivateData, NonPrimitiveOpPrivateData};
use p3_field::PrimeCharacteristicRing;
use p3_prover::MultiTableProver;

type F = BabyBear;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let depth = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);

    let mut builder = CircuitBuilder::<F>::new();

    // Public inputs: leaf hash and expected root hash
    let leaf_hash = builder.add_public_input();
    let expected_root = builder.add_public_input();

    // Add fake Merkle verification operation
    // This declares that leaf_hash and expected_root are connected to witness bus
    // The AIR constraints will verify the Merkle path is valid
    let merkle_op_id = builder.add_fake_merkle_verify(leaf_hash, expected_root);

    let circuit = builder.build();
    let mut runner = circuit.runner();

    // Set public inputs
    let leaf_value = F::from_u64(42); // Our leaf value
    let expected_root_value = compute_merkle_root_classical(leaf_value, depth);
    runner.set_public_inputs(&[leaf_value, expected_root_value])?;

    // Create private Merkle path data
    let private_data = create_merkle_path_data(leaf_value, depth);
    runner.set_complex_op_private_data(
        merkle_op_id,
        NonPrimitiveOpPrivateData::FakeMerkleVerify(private_data),
    )?;

    let traces = runner.run()?;
    let multi_prover = MultiTableProver::new();
    let proof = multi_prover.prove_all_tables(&traces)?;
    multi_prover.verify_all_tables(&proof)?;

    println!(
        "✅ Verified Merkle path for leaf {leaf_value} with depth {depth} → root {expected_root_value}"
    );

    Ok(())
}

/// Simulate classical Merkle root computation for testing
fn compute_merkle_root_classical(leaf: F, depth: usize) -> F {
    let mut current = leaf;

    // Simulate hashing up the tree
    for i in 0..depth {
        // Simple mock hash: hash(left, right) = left + right + i
        let sibling = F::from_u64((i + 1) as u64 * 10); // Mock sibling values
        current = current + sibling + F::from_u64(i as u64);
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
