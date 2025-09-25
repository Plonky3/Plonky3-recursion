use std::env;

/// Merkle verification circuit: Prove knowledge of a leaf in a Merkle tree
/// Public inputs: leaf_hash, leaf_index, expected_root
/// Private inputs: merkle path (siblings + directions)
use p3_baby_bear::BabyBear;
use p3_circuit::op::MerkleVerifyConfig;
use p3_circuit::tables::MerklePrivateData;
use p3_circuit::{CircuitBuilder, NonPrimitiveOpPrivateData};
use p3_circuit_prover::MultiTableProver;
use p3_circuit_prover::config::babybear_config::build_standard_config_babybear;
use p3_circuit_prover::prover::ProverError;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;

type F = BinomialExtensionField<BabyBear, 4>;

fn main() -> Result<(), ProverError> {
    let depth = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);
    let (config, merkle_config) = build_standard_config_babybear();

    let mut builder = CircuitBuilder::new();

    // Public inputs: leaf hash and expected root hash
    let leaf_hash = vec![builder.add_public_input(), builder.add_public_input()];
    let index_expr = builder.add_public_input();
    let expected_root = vec![builder.add_public_input(), builder.add_public_input()];

    // Add a Merkle verification operation
    // This declares that leaf_hash and expected_root are connected to witness bus
    // The AIR constraints will verify the Merkle path is valid
    let merkle_op_id =
        builder.add_merkle_verify(merkle_config.clone(), leaf_hash, index_expr, expected_root);

    let circuit = builder.build()?;
    let mut runner = circuit.runner();

    // Set public inputs
    let leaf_value = [F::ZERO, F::from_u64(42)]; // Our leaf value
    let siblings: Vec<(Vec<F>, Option<Vec<F>>)> = (0..depth)
        .map(|i| {
            (
                vec![F::ZERO, F::from_u64((i + 1) * 10)],
                if i % 2 == 0 {
                    None
                } else {
                    Some(vec![F::ZERO, F::from_u64(i + 1)])
                },
            )
        })
        .collect();
    let directions: Vec<bool> = (0..depth).map(|i| i % 2 == 0).collect();
    let index_value = F::from_u64(
        (0..32)
            .zip(directions.iter())
            .filter(|(_, dir)| **dir)
            .map(|(i, _)| 1 << i)
            .sum(),
    );
    let expected_root_value =
        compute_merkle_root(&merkle_config, &leaf_value, &siblings, &directions);

    runner.set_public_inputs(&[
        leaf_value[0],
        leaf_value[1],
        index_value,
        expected_root_value[0],
        expected_root_value[1],
    ])?;

    // Set private Merkle path data
    runner.set_non_primitive_op_private_data(
        merkle_op_id,
        NonPrimitiveOpPrivateData::MerkleVerify(MerklePrivateData {
            path_siblings: siblings,
        }),
    )?;

    let traces = runner.run()?;
    let multi_prover = MultiTableProver::new(config).with_merkle_table(merkle_config.into());
    let proof = multi_prover.prove_all_tables(&traces)?;
    multi_prover.verify_all_tables(&proof)?;

    println!(
        "✅ Verified Merkle path for leaf {leaf_value:?}, index {index_value} with depth {depth} → root {expected_root_value:?}",
    );

    Ok(())
}

pub type Hash = [BabyBear; 8];

/// Simulate classical Merkle root computation for testing
fn compute_merkle_root(
    merkle_config: &MerkleVerifyConfig<F>,
    leaf: &[F; 2],
    siblings: &[(Vec<F>, Option<Vec<F>>)],
    directions: &[bool],
) -> Vec<F> {
    directions.iter().zip(siblings.iter()).fold(
        leaf.to_vec(),
        |state, (direction, (sibling, other_sibling))| {
            let (left, right) = if *direction {
                (state.clone(), sibling.clone())
            } else {
                (sibling.clone(), state.clone())
            };
            let mut new_state = (merkle_config.compress)([&left, &right]);
            if let Some(other_sibling) = other_sibling {
                new_state = (merkle_config.compress)([&state, other_sibling]);
            }
            new_state
        },
    )
}
