use std::env;

/// Merkle verification circuit: Prove knowledge of a leaf in a Merkle tree
/// Public inputs: leaf_hash, leaf_index, expected_root
/// Private inputs: merkle path (siblings + directions)
use p3_baby_bear::BabyBear;
use p3_circuit::op::MerkleVerifyConfig;
use p3_circuit::tables::MerklePrivateData;
use p3_circuit::{CircuitBuilder, ExprId, MerkleOps, NonPrimitiveOpPrivateData};
use p3_circuit_prover::MultiTableProver;
use p3_circuit_prover::config::babybear_config::{
    baby_bear_standard_compression_function, build_standard_config_babybear,
};
use p3_circuit_prover::prover::ProverError;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;

type F = BinomialExtensionField<BabyBear, 4>;

fn main() -> Result<(), ProverError> {
    let depth = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);
    let config = build_standard_config_babybear();
    let compress = baby_bear_standard_compression_function();
    let merkle_config = MerkleVerifyConfig::babybear_quartic_extension_default(false);

    let mut builder = CircuitBuilder::new();
    builder.enable_merkle(&merkle_config);

    // Public inputs: leaf hash and expected root hash
    let leaf_hash = (0..merkle_config.ext_field_digest_elems)
        .map(|_| builder.add_public_input())
        .collect::<Vec<ExprId>>();
    let index = builder.add_public_input();
    let expected_root = (0..merkle_config.ext_field_digest_elems)
        .map(|_| builder.add_public_input())
        .collect::<Vec<ExprId>>();
    // Add a Merkle verification operation
    // This declares that leaf_hash and expected_root are connected to witness bus
    // The AIR constraints will verify the Merkle path is valid
    let merkle_op_id = builder.add_merkle_verify(&leaf_hash, &index, &expected_root)?;

    let circuit = builder.build()?;
    let mut runner = circuit.runner();

    // Set public inputs
    let leaf_value = [
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::from_u64(42),
    ]; // Our leaf value
    let siblings: Vec<(Vec<F>, Option<Vec<F>>)> = (0..depth)
        .map(|i| {
            (
                vec![
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::from_u64((i + 1) * 10),
                ],
                if i % 2 == 0 {
                    None
                } else {
                    Some(vec![
                        F::ZERO,
                        F::ZERO,
                        F::ZERO,
                        F::ZERO,
                        F::ZERO,
                        F::ZERO,
                        F::ZERO,
                        F::from_u64(i + 1),
                    ])
                },
            )
        })
        .collect(); // The siblings, containing extra siblings every other level
    let directions: Vec<bool> = (0..depth).map(|i| i % 2 == 0).collect();
    // the index is 0b1010...
    let index_value = F::from_u64(
        (0..32)
            .zip(directions.iter())
            .filter(|(_, dir)| **dir)
            .map(|(i, _)| 1 << i)
            .sum(),
    );
    let MerklePrivateData {
        path_states: intermediate_states,
        ..
    } = MerklePrivateData::new(
        &compress,
        &merkle_config,
        &leaf_value,
        &siblings,
        &directions,
    )?;
    let expected_root_value = intermediate_states
        .last()
        .expect("There is always at least the leaf hash")
        .clone();

    let mut public_inputs = vec![];
    public_inputs.extend(leaf_value);
    public_inputs.push(index_value);
    public_inputs.extend(&expected_root_value);

    runner.set_public_inputs(&public_inputs)?;
    // Set private Merkle path data
    runner.set_non_primitive_op_private_data(
        merkle_op_id,
        NonPrimitiveOpPrivateData::MerkleVerify(MerklePrivateData::new(
            &compress,
            &merkle_config,
            &leaf_value,
            &siblings,
            &directions,
        )?),
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
