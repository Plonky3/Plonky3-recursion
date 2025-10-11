use std::env;

/// Mmcs verification circuit: Prove knowledge of a leaf in a Mmcs tree
/// Public inputs: leaf_hash, leaf_index, expected_root
/// Private inputs: mmcs path (siblings + directions)
use p3_baby_bear::BabyBear;
use p3_circuit::ops::MmcsVerifyConfig;
use p3_circuit::tables::MmcsPrivateData;
use p3_circuit::{CircuitBuilder, ExprId, MmcsOps, NonPrimitiveOpPrivateData};
use p3_circuit_prover::prover::ProverError;
use p3_circuit_prover::{MultiTableProver, config};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

type F = BinomialExtensionField<BabyBear, 4>;

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}

fn main() -> Result<(), ProverError> {
    init_logger();

    let depth = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);
    let config = config::baby_bear().build();
    let compress = config::baby_bear_compression();
    let mmcs_config = MmcsVerifyConfig::babybear_quartic_extension_default();

    let mut builder = CircuitBuilder::new();
    builder.enable_mmcs(&mmcs_config);

    // Public inputs: leaf hash and expected root hash
    let leaf_hash = (0..mmcs_config.ext_field_digest_elems)
        .map(|_| builder.alloc_public_input("leaf_hash"))
        .collect::<Vec<ExprId>>();
    let index = builder.alloc_public_input("index");
    let expected_root = (0..mmcs_config.ext_field_digest_elems)
        .map(|_| builder.alloc_public_input("expected_root"))
        .collect::<Vec<ExprId>>();
    // Add a Mmcs verification operation
    // This declares that leaf_hash and expected_root are connected to witness bus
    // The AIR constraints will verify the Mmcs path is valid
    let mmcs_op_id = builder.add_mmcs_verify(&leaf_hash, &index, &expected_root)?;

    builder.dump_allocation_log();

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
                // Extra siblings on odd levels, but never on the last level
                if i % 2 == 0 || i == depth - 1 {
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
        .collect(); // The siblings, containing extra siblings every other level (except the last)
    let directions: Vec<bool> = (0..depth).map(|i| i % 2 == 0).collect();
    // the index is 0b1010...
    let index_value = F::from_u64(
        (0..32)
            .zip(directions.iter())
            .filter(|(_, dir)| **dir)
            .map(|(i, _)| 1 << i)
            .sum(),
    );
    let MmcsPrivateData {
        path_states: intermediate_states,
        ..
    } = MmcsPrivateData::new(&compress, &mmcs_config, &leaf_value, &siblings, &directions)?;
    let expected_root_value = intermediate_states
        .last()
        .expect("There is always at least the leaf hash")
        .clone();

    let mut public_inputs = vec![];
    public_inputs.extend(leaf_value);
    public_inputs.push(index_value);
    public_inputs.extend(&expected_root_value);

    runner.set_public_inputs(&public_inputs)?;
    // Set private Mmcs path data
    runner.set_non_primitive_op_private_data(
        mmcs_op_id,
        NonPrimitiveOpPrivateData::MmcsVerify(MmcsPrivateData::new(
            &compress,
            &mmcs_config,
            &leaf_value,
            &siblings,
            &directions,
        )?),
    )?;

    let traces = runner.run()?;
    let multi_prover = MultiTableProver::new(config).with_mmcs_table(mmcs_config.into());
    let proof = multi_prover.prove_all_tables(&traces)?;
    multi_prover.verify_all_tables(&proof)?;

    Ok(())
}
