use std::env;

/// Mmcs verification circuit: Prove knowledge of a leaf in a Mmcs tree
/// Public inputs: leaf_hash, leaf_index, expected_root
/// Private inputs: mmcs path (siblings + directions)
use p3_baby_bear::BabyBear;
use p3_circuit::ops::MmcsVerifyConfig;
use p3_circuit::tables::MmcsPrivateData;
use p3_circuit::{CircuitBuilder, ExprId, MmcsOps, NonPrimitiveOpPrivateData};
use p3_circuit_prover::{BatchStarkProver, config};
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logger();

    let depth = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);
    let config = config::baby_bear().build();
    let compress = config::baby_bear_compression();
    let mmcs_config = MmcsVerifyConfig::babybear_quartic_extension_default();

    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_mmcs(&mmcs_config);

    // Public inputs: leaf hash and expected root hash
    // The leaves will contain `mmcs_config.ext_field_digest_elems` wires,
    // when the leaf index is odd, and an empty vector otherwise. This means
    // we're proving the opening of an Mmcs to matrices of height 2^depth, 2^(depth -1), ...
    let leaves: Vec<Vec<ExprId>> = (0..depth)
        .map(|i| {
            (0..if i % 2 == 0 && i != depth - 1 {
                mmcs_config.ext_field_digest_elems
            } else {
                0
            })
                .map(|_| builder.alloc_public_input("leaf_hash"))
                .collect::<Vec<ExprId>>()
        })
        .collect();
    let directions: Vec<ExprId> = (0..depth)
        .map(|_| builder.alloc_public_input("directions"))
        .collect();
    let expected_root = (0..mmcs_config.ext_field_digest_elems)
        .map(|_| builder.alloc_public_input("expected_root"))
        .collect::<Vec<ExprId>>();
    // Add a Mmcs verification operation
    // This declares that leaf_hash and expected_root are connected to witness bus
    // The AIR constraints will verify the Mmcs path is valid
    let mmcs_op_id = builder.add_mmcs_verify(&leaves, &directions, &expected_root)?;

    builder.dump_allocation_log();

    let circuit = builder.build()?;
    let mut runner = circuit.runner();

    // Set public inputs
    //
    let leaves_value: Vec<Vec<F>> = (0..depth)
        .map(|i| {
            if i % 2 == 0 && i != depth - 1 {
                vec![
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::ZERO,
                    F::from_u64(42),
                ]
            } else {
                vec![]
            }
        })
        .collect(); // Our leaf value
    let siblings: Vec<Vec<F>> = (0..depth)
        .map(|i| {
            vec![
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::from_u64((i + 1) * 10),
            ]
        })
        .collect();

    // the index is 0b1010...
    let directions: Vec<bool> = (0..depth).map(|i| i % 2 == 0).collect();

    let MmcsPrivateData {
        path_states: intermediate_states,
        ..
    } = MmcsPrivateData::new(
        &compress,
        &mmcs_config,
        &leaves_value,
        &siblings,
        &directions,
    )?;
    let expected_root_value = intermediate_states
        .last()
        .expect("There is always at least the leaf hash")
        .0
        .clone();

    let mut public_inputs = vec![];
    public_inputs.extend(leaves_value.iter().flatten());
    public_inputs.extend(directions.iter().map(|dir| F::from_bool(*dir)));
    public_inputs.extend(&expected_root_value);

    runner.set_public_inputs(&public_inputs)?;
    // Set private Mmcs path data
    runner.set_non_primitive_op_private_data(
        mmcs_op_id,
        NonPrimitiveOpPrivateData::MmcsVerify(MmcsPrivateData::new(
            &compress,
            &mmcs_config,
            &leaves_value,
            &siblings,
            &directions,
        )?),
    )?;
    let traces = runner.run()?;
    let mut batch_prover = BatchStarkProver::new(config);
    batch_prover.register_mmcs_table(mmcs_config.clone());
    let proof = batch_prover.prove_all_tables(&traces)?;
    batch_prover.verify_all_tables(&proof)?;

    Ok(())
}
