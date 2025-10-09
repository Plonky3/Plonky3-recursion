use std::env;
use std::error::Error;

use p3_baby_bear::BabyBear;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::{BatchStarkProver, TablePacking, config};
use p3_field::PrimeCharacteristicRing;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

type F = BabyBear;

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}

fn main() -> Result<(), Box<dyn Error>> {
    init_logger();

    let mut builder = CircuitBuilder::new();

    builder.add_const(F::ZERO);

    // TODO: test squeeze hash

    builder.dump_allocation_log();

    let (circuit, _) = builder.build()?;
    let mut runner = circuit.runner();

    let traces = runner.run()?;
    let config = config::baby_bear().build();
    let prover = BatchStarkProver::new(config);
    let proof = prover.prove_all_tables(&traces)?;
    prover.verify_all_tables(&proof)?;
    Ok(())
}
