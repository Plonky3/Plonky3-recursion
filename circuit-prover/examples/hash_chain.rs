use std::env;
use std::error::Error;

/// Hash chain circuit: Prove correctness of a Poseidon2 hash chain
/// The circuit absorbs multiple inputs sequentially and squeezes outputs,
/// enforcing that the in-circuit hash matches the native computation.
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_circuit::ops::HashOps;
use p3_circuit::ops::hash::HashConfig;
use p3_circuit::tables::generate_poseidon2_trace;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::{BatchStarkProver, Poseidon2Config, TablePacking, config};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_symmetric::Permutation;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

type F = BabyBear;
const BASE_RATE: usize = 8;

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

    // Parse hash chain length from command line (default: 3)
    let chain_length = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);

    let expected_outputs = compute_hash_chain_native(chain_length);

    let mut builder = CircuitBuilder::<BabyBear>::new();

    // Enable hash operations with BabyBear D=4, WIDTH=16 configuration
    let hash_config = HashConfig::babybear_poseidon2_16(BASE_RATE);
    builder.enable_hash_squeeze(
        &hash_config,
        generate_poseidon2_trace::<F, BabyBearD4Width16>,
    );

    // First absorb (reset=true)
    let mut inputs: Vec<ExprId> = Vec::new();
    for i in 0..2 {
        let input = builder.alloc_const(F::from_u64(i as u64 + 1), "hash_input");
        inputs.push(input);
    }
    println!("Absorbing first inputs: {:?}", inputs);

    builder.add_hash_squeeze("poseidon2_16", &inputs, true)?;

    let mut final_output = Vec::new();
    // Following absorbs (reset=false)
    for step in 1..chain_length {
        inputs.clear();
        for i in 0..2 {
            let input = builder.alloc_const(F::from_u64((step * 2 + i + 1) as u64), "hash_input");
            inputs.push(input);
        }
        final_output = builder.add_hash_squeeze("poseidon2_16", &inputs, false)?;
    }

    // Squeeze outputs
    builder.dump_allocation_log();

    let (circuit, _) = builder.build()?;

    // Clone expr_to_widx before consuming circuit
    let expr_to_widx = circuit.expr_to_widx.clone();

    let runner = circuit.runner();

    let traces = runner.run()?;

    // Extract actual computed values from the witness trace
    let mut actual_outputs = Vec::new();
    for squeeze_output_expr in &final_output {
        let witness_id = expr_to_widx.get(squeeze_output_expr).ok_or_else(|| {
            format!(
                "Could not find witness ID for squeeze output ExprId({})",
                squeeze_output_expr.0
            )
        })?;

        let value = traces
            .witness_trace
            .index
            .iter()
            .position(|&idx| idx == *witness_id)
            .and_then(|pos| traces.witness_trace.values.get(pos))
            .ok_or_else(|| {
                format!(
                    "Could not find witness value for WitnessId({})",
                    witness_id.0
                )
            })?;

        actual_outputs.push(*value);
    }

    assert_eq!(
        actual_outputs.len(),
        expected_outputs.len(),
        "Number of actual outputs should match expected outputs"
    );
    for (i, (actual, expected)) in actual_outputs
        .iter()
        .zip(expected_outputs.iter())
        .enumerate()
    {
        assert_eq!(
            actual, expected,
            "Squeeze output {} should equal expected output {}",
            i, i
        );
    }

    assert!(traces.non_primitive_traces.contains_key("poseidon2"));
    if let Some(poseidon2_trace) = traces.non_primitive_traces.get("poseidon2") {
        assert!(
            poseidon2_trace.rows() > 0,
            "Poseidon2 trace should have operations"
        );
    }

    // Prove and verify the circuit
    let stark_config = config::baby_bear().build();
    let table_packing = TablePacking::new(4, 4, 1);
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table(Poseidon2Config::baby_bear_d1_width16());
    let proof = prover.prove_all_tables(&traces)?;
    prover.verify_all_tables(&proof)?;

    println!(
        "Successfully proved and verified Poseidon2 hash chain of length {}!",
        chain_length
    );

    Ok(())
}

/// Compute Poseidon2 hash chain natively
fn compute_hash_chain_native(chain_length: usize) -> Vec<F> {
    // Parameters: WIDTH=16, RATE_EXT=2, CAPACITY_EXT=2, D=4
    // RATE = RATE_EXT * D = 8 base elements
    const WIDTH: usize = 16;
    const RATE_EXT: usize = 2;
    const CAPACITY_EXT: usize = 2;
    const D: usize = 4;
    const RATE: usize = RATE_EXT * D; // 8

    let perm = default_babybear_poseidon2_16();
    let mut state = [F::ZERO; WIDTH];

    // Operation 1: First absorb (reset=true)
    // Reset clears capacity, then absorb fills rate
    for j in 0..CAPACITY_EXT * D {
        state[RATE_EXT * D + j] = F::ZERO;
    }
    // Absorb first 2 elements
    state[0] = F::from_u64(1);
    state[1] = F::from_u64(2);
    // Zero out remaining rate elements (for reset)
    for elem in state.iter_mut().take(RATE).skip(2) {
        *elem = F::ZERO;
    }
    state = perm.permute(state);

    // Subsequent absorbs (reset=false, continues from previous state)
    for step in 1..chain_length {
        let base_value = (step * 2 + 1) as u64;
        state[0] = F::from_u64(base_value);
        state[1] = F::from_u64(base_value + 1);
        state = perm.permute(state);
    }

    // Then we read the output, which is the `RATE` first elements of the final state

    // Squeeze outputs: extract first 2 elements from rate
    state[0..RATE].to_vec()
}
