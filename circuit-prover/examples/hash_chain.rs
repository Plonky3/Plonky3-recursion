use std::env;
use std::error::Error;

/// Hash chain circuit: Prove correctness of a Poseidon2 hash chain
/// The circuit absorbs multiple inputs sequentially and squeezes outputs,
/// enforcing that the in-circuit hash matches the native computation.
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_batch_stark::CommonData;
use p3_circuit::ops::poseidon_perm::{HashConfig, add_hash_squeeze};
use p3_circuit::tables::generate_poseidon2_trace;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProver, Poseidon2Config, TablePacking, config};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_symmetric::Permutation;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

type F = BabyBear;
type CF = BinomialExtensionField<F, 4>;
const BASE_RATE: usize = 2;

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

    let mut builder = CircuitBuilder::<CF>::new();

    // Enable hash operations with BabyBear D=4, WIDTH=16 configuration
    let hash_config = HashConfig::babybear_poseidon2_16(BASE_RATE);
    builder.enable_poseidon_perm::<BabyBearD4Width16>(
        generate_poseidon2_trace::<CF, BabyBearD4Width16>,
    );

    // Intially the inputs are constants
    let mut inputs: Vec<ExprId> = Vec::new();
    for i in 0..2 {
        let input = builder.alloc_const(CF::from_u64(i as u64 + 1), "hash_input");
        inputs.push(input);
    }
    println!("Absorbing first inputs: {:?}", inputs);

    // First absorb (reset=true)
    add_hash_squeeze(&mut builder, &hash_config, "poseidon2_16", &inputs, true)?;

    let mut final_output = Vec::new();
    // Following absorbs (reset=false)
    for step in 1..chain_length {
        inputs.clear();
        for i in 0..2 {
            let input = builder.alloc_const(CF::from_u64((step * 2 + i + 1) as u64), "hash_input");
            inputs.push(input);
        }
        final_output =
            add_hash_squeeze(&mut builder, &hash_config, "poseidon2_16", &inputs, false)?;
    }

    // Squeeze outputs
    builder.dump_allocation_log();

    let circuit = builder.build()?;

    // Clone expr_to_widx before consuming circuit
    let expr_to_widx = circuit.expr_to_widx.clone();

    let table_packing = TablePacking::new(4, 4, 1);

    let airs_degrees = get_airs_and_degrees_with_prep::<_, _, 1>(&circuit, table_packing).unwrap();

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

    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut common = CommonData::from_airs_and_degrees(&stark_config, &airs, &degrees);

    // Since preprocessed data is not yet supported for non-primitive operations,
    // we need to extend common data with `None` values for all non-primitive operations that are included in the proof.
    for (_, trace) in &traces.non_primitive_traces {
        if trace.rows() != 0
            && let Some(p) = common.preprocessed.as_mut()
        {
            p.instances.push(None);
        }
    }
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table(Poseidon2Config::baby_bear_d4_width16());
    let proof = prover.prove_all_tables(&traces, &common)?;
    prover.verify_all_tables(&proof, &common)?;

    println!(
        "Successfully proved and verified Poseidon2 hash chain of length {}!",
        chain_length
    );

    Ok(())
}

/// Compute Poseidon2 hash chain natively
fn compute_hash_chain_native(chain_length: usize) -> Vec<CF> {
    // Parameters: WIDTH=16, RATE_EXT=2, CAPACITY_EXT=2, D=4
    // RATE = RATE_EXT * D = 8 base elements
    const EXT_WIDTH: usize = 4;
    const RATE_EXT: usize = 2;
    const CAPACITY_EXT: usize = 2;
    const D: usize = 4;
    const RATE: usize = RATE_EXT * D; // 8

    let perm = default_babybear_poseidon2_16();
    let mut state = [CF::ZERO; EXT_WIDTH];

    // Operation 1: First absorb (reset=true)
    // Reset clears capacity, then absorb fills rate
    for j in 0..CAPACITY_EXT {
        state[RATE_EXT + j] = CF::ZERO;
    }
    // Absorb first 2 elements
    state[0] = CF::from_u64(1);
    state[1] = CF::from_u64(2);
    // Zero out remaining rate elements (for reset)
    for elem in state.iter_mut().take(RATE).skip(2) {
        *elem = CF::ZERO;
    }
    let mut flat_state = state
        .iter()
        .flat_map(|x| x.as_basis_coefficients_slice().to_vec())
        .collect::<Vec<F>>()
        .try_into()
        .unwrap();
    flat_state = perm.permute(flat_state);
    state = flat_state
        .chunks(D)
        .map(|coeffs| CF::from_basis_coefficients_slice(coeffs).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // Subsequent absorbs (reset=false, continues from previous state)
    for step in 1..chain_length {
        let base_value = (step * 2 + 1) as u64;
        state[0] = CF::from_u64(base_value);
        state[1] = CF::from_u64(base_value + 1);

        let mut flat_state = state
            .iter()
            .flat_map(|x| x.as_basis_coefficients_slice().to_vec())
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();
        flat_state = perm.permute(flat_state);
        state = flat_state
            .chunks(D)
            .map(|coeffs| CF::from_basis_coefficients_slice(coeffs).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }

    // Then we read the output, which is the `RATE` first elements of the final state

    // Squeeze outputs: extract first 2 elements from rate
    state[0..RATE_EXT].to_vec()
}
