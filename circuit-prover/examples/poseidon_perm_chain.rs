use std::env;
use std::error::Error;

/// Poseidon permutation chain example using the PoseidonPerm op.
///
/// Builds a chain of Poseidon permutations, exposes the initial inputs and the
/// final output limbs via CTL, and proves the trace.
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_batch_stark::CommonData;
use p3_circuit::ops::{PoseidonPermCall, PoseidonPermOps};
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

/// Initializes a global logger with default parameters.
pub fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}

type Base = BabyBear;
type Ext4 = BinomialExtensionField<Base, 4>;

const WIDTH: usize = 16;
const LIMB_SIZE: usize = 4; // D=4

fn main() -> Result<(), Box<dyn Error>> {
    init_logger();

    // Parse chain length from CLI (default: 3 permutations)
    let chain_length: usize = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);
    assert!(chain_length >= 1, "chain length must be at least 1");

    // Build an initial state of 4 extension limbs with distinct coefficients.
    let mut ext_limbs = [Ext4::ZERO; 4];
    for (limb, ext_limb) in ext_limbs.iter_mut().enumerate() {
        let coeffs: [Base; LIMB_SIZE] =
            core::array::from_fn(|j| Base::from_u64((limb * LIMB_SIZE + j + 1) as u64));
        *ext_limb = Ext4::from_basis_coefficients_slice(&coeffs).unwrap();
    }

    // Compute native permutation chain over the base field (flattened coefficients).
    let perm = default_babybear_poseidon2_16();
    let mut states_base = Vec::with_capacity(chain_length + 1);
    let mut state_base = flatten_ext_limbs(&ext_limbs);
    states_base.push(state_base);
    for _ in 0..chain_length {
        state_base = perm.permute(state_base);
        states_base.push(state_base);
    }
    let final_state = states_base.last().copied().unwrap();
    let final_limbs_ext = collect_ext_limbs(&final_state);

    let mut builder = CircuitBuilder::<Ext4>::new();
    builder.enable_poseidon_perm::<BabyBearD4Width16>(
        generate_poseidon2_trace::<Ext4, BabyBearD4Width16>,
    );

    // Allocate initial input limbs (exposed via CTL on the first row).
    let mut first_inputs_expr: Vec<ExprId> = Vec::with_capacity(4);
    for &val in &ext_limbs {
        first_inputs_expr.push(builder.alloc_const(val, "poseidon_perm_input"));
    }

    // Allocate expected outputs for limbs 0 and 1 of the final row (for CTL exposure).
    let mut final_output_exprs: Vec<ExprId> = Vec::with_capacity(2);
    for limb in final_limbs_ext.iter().take(2) {
        final_output_exprs.push(builder.alloc_const(*limb, "poseidon_perm_output"));
    }

    // Add permutation rows.
    for row in 0..chain_length {
        let is_first = row == 0;
        let is_last = row + 1 == chain_length;
        let mmcs_bit_zero = builder.alloc_const(Ext4::ZERO, "mmcs_bit_zero");

        let mut inputs: [Option<ExprId>; 4] = [None, None, None, None];
        if is_first {
            for limb in 0..4 {
                inputs[limb] = Some(first_inputs_expr[limb]);
            }
        }

        let mut outputs: [Option<ExprId>; 2] = [None, None];
        if is_last {
            outputs[0] = Some(final_output_exprs[0]);
            outputs[1] = Some(final_output_exprs[1]);
        }

        builder.add_poseidon_perm(PoseidonPermCall {
            new_start: is_first,
            merkle_path: false,
            mmcs_bit: Some(mmcs_bit_zero),
            inputs,
            outputs,
            mmcs_index_sum: None,
        })?;
    }

    let circuit = builder.build()?;
    let expr_to_widx = circuit.expr_to_widx.clone();

    let table_packing = TablePacking::new(1, 1, 1);
    let airs_degrees = get_airs_and_degrees_with_prep::<_, _, 1>(&circuit, table_packing).unwrap();

    let runner = circuit.runner();
    let traces = runner.run()?;

    // Sanity-check exposed outputs against the native computation.
    let mut observed_outputs = Vec::with_capacity(2);
    for out_expr in &final_output_exprs {
        let witness_id = expr_to_widx
            .get(out_expr)
            .ok_or("missing witness id for output expr")?;
        let value = traces
            .witness_trace
            .index
            .iter()
            .position(|&idx| idx == *witness_id)
            .and_then(|pos| traces.witness_trace.values.get(pos))
            .copied()
            .ok_or("missing witness value for output")?;
        observed_outputs.push(value);
    }
    assert_eq!(
        observed_outputs,
        final_limbs_ext[..2],
        "final exposed limbs must match native Poseidon permutation output"
    );

    assert!(
        traces
            .non_primitive_traces
            .get("poseidon2")
            .is_some_and(|t| t.rows() == chain_length),
        "Poseidon2 trace should contain one row per perm op"
    );

    // Prove and verify the circuit.
    let stark_config = config::baby_bear().build();

    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut common = CommonData::from_airs_and_degrees(&stark_config, &airs, &degrees);

    // TODO: Pad preprocessed instances for non-primitive tables (same workaround as other examples).
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

    println!("Successfully proved and verified Poseidon perm chain of length {chain_length}!");

    Ok(())
}

fn flatten_ext_limbs(limbs: &[Ext4; 4]) -> [Base; WIDTH] {
    let mut out = [Base::ZERO; WIDTH];
    for (i, limb) in limbs.iter().enumerate() {
        let coeffs = limb.as_basis_coefficients_slice();
        out[i * LIMB_SIZE..(i + 1) * LIMB_SIZE].copy_from_slice(coeffs);
    }
    out
}

fn collect_ext_limbs(state: &[Base; WIDTH]) -> [Ext4; 4] {
    let mut limbs = [Ext4::ZERO; 4];
    for i in 0..4 {
        let chunk = &state[i * LIMB_SIZE..(i + 1) * LIMB_SIZE];
        limbs[i] = Ext4::from_basis_coefficients_slice(chunk).unwrap();
    }
    limbs
}
