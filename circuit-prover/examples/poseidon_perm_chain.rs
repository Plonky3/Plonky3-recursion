use std::env;
use std::error::Error;

/// Poseidon permutation chain example using the PoseidonPerm op.
///
/// Builds a chain of Poseidon permutations and verifies the final output against a native
/// computation.
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_batch_stark::CommonData;
use p3_circuit::ops::{PoseidonPermCall, PoseidonPermOps};
use p3_circuit::tables::generate_poseidon2_trace;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::common::{NonPrimitiveConfig, get_airs_and_degrees_with_prep};
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
fn init_logger() {
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

    // Parse chain length from CLI (default: 3 permutations).
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
    let mut state_base = flatten_ext_limbs(&ext_limbs);
    for _ in 0..chain_length {
        state_base = perm.permute(state_base);
    }
    let final_state = state_base;
    let final_limbs_ext = collect_ext_limbs(&final_state);

    // Build the circuit.
    let mut builder = CircuitBuilder::<Ext4>::new();
    builder.enable_poseidon_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Ext4, BabyBearD4Width16>,
        perm,
    );

    // Allocate initial input limbs (constants for this example).
    let first_inputs_expr: [ExprId; 4] =
        core::array::from_fn(|i| builder.alloc_const(ext_limbs[i], "poseidon_perm_input"));

    // Allocate expected outputs for limbs 0 and 1 of the final row (for checking).
    let expected_final_output_exprs: [ExprId; 2] = core::array::from_fn(|i| {
        builder.alloc_const(final_limbs_ext[i], "poseidon_perm_expected_output")
    });

    // Add permutation rows.
    let mmcs_bit_zero = builder.alloc_const(Ext4::ZERO, "mmcs_bit_zero");
    let mut last_outputs: [Option<ExprId>; 2] = [None, None];

    for row in 0..chain_length {
        let is_first = row == 0;
        let is_last = row + 1 == chain_length;

        let mut inputs: [Option<ExprId>; 4] = [None, None, None, None];
        if is_first {
            for limb in 0..4 {
                inputs[limb] = Some(first_inputs_expr[limb]);
            }
        }

        let (_op_id, outputs) = builder.add_poseidon_perm(PoseidonPermCall {
            new_start: is_first,
            merkle_path: false,
            mmcs_bit: Some(mmcs_bit_zero),
            inputs,
            out_ctl: [is_last, is_last],
            mmcs_index_sum: None,
        })?;

        if is_last {
            last_outputs = outputs;

            let out0 = outputs[0].ok_or("missing out0 expr")?;
            let out1 = outputs[1].ok_or("missing out1 expr")?;
            builder.connect(out0, expected_final_output_exprs[0]);
            builder.connect(out1, expected_final_output_exprs[1]);
        }
    }

    let out0 = last_outputs[0].ok_or("missing out0 expr")?;
    let out1 = last_outputs[1].ok_or("missing out1 expr")?;

    // Build + run.
    let circuit = builder.build()?;
    let expr_to_widx = circuit.expr_to_widx.clone();

    let table_packing = TablePacking::new(1, 1, 1);
    let poseidon_config = Poseidon2Config::baby_bear_d4_width16();
    let airs_degrees = get_airs_and_degrees_with_prep::<_, _, 1>(
        &circuit,
        table_packing,
        Some(&[NonPrimitiveConfig::Poseidon2(poseidon_config.clone())]),
    )
    .unwrap();

    let runner = circuit.runner();
    let traces = runner.run()?;

    // Sanity-check exposed outputs against the native computation.
    let observed_out0 = {
        let wid = expr_to_widx
            .get(&out0)
            .ok_or("missing witness id for out0")?;
        let pos = traces
            .witness_trace
            .index
            .iter()
            .position(|&idx| idx == *wid)
            .ok_or("missing witness id for out0 in witness trace")?;
        *traces
            .witness_trace
            .values
            .get(pos)
            .ok_or("missing witness value for out0")?
    };
    let observed_out1 = {
        let wid = expr_to_widx
            .get(&out1)
            .ok_or("missing witness id for out1")?;
        let pos = traces
            .witness_trace
            .index
            .iter()
            .position(|&idx| idx == *wid)
            .ok_or("missing witness id for out1 in witness trace")?;
        *traces
            .witness_trace
            .values
            .get(pos)
            .ok_or("missing witness value for out1")?
    };

    assert_eq!(
        [observed_out0, observed_out1],
        [final_limbs_ext[0], final_limbs_ext[1]]
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
    let common = CommonData::from_airs_and_degrees(&stark_config, &airs, &degrees);

    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table(poseidon_config);
    let proof = prover.prove_all_tables(&traces, &common)?;
    prover.verify_all_tables(&proof, &common)?;

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
