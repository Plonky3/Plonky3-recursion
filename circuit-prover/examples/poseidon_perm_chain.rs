use std::collections::HashMap;
use std::env;
use std::error::Error;

/// Poseidon permutation chain example using the PoseidonPerm op.
///
/// Builds a chain of Poseidon permutations, verifies the final output against a native
/// computation, and demonstrates how Poseidon outputs can compose with other primitive
/// ops (addition, multiplication, bit decomposition).
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_batch_stark::CommonData;
use p3_circuit::op::WitnessHintsFiller;
use p3_circuit::ops::{PoseidonPermCall, PoseidonPermOps};
use p3_circuit::tables::generate_poseidon2_trace;
use p3_circuit::{CircuitBuilder, CircuitError, ExprId};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProver, Poseidon2Config, TablePacking, config};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
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

    // -------------------------------------------------------------------------
    // Demonstrate that Poseidon outputs can flow into other primitive ops.
    //
    // We simulate FRI-style "sample_bits" by:
    //   1) extracting base coefficients of an Ext4 element via witness hints,
    //   2) reconstructing the Ext4 element from those coefficients in-circuit,
    //   3) constraining the reconstruction to equal the Poseidon output,
    //   4) decomposing the base coefficient to bits and doing arithmetic on bits.
    // -------------------------------------------------------------------------

    // Native: extract the first base coefficient of final_limbs_ext[0]
    let out0_base_coeff: Base = final_limbs_ext[0].as_basis_coefficients_slice()[0];
    let out0_canonical = out0_base_coeff.as_canonical_u64();

    // We use 31 bits (full BabyBear width) because decompose_to_bits constrains the value
    // to equal the reconstruction from its bits.
    let log_max_height = 31;
    let expected_index = (out0_canonical as usize) & ((1usize << log_max_height) - 1);
    let expected_bit_sum = (expected_index as u64).count_ones() as u64;

    // In the circuit: extract *all* base coefficients from out0.
    let out0_coeffs =
        builder.alloc_witness_hints(ExtractAllCoeffsHint { input: out0 }, "out0_coeffs");
    let out0_c0 = out0_coeffs[0];
    let out0_c1 = out0_coeffs[1];
    let out0_c2 = out0_coeffs[2];
    let out0_c3 = out0_coeffs[3];

    // Reconstruct out0 from coefficients and constrain it equals the Poseidon output.
    let ext_basis: [Ext4; 4] = core::array::from_fn(|i| {
        let coeffs: [Base; 4] =
            core::array::from_fn(|j| if i == j { Base::ONE } else { Base::ZERO });
        Ext4::from_basis_coefficients_slice(&coeffs).unwrap()
    });

    let basis_exprs: [ExprId; 4] =
        core::array::from_fn(|i| builder.alloc_const(ext_basis[i], "ext_basis"));

    let mut reconstructed_out0 = builder.add_const(Ext4::ZERO);
    for (coeff, basis) in [out0_c0, out0_c1, out0_c2, out0_c3]
        .into_iter()
        .zip(basis_exprs)
    {
        let product = builder.mul(coeff, basis);
        reconstructed_out0 = builder.add(reconstructed_out0, product);
    }
    builder.connect(reconstructed_out0, out0);

    // Now it is sound to treat out0_c0 as "the base coefficient" used for bit sampling.
    let bits = builder.decompose_to_bits::<Base>(out0_c0, log_max_height)?;

    // Demonstrate arithmetic composability: out0 + out1
    let sum_outputs = builder.add(out0, out1);
    let expected_sum = final_limbs_ext[0] + final_limbs_ext[1];
    let expected_sum_expr = builder.alloc_const(expected_sum, "expected_sum_outputs");
    builder.connect(sum_outputs, expected_sum_expr);

    // Demonstrate arithmetic composability: out0 * out1
    let product_outputs = builder.mul(out0, out1);
    let expected_product = final_limbs_ext[0] * final_limbs_ext[1];
    let expected_product_expr = builder.alloc_const(expected_product, "expected_product_outputs");
    builder.connect(product_outputs, expected_product_expr);

    // Sum all bits (popcount).
    let mut bit_sum = builder.add_const(Ext4::ZERO);
    for &bit in &bits {
        bit_sum = builder.add(bit_sum, bit);
    }

    let expected_bit_sum_expr = builder.alloc_const(
        Ext4::from_prime_subfield(Base::from_u64(expected_bit_sum)),
        "expected_bit_sum",
    );
    builder.connect(bit_sum, expected_bit_sum_expr);

    // Reconstruct the index from bits and verify it matches expected_index.
    let reconstructed_index = builder.reconstruct_index_from_bits(&bits);
    let expected_index_expr = builder.alloc_const(
        Ext4::from_prime_subfield(Base::from_u64(expected_index as u64)),
        "expected_fri_query_index",
    );
    builder.connect(reconstructed_index, expected_index_expr);

    // Build + run.
    let circuit = builder.build()?;
    let expr_to_widx = circuit.expr_to_widx.clone();

    let table_packing = TablePacking::new(1, 1, 1);
    let airs_degrees = get_airs_and_degrees_with_prep::<_, _, 1>(&circuit, table_packing).unwrap();

    let runner = circuit.runner();
    let traces = runner.run()?;

    // Sanity-check exposed outputs against the native computation.
    let mut witness_map: HashMap<_, _> = HashMap::new();
    for (&idx, &val) in traces
        .witness_trace
        .index
        .iter()
        .zip(traces.witness_trace.values.iter())
    {
        witness_map.insert(idx, val);
    }

    let observed_out0 = {
        let wid = expr_to_widx
            .get(&out0)
            .ok_or("missing witness id for out0")?;
        *witness_map
            .get(wid)
            .ok_or("missing witness value for out0")?
    };
    let observed_out1 = {
        let wid = expr_to_widx
            .get(&out1)
            .ok_or("missing witness id for out1")?;
        *witness_map
            .get(wid)
            .ok_or("missing witness value for out1")?
    };

    assert_eq!(
        [observed_out0, observed_out1],
        [final_limbs_ext[0], final_limbs_ext[1]],
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

/// Witness hint that extracts *all* basis coefficients from an extension field element,
/// returning them as prime-subfield elements embedded in Ext4.
///
/// This is useful for operations like `sample_bits` that work on base field elements
/// but receive extension field inputs from Poseidon outputs.
///
/// IMPORTANT: to be sound, the circuit must reconstruct the extension element from
/// these coefficients and constrain it equals the original input (done in main()).
#[derive(Clone, Debug)]
struct ExtractAllCoeffsHint {
    input: ExprId,
}

impl WitnessHintsFiller<Ext4> for ExtractAllCoeffsHint {
    fn inputs(&self) -> &[ExprId] {
        core::slice::from_ref(&self.input)
    }

    fn n_outputs(&self) -> usize {
        4
    }

    fn compute_outputs(&self, inputs_val: Vec<Ext4>) -> Result<Vec<Ext4>, CircuitError> {
        let ext_val = inputs_val[0];
        let coeffs = ext_val.as_basis_coefficients_slice();
        Ok(coeffs
            .iter()
            .copied()
            .map(Ext4::from_prime_subfield)
            .collect())
    }
}
