use std::error::Error;

use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_batch_stark::CommonData;
use p3_circuit::op::NonPrimitiveOpPrivateData;
use p3_circuit::tables::{PoseidonPermPrivateData, generate_poseidon2_trace};
use p3_circuit::{CircuitBuilder, ExprId, PoseidonPermOps};
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

const LIMB_SIZE: usize = 4;
const WIDTH: usize = 16;

fn main() -> Result<(), Box<dyn Error>> {
    init_logger();

    // Three-row Merkle path example (2 levels):
    // Row 0: hashes leaf || sibling0 (merkle_path = true, new_start = true, mmcs_bit = 0)
    // Row 1: merkle_path = true, new_start = false, mmcs_bit = 1 (previous hash becomes right child),
    //        limbs 0-1 get prev_out limbs 2-3; limbs 2-3 take sibling1 as private inputs.
    // Row 2: merkle_path = true, new_start = false, mmcs_bit = 0 (previous hash becomes left child),
    //        limbs 0-1 get prev_out limbs 0-1; limbs 2-3 take sibling2 as private inputs.
    //
    // Tree shape (limb ranges = base-field coeff slices of Ext4):
    //          root (row2 out)
    //         /                 \
    //   row2 left (row1 out)   sibling2 [25..32]
    //      /          \
    // sibling1 [17..24]  row0 out
    //                     /     \
    //               leaf [1..8]  sibling0 [9..16]
    //
    // We expose final digest limbs 0-1 as public inputs and the mmcs_index_sum (should be binary 010 = 2).

    let perm = default_babybear_poseidon2_16();

    // Build leaf and siblings as extension limbs.
    let leaf_limb0 = Ext4::from_basis_coefficients_slice(&[
        Base::from_u64(1),
        Base::from_u64(2),
        Base::from_u64(3),
        Base::from_u64(4),
    ])
    .expect("extension from coeffs");
    let leaf_limb1 = Ext4::from_basis_coefficients_slice(&[
        Base::from_u64(5),
        Base::from_u64(6),
        Base::from_u64(7),
        Base::from_u64(8),
    ])
    .expect("extension from coeffs");
    let sibling0_limb2 = Ext4::from_basis_coefficients_slice(&[
        Base::from_u64(9),
        Base::from_u64(10),
        Base::from_u64(11),
        Base::from_u64(12),
    ])
    .expect("extension from coeffs");
    let sibling0_limb3 = Ext4::from_basis_coefficients_slice(&[
        Base::from_u64(13),
        Base::from_u64(14),
        Base::from_u64(15),
        Base::from_u64(16),
    ])
    .expect("extension from coeffs");

    let sibling1_limb2 = Ext4::from_basis_coefficients_slice(&[
        Base::from_u64(17),
        Base::from_u64(18),
        Base::from_u64(19),
        Base::from_u64(20),
    ])
    .expect("extension from coeffs");
    let sibling1_limb3 = Ext4::from_basis_coefficients_slice(&[
        Base::from_u64(21),
        Base::from_u64(22),
        Base::from_u64(23),
        Base::from_u64(24),
    ])
    .expect("extension from coeffs");
    let sibling2_limb2 = Ext4::from_basis_coefficients_slice(&[
        Base::from_u64(25),
        Base::from_u64(26),
        Base::from_u64(27),
        Base::from_u64(28),
    ])
    .expect("extension from coeffs");
    let sibling2_limb3 = Ext4::from_basis_coefficients_slice(&[
        Base::from_u64(29),
        Base::from_u64(30),
        Base::from_u64(31),
        Base::from_u64(32),
    ])
    .expect("extension from coeffs");

    // Native row 0 permutation: hash(leaf limbs, sibling0 limbs)
    let row0_state = [leaf_limb0, leaf_limb1, sibling0_limb2, sibling0_limb3];
    let row0_state_base = flatten_ext_limbs(&row0_state);
    let row0_out_base = perm.permute(row0_state_base);

    // Row 1 chaining: mmcs_bit = 1, so previous hash becomes right child (limbs 0-1 get prev_out[2..4])
    // limbs 2-3 from sibling1
    let mut row1_state_base = [Base::ZERO; WIDTH];
    // limbs 0-1 from row0 output limbs 2-3
    row1_state_base[0..2 * LIMB_SIZE].copy_from_slice(&row0_out_base[2 * LIMB_SIZE..4 * LIMB_SIZE]);
    // limbs 2-3 from sibling1
    let sibling1_flat =
        flatten_ext_limbs(&[sibling1_limb2, sibling1_limb3, Ext4::ZERO, Ext4::ZERO]);
    row1_state_base[2 * LIMB_SIZE..4 * LIMB_SIZE].copy_from_slice(&sibling1_flat[0..2 * LIMB_SIZE]);

    let row1_out_base = perm.permute(row1_state_base);

    // Row 2 chaining: mmcs_bit = 0, so previous hash becomes left child (limbs 0-1 get prev_out[0..2])
    // limbs 2-3 from sibling2
    let mut row2_state_base = [Base::ZERO; WIDTH];
    row2_state_base[0..2 * LIMB_SIZE].copy_from_slice(&row1_out_base[0..2 * LIMB_SIZE]);
    let sibling2_flat =
        flatten_ext_limbs(&[sibling2_limb2, sibling2_limb3, Ext4::ZERO, Ext4::ZERO]);
    row2_state_base[2 * LIMB_SIZE..4 * LIMB_SIZE].copy_from_slice(&sibling2_flat[0..2 * LIMB_SIZE]);

    let row2_out_base = perm.permute(row2_state_base);
    let row2_out_limbs = collect_ext_limbs(&row2_out_base);

    // mmcs_index_sum should be 2 (bits: row1=1, row2=0)
    let mmcs_index_sum_row2 = Base::from_u64(2);

    // Build circuit
    let mut builder = CircuitBuilder::<Ext4>::new();
    builder.enable_poseidon_perm::<BabyBearD4Width16>(
        generate_poseidon2_trace::<Ext4, BabyBearD4Width16>,
    );

    // Row 0: expose all inputs
    let mmcs_bit_row0 = builder.alloc_const(Ext4::from_prime_subfield(Base::ZERO), "mmcs_bit_row0");
    let inputs_row0: [ExprId; 4] = [
        builder.alloc_const(row0_state[0], "leaf0"),
        builder.alloc_const(row0_state[1], "leaf1"),
        builder.alloc_const(row0_state[2], "sibling0_2"),
        builder.alloc_const(row0_state[3], "sibling0_3"),
    ];

    builder.add_poseidon_perm(p3_circuit::ops::PoseidonPermCall {
        new_start: true,
        merkle_path: true,
        mmcs_bit: Some(mmcs_bit_row0),
        inputs: inputs_row0.map(Some),
        outputs: [None, None],
        mmcs_index_sum: None,
    })?;

    // Row 1: chain limbs 0-1, provide sibling1 in limbs 2-3, expose output limbs 0-1 and mmcs_index_sum.
    let sibling1_inputs: [Option<ExprId>; 4] = [
        None, None, None, // Private
        None, // Private
    ];
    // Public root limbs
    let out0 = builder.add_public_input();
    let out1 = builder.add_public_input();
    let mmcs_idx_sum_expr = builder.add_public_input();

    let mmcs_bit_row1 = builder.alloc_const(Ext4::from_prime_subfield(Base::ONE), "mmcs_bit_row1");
    let row1_op_id = builder.add_poseidon_perm(p3_circuit::ops::PoseidonPermCall {
        new_start: false,
        merkle_path: true,
        mmcs_bit: Some(mmcs_bit_row1),
        inputs: sibling1_inputs,
        outputs: [None, None],
        mmcs_index_sum: None,
    })?;

    // Row 2: merkle left
    let mmcs_bit_row2 = builder.alloc_const(Ext4::from_prime_subfield(Base::ZERO), "mmcs_bit_row2");
    let sibling2_inputs: [Option<ExprId>; 4] = [
        None, None, None, // Private
        None, // Private
    ];
    let row2_op_id = builder.add_poseidon_perm(p3_circuit::ops::PoseidonPermCall {
        new_start: false,
        merkle_path: true,
        mmcs_bit: Some(mmcs_bit_row2),
        inputs: sibling2_inputs,
        outputs: [Some(out0), Some(out1)],
        mmcs_index_sum: Some(mmcs_idx_sum_expr),
    })?;

    let circuit = builder.build()?;
    let table_packing = TablePacking::new(4, 4, 1);
    let poseidon_config = Poseidon2Config::baby_bear_d4_width16();
    let airs_degrees = get_airs_and_degrees_with_prep::<_, _, 1>(
        &circuit,
        table_packing,
        Some(&[NonPrimitiveConfig::Poseidon2(poseidon_config.clone())]),
    )?;
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let mut runner = circuit.runner();
    runner.set_public_inputs(&[
        row2_out_limbs[0],
        row2_out_limbs[1],
        Ext4::from_prime_subfield(mmcs_index_sum_row2),
    ])?;

    // Set private inputs for Row 1
    // Row 1: mmcs_bit = 1 (Right Child). Chaining into 2-3.
    // Private input (Sibling) goes to 0-1.
    let mut row1_private_inputs = [Ext4::ZERO; 4];
    row1_private_inputs[0] = sibling1_limb2; // Sibling at 0
    row1_private_inputs[1] = sibling1_limb3; // Sibling at 1

    runner.set_non_primitive_op_private_data(
        row1_op_id,
        NonPrimitiveOpPrivateData::PoseidonPerm(PoseidonPermPrivateData {
            input_values: row1_private_inputs.to_vec(),
        }),
    )?;

    // Set private inputs for Row 2
    // Row 2: mmcs_bit = 0 (Left Child). Chaining into 0-1.
    // Private input (Sibling) goes to 2-3.
    let mut row2_private_inputs = [Ext4::ZERO; 4];
    row2_private_inputs[2] = sibling2_limb2; // Sibling at 2
    row2_private_inputs[3] = sibling2_limb3; // Sibling at 3

    runner.set_non_primitive_op_private_data(
        row2_op_id,
        NonPrimitiveOpPrivateData::PoseidonPerm(PoseidonPermPrivateData {
            input_values: row2_private_inputs.to_vec(),
        }),
    )?;

    let traces = runner.run()?;

    // Check Poseidon trace rows and mmcs_index_sum exposure
    // The trace is stored over the circuit field (Ext4), not the base field
    let poseidon_trace = traces
        .non_primitive_trace::<p3_circuit::tables::Poseidon2Trace<Ext4>>("poseidon2")
        .expect("poseidon2 trace missing");
    assert_eq!(poseidon_trace.total_rows(), 3, "expected three perm rows");

    let stark_config = config::baby_bear().build();
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
