use std::error::Error;

use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_batch_stark::CommonData;
use p3_circuit::tables::generate_poseidon2_trace;
use p3_circuit::{CircuitBuilder, ExprId, PoseidonPermOps};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProver, Poseidon2Config, TablePacking, config};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_symmetric::Permutation;

type Base = BabyBear;
type Ext4 = BinomialExtensionField<Base, 4>;

const LIMB_SIZE: usize = 4;
const WIDTH: usize = 16;

fn main() -> Result<(), Box<dyn Error>> {
    // Two-row Merkle path example:
    // Row 0: hashes leaf || sibling0 (merkle_path = true, new_start = true)
    // Row 1: merkle_path = true, new_start = false, mmcs_bit = 1 (previous hash becomes right child),
    //        limbs 2-3 take sibling1 as private inputs, limbs 0-1 are chained from previous output.
    //
    // We expose final digest limbs 0-1 and the mmcs_index_sum (should be 1).

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

    // Native row 0 permutation: hash(leaf limbs, sibling0 limbs)
    let row0_state = [leaf_limb0, leaf_limb1, sibling0_limb2, sibling0_limb3];
    let row0_state_base = flatten_ext_limbs(&row0_state);
    let row0_out_base = perm.permute(row0_state_base);
    let _row0_out_limbs = collect_ext_limbs(&row0_out_base);

    // Row 1 chaining: mmcs_bit = 1, so previous hash becomes right child (limbs 0-1 get prev_out[2..4])
    // limbs 2-3 are sibling1 supplied privately.
    let mut row1_state_base = [Base::ZERO; WIDTH];
    // limbs 0-1 from row0 output limbs 2-3
    row1_state_base[0..LIMB_SIZE].copy_from_slice(&row0_out_base[2 * LIMB_SIZE..3 * LIMB_SIZE]);
    row1_state_base[LIMB_SIZE..2 * LIMB_SIZE]
        .copy_from_slice(&row0_out_base[3 * LIMB_SIZE..4 * LIMB_SIZE]);
    // limbs 2-3 from sibling1
    let sibling1_flat =
        flatten_ext_limbs(&[sibling1_limb2, sibling1_limb3, Ext4::ZERO, Ext4::ZERO]);
    row1_state_base[2 * LIMB_SIZE..3 * LIMB_SIZE].copy_from_slice(&sibling1_flat[0..LIMB_SIZE]);
    row1_state_base[3 * LIMB_SIZE..4 * LIMB_SIZE]
        .copy_from_slice(&sibling1_flat[LIMB_SIZE..2 * LIMB_SIZE]);

    let row1_out_base = perm.permute(row1_state_base);
    let row1_out_limbs = collect_ext_limbs(&row1_out_base);

    // mmcs_index_sum should be 1 (starting from 0, bit=1 on row1)
    let mmcs_index_sum_row1 = Base::ONE;

    // Build circuit
    let mut builder = CircuitBuilder::<Ext4>::new();
    builder.enable_poseidon_perm::<BabyBearD4Width16>(
        generate_poseidon2_trace::<Ext4, BabyBearD4Width16>,
    );

    // Row 0: expose all inputs
    let inputs_row0: [ExprId; 4] = [
        builder.alloc_const(row0_state[0], "leaf0"),
        builder.alloc_const(row0_state[1], "leaf1"),
        builder.alloc_const(row0_state[2], "sibling0_2"),
        builder.alloc_const(row0_state[3], "sibling0_3"),
    ];

    builder.add_poseidon_perm(p3_circuit::ops::PoseidonPermCall {
        new_start: true,
        merkle_path: true,
        mmcs_bit: false,
        inputs: inputs_row0.map(Some),
        outputs: [None, None],
        mmcs_index_sum: None,
    })?;

    // Row 1: chain limbs 0-1, provide sibling1 in limbs 2-3, expose output limbs 0-1 and mmcs_index_sum.
    let sibling1_inputs: [Option<ExprId>; 4] = [
        None,
        None,
        Some(builder.alloc_const(sibling1_limb2, "sibling1_2")),
        Some(builder.alloc_const(sibling1_limb3, "sibling1_3")),
    ];
    let out0 = builder.alloc_const(row1_out_limbs[0], "root_limb0");
    let out1 = builder.alloc_const(row1_out_limbs[1], "root_limb1");
    let mmcs_idx_sum_expr = builder.alloc_const(
        Ext4::from_prime_subfield(mmcs_index_sum_row1),
        "mmcs_index_sum",
    );

    builder.add_poseidon_perm(p3_circuit::ops::PoseidonPermCall {
        new_start: false,
        merkle_path: true,
        mmcs_bit: true,
        inputs: sibling1_inputs,
        outputs: [Some(out0), Some(out1)],
        mmcs_index_sum: Some(mmcs_idx_sum_expr),
    })?;

    let circuit = builder.build()?;
    let table_packing = TablePacking::new(4, 4, 1);
    let airs_degrees = get_airs_and_degrees_with_prep::<_, _, 1>(&circuit, table_packing)?;
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let runner = circuit.runner();
    let traces = runner.run()?;

    // Check Poseidon trace rows and mmcs_index_sum exposure
    let poseidon_trace = traces
        .non_primitive_trace::<p3_circuit::tables::Poseidon2Trace<Base>>("poseidon2")
        .expect("poseidon2 trace missing");
    assert_eq!(poseidon_trace.total_rows(), 2, "expected two perm rows");

    let stark_config = config::baby_bear().build();
    let mut common = CommonData::from_airs_and_degrees(&stark_config, &airs, &degrees);
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
