//! Bus-binding regression for the MMCS leaf-hash absorb.
//!
//! `verify_batch_circuit` packs each leaf's opened base-field coefficients into extension
//! limbs before absorbing them into the sponge. The recompose NPO table publishes only its
//! own output on the `WitnessChecks` bus: the packed limb's `v_0..v_{D-1}` columns are free
//! main-trace columns and the coefficient witness ids appear nowhere on the bus, so a limb
//! packed that way carries no relation to the coefficients the leaf is supposed to be made
//! of, and re-pointing the row at another coefficient group leaves the verifier's
//! preprocessed columns untouched. The ALU `mul_add` chain reads every coefficient as a
//! bus-bound operand and carries the operand witness ids in the ALU table's preprocessed
//! columns, so the limb is tied to the coefficients and the same edit is visible to the
//! verifier.
//!
//! Both tests build the leaf hash with the recompose NPO table *enabled*, which is the
//! configuration in which the two lowerings differ.

use p3_circuit::ops::{Op, Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{Circuit, CircuitBuilder, WitnessId};
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_matrix::Dimensions;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::Target;
use p3_recursion::pcs::verify_batch_circuit;

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;

const D: usize = 4;
const CFG: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D4_W16;
/// Leaf width in base-field coefficients: one full sponge rate, i.e. `rate_ext` full limbs.
const LEAF_WIDTH: usize = 8;

/// A single-matrix `verify_batch_circuit` over a leaf of `LEAF_WIDTH` opened coefficients.
///
/// A group of `D` unrelated public inputs is recomposed up front so the built circuit is
/// guaranteed to contain a `recompose` row: that pins down that the NPO table really is
/// enabled here, and therefore that the leaf hash's lowering is a choice rather than a
/// consequence of the table being absent.
fn build_leaf_hash_circuit() -> Circuit<EF> {
    let perm = default_koalabear_poseidon2_16();
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        perm,
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, EF>);

    let unrelated: Vec<Target> = (0..D).map(|_| builder.public_input()).collect();
    builder
        .recompose_base_coeffs_to_ext::<F>(&unrelated)
        .expect("recompose lowers through the NPO table");

    let cap: Vec<Vec<Target>> = vec![
        (0..CFG.rate_ext())
            .map(|_| builder.public_input())
            .collect(),
    ];
    let dimensions = [Dimensions {
        width: LEAF_WIDTH,
        height: 4,
    }];
    let index_bits: Vec<Target> = (0..2).map(|_| builder.public_input()).collect();
    let opened: Vec<Vec<Target>> = vec![(0..LEAF_WIDTH).map(|_| builder.public_input()).collect()];

    verify_batch_circuit::<F, EF>(
        &mut builder,
        CFG,
        &cap,
        &dimensions,
        &index_bits,
        &opened,
        None,
    )
    .expect("verify_batch_circuit builds");

    builder.build().expect("circuit builds")
}

fn is_npo_type(op: &Op<EF>, needle: &str) -> bool {
    match op {
        Op::NonPrimitiveOpWithExecutor { executor, .. } => {
            format!("{:?}", executor.op_type()).contains(needle)
        }
        _ => false,
    }
}

fn writes(op: &Op<EF>, wid: WitnessId) -> bool {
    match op {
        Op::Const { out, .. } | Op::Public { out, .. } | Op::Alu { out, .. } => *out == wid,
        Op::Hint { outputs, .. } => outputs.contains(&wid),
        Op::NonPrimitiveOpWithExecutor { outputs, .. } => outputs.iter().any(|o| o.contains(&wid)),
    }
}

/// Position of the op that writes `wid`.
fn writer_position(circuit: &Circuit<EF>, wid: WitnessId) -> usize {
    circuit
        .ops
        .iter()
        .position(|op| writes(op, wid))
        .unwrap_or_else(|| panic!("no op writes {wid:?}"))
}

/// Every witness read by a Poseidon2 permutation, in op order.
fn permutation_input_witnesses(circuit: &Circuit<EF>) -> Vec<WitnessId> {
    circuit
        .ops
        .iter()
        .filter(|op| is_npo_type(op, "poseidon2_perm"))
        .flat_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor { inputs, .. } => inputs.concat(),
            _ => unreachable!(),
        })
        .collect()
}

#[test]
fn leaf_hash_limbs_are_packed_by_the_alu_chain() {
    let circuit = build_leaf_hash_circuit();

    assert!(
        circuit.ops.iter().any(|op| is_npo_type(op, "recompose")),
        "the recompose NPO table must be enabled for this test to say anything"
    );

    let perm_inputs = permutation_input_witnesses(&circuit);
    assert!(
        !perm_inputs.is_empty(),
        "the leaf hash must run at least one permutation"
    );

    let mut alu_packed = 0;
    for wid in perm_inputs {
        let writer = &circuit.ops[writer_position(&circuit, wid)];
        assert!(
            !is_npo_type(writer, "recompose"),
            "a permutation reads {wid:?}, whose only writer is a recompose row: its packed \
             value is a free main-trace column"
        );
        alu_packed += usize::from(matches!(writer, Op::Alu { .. }));
    }
    assert!(
        alu_packed > 0,
        "the leaf's opened coefficients must reach the sponge through an ALU packing"
    );
}

#[test]
fn re_pointing_a_leaf_hash_packing_is_visible_to_the_verifier() {
    let honest = build_leaf_hash_circuit();

    // The first permutation limb whose packing is an ALU op, and one of its operands.
    let packed = permutation_input_witnesses(&honest)
        .into_iter()
        .find(|&wid| matches!(honest.ops[writer_position(&honest, wid)], Op::Alu { .. }))
        .expect("an ALU-packed permutation input");
    let packing_pos = writer_position(&honest, packed);
    let original_operand = match honest.ops[packing_pos] {
        Op::Alu { a, .. } => a,
        _ => unreachable!(),
    };

    // Re-point the packing at a different coefficient the same leaf already carries.
    let donor = permutation_input_witnesses(&honest)
        .into_iter()
        .filter_map(|wid| match honest.ops[writer_position(&honest, wid)] {
            Op::Alu { a, .. } if a != original_operand => Some(a),
            _ => None,
        })
        .next()
        .expect("a second ALU-packed permutation input to donate an operand");

    let mut edited = honest.clone();
    match &mut edited.ops[packing_pos] {
        Op::Alu { a, .. } => *a = donor,
        _ => unreachable!(),
    }

    let honest_prep = honest
        .generate_preprocessed_columns::<D>()
        .expect("honest preprocessed columns");
    let edited_prep = edited
        .generate_preprocessed_columns::<D>()
        .expect("edited preprocessed columns");
    assert!(
        honest_prep != edited_prep,
        "re-pointing the packing that feeds the leaf hash must change the constraint system \
         the verifier derives, not just prover-side data"
    );
}
