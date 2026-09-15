//! Bus-binding regression for the MMCS leaf-hash absorb.
//!
//! `verify_batch_circuit` packs each leaf's opened base-field coefficients into extension
//! limbs before absorbing them into the sponge. Eligible non-hiding binary D4/W16 Poseidon2
//! leaves use the `recompose/coeff` table, which publishes each coefficient on the
//! `WitnessChecks` bus and exposes coefficient identity in preprocessed metadata. Excluded
//! routes retain the legacy ALU lowering, including hiding-MMCS salts.

use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_circuit::ops::{Op, Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError, WitnessId};
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_matrix::Dimensions;
use p3_poseidon2_circuit_air::{BabyBearD4Width16, KoalaBearD4Width16};
use p3_recursion::Target;
use p3_recursion::pcs::verify_batch_circuit;

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type BabyEF = BinomialExtensionField<BabyBear, 4>;

const D: usize = 4;
const CFG: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D4_W16;
/// Leaf width in base-field coefficients: one full sponge rate, i.e. `rate_ext` full limbs.
const LEAF_WIDTH: usize = 8;
/// Leaf width that spans two sponge rate chunks with a tail shorter than one limb, so the
/// second absorb mixes the tail with coefficients carried over from the first permutation.
const PARTIAL_CHUNK_LEAF_WIDTH: usize = LEAF_WIDTH + 2;

/// A single-matrix `verify_batch_circuit` over a leaf of `LEAF_WIDTH` opened coefficients.
///
/// A group of `D` unrelated public inputs is recomposed up front so the built circuit is
/// guaranteed to contain a `recompose` row: that pins down that the NPO table really is
/// enabled here, and therefore that the leaf hash's lowering is a choice rather than a
/// consequence of the table being absent.
fn build_leaf_hash_circuit() -> Circuit<EF> {
    build_leaf_hash_circuit_of_width(LEAF_WIDTH)
}

fn build_leaf_hash_circuit_of_width(leaf_width: usize) -> Circuit<EF> {
    build_leaf_hash_circuit_with_options(leaf_width, false, true)
        .expect("eligible leaf hash circuit builds")
}

fn build_leaf_hash_circuit_with_salts(leaf_width: usize) -> Circuit<EF> {
    build_leaf_hash_circuit_with_options(leaf_width, true, true)
        .expect("salted leaf hash circuit builds")
}

fn build_leaf_hash_circuit_with_options(
    leaf_width: usize,
    salted: bool,
    enable_recompose: bool,
) -> Result<Circuit<EF>, CircuitBuilderError> {
    let perm = default_koalabear_poseidon2_16();
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        perm,
    );
    if enable_recompose {
        builder.enable_recompose::<F>(generate_recompose_trace::<F, EF>);
    }

    if enable_recompose {
        let unrelated: Vec<Target> = (0..D).map(|_| builder.public_input()).collect();
        builder
            .recompose_base_coeffs_to_ext::<F>(&unrelated)
            .expect("recompose lowers through the NPO table");
    }

    let cap: Vec<Vec<Target>> = vec![
        (0..CFG.rate_ext())
            .map(|_| builder.public_input())
            .collect(),
    ];
    let dimensions = [Dimensions {
        width: leaf_width,
        height: 4,
    }];
    let index_bits: Vec<Target> = (0..2).map(|_| builder.public_input()).collect();
    let opened: Vec<Vec<Target>> = vec![(0..leaf_width).map(|_| builder.public_input()).collect()];
    let salts = salted.then(|| vec![(0..2).map(|_| builder.public_input()).collect()]);

    verify_batch_circuit::<F, EF>(
        &mut builder,
        CFG,
        &cap,
        &dimensions,
        &index_bits,
        &opened,
        salts.as_deref(),
    )?;

    Ok(builder.build().expect("circuit builds"))
}

fn build_baby_bear_leaf_hash_circuit() -> Circuit<BabyEF> {
    let perm = default_babybear_poseidon2_16();
    let mut builder = CircuitBuilder::<BabyEF>::new();
    builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<BabyEF, BabyBearD4Width16>,
        perm,
    );
    builder.enable_recompose::<BabyBear>(generate_recompose_trace::<BabyBear, BabyEF>);

    let cap: Vec<Vec<Target>> = vec![
        (0..Poseidon2Config::BABY_BEAR_D4_W16.rate_ext())
            .map(|_| builder.public_input())
            .collect(),
    ];
    let dimensions = [Dimensions {
        width: LEAF_WIDTH,
        height: 4,
    }];
    let index_bits: Vec<Target> = (0..2).map(|_| builder.public_input()).collect();
    let opened: Vec<Vec<Target>> = vec![(0..LEAF_WIDTH).map(|_| builder.public_input()).collect()];

    verify_batch_circuit::<BabyBear, BabyEF>(
        &mut builder,
        Poseidon2Config::BABY_BEAR_D4_W16,
        &cap,
        &dimensions,
        &index_bits,
        &opened,
        None,
    )
    .expect("BabyBear verify_batch_circuit builds");

    builder.build().expect("BabyBear circuit builds")
}

fn is_npo_type<F: p3_field::Field>(op: &Op<F>, needle: &str) -> bool {
    match op {
        Op::NonPrimitiveOpWithExecutor { executor, .. } => {
            executor.op_type().as_str().contains(needle)
        }
        _ => false,
    }
}

fn writes<F: p3_field::Field>(op: &Op<F>, wid: WitnessId) -> bool {
    match op {
        Op::Const { out, .. } | Op::Public { out, .. } | Op::Alu { out, .. } => *out == wid,
        Op::Hint { outputs, .. } => outputs.contains(&wid),
        Op::NonPrimitiveOpWithExecutor { outputs, .. } => outputs.iter().any(|o| o.contains(&wid)),
    }
}

/// Position of the op that writes `wid`.
fn writer_position<F: p3_field::Field>(circuit: &Circuit<F>, wid: WitnessId) -> usize {
    circuit
        .ops
        .iter()
        .position(|op| writes(op, wid))
        .unwrap_or_else(|| panic!("no op writes {wid:?}"))
}

/// Every witness read by a Poseidon2 permutation, in op order.
fn permutation_input_witnesses<F: p3_field::Field>(circuit: &Circuit<F>) -> Vec<WitnessId> {
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
fn eligible_leaf_hash_limbs_use_coefficient_bound_recompose() {
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

    let mut coeff_packed = 0;
    let mut alu_packed = 0;
    for wid in perm_inputs {
        let writer = &circuit.ops[writer_position(&circuit, wid)];
        coeff_packed += usize::from(is_npo_type(writer, "recompose/coeff"));
        alu_packed += usize::from(matches!(writer, Op::Alu { .. }));
    }
    assert!(
        coeff_packed > 0,
        "the eligible leaf must use coefficient-bound recompose rows"
    );
    assert!(
        alu_packed == 0,
        "the eligible leaf's opened coefficients must not reach the sponge through ALU packing"
    );
}

#[test]
fn baby_bear_eligible_leaf_hash_uses_coefficient_bound_recompose() {
    let circuit = build_baby_bear_leaf_hash_circuit();
    let perm_inputs = permutation_input_witnesses(&circuit);
    assert!(
        perm_inputs.iter().any(|&wid| {
            is_npo_type(
                &circuit.ops[writer_position(&circuit, wid)],
                "recompose/coeff",
            )
        }),
        "BabyBear D4/W16 leaves must use coefficient-bound recompose rows"
    );
    assert!(
        perm_inputs
            .iter()
            .all(|&wid| !matches!(circuit.ops[writer_position(&circuit, wid)], Op::Alu { .. })),
        "BabyBear D4/W16 leaves must not use ALU packing"
    );
}

#[test]
fn re_pointing_a_leaf_hash_packing_is_visible_to_the_verifier() {
    let honest = build_leaf_hash_circuit();

    // The first permutation limb whose packing is a coefficient-bound row, and one of its
    // operands.
    let packed = permutation_input_witnesses(&honest)
        .into_iter()
        .find(|&wid| {
            is_npo_type(
                &honest.ops[writer_position(&honest, wid)],
                "recompose/coeff",
            )
        })
        .expect("a coefficient-bound permutation input");
    let packing_pos = writer_position(&honest, packed);
    let original_operand = match &honest.ops[packing_pos] {
        Op::NonPrimitiveOpWithExecutor { inputs, .. } => inputs[0][0],
        _ => unreachable!(),
    };

    // Re-point the packing at a different coefficient the same leaf already carries.
    let donor = permutation_input_witnesses(&honest)
        .into_iter()
        .filter_map(|wid| match &honest.ops[writer_position(&honest, wid)] {
            Op::NonPrimitiveOpWithExecutor { inputs, .. }
                if is_npo_type(
                    &honest.ops[writer_position(&honest, wid)],
                    "recompose/coeff",
                ) && inputs[0][0] != original_operand =>
            {
                Some(inputs[0][0])
            }
            _ => None,
        })
        .next()
        .expect("a second coefficient-bound permutation input to donate an operand");

    let mut edited = honest.clone();
    match &mut edited.ops[packing_pos] {
        Op::NonPrimitiveOpWithExecutor { inputs, .. } => inputs[0][0] = donor,
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
        "re-pointing a coefficient-bound packing must change the verifier's preprocessed \
         coefficient identity metadata, not just prover-side data"
    );
}

/// A leaf that spans more than one rate chunk carries the tail limb's remaining coefficients
/// over from the previous permutation's output.
///
/// Those carry-over coefficients are decomposition hints. Reconstructing them through the
/// coefficient-bound recompose table publishes each hint on the `WitnessChecks` bus and ties it
/// to the previous permutation output while preserving overwrite semantics for the unused slots.
#[test]
fn partial_chunk_carry_over_coefficients_use_coefficient_bound_recompose() {
    let circuit = build_leaf_hash_circuit_of_width(PARTIAL_CHUNK_LEAF_WIDTH);

    assert!(
        circuit.ops.iter().any(|op| is_npo_type(op, "recompose")),
        "the recompose NPO table must be enabled for this test to say anything"
    );

    let perm_inputs = permutation_input_witnesses(&circuit);
    let perm_count = circuit
        .ops
        .iter()
        .filter(|op| is_npo_type(op, "poseidon2_perm"))
        .count();
    assert!(
        perm_count >= 2,
        "the leaf must absorb across at least two permutations to reach the partial-chunk path"
    );

    let mut coeff_packed = 0;
    let mut alu_packed = 0;
    for wid in perm_inputs {
        let writer = &circuit.ops[writer_position(&circuit, wid)];
        coeff_packed += usize::from(is_npo_type(writer, "recompose/coeff"));
        alu_packed += usize::from(matches!(writer, Op::Alu { .. }));
    }
    assert!(
        coeff_packed > 0,
        "partial eligible leaves use coefficient-bound packing"
    );
    assert_eq!(
        alu_packed, 0,
        "partial eligible leaves do not use ALU packing"
    );

    // The carry-over decomposition itself must be reconstructed through the coefficient-bound
    // table: every hint output in the circuit is read by some `recompose/coeff` op.
    for op in &circuit.ops {
        if let Op::Hint { outputs, .. } = op {
            for out in outputs {
                assert!(
                    circuit.ops.iter().any(|other| matches!(
                        other,
                        Op::NonPrimitiveOpWithExecutor { inputs, .. }
                            if is_npo_type(other, "recompose/coeff")
                                && inputs.iter().flatten().any(|input| input == out)
                    )),
                    "hint output {out:?} is never read by a coefficient-bound recompose op, so \
                     nothing on the bus ties it to the value it was decomposed from"
                );
            }
        }
    }
}

#[test]
fn salted_leaf_hash_keeps_the_legacy_alu_lowering() {
    let circuit = build_leaf_hash_circuit_with_salts(LEAF_WIDTH);
    let perm_inputs = permutation_input_witnesses(&circuit);
    assert!(
        perm_inputs
            .iter()
            .any(|&wid| { matches!(circuit.ops[writer_position(&circuit, wid)], Op::Alu { .. }) }),
        "hiding leaves must keep their ALU packing"
    );
    assert!(
        !circuit
            .ops
            .iter()
            .any(|op| is_npo_type(op, "recompose/coeff")),
        "hiding leaves must not select coefficient-bound packing"
    );
}

#[test]
fn eligible_leaf_hash_fails_closed_without_coefficient_table() {
    let error = build_leaf_hash_circuit_with_options(LEAF_WIDTH, false, false)
        .expect_err("eligible coefficient-bound packing requires the enabled table");
    assert!(
        matches!(error, CircuitBuilderError::RecomposeCoeffLookupsUnavailable),
        "eligible calls must not silently fall back to ALU packing: {error:?}"
    );
}
