//! Chained BLAKE3 compressions through the native bus, with the BLAKE3 table bit-committed.

use p3_circuit::Op;
use p3_circuit::ops::{BLAKE3_INPUT_WORDS, NativeTower128Target, blake3_compress, words_to_limbs};
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit, NativeBusTrace};

use super::keccak_chain::{native_bus, tables};
use super::*;
use crate::verifier::BinaryAirConstraintPlan;
use crate::verifier::binary_field_policy::NativeTower128Relation;

const CALLS: usize = 3;

pub(super) fn raw(limb: u16) -> F {
    F::from_raw_coordinates(limb.into()).unwrap()
}

/// The counter, block length and flags of chain call `call`: a full 64-byte block, no flags.
const fn tail(call: usize) -> [u32; 4] {
    [call as u32, 0, 64, 0]
}

/// `CALLS` chained BLAKE3 compressions of one public block: call `i` compresses it from the
/// previous chaining value, the public one for the first call, with counter `i`. The last
/// chaining value is bound to public values. Returns the circuit and its statement.
pub(super) fn blake3_chain() -> (Circuit<F>, Vec<F>) {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let block = b.alloc_public_input_array::<32>("block");
    let mut cv = b.alloc_public_input_array::<16>("chaining value");
    for call in 0..CALLS {
        let mut input: Vec<_> = block.iter().chain(&cv).copied().collect();
        for limb in words_to_limbs(&tail(call)) {
            input.push(b.define_const(raw(limb)));
        }
        cv = b.add_native_blake3_compress(&input).unwrap();
    }
    for actual in cv {
        let expected = b.public_input();
        b.connect(actual, expected);
    }
    let circuit = b.build().unwrap();

    let block: [u32; 16] = core::array::from_fn(|j| (j as u32 + 1).wrapping_mul(0x9E37_79B1));
    let mut cv: [u32; 8] =
        core::array::from_fn(|j| 0x6A09_E667_u32.rotate_left(5 * j as u32) ^ j as u32);
    let mut statement = words_to_limbs(&block);
    statement.extend(words_to_limbs(&cv));
    for call in 0..CALLS {
        let mut input = [0; BLAKE3_INPUT_WORDS];
        input[..16].copy_from_slice(&block);
        input[16..24].copy_from_slice(&cv);
        input[24..].copy_from_slice(&tail(call));
        cv = core::array::from_fn(|j| blake3_compress(&input)[j]);
    }
    statement.extend(words_to_limbs(&cv));
    (circuit, statement.into_iter().map(raw).collect())
}

/// The BLAKE3 table, the last AIR, bit-committed.
fn blake3_table(prepared: &NativeBusCircuit<F>) -> usize {
    let table = prepared.packed_table_index().unwrap();
    assert_eq!(table, prepared.airs().len() - 1);
    table
}

fn blake3_chain_proof() -> Mixed {
    let (circuit, statement) = blake3_chain();
    let prepared = native_bus(&circuit, KeccakCommitment::Bits);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let mixed = Mixed::prove(
        prepared
            .airs()
            .iter()
            .map(|air| TestAir::Bus(Box::new(air.clone())))
            .collect(),
        prepared.log_heights().to_vec(),
        prepared.public_values(&statement).unwrap(),
        blake3_table(&prepared),
        tables(prepared.trace_tables(&witness).unwrap()),
    );
    let (_, _, bits) = mixed.parameters.packed.as_ref().unwrap();
    assert_eq!(Some(*bits), prepared.packed_bit_variables());
    assert_eq!(
        mixed.parameters.dense.configuration().num_variables(),
        prepared.main_variables()
    );
    mixed
}

#[test]
fn blake3_chain_imports_with_the_native_continuation() {
    let mixed = blake3_chain_proof();
    assert!(mixed.proof.opening.packed.is_some());
    let verifier = mixed.verifier();
    mixed.honest_private_values::<Native>(&verifier);
    mixed.assert_tampers_refused_by_import(&verifier);
}

/// The native circuit accepts the honest chain and refuses it once an opened value of the
/// bit-committed BLAKE3 table changes.
#[test]
fn blake3_chain_satisfies_the_native_circuit() {
    let mixed = blake3_chain_proof();
    let verifier = mixed.verifier();
    let (input, private) = mixed.honest_private_values::<Native>(&verifier);
    let (circuit, _) = native_circuit(&verifier);
    let public = mixed.public_values::<Native>();
    assert!(accepts(&circuit, &private, &public));
    let (_, packed) = opening_offsets::<Native>(&input, &verifier.input_shape());
    let values = &mixed.proof.opening.packed.as_ref().unwrap().values;
    assert!(private[packed..].starts_with(values));
    let mut tampered = private;
    Native::flip(&mut tampered[packed]);
    assert!(!accepts(&circuit, &tampered, &public));
}

/// Whether the multi-stark verifier accepts the proof of `mixed`.
fn verifies(mixed: &Mixed) -> bool {
    let refs = mixed.airs.iter().collect::<Vec<_>>();
    let (_, verifying) = setup(&mixed.config, &refs, &mut challenger()).unwrap();
    verify(
        &mixed.config,
        VerifierInstances::new(
            refs.iter()
                .zip(&mixed.heights)
                .zip(&mixed.public)
                .map(|((air, &height), public)| {
                    VerifierInstance::new(*air, &verifying, height, public)
                })
                .collect(),
        ),
        &mixed.proof,
        0,
        &mut challenger(),
    )
    .is_ok()
}

/// A proof over the packed bits of the BLAKE3 table verifies. Once one committed bit changes,
/// the prover refuses a bit that breaks the witness bus, and the verifier refuses the proof of
/// a bit inside the compression, whose constraints no longer hold.
#[test]
fn forged_packed_bit_is_refused() {
    let (circuit, statement) = blake3_chain();
    let prepared = native_bus(&circuit, KeccakCommitment::Bits);
    let table = blake3_table(&prepared);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let prove = |flip: Option<usize>| {
        let mut traces = prepared.trace_tables(&witness).unwrap();
        if let Some(word) = flip {
            let NativeBusTrace::PackedBits { words, .. } = &mut traces[table] else {
                panic!("the BLAKE3 table is packed");
            };
            words.values[word] ^= 1;
        }
        Mixed::prove(
            prepared
                .airs()
                .iter()
                .map(|air| TestAir::Bus(Box::new(air.clone())))
                .collect(),
            prepared.log_heights().to_vec(),
            prepared.public_values(&statement).unwrap(),
            table,
            tables(traces),
        )
    };
    assert!(verifies(&prove(None)));
    let words = match &prepared.trace_tables(&witness).unwrap()[table] {
        NativeBusTrace::PackedBits { words, .. } => words.values.len(),
        NativeBusTrace::Dense(_) => panic!("the BLAKE3 table is packed"),
    };
    // The first word holds bits of an input limb and the last a bit of an output limb, which
    // the witness bus refuses at proving; a bit of an inner round leaves the bus balanced and
    // the compression's constraints unsatisfied.
    let attempt =
        |word| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove(Some(word))));
    assert!(attempt(0).is_err());
    assert!(attempt(words - 1).is_err());
    assert!(!verifies(&attempt(words / 2).unwrap()));
}

/// The BLAKE3 table's AIR and its position, with the bit-committed table's interactions.
fn blake3_plan(
    prepared: &NativeBusCircuit<F>,
    bits: bool,
) -> (BinaryAirConstraintPlan<F, F>, Vec<alloc::string::String>) {
    let table = prepared.airs().len() - 1;
    let (plan, interactions) = BinaryAirConstraintPlan::<F, F>::with_interaction_limits(
        &prepared.airs()[table],
        prepared.log_heights()[table],
        &limits(),
        bits,
    )
    .unwrap();
    let names = interactions
        .into_iter()
        .map(|interaction| interaction.bus_name)
        .collect();
    (plan, names)
}

/// Rows of the verifier's native gate table for the BLAKE3 AIR's constraint check, counted as
/// the ALU operations the evaluation adds to a circuit, next to its constants.
fn blake3_check_ops(plan: &BinaryAirConstraintPlan<F, F>) -> (usize, usize) {
    let mut b = CircuitBuilder::<F>::new();
    let mut targets = |count: usize| -> Vec<NativeTower128Target> {
        (0..count)
            .map(|_| {
                let value = b.public_input();
                b.native_tower128_from_expr(value)
            })
            .collect()
    };
    let point = targets(plan.log_height());
    let current = targets(plan.main_width());
    let next = targets(plan.next_columns().len());
    let preprocessed = targets(plan.preprocessed_width());
    let preprocessed_next = targets(plan.preprocessed_next_columns().len());
    let public = targets(plan.public_value_count());
    let alpha = targets(1).remove(0);
    let evaluation = plan
        .evaluate_using::<NativeTower128Relation<F>, F>(
            &mut b,
            &point,
            &current,
            &next,
            &preprocessed,
            &preprocessed_next,
            &public,
            &alpha,
        )
        .unwrap();
    for value in core::iter::once(&evaluation.folded)
        .chain(evaluation.bus_fields.iter().flatten())
        .chain(evaluation.bus_activations.iter().flatten())
    {
        b.assert_zero(value.as_expr());
    }
    let circuit = b.build().unwrap();
    let alu = circuit
        .ops
        .iter()
        .filter(|op| matches!(op, Op::Alu { .. }))
        .count();
    let constants = circuit
        .ops
        .iter()
        .filter(|op| matches!(op, Op::Const { .. }))
        .count();
    (alu, constants)
}

/// Metadata entries of the BLAKE3 table's AIR exceed the default verifier limit and stay under
/// a quarter of the raised one, and its constraint check stays within a fixed number of gate
/// rows, in both commitment modes. Its interactions all name the witness bus.
#[test]
fn blake3_table_plan_fits_its_limits() {
    /// The default `VerifierLimits::max_metadata_entries`.
    const DEFAULT_METADATA_ENTRIES: usize = 1 << 16;
    const MAX_CHECK_GATE_ROWS: usize = 120_000;
    let (circuit, _) = blake3_chain();
    for (mode, bits) in [
        (KeccakCommitment::Dense, false),
        (KeccakCommitment::Bits, true),
    ] {
        let prepared = native_bus(&circuit, mode);
        let (plan, names) = blake3_plan(&prepared, bits);
        let entries = plan.input_resource_usage().metadata_entries;
        let (gate_rows, constants) = blake3_check_ops(&plan);
        std::println!(
            "{mode:?}: {entries} metadata entries, {gate_rows} check gate rows, {constants} \
             check constants"
        );
        assert!(
            DEFAULT_METADATA_ENTRIES < entries && entries <= 1 << 18,
            "{entries} metadata entries"
        );
        assert!(gate_rows <= MAX_CHECK_GATE_ROWS, "{gate_rows} gate rows");
        assert!(!names.is_empty());
        assert!(
            names.iter().all(|name| name == "mixed.witness"),
            "{names:?}"
        );
    }
}
