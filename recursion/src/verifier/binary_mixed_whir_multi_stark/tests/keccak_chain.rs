//! Three chained Keccak-f calls through the native bus, with the Keccak table bit-committed.

use p3_circuit::ops::keccak_state_to_limbs;
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit, NativeBusTrace};
use p3_keccak::KeccakF;
use p3_sumcheck::strategy::VariableOrder;
use p3_symmetric::Permutation;

use super::*;
use crate::verifier::{BinaryWhirMultiStarkPreprocessing, BinaryWhirMultiStarkVerifier};

const CALLS: usize = 3;

/// Three chained Keccak-f calls from a public input state to a public output state, and the
/// statement of a fixed input.
fn keccak_chain() -> (Circuit<F>, Vec<F>) {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let mut state = builder.alloc_public_input_array::<100>("input").to_vec();
    for _ in 0..CALLS {
        state = builder.add_native_keccak_f1600(&state).unwrap().to_vec();
    }
    let expected = builder.alloc_public_input_array::<100>("output");
    for (actual, expected) in state.iter().zip(expected) {
        builder.connect(*actual, expected);
    }
    let circuit = builder.build().unwrap();

    let input: [u64; 25] =
        core::array::from_fn(|i| 0x8123456789abcdefu64.rotate_left(3 * i as u32));
    let mut output = input;
    for _ in 0..CALLS {
        KeccakF.permute_mut(&mut output);
    }
    let statement = [input, output]
        .iter()
        .flat_map(keccak_state_to_limbs)
        .map(|limb| F::from_raw_coordinates(limb as u128).unwrap())
        .collect();
    (circuit, statement)
}

pub(super) fn native_bus(circuit: &Circuit<F>, keccak: KeccakCommitment) -> NativeBusCircuit<F> {
    NativeBusCircuit::with_options(
        circuit,
        "mixed",
        FOLDING,
        DirectCircuitLimits::default(),
        keccak,
    )
    .unwrap()
}

/// Every table as proven: dense tables as field cells, the bit-committed one as packed bits.
fn tables(traces: Vec<NativeBusTrace<F>>) -> Vec<Table<F>> {
    traces
        .into_iter()
        .map(|trace| match trace {
            NativeBusTrace::Dense(matrix) => Table::new(matrix.transpose()),
            NativeBusTrace::PackedBits { words, log_height } => {
                Table::from_packed_bits(words, log_height)
            }
        })
        .collect()
}

fn keccak_chain_proof() -> Mixed {
    let (circuit, statement) = keccak_chain();
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
        prepared.keccak_table_index().unwrap(),
        tables(prepared.trace_tables(&witness).unwrap()),
    );
    // The parameters follow the bus circuit's own sizes.
    let (_, _, bits) = mixed.parameters.packed.as_ref().unwrap();
    assert_eq!(Some(*bits), prepared.packed_bit_variables());
    assert_eq!(
        mixed.parameters.dense.configuration().num_variables(),
        prepared.main_variables()
    );
    mixed
}

#[test]
fn keccak_chain_imports_with_the_native_continuation() {
    let mixed = keccak_chain_proof();
    assert!(mixed.proof.opening.packed.is_some());
    let verifier = mixed.verifier();
    mixed.honest_private_values::<Prime>(&verifier);
    mixed.assert_tampers_refused_by_import(&verifier);
}

/// The prime-field relation reads 3250 opened Keccak values and evaluates 1650 constraints.
/// In debug its circuit passed 20 GB after 600 s without finishing.
#[test]
#[ignore = "builds a prime-field verifier of the bit-committed Keccak relation above 20 GB in debug; run explicitly"]
fn keccak_chain_satisfies_the_prime_circuit() {
    let mixed = keccak_chain_proof();
    let verifier = mixed.verifier();
    let (_, private) = mixed.honest_private_values::<Prime>(&verifier);
    let circuit = prime_circuit(&verifier);
    assert!(accepts(&circuit, &private, &mixed.public_values::<Prime>()));
}

/// The native circuit accepts the honest chain and refuses it once an opened value of the
/// bit-committed Keccak table changes.
#[test]
fn keccak_chain_satisfies_the_native_circuit() {
    let mixed = keccak_chain_proof();
    let verifier = mixed.verifier();
    let (input, private) = mixed.honest_private_values::<Native>(&verifier);
    let (circuit, _) = native_circuit(&verifier);
    let public = mixed.public_values::<Native>();
    assert!(accepts(&circuit, &private, &public));
    // The packed opening's witnesses start with the opened Keccak values.
    let (_, packed) = opening_offsets::<Native>(&input, &verifier.input_shape());
    let values = &mixed.proof.opening.packed.as_ref().unwrap().values;
    assert!(private[packed..].starts_with(values));
    let mut tampered = private;
    Native::flip(&mut tampered[packed]);
    assert!(!accepts(&circuit, &tampered, &public));
}

/// Expression nodes of the native verifier of the chain with its Keccak table bit-committed,
/// as measured. The bound is 1.2 times this count, updatable when the native transcript, the
/// WHIR kernel or the Keccak AIR change.
const MEASURED_MIXED_NODES: usize = 811_760;

/// Prints the native verifier's expression nodes for the chain with its Keccak table
/// bit-committed next to the native dense verifier's for the same chain with every table
/// committed densely, under the same parameters.
#[test]
fn native_verifier_nodes_of_the_keccak_chain() {
    let (circuit, _) = keccak_chain();
    let bits = native_bus(&circuit, KeccakCommitment::Bits);
    let keccak = bits.keccak_table_index().unwrap();
    let parameters = Parameters::new(bits.airs(), bits.log_heights(), Some(keccak));
    let verifier = parameters
        .verifier(
            bits.airs(),
            bits.log_heights(),
            keccak,
            parameters.preprocessed_cap(bits.airs()),
        )
        .unwrap();
    let (_, mixed_nodes) = native_circuit(&verifier);

    let dense = native_bus(&circuit, KeccakCommitment::Dense);
    let parameters = Parameters::new(dense.airs(), dense.log_heights(), None);
    let preprocessed = parameters.preprocessed.as_ref().unwrap();
    let verifier = BinaryWhirMultiStarkVerifier::<F>::with_preprocessing(
        &dense.airs().iter().collect::<Vec<_>>(),
        dense.log_heights(),
        parameters.dense.configuration(),
        VariableOrder::Suffix,
        HASH,
        CAP_HEIGHT,
        0,
        MAX_TAU_DRAWS,
        BinaryWhirMultiStarkPreprocessing {
            config: preprocessed.configuration().clone(),
            order: VariableOrder::Suffix,
            hash: HASH,
            cap_height: CAP_HEIGHT,
            commitment: parameters.preprocessed_cap(dense.airs()).unwrap(),
        },
        &limits(),
    )
    .unwrap();
    let shape = verifier.input_shape();
    let (mut b, public) = native_builder(shape.public_value_counts());
    let targets = shape.allocate_native_targets(&mut b).unwrap();
    let ch = native_challenger(&mut b);
    let before = b.construction_usage().unwrap().expression_nodes;
    verifier
        .verify_native(&mut b, ch, &public, &targets)
        .unwrap();
    let dense_nodes = b.construction_usage().unwrap().expression_nodes - before;

    std::println!(
        "native verifier of {CALLS} chained Keccak-f calls: {mixed_nodes} nodes with the Keccak \
         table bit-committed, {dense_nodes} with every table committed densely"
    );
    assert!(
        mixed_nodes * 5 <= MEASURED_MIXED_NODES * 6,
        "{mixed_nodes} mixed native verifier nodes"
    );
}

#[test]
fn dense_verifier_refuses_the_bits_mode_airs() {
    let (circuit, _) = keccak_chain();
    for keccak in [KeccakCommitment::Dense, KeccakCommitment::Bits] {
        let prepared = native_bus(&circuit, keccak);
        let airs = prepared.airs().iter().collect::<Vec<_>>();
        let parameters = Parameters::new(prepared.airs(), prepared.log_heights(), None);
        let verifier = BinaryWhirMultiStarkVerifier::<F>::with_preprocessing(
            &airs,
            prepared.log_heights(),
            parameters.dense.configuration(),
            VariableOrder::Suffix,
            HASH,
            CAP_HEIGHT,
            0,
            MAX_TAU_DRAWS,
            BinaryWhirMultiStarkPreprocessing {
                config: parameters.preprocessed.unwrap().configuration().clone(),
                order: VariableOrder::Suffix,
                hash: HASH,
                cap_height: CAP_HEIGHT,
                commitment: placeholder_cap(),
            },
            &limits(),
        );
        match keccak {
            KeccakCommitment::Dense => {
                verifier.unwrap();
            }
            KeccakCommitment::Bits => assert!(matches!(
                verifier,
                Err(VerificationError::InvalidProofShape(message))
                    if message == "binary AIR requires a Boolean trace commitment"
            )),
        }
    }
}

#[test]
fn bit_committed_table_must_be_exactly_the_boolean_assuming_air() {
    let (circuit, _) = keccak_chain();
    let bits = native_bus(&circuit, KeccakCommitment::Bits);
    let keccak = bits.keccak_table_index().unwrap();
    let parameters = Parameters::new(bits.airs(), bits.log_heights(), Some(keccak));
    let build = |airs: &[NativeBusCircuitAir<F>], heights: &[usize], table: usize| {
        parameters.verifier(airs, heights, table, Some(placeholder_cap()))
    };
    let refused = |result: Result<_, VerificationError>, expected: &str| {
        assert!(
            matches!(&result, Err(VerificationError::InvalidProofShape(message)) if message == expected),
            "{expected}"
        );
    };
    let mismatch =
        "binary mixed WHIR MultiStark bit-committed table is not exactly the Boolean-assuming AIR";

    build(bits.airs(), bits.log_heights(), keccak).unwrap();
    // The configured table's AIR keeps its booleanity constraints, so no AIR assumes bits.
    let dense = native_bus(&circuit, KeccakCommitment::Dense);
    refused(build(dense.airs(), dense.log_heights(), keccak), mismatch);
    // The configured table is a dense one, while the Keccak AIR assumes bits.
    refused(build(bits.airs(), bits.log_heights(), 0), mismatch);
    // A second Boolean-assuming AIR outside the configured table.
    let mut airs = bits.airs().to_vec();
    airs.push(airs[keccak].clone());
    let mut heights = bits.log_heights().to_vec();
    heights.push(heights[keccak]);
    refused(build(&airs, &heights, keccak), mismatch);
    refused(
        build(bits.airs(), bits.log_heights(), bits.airs().len()),
        "binary mixed WHIR MultiStark packed table index exceeds the AIRs",
    );
}
