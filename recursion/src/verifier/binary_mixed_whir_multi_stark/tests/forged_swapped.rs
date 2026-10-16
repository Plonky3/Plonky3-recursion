//! A swapped digest limb that the Keccak table's output bits do not give.

use p3_air::check_constraints;
use p3_circuit::ops::keccak_state_to_limbs;
use p3_circuit::tables::WitnessTrace;
use p3_circuit_prover::native_bus::KeccakCommitment;
use p3_keccak::KeccakF;
use p3_multi_stark::ProvingError;
use p3_symmetric::Permutation;

use super::keccak_chain::native_bus;
use super::*;

/// The swapped digest limb whose claim is forged.
const LIMB: usize = 3;

/// A prover claims a swapped digest limb that is not the byte swap of the call's output limb.
/// The fanout, public and bridge rows all carry the forged value, so the witness bus balances
/// and every table satisfies its own constraints. The bridge pulls the value from the hash bus,
/// where the Keccak table pushes the byte swap of the honest output limb from the same output
/// bits, so under either commitment of the Keccak table the hash bus does not balance and the
/// bus argument refuses the traces.
#[test]
fn forged_swapped_digest_limb_is_refused_in_both_modes() {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let input = b.alloc_public_input_array::<100>("input");
    let expected = b.alloc_public_input_array::<16>("swapped digest");
    let (_, swapped) = b
        .add_native_keccak_f1600_with_swapped_digest(&input)
        .unwrap();
    for (actual, expected) in swapped.into_iter().zip(expected) {
        b.connect(actual, expected);
    }
    let circuit = b.build().unwrap();
    let state: [u64; 25] =
        core::array::from_fn(|i| 0x7f4a7c159e3779b9u64.rotate_left(11 * i as u32) ^ i as u64);
    let output = keccak_state_to_limbs(&KeccakF.permute(state));
    let raw = |limb: u16| F::from_raw_coordinates(limb.into()).unwrap();
    let statement: Vec<F> = keccak_state_to_limbs(&state)
        .into_iter()
        .chain(output[..16].iter().map(|limb| limb.swap_bytes()))
        .map(raw)
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let honest = runner.run().unwrap().witness_trace;

    // The forged claim reads the output limb's bytes in their unswapped order.
    assert_ne!(output[LIMB], output[LIMB].swap_bytes());
    let mut claimed = statement.clone();
    claimed[100 + LIMB] = raw(output[LIMB]);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&claimed).unwrap();
    assert!(runner.run().is_err(), "the runner computes the honest swap");
    let id = circuit.public_rows[100 + LIMB];
    let swapped_output = circuit.ops.iter().find_map(|op| match op {
        p3_circuit::Op::NonPrimitiveOpWithExecutor { outputs, .. } => Some(outputs[0][100 + LIMB]),
        _ => None,
    });
    assert_eq!(
        swapped_output,
        Some(id),
        "the claim is the call's swapped output"
    );
    let mut values: Vec<F> = honest
        .index
        .iter()
        .map(|&id| *honest.get_value(id).unwrap())
        .collect();
    values[id.0 as usize] = claimed[100 + LIMB];
    let forged = WitnessTrace::new(values);

    for mode in [KeccakCommitment::Dense, KeccakCommitment::Bits] {
        let bus = native_bus(&circuit, mode);
        let config =
            Parameters::new(bus.airs(), bus.log_heights(), bus.keccak_table_index()).config();
        let airs = bus.airs().iter().collect::<Vec<_>>();
        let (proving, _) = setup(&config, &airs, &mut challenger()).unwrap();
        let attempt = |traces: &[RowMajorMatrix<F>], statement: &[F]| {
            let public = bus.public_values(statement).unwrap();
            for ((air, trace), public) in airs.iter().zip(traces).zip(&public) {
                check_constraints(*air, trace, public);
            }
            let tables = traces
                .iter()
                .map(|trace| Table::new(trace.clone().transpose()));
            prove(
                &config,
                ProverInstances::new(
                    airs.iter()
                        .zip(tables)
                        .zip(&public)
                        .map(|((air, table), public)| {
                            ProverInstance::new(*air, table, &proving, public)
                        })
                        .collect(),
                ),
                0,
                &mut challenger(),
            )
        };
        assert!(attempt(&bus.traces(&honest).unwrap(), &statement).is_ok());

        // Trace generation byte-swaps the bridge's limbs; the call's output row is row 1.
        let mut traces = bus.traces(&forged).unwrap();
        let bridge = traces.len() - 1;
        let cell = 116 + 100 + LIMB;
        assert_eq!(traces[bridge].values[cell], statement[100 + LIMB]);
        traces[bridge].values[cell] = claimed[100 + LIMB];
        let proven = attempt(&traces, &claimed);
        assert!(
            matches!(proven, Err(ProvingError::BusArgument(_))),
            "{mode:?}: {:?}",
            proven.err()
        );
    }
}
