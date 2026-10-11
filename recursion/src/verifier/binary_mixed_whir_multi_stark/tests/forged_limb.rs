//! A forged sixteen-bit limb with its seventeenth coordinate lifted into the Keccak state.

use p3_binary_pcs::BooleanTraceCommitmentError;
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::{AluOpKind, Op, WitnessId};
use p3_circuit_prover::native_bus::KeccakCommitment;
use p3_keccak::Keccak256Hash;
use p3_keccak_air::NUM_KECCAK_BINARY_COLS;
use p3_multi_stark::ProvingError;
use p3_multi_stark::zerocheck::ZerocheckError;
use p3_symmetric::CryptographicHasher;
use p3_whir::WhirConfigError;

use super::keccak_chain::native_bus;
use super::*;
use crate::artifact::binary_native::MixedWhirError;

/// The assignment reached by replaying `circuit` from `public` and `private` as the runner
/// does, except that hints and native Keccak calls keep their `honest` outputs: the witness of
/// a prover who claims the honest digests.
fn replay(circuit: &Circuit<F>, honest: &[F], public: &[F], private: &[F]) -> Vec<F> {
    fn assign(w: &mut [Option<F>], id: WitnessId, value: F) {
        let slot = &mut w[id.0 as usize];
        assert!(
            slot.is_none_or(|old| old == value),
            "replay conflict at {id:?}"
        );
        *slot = Some(value);
    }
    const fn get(w: &[Option<F>], id: WitnessId) -> F {
        w[id.0 as usize].expect("operand assigned before use")
    }
    let mut w = vec![None; circuit.witness_count as usize];
    for (&id, &value) in circuit.public_rows.iter().zip(public) {
        assign(&mut w, id, value);
    }
    for (&id, &value) in circuit.private_input_rows.iter().zip(private) {
        assign(&mut w, id, value);
    }
    for op in &circuit.ops {
        match op {
            Op::Const { out, val } => assign(&mut w, *out, *val),
            Op::Public { .. } => {}
            Op::Hint { outputs, .. } => {
                for &id in outputs {
                    assign(&mut w, id, honest[id.0 as usize]);
                }
            }
            Op::NonPrimitiveOpWithExecutor { outputs, .. } => {
                for &id in outputs.iter().flatten() {
                    assign(&mut w, id, honest[id.0 as usize]);
                }
            }
            &Op::Alu {
                kind,
                a,
                b,
                c,
                out,
                intermediate_out,
            } => {
                let a_val = get(&w, a);
                let (id, value) = match (kind, w[b.0 as usize]) {
                    (AluOpKind::Add, None) => (b, get(&w, out) - a_val),
                    (AluOpKind::Mul, None) => (b, get(&w, out) * a_val.inverse()),
                    (AluOpKind::Add, Some(b_val)) => (out, a_val + b_val),
                    (AluOpKind::Mul, Some(b_val)) => (out, a_val * b_val),
                    (AluOpKind::BoolCheck, _) => (out, a_val),
                    (AluOpKind::MulAdd, _) => {
                        let product = a_val * get(&w, b);
                        if let Some(id) = intermediate_out {
                            assign(&mut w, id, product);
                        }
                        (out, product + c.map_or(F::ZERO, |c| get(&w, c)))
                    }
                    (AluOpKind::HornerAcc, _) => {
                        let accumulator = get(&w, intermediate_out.unwrap());
                        (out, accumulator * get(&w, b) + get(&w, c.unwrap()) - a_val)
                    }
                };
                assign(&mut w, id, value);
            }
        }
    }
    w.into_iter()
        .zip(honest)
        .map(|(value, &old)| value.unwrap_or(old))
        .collect()
}

/// Writes `forged` into every fanout, gate and bridge cell whose fixed label names a witness
/// that differs from `honest`, and returns how many cells of each of those three tables
/// changed. Keccak bit rows are left as they are.
fn patch_witness_cells(
    airs: &[NativeBusCircuitAir<F>],
    traces: &mut [RowMajorMatrix<F>],
    honest: &[F],
    forged: &[F],
) -> [usize; 3] {
    let mut patched = [0; 3];
    for (air, trace) in airs.iter().zip(traces) {
        let table = match (air.width(), air.preprocessed_width()) {
            (1, 4) => 0,
            (5, 12) => 1,
            (100, 102) => 2,
            _ => continue,
        };
        let labels = air.preprocessed_trace().unwrap();
        let width = trace.width;
        for (row, labels) in labels.values.chunks(labels.width).enumerate() {
            for (column, label) in labels[..width].iter().enumerate() {
                // A label is a witness index plus one; zero marks an unused slot.
                let id = label.to_raw_coordinates() as usize;
                if id != 0 && forged[id - 1] != honest[id - 1] {
                    trace.values[row * width + column] = forged[id - 1];
                    patched[table] += 1;
                }
            }
        }
    }
    patched
}

/// A word with a seventeenth coordinate absorbed in the second Keccak block passes the fanout,
/// gate and bridge rows. Lifting the matching Keccak state bit to carry it leaves a state cell
/// outside {0, 1}, and the forged traces are refused in both modes. Under the dense commitment
/// they prove, and the zerocheck refuses the proof; the lifted cell breaks the Keccak AIR's
/// constraints, booleanity and the round transition alike, so this does not show which of them
/// refuses it. Under the bit commitment the commitment refuses the cell before the transcript
/// moves, so nothing is bound.
#[test]
fn forged_sixteen_bit_limb_is_refused_in_both_modes() {
    const WORDS: usize = 70;
    const SECOND_BLOCK: usize = 68;
    /// The first state bit of the first lane, in the first row of the second call.
    const LIFTED_ROW: usize = 25;
    const LIFTED_COLUMN: usize = 25;
    let words: Vec<u16> = (0..WORDS as u16)
        .map(|i| i.wrapping_mul(0x9e37) ^ 0x5a5a)
        .collect();
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let hashed = Keccak256Hash.hash_iter(bytes.iter().copied());
    let encode = |word: u16| F::from_raw_coordinates(word.into()).unwrap();

    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let expected = b.alloc_public_input_array::<16>("digest");
    let message = b.alloc_private_inputs(WORDS, "message words");
    let digest = NativeBinaryEncoding::hash_words(&mut b, HASH, &message).unwrap();
    for (&limb, &expected) in digest.iter().zip(&expected) {
        b.connect(limb, expected);
    }
    let circuit = b.build().unwrap();
    let statement: Vec<F> = bytes_to_limbs(&hashed).into_iter().map(encode).collect();
    let private: Vec<F> = words.iter().map(|&word| encode(word)).collect();

    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&private).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest: Vec<F> = witness
        .index
        .iter()
        .map(|&id| *witness.get_value(id).unwrap())
        .collect();
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    let mut forged_private = private.clone();
    forged_private[SECOND_BLOCK] += wide;
    let forged = replay(&circuit, &honest, &statement, &forged_private);

    // Both modes generate the same dense traces; only the Keccak AIR and the commitment differ.
    let bits = native_bus(&circuit, KeccakCommitment::Bits);
    let dense = native_bus(&circuit, KeccakCommitment::Dense);
    let keccak = bits.keccak_table_index().unwrap();
    let public = bits.public_values(&statement).unwrap();
    let mut traces = bits.traces(&witness).unwrap();
    let [fanout, gates, bridge] = patch_witness_cells(bits.airs(), &mut traces, &honest, &forged);
    assert!(fanout > 0 && gates > 0 && bridge == 1);
    assert_eq!(traces[keccak].width, NUM_KECCAK_BINARY_COLS);
    let cell = LIFTED_ROW * NUM_KECCAK_BINARY_COLS + LIFTED_COLUMN;
    assert!(traces[keccak].values[cell] == F::ZERO || traces[keccak].values[cell] == F::ONE);
    traces[keccak].values[cell] += wide;
    let forged_tables = || {
        traces
            .iter()
            .map(|trace| Table::new(trace.clone().transpose()))
            .collect::<Vec<_>>()
    };

    // Dense: the forged traces prove, and the zerocheck refuses the proof.
    let config = Parameters::new(dense.airs(), dense.log_heights(), None).config();
    let airs = dense.airs().iter().collect::<Vec<_>>();
    let (proving, verifying) = setup(&config, &airs, &mut challenger()).unwrap();
    let proof = prove(
        &config,
        ProverInstances::new(
            airs.iter()
                .zip(forged_tables())
                .zip(&public)
                .map(|((air, table), public)| ProverInstance::new(*air, table, &proving, public))
                .collect(),
        ),
        0,
        &mut challenger(),
    )
    .unwrap();
    let verified = verify(
        &config,
        VerifierInstances::new(
            airs.iter()
                .zip(dense.log_heights())
                .zip(&public)
                .map(|((air, &height), public)| {
                    VerifierInstance::new(*air, &verifying, height, public)
                })
                .collect(),
        ),
        &proof,
        0,
        &mut challenger(),
    );
    assert!(
        matches!(
            verified,
            Err(p3_multi_stark::VerificationError::Zerocheck(
                ZerocheckError::FinalSumMismatch
            ))
        ),
        "{verified:?}"
    );

    // Bits: the commitment refuses the cell before binding anything, and so does the prover.
    let config = Parameters::new(bits.airs(), bits.log_heights(), Some(keccak)).config();
    let refused = |error: &MixedWhirError<WhirConfigError>| {
        matches!(
            error,
            MixedWhirError::Packed(BooleanTraceCommitmentError::NonBooleanCell { table, column })
                if *table == keccak && *column == LIFTED_COLUMN
        )
    };
    let mut moved = challenger();
    let mut untouched = moved.clone();
    assert!(refused(
        &config
            .main
            .commit(forged_tables(), &mut moved)
            .err()
            .unwrap()
    ));
    assert_eq!(
        moved.sample_algebra_element::<F>(),
        untouched.sample_algebra_element::<F>()
    );
    let airs = bits.airs().iter().collect::<Vec<_>>();
    let (proving, _) = setup(&config, &airs, &mut challenger()).unwrap();
    let proven = prove(
        &config,
        ProverInstances::new(
            airs.iter()
                .zip(forged_tables())
                .zip(&public)
                .map(|((air, table), public)| ProverInstance::new(*air, table, &proving, public))
                .collect(),
        ),
        0,
        &mut challenger(),
    );
    assert!(matches!(proven, Err(ProvingError::Pcs { ref source, .. }) if refused(source)));
}
