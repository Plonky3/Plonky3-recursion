//! Native product buses bind every fixed circuit occurrence without pushforwards.

use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_air::{BaseAir, check_constraints};
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{AluOpKind, Circuit, CircuitBuilder, Op, WitnessId};
use p3_circuit_prover::native_bus::{NativeBusCircuit, NativeBusCircuitAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak::Keccak256Hash;
use p3_keccak_air::{KECCAK_BINARY_ROWS_PER_PERM, NUM_KECCAK_BINARY_COLS};
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::VerifierLimits;
use p3_symmetric::CryptographicHasher;

type F = BinaryField128;

fn spec(prepared: &NativeBusCircuit<F>) -> BinaryNativeVerifierSpec {
    spec_dimensions(prepared.main_variables(), prepared.preprocessed_variables())
}

fn spec_dimensions(main: usize, preprocessed: Option<usize>) -> BinaryNativeVerifierSpec {
    let parameters = |n| BinaryNativePcsParameters {
        config: BinaryPcsConfig::try_new::<F, F>(
            n,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 8,
            },
        )
        .unwrap(),
        hash: ByteHash::Keccak256,
        cap_height: 0,
        max_query_draws: 128,
    };
    BinaryNativeVerifierSpec {
        main: parameters(main),
        preprocessed: preprocessed.map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-bus-circuit-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 4,
    }
}

#[test]
fn composed_circuits_cannot_cross_match_public_witnesses() {
    let constants = [
        F::from_repr(0x8123456789abcdef),
        F::from_repr(0xfedcba9876543210),
    ];
    let circuits: Vec<_> = constants
        .iter()
        .map(|&constant| {
            let mut b = CircuitBuilder::<F>::new();
            let public = b.public_input();
            let value = b.define_const(constant);
            b.connect(value, public);
            b.build().unwrap()
        })
        .collect();
    let prepared: Vec<_> = circuits
        .iter()
        .zip(["left", "right"])
        .map(|(circuit, namespace)| NativeBusCircuit::new(circuit, namespace).unwrap())
        .collect();
    let airs: Vec<_> = prepared
        .iter()
        .flat_map(|p| p.airs().iter().cloned())
        .collect();
    let heights: Vec<_> = prepared
        .iter()
        .flat_map(|p| p.log_heights().iter().copied())
        .collect();
    let main_cells: usize = airs
        .iter()
        .zip(&heights)
        .map(|(air, &log)| air.width() << log)
        .sum();
    let pp_cells: usize = airs
        .iter()
        .zip(&heights)
        .map(|(air, &log)| air.preprocessed_width() << log)
        .sum();
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        airs.clone(),
        heights,
        spec_dimensions(
            main_cells.next_power_of_two().ilog2() as usize,
            Some(pp_cells.next_power_of_two().ilog2() as usize),
        ),
        &VerifierLimits::default(),
    )
    .unwrap();
    let mut traces = Vec::new();
    let mut public = Vec::new();
    for ((circuit, prepared), constant) in circuits.iter().zip(&prepared).zip(constants) {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[constant]).unwrap();
        traces.extend(
            prepared
                .traces(&runner.run().unwrap().witness_trace)
                .unwrap(),
        );
        public.extend(prepared.public_values(&[constant]).unwrap());
    }
    let proof = prover.prove(&public, traces.clone()).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let public_tables: Vec<_> = airs
        .iter()
        .enumerate()
        .filter_map(|(i, air)| (air.num_public_values() != 0).then_some(i))
        .collect();
    let [left, right] = public_tables.as_slice() else {
        panic!("two public tables")
    };
    traces.swap(*left, *right);
    public.swap(*left, *right);
    for ((air, trace), expected) in airs.iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, expected);
    }
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.prove(&public, traces)
    }));
    if let Ok(Ok(proof)) = attempt {
        assert!(authority.verify_native(&proof, &public).is_err());
    }
}

#[test]
fn native_product_bus_authenticates_repeated_gate_reads() {
    let [a, factor, constant] = [0x8123456789abcdef, 0xfedcba9876543210, 0x8912].map(F::from_repr);
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let expected = b.public_input();
    let private = b.alloc_private_input("factor");
    let product = b.mul(input, private);
    let reused = b.mul(product, input);
    let c = b.define_const(constant);
    let out = b.add(reused, c);
    b.connect(out, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared),
        &VerifierLimits::default(),
    )
    .unwrap();
    let statement = [a, a * factor * a + constant];
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&[factor]).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let proof = prover.prove(&public, traces.clone()).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    assert!(proof.indexed.is_none());
    assert!(proof.bus.is_some());
    let mut wrong = public.clone();
    *wrong
        .iter_mut()
        .find(|v| !v.is_empty())
        .unwrap()
        .last_mut()
        .unwrap() += F::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());
    // A different row-local multiplication still reads the fixed original IDs.
    let gate = traces.iter().position(|trace| trace.width == 5).unwrap();
    let pp = prepared.airs()[gate].preprocessed_trace().unwrap();
    let row = pp
        .values
        .as_chunks::<12>()
        .0
        .iter()
        .position(|row| row[8] == F::ONE)
        .unwrap();
    let mut forged = traces;
    let payload = &mut forged[gate].values[5 * row..5 * (row + 1)];
    payload[0] += F::ONE;
    payload[4] = payload[0] * payload[1];
    check_constraints(&prepared.airs()[gate], &forged[gate], &[]);
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.prove(&public, forged)
    }));
    if let Ok(Ok(proof)) = attempt {
        assert!(authority.verify_native(&proof, &public).is_err());
    }
}

#[test]
fn native_product_buses_authenticate_keccak_call_boundaries() {
    let message = b"abc";
    let digest = Keccak256Hash.hash_iter(message.iter().copied());
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let input = b.alloc_public_input_array::<3>("message");
    let expected = b.alloc_public_input_array::<32>("digest");
    let actual = b.native_keccak256_bytes(&input).unwrap();
    for i in 0..32 {
        b.connect(actual[i], expected[i]);
    }
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared),
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    let statement: Vec<_> = message
        .iter()
        .chain(&digest)
        .map(|&byte| F::from_raw_coordinates(byte as u128).unwrap())
        .collect();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let proof = prover.prove(&public, traces.clone()).unwrap();
    assert!(proof.indexed.is_none());
    assert!(proof.bus.is_some());
    authority.verify_native(&proof, &public).unwrap();
    let mut wrong = public.clone();
    *wrong
        .iter_mut()
        .find(|v| !v.is_empty())
        .unwrap()
        .last_mut()
        .unwrap() += F::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());
    // Each boundary keeps its frozen tag and witness IDs. Swapping payloads
    // cannot substitute an unordered pair of genuine permutation boundaries.
    let mut forged = traces;
    let bridge = forged.last_mut().unwrap();
    for i in 0..100 {
        bridge.values.swap(i, 100 + i);
    }
    check_constraints(prepared.airs().last().unwrap(), bridge, &[]);
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.prove(&public, forged)
    }));
    if let Ok(Ok(proof)) = attempt {
        assert!(authority.verify_native(&proof, &public).is_err());
    }
}

/// The assignment reached by replaying `circuit` from `public` and `private`
/// as the runner does, except that hints and native Keccak calls keep their
/// `honest` outputs: the witness of a prover who claims the honest digests.
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

/// Writes `forged` into every fanout, gate and bridge cell whose fixed label
/// names a witness that differs from `honest`, and returns how many cells of
/// each of those three tables changed. Keccak bit rows are left as they are.
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

/// From the second Keccak block on, an absorbed word reaches the AIR only
/// through the lane `out + word`, a gate output whose `out` is the previous
/// call's output. A word with a seventeenth coordinate makes that lane wide:
/// the fanout, gate and bridge rows accept it, the hash bus does not, and
/// lifting the Keccak lane instead leaves a state cell outside {0, 1}.
#[test]
fn native_keccak_lanes_range_check_words_after_the_first_block() {
    const WORDS: usize = 70;
    const SECOND_BLOCK: usize = 68;
    let words: Vec<u16> = (0..WORDS as u16)
        .map(|i| i.wrapping_mul(0x9e37) ^ 0x5a5a)
        .collect();
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let hashed = Keccak256Hash.hash_iter(bytes.iter().copied());
    let encode = |word: u16| F::from_raw_coordinates(word.into()).unwrap();

    // The host word hash that absorbs observed transcript words.
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let expected = b.alloc_public_input_array::<16>("digest");
    let message = b.alloc_private_inputs(WORDS, "message words");
    let digest = NativeBinaryEncoding::hash_words(&mut b, ByteHash::Keccak256, &message).unwrap();
    for (&limb, &expected) in digest.iter().zip(&expected) {
        b.connect(limb, expected);
    }
    let circuit = b.build().unwrap();
    let statement: Vec<F> = bytes_to_limbs(&hashed).into_iter().map(encode).collect();
    let private: Vec<F> = words.iter().map(|&word| encode(word)).collect();

    let prepared = NativeBusCircuit::new(&circuit, "words").unwrap();
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared),
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&private).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest: Vec<F> = witness
        .index
        .iter()
        .map(|&id| *witness.get_value(id).unwrap())
        .collect();
    let mut traces = prepared.traces(&witness).unwrap();
    let proof = prover.prove(&public, traces.clone()).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let rejects = |traces: Vec<RowMajorMatrix<F>>| {
        let attempt = catch_unwind(AssertUnwindSafe(|| prover.prove(&public, traces)));
        if let Ok(Ok(proof)) = attempt {
            assert!(authority.verify_native(&proof, &public).is_err());
        }
    };

    let calls: Vec<_> = circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor { inputs, .. } => Some(&inputs[0]),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 2, "two absorbed blocks");
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    let mut forged_private = private.clone();
    forged_private[SECOND_BLOCK] += wide;
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&forged_private).unwrap();
    assert!(runner.run().is_err(), "the runner refuses a wide lane");

    let forged = replay(&circuit, &honest, &statement, &forged_private);
    let lanes: Vec<_> = calls
        .iter()
        .enumerate()
        .flat_map(|(c, ids)| {
            ids.iter()
                .enumerate()
                .filter(|&(_, id)| forged[id.0 as usize] != honest[id.0 as usize])
                .map(move |(l, _)| (c, l))
        })
        .collect();
    assert_eq!(lanes, [(1, 0)], "the first lane of the second block");
    let [fanout, gates, bridge] =
        patch_witness_cells(prepared.airs(), &mut traces, &honest, &forged);
    assert!(fanout > 0 && gates > 0 && bridge == 1);
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }
    rejects(traces.clone());

    let keccak = prepared
        .airs()
        .iter()
        .position(|air| air.width() == NUM_KECCAK_BINARY_COLS)
        .unwrap();
    assert_eq!(F::from_raw_coordinates(1), Some(F::ONE));
    traces[keccak].values
        [KECCAK_BINARY_ROWS_PER_PERM * NUM_KECCAK_BINARY_COLS + KECCAK_BINARY_ROWS_PER_PERM] +=
        wide;
    let local = catch_unwind(AssertUnwindSafe(|| {
        check_constraints(&prepared.airs()[keccak], &traces[keccak], &[]);
    }));
    assert!(local.is_err(), "the lifted lane leaves a non-Boolean cell");
    rejects(traces);
}

/// A native WHIR leaf splits each opened value into hinted words bound by
/// `value = sum_j word_j * x^(16j)` and absorbs them as Keccak lanes. Moving
/// coordinate `16 * (j + 1)` of a value into word `j` as a seventeenth
/// coordinate keeps that sum and the low sixteen coordinates of every lane,
/// so only the lane range check separates the forged opening from the
/// committed one. For a lane of each of the leaf's two Keccak blocks, the
/// fanout, gate and bridge rows accept the forgery, the hash bus does not,
/// and lifting the Keccak lane instead leaves a state cell outside {0, 1}.
#[test]
fn native_keccak_lanes_range_check_word_leaves_in_both_blocks() {
    // Sixteen Tower128 values: a 256-byte leaf absorbed in two blocks.
    const VALUES: usize = 16;
    let values: Vec<u128> = (0..VALUES as u128)
        .map(|i| 0x492f307c9bfa3e514379dc5a1b279591u128.wrapping_mul(i + 13))
        .collect();
    let bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let root = Keccak256Hash.hash_iter(bytes.iter().copied());

    // One leaf of a one-row tree: its digest is the only cap root.
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap = b.alloc_public_input_array::<16>("root");
    let row = b.alloc_private_inputs(VALUES, "row values");
    let mut words = Vec::new();
    for &value in &row {
        let value = b.native_tower128_from_expr(value);
        words.extend(b.native_tower128_unchecked_words(&value, 8).unwrap());
    }
    b.verify_byte_hash_mmcs_opening_words_with_host::<NativeBinaryEncoding>(
        ByteHash::Keccak256,
        &[words],
        &[1],
        &[],
        &[],
        &[cap.to_vec()],
    )
    .unwrap();
    let circuit = b.build().unwrap();
    let statement: Vec<F> = bytes_to_limbs(&root)
        .into_iter()
        .map(|word| F::from_raw_coordinates(word.into()).unwrap())
        .collect();
    let private: Vec<F> = values.iter().map(|&value| F::from_repr(value)).collect();

    let prepared = NativeBusCircuit::new(&circuit, "leaf").unwrap();
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared),
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&private).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest: Vec<F> = witness
        .index
        .iter()
        .map(|&id| *witness.get_value(id).unwrap())
        .collect();
    let honest_traces = prepared.traces(&witness).unwrap();
    let proof = prover.prove(&public, honest_traces.clone()).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let rejects = |traces: Vec<RowMajorMatrix<F>>| {
        let attempt = catch_unwind(AssertUnwindSafe(|| prover.prove(&public, traces)));
        if let Ok(Ok(proof)) = attempt {
            assert!(authority.verify_native(&proof, &public).is_err());
        }
    };

    let calls: Vec<_> = circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor { inputs, .. } => Some(&inputs[0]),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 2, "two absorbed blocks");
    let keccak = prepared
        .airs()
        .iter()
        .position(|air| air.width() == NUM_KECCAK_BINARY_COLS)
        .unwrap();
    assert_eq!(F::from_raw_coordinates(1), Some(F::ONE));
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    // Words 0 and 68 open the first and second Keccak blocks.
    for (value, word, call) in [(0, 0, 0), (8, 4, 1)] {
        let split = circuit
            .ops
            .iter()
            .find_map(|op| match op {
                Op::Hint {
                    inputs, outputs, ..
                } if inputs[..] == [circuit.private_input_rows[value]] => Some(outputs),
                _ => None,
            })
            .unwrap();
        assert_eq!(split.len(), 8);
        let mut hinted = honest.clone();
        hinted[split[word].0 as usize] += wide;
        let mut forged_private = private.clone();
        forged_private[value] = F::from_repr(values[value] ^ (1 << (16 * (word + 1))));
        let mut runner = circuit.runner();
        runner.set_public_inputs(&statement).unwrap();
        runner.set_private_inputs(&forged_private).unwrap();
        assert!(
            runner.run().is_err(),
            "the runner refuses the forged opening"
        );

        let forged = replay(&circuit, &hinted, &statement, &forged_private);
        let lanes: Vec<_> = calls
            .iter()
            .enumerate()
            .flat_map(|(c, ids)| {
                ids.iter()
                    .enumerate()
                    .filter(|&(_, id)| forged[id.0 as usize] != honest[id.0 as usize])
                    .map(move |(l, _)| (c, l))
            })
            .collect();
        assert_eq!(lanes, [(call, 0)], "the first lane of block {call}");
        let mut traces = honest_traces.clone();
        let [fanout, gates, bridge] =
            patch_witness_cells(prepared.airs(), &mut traces, &honest, &forged);
        assert!(fanout > 0 && gates > 0 && bridge == 1);
        for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
            check_constraints(air, trace, public);
        }
        rejects(traces.clone());

        traces[keccak].values[call * KECCAK_BINARY_ROWS_PER_PERM * NUM_KECCAK_BINARY_COLS
            + KECCAK_BINARY_ROWS_PER_PERM] += wide;
        let local = catch_unwind(AssertUnwindSafe(|| {
            check_constraints(&prepared.airs()[keccak], &traces[keccak], &[]);
        }));
        assert!(local.is_err(), "the lifted lane leaves a non-Boolean cell");
        rejects(traces);
    }
}

/// A native WHIR verifier gives proof-supplied Merkle siblings no range check
/// of their own. Each level selects its compression inputs from the current
/// digest and the sibling under a Boolean index bit, sampled or a constant
/// stratum bit, so each sibling word equals a first-block lane of that
/// compression's native Keccak call. In a complete native WHIR verifier, a
/// prover who claims the honest digests for a sibling word with a seventeenth
/// coordinate satisfies every fanout, gate and bridge row, but the hash bus
/// rejects it, and lifting the Keccak lane instead leaves a state cell
/// outside {0, 1}. A Keccak padding row isolates that Booleanity constraint.
#[test]
fn native_keccak_lanes_range_check_whir_merkle_siblings() {
    use p3_binary_pcs::whir::BinaryWhirDomain;
    use p3_commit::MultilinearPcs;
    use p3_multilinear_util::point::Point;
    use p3_recursion::BinaryTower128Challenger;
    use p3_recursion::pcs::binary::BinaryWhirVerifier;
    use p3_sumcheck::layout::{Layout, SuffixProver, Table, plan_stacked_layout};
    use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
    use p3_test_utils::binary_field_params::keccak;
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};
    type Ch = keccak::LevelChallenger<F>;
    type L = SuffixProver<F, F>;
    const CAP_HEIGHT: usize = 1;
    const VARIABLES: usize = 6;

    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(VARIABLES, 1),
        vec![OpeningBatch::new(vec![0], vec![0])],
    )]);
    let domain = BinaryWhirDomain::<F>::default();
    let config = WhirConfig::<F, F, Ch>::new_with_domain(
        plan_stacked_layout(&protocol.table_shapes()).0,
        ProtocolParameters {
            security_level: 8,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(2),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        &domain,
    )
    .unwrap();
    let mmcs = keccak::LevelMmcs::<F>::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        CAP_HEIGHT,
    );
    let pcs = WhirProver::<F, F, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
    let recursive = BinaryWhirVerifier::<F>::new(
        &config,
        protocol.clone(),
        L::variable_order(),
        ByteHash::Keccak256,
        CAP_HEIGHT,
    )
    .unwrap();
    let shape = recursive.input_shape();
    let make = || Ch::from_hasher(vec![129, 9, 251], keccak::byte_hash());
    let dense = |i: usize| {
        F::from_repr(0x492f307c9bfa3e514379dc5a1b279591u128.wrapping_mul(i as u128 + 13))
    };
    let table = Table::new(RowMajorMatrix::new(
        (0..1 << VARIABLES).map(dense).collect(),
        1 << VARIABLES,
    ));
    let witness = L::new_witness(vec![table], config.round_folding_factor(0));
    let points = vec![Point::new((0..VARIABLES).map(|j| dense(j + 71)).collect())];
    let mut prover_ch = make();
    let (commitment, data) = pcs.commit(witness, &mut prover_ch).unwrap();
    let opened = pcs
        .open_at(data, &protocol, &points, &mut prover_ch)
        .unwrap();
    let mut entry = make();
    pcs.observe_commitment(&commitment, &mut entry);
    let imported = recursive
        .import_native(&config, &mmcs, &commitment, &points, &opened, &mut entry)
        .unwrap();

    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap: Vec<_> = (0..1 << CAP_HEIGHT)
        .map(|_| b.alloc_public_input_array::<16>("root").to_vec())
        .collect();
    let point: Vec<_> = (0..VARIABLES)
        .map(|_| {
            let coordinate = b.public_input();
            b.native_tower128_from_expr(coordinate)
        })
        .collect();
    let proof = shape.allocate_native_targets(&mut b).unwrap();
    let initial =
        [129u8, 9, 251].map(|byte| b.define_const(F::from_raw_coordinates(byte.into()).unwrap()));
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, F>(
        &mut b,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    recursive
        .observe_commitment_with_host::<NativeBinaryEncoding, F>(&mut b, &mut ch, &cap)
        .unwrap();
    recursive
        .verify_at_native(&mut b, ch, &cap, &[point], &proof)
        .unwrap();
    let circuit = b.build().unwrap();
    let statement: Vec<F> = commitment
        .roots()
        .iter()
        .flat_map(|root| bytes_to_limbs(root))
        .map(|word| F::from_raw_coordinates(word.into()).unwrap())
        .chain(points[0].iter().copied())
        .collect();
    let private = imported.private_native_values(&shape).unwrap();

    let prepared = NativeBusCircuit::new(&circuit, "whir").unwrap();
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(&prepared),
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&private).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest: Vec<F> = witness
        .index
        .iter()
        .map(|&id| *witness.get_value(id).unwrap())
        .collect();
    let honest_traces = prepared.traces(&witness).unwrap();
    let honest_proof = prover.prove(&public, honest_traces.clone()).unwrap();
    authority.verify_native(&honest_proof, &public).unwrap();
    let rejects = |traces: Vec<RowMajorMatrix<F>>| {
        let attempt = catch_unwind(AssertUnwindSafe(|| prover.prove(&public, traces)));
        if let Ok(Ok(proof)) = attempt {
            assert!(authority.verify_native(&proof, &public).is_err());
        }
    };

    let calls: Vec<_> = circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor { inputs, .. } => Some(&inputs[0]),
            _ => None,
        })
        .collect();
    let keccak = prepared
        .airs()
        .iter()
        .position(|air| air.width() == NUM_KECCAK_BINARY_COLS)
        .unwrap();
    assert_eq!(F::from_raw_coordinates(1), Some(F::ONE));
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    // The first query's lowest index bit is sampled, so its first sibling
    // reaches the hash through `select` gates. Its next bit is a constant
    // stratum bit, which makes the second sibling itself a Keccak lane.
    let path = &proof.final_paths[0];
    assert!(path.len() >= 2, "a path through two compressions");
    for (level, word, through_gates) in [(0, 3, true), (1, 5, false)] {
        let id = circuit.expr_to_widx[&path[level][word]];
        let input = circuit
            .private_input_rows
            .iter()
            .position(|&row| row == id)
            .unwrap();
        let mut forged_private = private.clone();
        forged_private[input] += wide;
        let mut runner = circuit.runner();
        runner.set_public_inputs(&statement).unwrap();
        runner.set_private_inputs(&forged_private).unwrap();
        assert!(runner.run().is_err(), "the runner refuses a wide lane");

        let forged = replay(&circuit, &honest, &statement, &forged_private);
        let lanes: Vec<_> = calls
            .iter()
            .enumerate()
            .flat_map(|(c, ids)| {
                ids.iter()
                    .enumerate()
                    .filter(|&(_, id)| forged[id.0 as usize] != honest[id.0 as usize])
                    .map(move |(l, _)| (c, l))
            })
            .collect();
        let [(call, lane)] = lanes[..] else {
            panic!("exactly one wide Keccak input lane, got {lanes:?}");
        };
        assert!(lane % 16 == word && lane < 32, "a first-block digest lane");
        let mut traces = honest_traces.clone();
        let [fanout, gates, bridge] =
            patch_witness_cells(prepared.airs(), &mut traces, &honest, &forged);
        assert!(fanout > 0 && bridge == 1 && (gates > 0) == through_gates);
        // Only the hash bus can reject this: every table holds locally.
        for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
            check_constraints(air, trace, public);
        }
        rejects(traces.clone());

        // Lifting the Keccak lane to the wide value through its unit-weight
        // bit balances the hash bus but leaves a state cell outside {0, 1}.
        traces[keccak].values[call * KECCAK_BINARY_ROWS_PER_PERM * NUM_KECCAK_BINARY_COLS
            + KECCAK_BINARY_ROWS_PER_PERM
            + 16 * lane] += wide;
        let local = catch_unwind(AssertUnwindSafe(|| {
            check_constraints(&prepared.airs()[keccak], &traces[keccak], &[]);
        }));
        assert!(local.is_err(), "a wide Keccak lane needs a non-Boolean bit");
        rejects(traces);
    }

    // A padding output row after another output row is read by no round map
    // and no active bus row, so only Booleanity constrains its state cells.
    let mut padded = honest_traces;
    let height = padded[keccak].values.len() / NUM_KECCAK_BINARY_COLS;
    let row = (calls.len() * KECCAK_BINARY_ROWS_PER_PERM + height) / 2;
    assert!(calls.len() * KECCAK_BINARY_ROWS_PER_PERM < row && row < height);
    let schedule = prepared.airs()[keccak].preprocessed_trace().unwrap();
    assert_eq!(schedule.values[3 * row..3 * row + 3], [F::ZERO; 3]);
    for r in [row - 1, row] {
        let flags =
            &padded[keccak].values[r * NUM_KECCAK_BINARY_COLS..][..KECCAK_BINARY_ROWS_PER_PERM];
        let (round, output) = flags.split_at(KECCAK_BINARY_ROWS_PER_PERM - 1);
        assert!(round.iter().all(|&flag| flag == F::ZERO) && output == [F::ONE]);
    }
    padded[keccak].values[row * NUM_KECCAK_BINARY_COLS + KECCAK_BINARY_ROWS_PER_PERM] = wide;
    rejects(padded.clone());
    let local = catch_unwind(AssertUnwindSafe(|| {
        check_constraints(&prepared.airs()[keccak], &padded[keccak], &[]);
    }));
    assert!(local.is_err(), "a padding state cell outside {{0, 1}}");
}

#[test]
fn product_bus_circuit_proves_over_poly64_with_poly192_challenges() {
    use p3_binary_field::Poly64;
    use p3_recursion::artifact::{
        BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    };
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};
    let mut builder = CircuitBuilder::<Poly64>::new();
    let input = builder.public_input();
    let expected = builder.public_input();
    let factor = builder.alloc_private_input("factor");
    let product = builder.mul(input, factor);
    builder.connect(product, expected);
    let circuit = builder.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "poly").unwrap();
    let [a, b] = [0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210].map(Poly64::new);
    let statement = [a, a * b];
    let public = prepared.public_values(&statement).unwrap();
    let parameters = |variables| {
        BinaryNativePolyWhirPcsParameters::new(
            variables,
            ProtocolParameters {
                starting_log_inv_rate: 2,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                security_level: 24,
                pow_bits: 0,
            },
            ByteHash::Keccak256,
            0,
        )
        .unwrap()
    };
    let spec = BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables()),
        preprocessed: prepared.preprocessed_variables().map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-poly-bus-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 16,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&[b]).unwrap();
    let proof = prover
        .prove(
            &public,
            prepared
                .traces(&runner.run().unwrap().witness_trace)
                .unwrap(),
        )
        .unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let mut wrong = public;
    wrong.last_mut().unwrap()[1] += Poly64::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());
}
