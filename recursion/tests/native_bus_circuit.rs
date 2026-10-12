//! Native product buses bind every fixed circuit occurrence without pushforwards.

use core::borrow::Borrow;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_air::{BaseAir, check_constraints};
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_blake3::Blake3;
use p3_blake3_air::{
    Blake3BinaryCols, Blake3CompressionInput, NUM_BLAKE3_BINARY_COLS, generate_binary_trace_rows,
};
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{
    BLAKE3_INPUT_WORDS, ByteHash, KECCAK_STATE_LIMBS, KECCAK256_RATE_BYTES, NpoTypeId,
    blake3_compress, bytes_to_limbs, keccak_limbs_to_state, keccak_state_to_limbs, limbs_to_words,
    words_to_limbs,
};
use p3_circuit::tables::WitnessTrace;
use p3_circuit::{AluOpKind, Circuit, CircuitBuilder, ExprId, Op, WitnessId};
use p3_circuit_prover::native_bus::{NativeBusCircuit, NativeBusCircuitAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_keccak_air::{KECCAK_BINARY_ROWS_PER_PERM, NUM_KECCAK_BINARY_COLS};
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::VerifierLimits;
use p3_symmetric::{CryptographicHasher, Permutation};

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
        .as_chunks::<14>()
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
    let width = bridge.width;
    for i in 0..width {
        bridge.values.swap(i, width + i);
    }
    check_constraints(prepared.airs().last().unwrap(), bridge, &[]);
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prover.prove(&public, forged)
    }));
    if let Ok(Ok(proof)) = attempt {
        assert!(authority.verify_native(&proof, &public).is_err());
    }
}

/// A message whose first padded block is circuit constants starts its only
/// Keccak-f call from that block's precomputed state, fixed by constant
/// gates. `hash` returns the Keccak-256 digest units of a message of
/// `bits`-wide units, here 136 constant bytes and three public units, and the
/// circuit binds them to public inputs. A prover who runs the circuit with
/// one other capacity limb constant and claims the digest that follows
/// satisfies every table but that limb's constant gate, so the proof is
/// rejected.
fn reject_forged_constant_state<F: BinaryCoordinateField>(
    bits: usize,
    hash: impl FnOnce(&mut CircuitBuilder<F>, &[ExprId]) -> Vec<ExprId>,
    setup: impl Fn(&NativeBusCircuit<F>, Vec<Vec<F>>) -> Accepts<F>,
) {
    let prefix = KECCAK256_RATE_BYTES * 8 / bits;
    let units: Vec<u16> = (0..prefix as u16 + 3)
        .map(|i| (i.wrapping_mul(0x9e37) ^ 0x5a5a) >> (16 - bits))
        .collect();
    let message: Vec<u8> = units
        .iter()
        .flat_map(|unit| unit.to_le_bytes().into_iter().take(bits / 8))
        .collect();
    // The digest units of sixteen low-first digest limbs.
    let digest = |limbs: &[u16]| -> Vec<u16> {
        if bits == 16 {
            limbs.to_vec()
        } else {
            limbs
                .iter()
                .flat_map(|limb| limb.to_le_bytes())
                .map(u16::from)
                .collect()
        }
    };
    let encode = |unit: u16| F::from_raw_coordinates(unit.into()).unwrap();
    let statement = |digest: Vec<u16>| -> Vec<F> {
        units[prefix..]
            .iter()
            .copied()
            .chain(digest)
            .map(encode)
            .collect()
    };

    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let mut input: Vec<_> = units[..prefix]
        .iter()
        .map(|&unit| b.define_const(encode(unit)))
        .collect();
    input.extend(b.alloc_public_input_array::<3>("message suffix"));
    for unit in hash(&mut b, &input) {
        let expected = b.public_input();
        b.connect(unit, expected);
    }
    let mut circuit = b.build().unwrap();
    let calls: Vec<_> = circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor { inputs, .. } => Some(inputs[0].clone()),
            _ => None,
        })
        .collect();
    let [input] = &calls[..] else {
        panic!("the constant block takes no Keccak-f call")
    };

    let prepared = NativeBusCircuit::new(&circuit, "prefix").unwrap();
    let honest = statement(digest(&bytes_to_limbs(
        &Keccak256Hash.hash_iter(message.iter().copied()),
    )));
    let mut runner = circuit.runner();
    runner.set_public_inputs(&honest).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let public = prepared.public_values(&honest).unwrap();
    assert!(setup(&prepared, public)(prepared.traces(&witness).unwrap()));

    // A nonzero capacity limb constant that no other operation reads.
    let reads = |id: WitnessId| -> usize {
        circuit
            .ops
            .iter()
            .map(|op| match op {
                Op::Alu {
                    a,
                    b,
                    c,
                    intermediate_out,
                    ..
                } => [Some(*a), Some(*b), *c, *intermediate_out]
                    .into_iter()
                    .filter(|&read| read == Some(id))
                    .count(),
                Op::Hint { inputs, .. } => inputs.iter().filter(|&&read| read == id).count(),
                Op::NonPrimitiveOpWithExecutor { inputs, .. } => {
                    inputs.iter().flatten().filter(|&&read| read == id).count()
                }
                _ => 0,
            })
            .sum()
    };
    let value = |id: WitnessId| *witness.get_value(id).unwrap();
    let lane = (KECCAK256_RATE_BYTES / 2..KECCAK_STATE_LIMBS)
        .find(|&lane| value(input[lane]) != F::ZERO && reads(input[lane]) == 1)
        .unwrap();
    let mut limbs: Vec<u16> = input
        .iter()
        .map(|&id| u16::try_from(value(id).to_raw_coordinates()).unwrap())
        .collect();
    limbs[lane] ^= 1;
    let forged_limb = encode(limbs[lane]);
    let permuted =
        keccak_state_to_limbs(&KeccakF.permute(keccak_limbs_to_state(&limbs.try_into().unwrap())));
    let claimed = statement(digest(&permuted[..16]));
    // The prover runs the same operations with that one constant changed,
    // while `prepared` keeps the circuit's constant gate.
    let position = circuit
        .ops
        .iter()
        .position(|op| matches!(*op, Op::Const { out, .. } if out == input[lane]))
        .unwrap();
    circuit.ops[position] = Op::Const {
        out: input[lane],
        val: forged_limb,
    };
    let mut runner = circuit.runner();
    runner.set_public_inputs(&claimed).unwrap();
    let forged = runner.run().unwrap().witness_trace;

    let public = prepared.public_values(&claimed).unwrap();
    let traces = prepared.traces(&forged).unwrap();
    let gates = prepared
        .airs()
        .iter()
        .position(|air| air.width() == 5)
        .unwrap();
    for (table, ((air, trace), public)) in
        prepared.airs().iter().zip(&traces).zip(&public).enumerate()
    {
        let local = catch_unwind(AssertUnwindSafe(|| check_constraints(air, trace, public)));
        assert_eq!(local.is_err(), table == gates, "table {table}");
    }
    assert!(!setup(&prepared, public)(traces));
}

#[test]
fn native_product_buses_fix_the_precomputed_state_of_constant_words() {
    reject_forged_constant_state(
        16,
        |b, message| b.native_keccak256_words(message).unwrap().to_vec(),
        tower_accepts,
    );
}

#[test]
fn native_product_buses_fix_the_precomputed_state_of_constant_bytes() {
    reject_forged_constant_state(
        8,
        |b, message| b.native_keccak256_bytes(message).unwrap().to_vec(),
        tower_accepts,
    );
}

#[test]
fn native_product_buses_fix_the_precomputed_state_of_constant_poly64_words() {
    reject_forged_constant_state(
        16,
        |b, message| b.native_keccak256_words(message).unwrap().to_vec(),
        poly64_accepts,
    );
}

#[test]
fn native_product_buses_fix_the_precomputed_state_of_constant_poly64_bytes() {
    reject_forged_constant_state(
        8,
        |b, message| b.native_keccak256_bytes(message).unwrap().to_vec(),
        poly64_accepts,
    );
}

/// The assignment reached by replaying `circuit` from `public` and `private`
/// as the runner does, except that hints and native hash calls keep their
/// `honest` outputs: the witness of a prover who claims the honest digests.
fn replay<F: Field>(circuit: &Circuit<F>, honest: &[F], public: &[F], private: &[F]) -> Vec<F> {
    fn assign<F: Field>(w: &mut [Option<F>], id: WitnessId, value: F) {
        let slot = &mut w[id.0 as usize];
        assert!(
            slot.is_none_or(|old| old == value),
            "replay conflict at {id:?}"
        );
        *slot = Some(value);
    }
    const fn get<F: Copy>(w: &[Option<F>], id: WitnessId) -> F {
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
/// each of those three tables changed. Hash-table bit rows are left as they are.
fn patch_witness_cells<F: BinaryCoordinateField>(
    airs: &[NativeBusCircuitAir<F>],
    traces: &mut [RowMajorMatrix<F>],
    honest: &[F],
    forged: &[F],
) -> [usize; 3] {
    let mut patched = [0; 3];
    for (air, trace) in airs.iter().zip(traces) {
        let table = match (air.width(), air.preprocessed_width()) {
            (1, 4) => 0,
            (5, 14) => 1,
            (116, 119) => 2,
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

/// The Keccak trace cell of bit 0 of input lane `lane` of call `call`: row
/// `call * KECCAK_BINARY_ROWS_PER_PERM`, column
/// `KECCAK_BINARY_ROWS_PER_PERM + 16 * lane`. Asserts that the sixteen bits
/// from there, bit `t` weighted by `x_t`, pack to `expected`, the honest lane
/// witness, so adding `d` to the cell adds `d` to exactly that lane.
fn keccak_input_cell<F: BinaryCoordinateField>(
    keccak: &RowMajorMatrix<F>,
    call: usize,
    lane: usize,
    expected: F,
) -> usize {
    let cell = call * KECCAK_BINARY_ROWS_PER_PERM * NUM_KECCAK_BINARY_COLS
        + KECCAK_BINARY_ROWS_PER_PERM
        + 16 * lane;
    let packed = (0..16).fold(F::ZERO, |sum, t| {
        sum + keccak.values[cell + t] * F::from_raw_coordinates(1 << t).unwrap()
    });
    assert_eq!(packed, expected, "lane {lane} of Keccak call {call}");
    cell
}

/// An absorbed word reaches the AIR as a Keccak lane: in the first block the
/// lane is the word itself, and from the second block on it is `out + word`,
/// a gate output whose `out` is the previous call's output. A word with a
/// seventeenth coordinate makes that lane wide: the fanout, gate and bridge
/// rows accept it, the hash bus does not, and lifting the Keccak lane instead
/// leaves a state cell outside {0, 1}. `hash` binds the Keccak digest of
/// 70 private words to the 16 public digest words.
fn reject_wide_message_words(hash: impl FnOnce(&mut CircuitBuilder<F>, &[ExprId], &[ExprId])) {
    const WORDS: usize = 70;
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
    hash(&mut b, &message, &expected);
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
    // Word 5 is lane 5 of the first block; word 68 opens the second block.
    for (word, call, lane, through_gates) in [(5, 0, 5, false), (68, 1, 0, true)] {
        let mut forged_private = private.clone();
        forged_private[word] += wide;
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
        assert_eq!(lanes, [(call, lane)], "lane {lane} of block {call}");
        let mut traces = honest_traces.clone();
        let [fanout, gates, bridge] =
            patch_witness_cells(prepared.airs(), &mut traces, &honest, &forged);
        assert!(fanout > 0 && bridge == 1 && (gates > 0) == through_gates);
        for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
            check_constraints(air, trace, public);
        }
        rejects(traces.clone());

        let cell = keccak_input_cell(
            &traces[keccak],
            call,
            lane,
            honest[calls[call][lane].0 as usize],
        );
        traces[keccak].values[cell] += wide;
        let local = catch_unwind(AssertUnwindSafe(|| {
            check_constraints(&prepared.airs()[keccak], &traces[keccak], &[]);
        }));
        assert!(local.is_err(), "the lifted lane leaves a non-Boolean cell");
        rejects(traces);
    }
}

/// The host word hash that absorbs observed transcript words.
#[test]
fn native_keccak_lanes_range_check_words_in_both_blocks() {
    reject_wide_message_words(|b, message, expected| {
        let digest = NativeBinaryEncoding::hash_words(b, ByteHash::Keccak256, message).unwrap();
        for (&limb, &expected) in digest.iter().zip(expected) {
            b.connect(limb, expected);
        }
    });
}

/// The subtree gadget that hashes grouped coset leaves: one leaf of a
/// one-row tree, whose digest is the only cap root.
#[test]
fn native_keccak_lanes_range_check_subtree_leaf_words_in_both_blocks() {
    reject_wide_message_words(|b, message, expected| {
        b.verify_byte_hash_mmcs_subtree_words_with_host::<NativeBinaryEncoding>(
            ByteHash::Keccak256,
            &[message.to_vec()],
            1,
            &[],
            &[],
            &[expected.to_vec()],
        )
        .unwrap();
    });
}

/// Whether a proof of the given traces verifies under a fixed statement.
pub(crate) type Accepts<F> = Box<dyn Fn(Vec<RowMajorMatrix<F>>) -> bool>;

/// A native WHIR leaf splits each opened value into `count` hinted words
/// bound by `value = sum_j word_j * x_(16j)`, where `x_c` has the single raw
/// coordinate `c`, and absorbs them as Keccak lanes. `split` emits that split
/// and `setup` returns whether a proof of the given traces verifies. Each
/// forgery `(value, word, moved, call, lane)` flips coordinate `moved` of a
/// value and adds `x_moved / x_(16 * word)` to that word, which keeps the sum.
/// The quotient has no coordinate below sixteen, so every lane keeps the
/// sixteen low coordinates it absorbs and only the lane range check separates
/// the forged opening from the committed one: lane `lane` of Keccak call
/// `call` turns wide, the fanout, gate and bridge rows accept it, the hash bus
/// does not, and lifting the Keccak lane instead leaves a state cell outside
/// {0, 1}.
fn reject_wide_leaf_words<F: BinaryCoordinateField>(
    values: &[F],
    count: usize,
    blocks: usize,
    forgeries: &[(usize, usize, usize, usize, usize)],
    split: impl Fn(&mut CircuitBuilder<F>, ExprId, usize) -> Vec<ExprId>,
    setup: impl FnOnce(&NativeBusCircuit<F>, Vec<Vec<F>>) -> Accepts<F>,
) {
    let bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| {
            value
                .to_raw_coordinates()
                .to_le_bytes()
                .into_iter()
                .take(2 * count)
        })
        .collect();
    let root = Keccak256Hash.hash_iter(bytes.iter().copied());

    // One leaf of a one-row tree: its digest is the only cap root.
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap = b.alloc_public_input_array::<16>("root");
    let row = b.alloc_private_inputs(values.len(), "row values");
    let mut words = Vec::new();
    for &value in &row {
        words.extend(split(&mut b, value, count));
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
    let private = values.to_vec();

    let prepared = NativeBusCircuit::new(&circuit, "leaf").unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let accepts = setup(&prepared, public.clone());
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
    assert!(accepts(honest_traces.clone()), "the honest traces prove");

    let calls: Vec<_> = circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor { inputs, .. } => Some(&inputs[0]),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), blocks, "absorbed blocks");
    let keccak = prepared
        .airs()
        .iter()
        .position(|air| air.width() == NUM_KECCAK_BINARY_COLS)
        .unwrap();
    assert_eq!(F::from_raw_coordinates(1), Some(F::ONE));
    let monomial = |coordinate: usize| F::from_raw_coordinates(1 << coordinate).unwrap();
    for &(value, word, moved, call, lane) in forgeries {
        let wide = monomial(moved) * monomial(16 * word).inverse();
        assert_eq!(
            wide.to_raw_coordinates() & 0xffff,
            0,
            "lane bytes unchanged"
        );
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
        assert_eq!(split.len(), count);
        let mut hinted = honest.clone();
        hinted[split[word].0 as usize] += wide;
        let mut forged_private = private.clone();
        forged_private[value] += monomial(moved);
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
        assert_eq!(lanes, [(call, lane)], "lane {lane} of block {call}");
        let mut traces = honest_traces.clone();
        let [fanout, gates, bridge] =
            patch_witness_cells(prepared.airs(), &mut traces, &honest, &forged);
        assert!(fanout > 0 && gates > 0 && bridge == 1);
        for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
            check_constraints(air, trace, public);
        }
        assert!(!accepts(traces.clone()));

        let cell = keccak_input_cell(
            &traces[keccak],
            call,
            lane,
            honest[calls[call][lane].0 as usize],
        );
        traces[keccak].values[cell] += wide;
        let local = catch_unwind(AssertUnwindSafe(|| {
            check_constraints(&prepared.airs()[keccak], &traces[keccak], &[]);
        }));
        assert!(local.is_err(), "the lifted lane leaves a non-Boolean cell");
        assert!(!accepts(traces));
    }
}

/// Splits a private Tower128 value into its unchecked raw words.
fn tower_words(b: &mut CircuitBuilder<F>, value: ExprId, count: usize) -> Vec<ExprId> {
    let value = b.native_tower128_from_expr(value);
    b.native_tower128_unchecked_words(&value, count).unwrap()
}

/// Proves Tower128 traces under a native binary PCS authority for `prepared`.
pub(crate) fn tower_accepts(prepared: &NativeBusCircuit<F>, public: Vec<Vec<F>>) -> Accepts<F> {
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(prepared),
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    Box::new(move |traces| {
        let attempt = catch_unwind(AssertUnwindSafe(|| prover.prove(&public, traces)));
        matches!(attempt, Ok(Ok(proof)) if authority.verify_native(&proof, &public).is_ok())
    })
}

/// Proves Poly64 traces under a native Poly64 WHIR authority for `prepared`.
pub(crate) fn poly64_accepts(
    prepared: &NativeBusCircuit<p3_binary_field::Poly64>,
    public: Vec<Vec<p3_binary_field::Poly64>>,
) -> Accepts<p3_binary_field::Poly64> {
    use p3_recursion::artifact::{
        BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    };
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};
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
        initial_bytes: b"native-bus-circuit-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 16,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec,
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    Box::new(move |traces| {
        let attempt = catch_unwind(AssertUnwindSafe(|| prover.prove(&public, traces)));
        matches!(attempt, Ok(Ok(proof)) if authority.verify_native(&proof, &public).is_ok())
    })
}

/// Sixteen Tower128 values form a 256-byte leaf absorbed in two Keccak
/// blocks, whose first lanes are words 0 and 68.
#[test]
fn native_keccak_lanes_range_check_word_leaves_in_both_blocks() {
    let values: Vec<F> = (0..16)
        .map(|i| F::from_repr(0x492f307c9bfa3e514379dc5a1b279591u128.wrapping_mul(i + 13)))
        .collect();
    reject_wide_leaf_words(
        &values,
        8,
        2,
        &[(0, 0, 16, 0, 0), (8, 4, 80, 1, 0)],
        tower_words,
        tower_accepts,
    );
}

/// Sixteen Tower32 base values form a 64-byte leaf of two words per value.
/// Moving coordinate 32 of a value into its second word gives a value outside
/// Tower32 with the same leaf bytes, so the lane range check is also what
/// keeps base rows in Tower32.
#[test]
fn native_keccak_lanes_range_check_tower32_leaf_words() {
    let values: Vec<F> = (0..16)
        .map(|i| F::from_repr(u128::from(0x9bfa3e51u32.wrapping_mul(i + 13))))
        .collect();
    reject_wide_leaf_words(
        &values,
        2,
        1,
        &[(0, 0, 16, 0, 0), (15, 1, 32, 0, 31)],
        tower_words,
        tower_accepts,
    );
}

/// Twenty-four Poly64 values form a 192-byte leaf of four words per value,
/// absorbed in two Keccak blocks whose first lanes are words 0 and 68. A word
/// of degree below sixteen times `x^(16j)` needs no reduction, so moving a
/// coefficient at or above `16 * (j + 1)` of a value into its word `j` keeps
/// the value and the leaf bytes; only the lane range check rejects it.
#[test]
fn native_keccak_lanes_range_check_poly64_leaf_words_in_both_blocks() {
    use p3_binary_field::Poly64;
    let values: Vec<Poly64> = (0..24)
        .map(|i| Poly64::new(0x9bfa_3e51_4379_dc5bu64.wrapping_mul(i + 13)))
        .collect();
    reject_wide_leaf_words(
        &values,
        4,
        2,
        &[
            (0, 0, 16, 0, 0),
            (16, 2, 48, 0, 66),
            (17, 0, 16, 1, 0),
            (18, 1, 40, 1, 5),
        ],
        |b, value, count| b.native_poly64_unchecked_words(value, count).unwrap(),
        poly64_accepts,
    );
}

/// Each WHIR site that grinds splits its witness into `base_bits / 16` hinted
/// words bound by `witness = sum_j word_j * x_(16j)` and observes them, so the
/// refill of the draw after it absorbs each word as a Keccak lane or a BLAKE3
/// block word; a site without grinding splits nothing. Returns each split witness's private input
/// position and words, given the rows of every site's witness, and asserts
/// that the first hint on each witness row is that word split.
fn grinding_words<'a, F: Field>(
    circuit: &'a Circuit<F>,
    witnesses: &[WitnessId],
    base_bits: usize,
) -> Vec<(usize, &'a [WitnessId])> {
    let sites: Vec<_> = witnesses
        .iter()
        .filter_map(|&row| {
            let split = circuit.ops.iter().find_map(|op| match op {
                Op::Hint {
                    inputs, outputs, ..
                } if inputs[..] == [row] => Some(&outputs[..]),
                _ => None,
            })?;
            let position = circuit
                .private_input_rows
                .iter()
                .position(|&private_row| private_row == row)
                .unwrap();
            Some((position, split))
        })
        .collect();
    assert!(!sites.is_empty(), "a site grinds");
    for (_, split) in &sites {
        assert_eq!(
            split.len(),
            base_bits / 16,
            "a grinding witness splits into sixteen-bit words"
        );
    }
    sites
}

/// Whether the runner completes `circuit` from `statement` and `private`.
fn circuit_runs<F: Field>(circuit: &Circuit<F>, statement: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(statement)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

/// Flipping the top coordinate of any word of a grinding witness (see
/// [`grinding_words`]) of `circuit` changes the absorbed lanes, which the draws
/// after it bind, and flipping the first coordinate above `base_bits` leaves no
/// split; the runner refuses both.
pub(crate) fn reject_flipped_grinding_bits<F: BinaryCoordinateField>(
    circuit: &Circuit<F>,
    statement: &[F],
    private: &[F],
    witnesses: &[WitnessId],
    base_bits: usize,
) {
    assert!(
        circuit_runs(circuit, statement, private),
        "the honest witnesses run"
    );
    let above = (base_bits < F::COORDINATE_BITS).then_some(base_bits);
    for (position, split) in grinding_words(circuit, witnesses, base_bits) {
        for coordinate in (0..split.len()).map(|j| 16 * j + 15).chain(above) {
            let mut wrong = private.to_vec();
            wrong[position] += F::from_raw_coordinates(1 << coordinate).unwrap();
            assert!(
                !circuit_runs(circuit, statement, &wrong),
                "flipped witness coordinate {coordinate}"
            );
        }
    }
}

/// The forgery `(word, moved)` flips coordinate `moved` of the first grinding
/// witness (see [`grinding_words`]) and adds `x_moved / x_(16 * word)` to that
/// word, which keeps the words' sum. The quotient has no coordinate below
/// sixteen, so every absorbed byte stays honest and only the hash input's range
/// check separates the forged witness from the honest one. Under Keccak one
/// lane turns wide, the fanout, gate and bridge rows accept it, the hash bus
/// does not, and lifting the Keccak lane instead leaves a state cell outside
/// {0, 1}. Under BLAKE3 one block word of a compression turns wide, the fanout
/// and gate rows accept it, the witness bus does not, and lifting the
/// compression's bit instead leaves a cell outside {0, 1}.
pub(crate) fn reject_wide_grinding_word<F: BinaryCoordinateField>(
    circuit: &Circuit<F>,
    statement: &[F],
    private: &[F],
    witnesses: &[WitnessId],
    base_bits: usize,
    (word, moved): (usize, usize),
    setup: impl FnOnce(&NativeBusCircuit<F>, Vec<Vec<F>>) -> Accepts<F>,
) {
    let monomial = |coordinate: usize| F::from_raw_coordinates(1 << coordinate).unwrap();
    let wide = monomial(moved) * monomial(16 * word).inverse();
    assert_eq!(
        wide.to_raw_coordinates() & 0xffff,
        0,
        "lane bytes unchanged"
    );
    let (value, split) = grinding_words(circuit, witnesses, base_bits)[0];
    let prepared = NativeBusCircuit::new(circuit, "grinding").unwrap();
    let public = prepared.public_values(statement).unwrap();
    let accepts = setup(&prepared, public.clone());
    let mut forged_private = private.to_vec();
    forged_private[value] += monomial(moved);
    if !blake3_calls(circuit).is_empty() {
        let forgery = Blake3Forgery::new(circuit, &prepared, statement, private, accepts);
        let mut hinted = forgery.honest.clone();
        hinted[split[word].0 as usize] += wide;
        forgery.reject_wide_limb(&hinted, &forged_private, true);
        return;
    }
    let mut runner = circuit.runner();
    runner.set_public_inputs(statement).unwrap();
    runner.set_private_inputs(private).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest: Vec<F> = witness
        .index
        .iter()
        .map(|&id| *witness.get_value(id).unwrap())
        .collect();
    let honest_traces = prepared.traces(&witness).unwrap();
    assert!(accepts(honest_traces.clone()), "the honest traces prove");

    let calls: Vec<_> = circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor {
                executor, inputs, ..
            } if executor.op_type() == &NpoTypeId::native_keccak_f1600() => Some(&inputs[0]),
            _ => None,
        })
        .collect();
    let keccak = prepared
        .airs()
        .iter()
        .position(|air| air.width() == NUM_KECCAK_BINARY_COLS)
        .unwrap();
    let mut hinted = honest.clone();
    hinted[split[word].0 as usize] += wide;
    assert!(
        !circuit_runs(circuit, statement, &forged_private),
        "the runner refuses the forged witness"
    );

    let forged = replay(circuit, &hinted, statement, &forged_private);
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
        panic!("one lane changes, not {lanes:?}");
    };
    assert_ne!(
        forged[calls[call][lane].0 as usize].to_raw_coordinates() >> 16,
        0,
        "lane {lane} of Keccak call {call} is wide"
    );
    let mut traces = honest_traces;
    let [fanout, gates, bridge] =
        patch_witness_cells(prepared.airs(), &mut traces, &honest, &forged);
    assert!(fanout > 0 && gates > 0 && bridge == 1);
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }
    assert!(!accepts(traces.clone()));

    let cell = keccak_input_cell(
        &traces[keccak],
        call,
        lane,
        honest[calls[call][lane].0 as usize],
    );
    traces[keccak].values[cell] += wide;
    let local = catch_unwind(AssertUnwindSafe(|| {
        check_constraints(&prepared.airs()[keccak], &traces[keccak], &[]);
    }));
    assert!(local.is_err(), "the lifted lane leaves a non-Boolean cell");
}

/// A proof-supplied Merkle sibling reaches the hash only through a level's
/// `select`: under a constant index bit the sibling limb itself is a native
/// Keccak input lane, and under a private bit the lane is a gate output equal
/// to it. A prover who claims the honest digests for a sibling limb with a
/// seventeenth coordinate satisfies every fanout, gate and bridge row, but the
/// hash bus pairs that bridge lane with a sum of Keccak state cells. Those
/// cells cannot reach the wide value while staying Boolean.
#[test]
fn native_keccak_lanes_range_check_merkle_siblings() {
    let leaf_bytes: Vec<[u8; 4]> = (0..4u8)
        .map(|k| [k, 0x80 | k, 0x5a ^ k, 0xff - k])
        .collect();
    let hash = |bytes: &[u8]| Keccak256Hash.hash_iter(bytes.iter().copied());
    let compress = |left: &[u8; 32], right: &[u8; 32]| hash(&[*left, *right].concat());
    let leaves: Vec<_> = leaf_bytes.iter().map(|bytes| hash(bytes)).collect();
    let nodes = [
        compress(&leaves[0], &leaves[1]),
        compress(&leaves[2], &leaves[3]),
    ];
    let root = compress(&nodes[0], &nodes[1]);
    let words = |bytes: &[u8]| -> Vec<F> {
        bytes_to_limbs(bytes)
            .into_iter()
            .map(|word| F::from_raw_coordinates(word.into()).unwrap())
            .collect()
    };

    // Leaf 1 of four: a constant low index bit, as for a per-symbol leaf of a
    // coset, and a private high bit.
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let leaf = b.alloc_public_input_array::<2>("leaf words");
    let cap = b.alloc_public_input_array::<16>("root");
    let low = b.define_const(F::ONE);
    let high = b.alloc_private_input("high index bit");
    let siblings: Vec<_> = (0..2)
        .map(|_| b.alloc_private_inputs(16, "sibling"))
        .collect();
    b.verify_byte_hash_mmcs_subtree_words_with_host::<NativeBinaryEncoding>(
        ByteHash::Keccak256,
        &[leaf.to_vec()],
        4,
        &[low, high],
        &siblings,
        &[cap.to_vec()],
    )
    .unwrap();
    let circuit = b.build().unwrap();
    let statement = [words(&leaf_bytes[1]), words(&root)].concat();
    let private = [vec![F::ZERO], words(&leaves[0]), words(&nodes[1])].concat();

    let prepared = NativeBusCircuit::new(&circuit, "merkle").unwrap();
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
    let traces = prepared.traces(&witness).unwrap();
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
    assert_eq!(calls.len(), 3, "one leaf hash and two compressions");
    let keccak = prepared
        .airs()
        .iter()
        .position(|air| air.width() == NUM_KECCAK_BINARY_COLS)
        .unwrap();
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    // (private input, its Keccak call and lane, whether gates read it)
    for (input, call, lane, through_gates) in [(1 + 3, 1, 3, false), (1 + 16 + 5, 2, 16 + 5, true)]
    {
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
        assert_eq!(lanes, [(call, lane)], "exactly one wide Keccak input lane");
        let mut traces = traces.clone();
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
        assert_eq!(F::from_raw_coordinates(1), Some(F::ONE));
        let cell = call * KECCAK_BINARY_ROWS_PER_PERM * NUM_KECCAK_BINARY_COLS
            + KECCAK_BINARY_ROWS_PER_PERM
            + 16 * lane;
        traces[keccak].values[cell] += wide;
        let local = catch_unwind(AssertUnwindSafe(|| {
            check_constraints(&prepared.airs()[keccak], &traces[keccak], &[]);
        }));
        assert!(local.is_err(), "a wide Keccak lane needs a non-Boolean bit");
        rejects(traces);
    }

    // A padding output row after another output row is read by no round map
    // and no active bus row, so only Booleanity constrains its state cells.
    let mut padded = traces;
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
    reject_wide_whir_siblings(
        &circuit,
        &prepared,
        &statement,
        &private,
        &proof.final_paths[0],
        |traces| {
            let attempt = catch_unwind(AssertUnwindSafe(|| prover.prove(&public, traces)));
            matches!(attempt, Ok(Ok(proof)) if authority.verify_native(&proof, &public).is_ok())
        },
    );
}

/// The forgeries of [`native_keccak_lanes_range_check_whir_merkle_siblings`]
/// against the native WHIR verifier `circuit`: `path` is its first final-round
/// query path, and `accepts` proves traces of `prepared` and reports whether
/// the proof verifies.
fn reject_wide_whir_siblings<F: BinaryCoordinateField>(
    circuit: &Circuit<F>,
    prepared: &NativeBusCircuit<F>,
    statement: &[F],
    private: &[F],
    path: &[Vec<ExprId>],
    accepts: impl Fn(Vec<RowMajorMatrix<F>>) -> bool,
) {
    let public = prepared.public_values(statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(statement).unwrap();
    runner.set_private_inputs(private).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest: Vec<F> = witness
        .index
        .iter()
        .map(|&id| *witness.get_value(id).unwrap())
        .collect();
    let honest_traces = prepared.traces(&witness).unwrap();
    assert!(accepts(honest_traces.clone()), "the honest traces prove");

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
    assert!(path.len() >= 2, "a path through two compressions");
    for (level, word, through_gates) in [(0, 3, true), (1, 5, false)] {
        let id = circuit.expr_to_widx[&path[level][word]];
        let input = circuit
            .private_input_rows
            .iter()
            .position(|&row| row == id)
            .unwrap();
        let mut forged_private = private.to_vec();
        forged_private[input] += wide;
        let mut runner = circuit.runner();
        runner.set_public_inputs(statement).unwrap();
        runner.set_private_inputs(&forged_private).unwrap();
        assert!(runner.run().is_err(), "the runner refuses a wide lane");

        let forged = replay(circuit, &honest, statement, &forged_private);
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
        assert!(!accepts(traces.clone()));

        // Lifting the Keccak lane to the wide value through its unit-weight
        // bit balances the hash bus but leaves a state cell outside {0, 1}.
        let cell = keccak_input_cell(
            &traces[keccak],
            call,
            lane,
            honest[calls[call][lane].0 as usize],
        );
        traces[keccak].values[cell] += wide;
        let local = catch_unwind(AssertUnwindSafe(|| {
            check_constraints(&prepared.airs()[keccak], &traces[keccak], &[]);
        }));
        assert!(local.is_err(), "a wide Keccak lane needs a non-Boolean bit");
        assert!(!accepts(traces));
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
    assert!(!accepts(padded.clone()));
    let local = catch_unwind(AssertUnwindSafe(|| {
        check_constraints(&prepared.airs()[keccak], &padded[keccak], &[]);
    }));
    assert!(local.is_err(), "a padding state cell outside {{0, 1}}");
}

/// [`native_keccak_lanes_range_check_whir_merkle_siblings`] for a Poly64
/// native WHIR verifier, which shares the WHIR kernel and draws Poly192
/// challenges.
#[test]
fn native_keccak_lanes_range_check_poly64_whir_merkle_siblings() {
    use p3_binary_field::{Poly64, Poly192};
    use p3_binary_pcs::whir::BinaryWhirDomain;
    use p3_commit::MultilinearPcs;
    use p3_multilinear_util::point::Point;
    use p3_recursion::BinaryTower128Challenger;
    use p3_recursion::artifact::{
        BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    };
    use p3_recursion::pcs::binary::BinaryPolyWhirVerifier;
    use p3_sumcheck::layout::{Layout, SuffixProver, Table, plan_stacked_layout};
    use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
    use p3_test_utils::binary_field_params::keccak;
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};
    type P = Poly64;
    type Ch = keccak::LevelChallenger<P>;
    type L = SuffixProver<P, Poly192>;
    const CAP_HEIGHT: usize = 1;
    const VARIABLES: usize = 6;

    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(VARIABLES, 1),
        vec![OpeningBatch::new(vec![0], vec![0])],
    )]);
    let domain = BinaryWhirDomain::<P>::default();
    let config = WhirConfig::<Poly192, P, Ch>::new_with_domain(
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
    let mmcs = keccak::LevelMmcs::<P>::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        CAP_HEIGHT,
    );
    let pcs = WhirProver::<Poly192, P, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
    let recursive = BinaryPolyWhirVerifier::new(
        &config,
        protocol.clone(),
        L::variable_order(),
        ByteHash::Keccak256,
        CAP_HEIGHT,
    )
    .unwrap();
    let shape = recursive.input_shape();
    let make = || Ch::from_hasher(vec![129, 9, 251], keccak::byte_hash());
    let dense = |i: usize| P::new(0x8123456789abcdefu64.wrapping_mul(i as u64 + 13));
    let table = Table::new(RowMajorMatrix::new(
        (0..1 << VARIABLES).map(dense).collect(),
        1 << VARIABLES,
    ));
    let witness = L::new_witness(vec![table], config.round_folding_factor(0));
    let points = vec![Point::new(
        (0..VARIABLES)
            .map(|j| Poly192::new(core::array::from_fn(|k| dense(3 * j + k + 71))))
            .collect(),
    )];
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

    let mut b = CircuitBuilder::<P>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap: Vec<_> = (0..1 << CAP_HEIGHT)
        .map(|_| b.alloc_public_input_array::<16>("root").to_vec())
        .collect();
    let point: Vec<_> = (0..VARIABLES)
        .map(|_| {
            let coefficients = core::array::from_fn(|_| b.public_input());
            b.native_poly192_from_coefficients(coefficients)
        })
        .collect();
    let proof = shape.allocate_native_targets(&mut b).unwrap();
    let initial =
        [129u8, 9, 251].map(|byte| b.define_const(P::from_raw_coordinates(byte.into()).unwrap()));
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, P>(
        &mut b,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    recursive
        .observe_commitment_with_host::<NativeBinaryEncoding, P>(&mut b, &mut ch, &cap)
        .unwrap();
    recursive
        .verify_at_native(&mut b, ch, &cap, &[point], &proof)
        .unwrap();
    let circuit = b.build().unwrap();
    let statement: Vec<P> = commitment
        .roots()
        .iter()
        .flat_map(|root| bytes_to_limbs(root))
        .map(|word| P::from_raw_coordinates(word.into()).unwrap())
        .chain(points[0].iter().flat_map(|value| value.coefficients()))
        .collect();
    let private = imported.private_native_values(&shape).unwrap();

    let prepared = NativeBusCircuit::new(&circuit, "polywhir").unwrap();
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
        initial_bytes: b"native-bus-circuit-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 16,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec,
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    let public = prepared.public_values(&statement).unwrap();
    reject_wide_whir_siblings(
        &circuit,
        &prepared,
        &statement,
        &private,
        &proof.final_paths[0],
        |traces| {
            let attempt = catch_unwind(AssertUnwindSafe(|| prover.prove(&public, traces)));
            matches!(attempt, Ok(Ok(proof)) if authority.verify_native(&proof, &public).is_ok())
        },
    );
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

/// A prover may replace either hinted output. Keep the actual extractor's
/// compiled constraints and replay all witness occurrences under those hints.
fn check_sparse_coordinate_hints<F: BinaryCoordinateField>(
    dual: F,
    trace_one: F,
    setup: impl Fn(&NativeBusCircuit<F>, Vec<Vec<F>>) -> Accepts<F>,
) {
    use p3_circuit::ops::binary_native::BinaryCoordinateExtractor;
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let expected = b.public_input();
    let bit = BinaryCoordinateExtractor::<F>::new(3)
        .unwrap()
        .extract(&mut b, input)
        .unwrap();
    b.connect(bit, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "sparse-coordinate").unwrap();
    let public = [F::ZERO, F::ZERO];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest: Vec<_> = (0..circuit.witness_count)
        .map(|i| *witness.get_value(WitnessId(i)).unwrap())
        .collect();
    let honest_traces = prepared.traces(&witness).unwrap();
    assert!(setup(&prepared, prepared.public_values(&public).unwrap())(
        honest_traces.clone()
    ));
    let outputs = circuit
        .ops
        .iter()
        .find_map(|op| {
            if let Op::Hint { outputs, .. } = op {
                Some(outputs)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(outputs.len(), 2);

    // The other Artin-Schreier root also satisfies the same proof circuit.
    let mut hinted = honest.clone();
    hinted[outputs[1].0 as usize] += F::ONE;
    let alternate = replay(&circuit, &hinted, &public, &[]);
    let mut alternate_traces = honest_traces.clone();
    patch_witness_cells(prepared.airs(), &mut alternate_traces, &honest, &alternate);
    assert!(setup(&prepared, prepared.public_values(&public).unwrap())(
        alternate_traces
    ));

    // With z=0 and x=kappa*t/delta, the field equation holds for any t.
    // Only the actual emitted Boolean gate rejects this non-Boolean t.
    let non_boolean = F::from_raw_coordinates(2).unwrap();
    let forged_public = [trace_one * non_boolean / dual, non_boolean];
    hinted[outputs[0].0 as usize] = non_boolean;
    hinted[outputs[1].0 as usize] = F::ZERO;
    let forged = replay(&circuit, &hinted, &forged_public, &[]);
    let mut forged_traces = honest_traces;
    patch_witness_cells(prepared.airs(), &mut forged_traces, &honest, &forged);
    let values = prepared.public_values(&forged_public).unwrap();
    // Public rows repeat the new statement rather than witness-labelled cells.
    for (trace, public) in forged_traces.iter_mut().zip(&values) {
        if !public.is_empty() {
            assert_eq!(trace.width, public.len());
            for row in trace.values.chunks_mut(trace.width) {
                row.copy_from_slice(public);
            }
        }
    }
    let failed: Vec<_> = prepared
        .airs()
        .iter()
        .zip(&forged_traces)
        .zip(&values)
        .filter_map(|((air, trace), public)| {
            catch_unwind(AssertUnwindSafe(|| check_constraints(air, trace, public)))
                .is_err()
                .then_some(air.width())
        })
        .collect();
    assert_eq!(failed, [5], "only the Boolean gate AIR should reject");
    assert!(!setup(&prepared, values)(forged_traces));
}

#[test]
fn sparse_tower_coordinate_proof_rejects_non_boolean_hints() {
    check_sparse_coordinate_hints(
        p3_recursion::pcs::binary::binary128_trace_dual_basis()[3],
        F::from_repr(1u128 << 64),
        tower_accepts,
    );
}

#[test]
fn sparse_poly_coordinate_proof_rejects_non_boolean_hints() {
    use p3_binary_field::Poly64;
    check_sparse_coordinate_hints(
        p3_recursion::pcs::binary::poly64_trace_dual_basis()[3],
        Poly64::new(1u64 << 61),
        poly64_accepts,
    );
}

/// `bit * k + addend` for a public Boolean `bit`: the gate table checks the bit in the row of
/// the product, which reads `k` from preprocessing. A prover may claim a non-Boolean bit that
/// satisfies the product, or the product with another constant; each leaves only that row
/// unsatisfied, and the proof is refused.
fn check_fused_constant_product<F: BinaryCoordinateField>(
    setup: impl Fn(&NativeBusCircuit<F>, Vec<Vec<F>>) -> Accepts<F>,
) {
    let constant = F::from_raw_coordinates(0x8912).unwrap();
    let addend = F::from_raw_coordinates(0x5a5a).unwrap();
    let mut b = CircuitBuilder::<F>::new();
    let [bit, addend_input, expected] = b.alloc_public_input_array::<3>("bit, addend, product");
    b.assert_bool(bit);
    let k = b.define_const(constant);
    let out = b.mul_add(bit, k, addend_input);
    b.connect(out, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "fused-product").unwrap();
    let gate = prepared
        .airs()
        .iter()
        .position(|air| air.width() == 5)
        .unwrap();
    let pp = prepared.airs()[gate].preprocessed_trace().unwrap();
    let rows = pp.values.as_chunks::<14>().0;
    // Selector 3 is the Boolean gate and selector 7 the checked product with a constant.
    assert!(rows.iter().all(|row| row[9] == F::ZERO));
    let fused: Vec<_> = rows.iter().filter(|row| row[13] == F::ONE).collect();
    assert_eq!(fused.len(), 1);
    assert_eq!(fused[0][5], constant);

    let statement = [F::ONE, addend, constant + addend];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest: Vec<_> = (0..circuit.witness_count)
        .map(|i| *witness.get_value(WitnessId(i)).unwrap())
        .collect();
    let honest_traces = prepared.traces(&witness).unwrap();
    assert!(setup(
        &prepared,
        prepared.public_values(&statement).unwrap()
    )(honest_traces.clone()));
    let accepts = |forged: &[F], statement: [F; 3]| {
        let mut traces = honest_traces.clone();
        patch_witness_cells(prepared.airs(), &mut traces, &honest, forged);
        let values = prepared.public_values(&statement).unwrap();
        for (trace, public) in traces.iter_mut().zip(&values) {
            if !public.is_empty() {
                for row in trace.values.chunks_mut(trace.width) {
                    row.copy_from_slice(public);
                }
            }
        }
        let failed: Vec<_> = prepared
            .airs()
            .iter()
            .zip(&traces)
            .zip(&values)
            .filter_map(|((air, trace), public)| {
                catch_unwind(AssertUnwindSafe(|| check_constraints(air, trace, public)))
                    .is_err()
                    .then_some(air.width())
            })
            .collect();
        assert_eq!(failed, [5], "only the gate AIR should reject");
        setup(&prepared, values)(traces)
    };

    let two = F::from_raw_coordinates(2).unwrap();
    let non_boolean = [two, addend, two * constant + addend];
    assert!(!accepts(
        &replay(&circuit, &honest, &non_boolean, &[]),
        non_boolean
    ));

    let other_constant = [F::ONE, addend, constant + F::ONE + addend];
    let mut forged = honest.clone();
    forged[circuit.public_rows[2].0 as usize] = other_constant[2];
    assert!(!accepts(&forged, other_constant));
}

#[test]
fn fused_tower_constant_products_refuse_non_boolean_bits_and_other_constants() {
    check_fused_constant_product(tower_accepts);
}

#[test]
fn fused_poly_constant_products_refuse_non_boolean_bits_and_other_constants() {
    check_fused_constant_product(poly64_accepts);
}

fn limb_value<F: BinaryCoordinateField>(limb: u16) -> F {
    F::from_raw_coordinates(limb.into()).unwrap()
}

/// `calls` chained BLAKE3 compressions of one public block: call `i` compresses it from the
/// previous chaining value, the public one for the first call, with counter `i`. The last
/// chaining value is bound to public values. Returns the circuit and its statement.
fn blake3_chain<F: BinaryCoordinateField>(calls: usize) -> (Circuit<F>, Vec<F>) {
    let tail = |call: usize| [call as u32, 0, 64, 0];
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let block = b.alloc_public_input_array::<32>("block");
    let mut cv = b.alloc_public_input_array::<16>("chaining value");
    for call in 0..calls {
        let mut input: Vec<_> = block.iter().chain(&cv).copied().collect();
        for limb in words_to_limbs(&tail(call)) {
            input.push(b.define_const(limb_value(limb)));
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
    for call in 0..calls {
        let mut input = [0; BLAKE3_INPUT_WORDS];
        input[..16].copy_from_slice(&block);
        input[16..24].copy_from_slice(&cv);
        input[24..].copy_from_slice(&tail(call));
        cv = core::array::from_fn(|j| blake3_compress(&input)[j]);
    }
    statement.extend(words_to_limbs(&cv));
    (circuit, statement.into_iter().map(limb_value).collect())
}

/// The inputs and outputs of the native BLAKE3 compressions of a circuit, in call order.
fn blake3_calls<F: Field>(circuit: &Circuit<F>) -> Vec<(Vec<WitnessId>, Vec<WitnessId>)> {
    circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                ..
            } if executor.op_type() == &NpoTypeId::native_blake3_compress() => {
                Some((inputs[0].clone(), outputs[0].clone()))
            }
            _ => None,
        })
        .collect()
}

/// The BLAKE3 table is the last AIR of a native bus circuit.
fn blake3_table<F: BinaryCoordinateField>(prepared: &NativeBusCircuit<F>) -> usize {
    assert_eq!(prepared.packed_table_index(), None);
    prepared.airs().len() - 1
}

/// The column of `cell` in a row of the BLAKE3 table.
fn blake3_column(cell: impl Fn(&Blake3BinaryCols<usize>) -> usize) -> usize {
    let indices: Vec<usize> = (0..NUM_BLAKE3_BINARY_COLS).collect();
    cell(indices.as_slice().borrow())
}

fn witness_values<F: BinaryCoordinateField>(witness: &WitnessTrace<F>) -> Vec<F> {
    witness
        .index
        .iter()
        .map(|&id| *witness.get_value(id).unwrap())
        .collect()
}

#[test]
fn native_blake3_chain_proves_over_tower128() {
    let (circuit, statement) = blake3_chain::<F>(3);
    let prepared = NativeBusCircuit::new(&circuit, "blake3").unwrap();
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
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let proof = prover.prove(&public, traces).unwrap();
    assert!(proof.indexed.is_none());
    assert!(proof.bus.is_some());
    authority.verify_native(&proof, &public).unwrap();
    let mut wrong = public;
    *wrong
        .iter_mut()
        .find(|v| !v.is_empty())
        .unwrap()
        .last_mut()
        .unwrap() += F::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());
}

#[test]
fn native_blake3_chain_proves_over_poly64() {
    use p3_binary_field::Poly64;
    let (circuit, statement) = blake3_chain::<Poly64>(2);
    let prepared = NativeBusCircuit::new(&circuit, "blake3").unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    assert!(poly64_accepts(&prepared, public)(traces));
}

/// 3073 public bytes are four chunks, the last a single byte: forty-nine leaf compressions and
/// three parents. The circuit's digest is the BLAKE3 digest of the bytes. Returns the prepared
/// circuit, its public values and its dense traces.
fn blake3_multi_chunk_bytes() -> (NativeBusCircuit<F>, Vec<Vec<F>>, Vec<RowMajorMatrix<F>>) {
    const BYTES: usize = 3073;
    let message: Vec<u8> = (0..BYTES).map(|i| (i * 31 + 7) as u8).collect();
    let digest = Blake3.hash_iter(message.iter().copied());
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let input = b.alloc_public_inputs(BYTES, "message");
    let expected = b.alloc_public_input_array::<32>("digest");
    let actual = b.native_blake3_bytes(&input).unwrap();
    for (&actual, &expected) in actual.iter().zip(&expected) {
        b.connect(actual, expected);
    }
    let circuit = b.build().unwrap();
    assert_eq!(blake3_calls(&circuit).len(), 52);
    let statement: Vec<_> = message
        .iter()
        .chain(&digest)
        .map(|&byte| F::from_raw_coordinates(byte.into()).unwrap())
        .collect();
    let prepared = NativeBusCircuit::new(&circuit, "bytes").unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    (prepared, public, traces)
}

/// The runner accepts the p3 digest of the multi-chunk message, every table satisfies its local
/// constraints over the circuit's traces, and the traces prove.
#[test]
fn native_blake3_bytes_prove_the_digest_of_a_multi_chunk_message() {
    let (prepared, public, traces) = blake3_multi_chunk_bytes();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }
    assert!(tower_accepts(&prepared, public)(traces));
}

/// The honest run of a circuit with native BLAKE3 calls, against which one wide input limb is
/// forged at a time.
struct Blake3Forgery<'a, F: BinaryCoordinateField> {
    circuit: &'a Circuit<F>,
    prepared: &'a NativeBusCircuit<F>,
    statement: &'a [F],
    public: Vec<Vec<F>>,
    honest: Vec<F>,
    traces: Vec<RowMajorMatrix<F>>,
    calls: Vec<(Vec<WitnessId>, Vec<WitnessId>)>,
    table: usize,
    accepts: Accepts<F>,
}

impl<'a, F: BinaryCoordinateField> Blake3Forgery<'a, F> {
    /// Runs `circuit` honestly and asserts that `accepts` proves its traces.
    fn new(
        circuit: &'a Circuit<F>,
        prepared: &'a NativeBusCircuit<F>,
        statement: &'a [F],
        private: &[F],
        accepts: Accepts<F>,
    ) -> Self {
        let mut runner = circuit.runner();
        runner.set_public_inputs(statement).unwrap();
        runner.set_private_inputs(private).unwrap();
        let witness = runner.run().unwrap().witness_trace;
        let traces = prepared.traces(&witness).unwrap();
        assert!(accepts(traces.clone()), "the honest traces prove");
        Self {
            circuit,
            prepared,
            statement,
            public: prepared.public_values(statement).unwrap(),
            honest: witness_values(&witness),
            traces,
            calls: blake3_calls(circuit),
            table: blake3_table(prepared),
            accepts,
        }
    }

    /// Whether the local constraints of the BLAKE3 table fail on `trace`.
    fn table_fails_locally(&self, trace: &RowMajorMatrix<F>) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            check_constraints(&self.prepared.airs()[self.table], trace, &[]);
        }))
        .is_err()
    }

    /// Forges `forged_private`, whose one changed private input is a limb with a seventeenth
    /// coordinate, and returns the `(call, input)` of the only BLAKE3 input it changes. The
    /// runner refuses the limb. A prover who keeps the `claimed` hint and call outputs satisfies
    /// every fanout and gate row, and the BLAKE3 table, which holds no bridge, cannot carry the
    /// limb in its bits, so the witness bus refuses the traces. Lifting the limb's lowest bit to
    /// carry it balances the bus and leaves a cell outside {0, 1}. `through_gates` is whether
    /// gate rows read the forged value. The limb must be a block input of its call.
    fn reject_wide_limb(
        &self,
        claimed: &[F],
        forged_private: &[F],
        through_gates: bool,
    ) -> (usize, usize) {
        let wide = F::from_raw_coordinates(1 << 16).unwrap();
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(self.statement).unwrap();
        runner.set_private_inputs(forged_private).unwrap();
        assert!(runner.run().is_err(), "the runner refuses a wide limb");

        let forged = replay(self.circuit, claimed, self.statement, forged_private);
        let changed: Vec<_> = self
            .calls
            .iter()
            .enumerate()
            .flat_map(|(c, (inputs, _))| {
                inputs
                    .iter()
                    .enumerate()
                    .filter(|&(_, id)| forged[id.0 as usize] != self.honest[id.0 as usize])
                    .map(move |(i, _)| (c, i))
            })
            .collect();
        let [(call, index)] = changed[..] else {
            panic!("exactly one wide BLAKE3 input limb, got {changed:?}");
        };
        assert!(index < 32, "a block input");
        let mut traces = self.traces.clone();
        let [fanout, gates, bridge] =
            patch_witness_cells(self.prepared.airs(), &mut traces, &self.honest, &forged);
        assert!(fanout > 0 && bridge == 0 && (gates > 0) == through_gates);
        // Only the witness bus can reject this: every table holds locally.
        for ((air, trace), public) in self.prepared.airs().iter().zip(&traces).zip(&self.public) {
            check_constraints(air, trace, public);
        }
        assert!(
            !(self.accepts)(traces.clone()),
            "the table carries a wide limb"
        );

        // The limb's bits are bits `16 * (index % 2)..` of block word `index / 2`.
        let bit = |t: usize| {
            call * NUM_BLAKE3_BINARY_COLS
                + blake3_column(|cols| cols.block[index / 2][16 * (index % 2) + t])
        };
        let packed = (0..16).fold(F::ZERO, |sum, t| {
            sum + traces[self.table].values[bit(t)] * F::from_raw_coordinates(1 << t).unwrap()
        });
        assert_eq!(packed, self.honest[self.calls[call].0[index].0 as usize]);
        traces[self.table].values[bit(0)] += wide;
        assert!(
            self.table_fails_locally(&traces[self.table]),
            "the lifted bit leaves a non-Boolean cell"
        );
        assert!(
            !(self.accepts)(traces),
            "the dense table carries a wide limb"
        );
        (call, index)
    }

    /// A padding row of the table has a bit outside {0, 1}: its constraints refuse it, although
    /// no bus row reads it.
    fn reject_non_boolean_padding_cell(&self) {
        let height = self.traces[self.table].values.len() / NUM_BLAKE3_BINARY_COLS;
        assert!(self.calls.len() < height, "a padding row");
        let mut padded = self.traces.clone();
        let cell = (height - 1) * NUM_BLAKE3_BINARY_COLS + blake3_column(|cols| cols.block[0][0]);
        padded[self.table].values[cell] = F::from_raw_coordinates(1 << 16).unwrap();
        assert!(self.table_fails_locally(&padded[self.table]));
        assert!(!(self.accepts)(padded));
    }
}

/// 520 private limbs are 1040 bytes, two chunks: the sixteen blocks of the first chunk, the one
/// block of the second, whose counter is 1, and their parent are eighteen calls, in that order.
/// `hash` binds the BLAKE3 digest of the limbs' bytes to the 16 public digest words. Limb 5 is
/// input 5 of the first block, limb 262 is input 6 of block 8, in the middle of the first chunk,
/// and limb 515 is input 3 of the last block, the second chunk's.
fn reject_wide_blake3_message_words(
    hash: impl FnOnce(&mut CircuitBuilder<F>, &[ExprId], &[ExprId]),
) {
    const LIMBS: usize = 520;
    let limbs: Vec<u16> = (0..LIMBS as u16)
        .map(|i| i.wrapping_mul(0x9e37) ^ 0x5a5a)
        .collect();
    let bytes: Vec<u8> = limbs.iter().flat_map(|limb| limb.to_le_bytes()).collect();
    let digest = Blake3.hash_iter(bytes.iter().copied());

    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let expected = b.alloc_public_input_array::<16>("digest");
    let message = b.alloc_private_inputs(LIMBS, "message limbs");
    hash(&mut b, &message, &expected);
    let circuit = b.build().unwrap();
    let statement: Vec<F> = bytes_to_limbs(&digest)
        .into_iter()
        .map(limb_value)
        .collect();
    let private: Vec<F> = limbs.iter().map(|&limb| limb_value(limb)).collect();

    let prepared = NativeBusCircuit::new(&circuit, "words").unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let forgery = Blake3Forgery::new(
        &circuit,
        &prepared,
        &statement,
        &private,
        tower_accepts(&prepared, public),
    );
    assert_eq!(forgery.calls.len(), 18, "two chunks and their parent");
    // Input 48 is the low limb of a call's counter.
    let counter = forgery.calls[16].0[48];
    assert_eq!(forgery.honest[counter.0 as usize], limb_value(1));
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    for (limb, at) in [(5, (0, 5)), (262, (8, 6)), (515, (16, 3))] {
        let mut forged_private = private.clone();
        forged_private[limb] += wide;
        let forged = forgery.reject_wide_limb(&forgery.honest, &forged_private, false);
        assert_eq!(forged, at, "limb {limb}");
    }
    forgery.reject_non_boolean_padding_cell();
}

/// The host word hash that absorbs observed transcript words.
#[test]
fn native_blake3_words_range_check_words_in_blocks() {
    reject_wide_blake3_message_words(|b, message, expected| {
        let digest = NativeBinaryEncoding::hash_words(b, ByteHash::Blake3, message).unwrap();
        for (&limb, &expected) in digest.iter().zip(expected) {
            b.connect(limb, expected);
        }
    });
}

/// The subtree gadget that hashes grouped coset leaves: one leaf of a one-row tree, whose
/// digest is the only cap root.
#[test]
fn native_blake3_words_range_check_subtree_leaf_words_in_blocks() {
    reject_wide_blake3_message_words(|b, message, expected| {
        b.verify_byte_hash_mmcs_subtree_words_with_host::<NativeBinaryEncoding>(
            ByteHash::Blake3,
            &[message.to_vec()],
            1,
            &[],
            &[],
            &[expected.to_vec()],
        )
        .unwrap();
    });
}

/// A native WHIR leaf splits each opened value into `count` hinted words bound by
/// `value = sum_j word_j * x_(16j)`, where `x_c` has the single raw coordinate `c`, and hashes
/// them as BLAKE3 block limbs. `split` emits that split and `accepts` proves traces of the
/// prepared circuit. Each forgery `(value, word, moved)` flips coordinate `moved` of a value and
/// adds `x_moved / x_(16 * word)` to that word, which keeps the sum. The quotient has no
/// coordinate below sixteen, so every limb keeps the sixteen low coordinates it hashes and only
/// the table's range check separates the forged opening from the committed one: limb
/// `value * count + word` of the leaf turns wide, the fanout and gate rows accept it, the
/// witness bus does not, and lifting the table's bit instead leaves a cell outside {0, 1}.
fn reject_wide_blake3_leaf_words<F: BinaryCoordinateField>(
    values: &[F],
    count: usize,
    forgeries: &[(usize, usize, usize)],
    split: impl Fn(&mut CircuitBuilder<F>, ExprId, usize) -> Vec<ExprId>,
    setup: impl FnOnce(&NativeBusCircuit<F>, Vec<Vec<F>>) -> Accepts<F>,
) {
    let bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| {
            value
                .to_raw_coordinates()
                .to_le_bytes()
                .into_iter()
                .take(2 * count)
        })
        .collect();
    let root = Blake3.hash_iter(bytes.iter().copied());

    // One leaf of a one-row tree: its digest is the only cap root.
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let cap = b.alloc_public_input_array::<16>("root");
    let row = b.alloc_private_inputs(values.len(), "row values");
    let mut words = Vec::new();
    for &value in &row {
        words.extend(split(&mut b, value, count));
    }
    b.verify_byte_hash_mmcs_opening_words_with_host::<NativeBinaryEncoding>(
        ByteHash::Blake3,
        &[words],
        &[1],
        &[],
        &[],
        &[cap.to_vec()],
    )
    .unwrap();
    let circuit = b.build().unwrap();
    let statement: Vec<F> = bytes_to_limbs(&root).into_iter().map(limb_value).collect();
    let private = values.to_vec();

    let prepared = NativeBusCircuit::new(&circuit, "leaf").unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let accepts = setup(&prepared, public);
    let forgery = Blake3Forgery::new(&circuit, &prepared, &statement, &private, accepts);
    let limbs = values.len() * count;
    assert_eq!(forgery.calls.len(), limbs.div_ceil(32), "hashed blocks");
    let monomial = |coordinate: usize| F::from_raw_coordinates(1 << coordinate).unwrap();
    for &(value, word, moved) in forgeries {
        let wide = monomial(moved) * monomial(16 * word).inverse();
        assert_eq!(wide.to_raw_coordinates() & 0xffff, 0, "limb bits unchanged");
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
        assert_eq!(split.len(), count);
        let mut hinted = forgery.honest.clone();
        hinted[split[word].0 as usize] += wide;
        let mut forged_private = private.clone();
        forged_private[value] += monomial(moved);
        let limb = value * count + word;
        let forged = forgery.reject_wide_limb(&hinted, &forged_private, true);
        assert_eq!(forged, (limb / 32, limb % 32), "value {value} word {word}");
    }
}

/// Sixteen Tower128 values form a 256-byte leaf of eight limbs per value, hashed in four
/// blocks; limb 68 is input 4 of the third.
#[test]
fn native_blake3_words_range_check_word_leaves_in_blocks() {
    let values: Vec<F> = (0..16)
        .map(|i| F::from_repr(0x492f307c9bfa3e514379dc5a1b279591u128.wrapping_mul(i + 13)))
        .collect();
    reject_wide_blake3_leaf_words(
        &values,
        8,
        &[(0, 0, 16), (8, 4, 80), (15, 6, 120)],
        tower_words,
        tower_accepts,
    );
}

/// Sixteen Tower32 base values form a 64-byte leaf of two limbs per value. Moving coordinate 32
/// of a value into its second limb gives a value outside Tower32 with the same leaf bytes, so
/// the table's range check is also what keeps base rows in Tower32.
#[test]
fn native_blake3_words_range_check_tower32_leaf_words() {
    let values: Vec<F> = (0..16)
        .map(|i| F::from_repr(u128::from(0x9bfa3e51u32.wrapping_mul(i + 13))))
        .collect();
    reject_wide_blake3_leaf_words(
        &values,
        2,
        &[(0, 0, 16), (15, 1, 32)],
        tower_words,
        tower_accepts,
    );
}

/// Twenty-four Poly64 values form a 192-byte leaf of four limbs per value, hashed in three
/// blocks. A limb of degree below sixteen times `x^(16j)` needs no reduction, so moving a
/// coefficient at or above `16 * (j + 1)` of a value into its limb `j` keeps the value and the
/// leaf bytes; only the table's range check rejects it.
#[test]
fn native_blake3_words_range_check_poly64_leaf_words_in_blocks() {
    use p3_binary_field::Poly64;
    let values: Vec<Poly64> = (0..24)
        .map(|i| Poly64::new(0x9bfa_3e51_4379_dc5bu64.wrapping_mul(i + 13)))
        .collect();
    reject_wide_blake3_leaf_words(
        &values,
        4,
        &[(0, 0, 16), (16, 2, 48), (17, 0, 16), (18, 1, 40)],
        |b, value, count| b.native_poly64_unchecked_words(value, count).unwrap(),
        poly64_accepts,
    );
}

/// A proof-supplied Merkle sibling reaches the hash only through a level's `select`: under a
/// constant index bit the sibling limb itself is a block input of the compression, and under a
/// private bit the input is a gate output equal to it. A prover who claims the honest digests
/// for a sibling limb with a seventeenth coordinate satisfies every fanout and gate row, but
/// the table cannot carry that limb in bits that stay Boolean.
#[test]
fn native_blake3_words_range_check_merkle_siblings() {
    let leaf_bytes: Vec<[u8; 4]> = (0..4u8)
        .map(|k| [k, 0x80 | k, 0x5a ^ k, 0xff - k])
        .collect();
    let hash = |bytes: &[u8]| Blake3.hash_iter(bytes.iter().copied());
    let compress = |left: &[u8; 32], right: &[u8; 32]| hash(&[*left, *right].concat());
    let leaves: Vec<_> = leaf_bytes.iter().map(|bytes| hash(bytes)).collect();
    let nodes = [
        compress(&leaves[0], &leaves[1]),
        compress(&leaves[2], &leaves[3]),
    ];
    let root = compress(&nodes[0], &nodes[1]);
    let words =
        |bytes: &[u8]| -> Vec<F> { bytes_to_limbs(bytes).into_iter().map(limb_value).collect() };

    // Leaf 1 of four: a constant low index bit, as for a per-symbol leaf of a coset, and a
    // private high bit.
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let leaf = b.alloc_public_input_array::<2>("leaf words");
    let cap = b.alloc_public_input_array::<16>("root");
    let low = b.define_const(F::ONE);
    let high = b.alloc_private_input("high index bit");
    let siblings: Vec<_> = (0..2)
        .map(|_| b.alloc_private_inputs(16, "sibling"))
        .collect();
    b.verify_byte_hash_mmcs_subtree_words_with_host::<NativeBinaryEncoding>(
        ByteHash::Blake3,
        &[leaf.to_vec()],
        4,
        &[low, high],
        &siblings,
        &[cap.to_vec()],
    )
    .unwrap();
    let circuit = b.build().unwrap();
    let statement = [words(&leaf_bytes[1]), words(&root)].concat();
    let private = [vec![F::ZERO], words(&leaves[0]), words(&nodes[1])].concat();

    let prepared = NativeBusCircuit::new(&circuit, "merkle").unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let forgery = Blake3Forgery::new(
        &circuit,
        &prepared,
        &statement,
        &private,
        tower_accepts(&prepared, public),
    );
    assert_eq!(forgery.calls.len(), 3, "one leaf hash and two compressions");
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    // (private input, its call and block input, whether gates read it)
    for (input, at, through_gates) in [(1 + 3, (1, 3), false), (1 + 16 + 5, (2, 16 + 5), true)] {
        let mut forged_private = private.clone();
        forged_private[input] += wide;
        let forged = forgery.reject_wide_limb(&forgery.honest, &forged_private, through_gates);
        assert_eq!(forged, at, "private input {input}");
    }
    forgery.reject_non_boolean_padding_cell();
}

/// A native WHIR verifier gives proof-supplied Merkle siblings no range check of their own.
/// Each level selects its compression inputs from the current digest and the sibling under a
/// Boolean index bit, sampled or a constant stratum bit, so each sibling limb equals a block
/// input of that compression's native BLAKE3 call. In a complete native WHIR verifier, a prover
/// who claims the honest digests for a sibling limb with a seventeenth coordinate satisfies
/// every fanout and gate row, but the witness bus rejects it, and lifting the table's bit
/// instead leaves a cell outside {0, 1}. A padding row, which no bus row reads, is still
/// constrained by the table.
#[test]
fn native_blake3_words_range_check_whir_merkle_siblings() {
    use p3_binary_pcs::whir::BinaryWhirDomain;
    use p3_commit::MultilinearPcs;
    use p3_multilinear_util::point::Point;
    use p3_recursion::BinaryTower128Challenger;
    use p3_recursion::pcs::binary::BinaryWhirVerifier;
    use p3_sumcheck::layout::{Layout, SuffixProver, Table, plan_stacked_layout};
    use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
    use p3_test_utils::binary_field_params::blake3;
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};
    type Ch = blake3::LevelChallenger<F>;
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
    let mmcs = blake3::LevelMmcs::<F>::new(
        blake3::FieldHash::new(blake3::byte_hash()),
        blake3::Compress::new(blake3::byte_hash()),
        CAP_HEIGHT,
    );
    let pcs = WhirProver::<F, F, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
    let recursive = BinaryWhirVerifier::<F>::new(
        &config,
        protocol.clone(),
        L::variable_order(),
        ByteHash::Blake3,
        CAP_HEIGHT,
    )
    .unwrap();
    let shape = recursive.input_shape();
    let make = || Ch::from_hasher(vec![129, 9, 251], blake3::byte_hash());
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
    b.enable_native_blake3_compress().unwrap();
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
        ByteHash::Blake3,
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
    let public = prepared.public_values(&statement).unwrap();
    reject_wide_blake3_whir_siblings(
        &circuit,
        &prepared,
        &statement,
        &private,
        &proof.final_paths[0],
        tower_accepts(&prepared, public),
    );
}

/// The forgeries of [`native_blake3_words_range_check_whir_merkle_siblings`] against the native
/// WHIR verifier `circuit`: `path` is its first final-round query path, and `accepts` proves
/// traces of `prepared` and reports whether the proof verifies.
fn reject_wide_blake3_whir_siblings<F: BinaryCoordinateField>(
    circuit: &Circuit<F>,
    prepared: &NativeBusCircuit<F>,
    statement: &[F],
    private: &[F],
    path: &[Vec<ExprId>],
    accepts: Accepts<F>,
) {
    let forgery = Blake3Forgery::new(circuit, prepared, statement, private, accepts);
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    // The first query's lowest index bit is sampled, so its first sibling reaches the hash
    // through `select` gates. Its next bit is a constant stratum bit, which makes the second
    // sibling itself a block input.
    assert!(path.len() >= 2, "a path through two compressions");
    for (level, word, through_gates) in [(0, 3, true), (1, 5, false)] {
        let id = circuit.expr_to_widx[&path[level][word]];
        let input = circuit
            .private_input_rows
            .iter()
            .position(|&row| row == id)
            .unwrap();
        let mut forged_private = private.to_vec();
        forged_private[input] += wide;
        let (_, index) = forgery.reject_wide_limb(&forgery.honest, &forged_private, through_gates);
        assert!(
            index % 16 == word,
            "a digest limb of the compression's block"
        );
    }
    forgery.reject_non_boolean_padding_cell();
}

/// [`native_blake3_words_range_check_whir_merkle_siblings`] for a Poly64
/// native WHIR verifier, which shares the WHIR kernel and draws Poly192
/// challenges.
#[test]
fn native_blake3_words_range_check_poly64_whir_merkle_siblings() {
    use p3_binary_field::{Poly64, Poly192};
    use p3_binary_pcs::whir::BinaryWhirDomain;
    use p3_commit::MultilinearPcs;
    use p3_multilinear_util::point::Point;
    use p3_recursion::BinaryTower128Challenger;
    use p3_recursion::pcs::binary::BinaryPolyWhirVerifier;
    use p3_sumcheck::layout::{Layout, SuffixProver, Table, plan_stacked_layout};
    use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
    use p3_test_utils::binary_field_params::blake3;
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};
    type P = Poly64;
    type Ch = blake3::LevelChallenger<P>;
    type L = SuffixProver<P, Poly192>;
    const CAP_HEIGHT: usize = 1;
    const VARIABLES: usize = 6;

    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(VARIABLES, 1),
        vec![OpeningBatch::new(vec![0], vec![0])],
    )]);
    let domain = BinaryWhirDomain::<P>::default();
    let config = WhirConfig::<Poly192, P, Ch>::new_with_domain(
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
    let mmcs = blake3::LevelMmcs::<P>::new(
        blake3::FieldHash::new(blake3::byte_hash()),
        blake3::Compress::new(blake3::byte_hash()),
        CAP_HEIGHT,
    );
    let pcs = WhirProver::<Poly192, P, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
    let recursive = BinaryPolyWhirVerifier::new(
        &config,
        protocol.clone(),
        L::variable_order(),
        ByteHash::Blake3,
        CAP_HEIGHT,
    )
    .unwrap();
    let shape = recursive.input_shape();
    let make = || Ch::from_hasher(vec![129, 9, 251], blake3::byte_hash());
    let dense = |i: usize| P::new(0x8123456789abcdefu64.wrapping_mul(i as u64 + 13));
    let table = Table::new(RowMajorMatrix::new(
        (0..1 << VARIABLES).map(dense).collect(),
        1 << VARIABLES,
    ));
    let witness = L::new_witness(vec![table], config.round_folding_factor(0));
    let points = vec![Point::new(
        (0..VARIABLES)
            .map(|j| Poly192::new(core::array::from_fn(|k| dense(3 * j + k + 71))))
            .collect(),
    )];
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

    let mut b = CircuitBuilder::<P>::new();
    b.enable_native_blake3_compress().unwrap();
    let cap: Vec<_> = (0..1 << CAP_HEIGHT)
        .map(|_| b.alloc_public_input_array::<16>("root").to_vec())
        .collect();
    let point: Vec<_> = (0..VARIABLES)
        .map(|_| {
            let coefficients = core::array::from_fn(|_| b.public_input());
            b.native_poly192_from_coefficients(coefficients)
        })
        .collect();
    let proof = shape.allocate_native_targets(&mut b).unwrap();
    let initial =
        [129u8, 9, 251].map(|byte| b.define_const(P::from_raw_coordinates(byte.into()).unwrap()));
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, P>(
        &mut b,
        ByteHash::Blake3,
        &initial,
    )
    .unwrap();
    recursive
        .observe_commitment_with_host::<NativeBinaryEncoding, P>(&mut b, &mut ch, &cap)
        .unwrap();
    recursive
        .verify_at_native(&mut b, ch, &cap, &[point], &proof)
        .unwrap();
    let circuit = b.build().unwrap();
    let statement: Vec<P> = commitment
        .roots()
        .iter()
        .flat_map(|root| bytes_to_limbs(root))
        .map(|word| P::from_raw_coordinates(word.into()).unwrap())
        .chain(points[0].iter().flat_map(|value| value.coefficients()))
        .collect();
    let private = imported.private_native_values(&shape).unwrap();

    let prepared = NativeBusCircuit::new(&circuit, "polywhir").unwrap();
    let public = prepared.public_values(&statement).unwrap();
    reject_wide_blake3_whir_siblings(
        &circuit,
        &prepared,
        &statement,
        &private,
        &proof.final_paths[0],
        poly64_accepts(&prepared, public),
    );
}

/// A prover who claims a different output limb of a call than the table computes is refused:
/// the table pushes the true limb, which no reader of the claimed one matches.
#[test]
fn native_blake3_chain_refuses_a_wrong_output_limb() {
    let (circuit, statement) = blake3_chain::<F>(3);
    let prepared = NativeBusCircuit::new(&circuit, "blake3").unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let accepts = tower_accepts(&prepared, public);
    assert!(accepts(prepared.traces(&witness).unwrap()));
    let calls = blake3_calls(&circuit);
    // The first call's output feeds the second call; the last call's output is the statement.
    for (call, index) in [(0, 3), (2, 0), (2, 15)] {
        let id = calls[call].1[index];
        let mut values = witness_values(&witness);
        values[id.0 as usize] += F::ONE;
        let forged = WitnessTrace::new(values);
        assert!(
            !accepts(prepared.traces(&forged).unwrap()),
            "output {index} of call {call}"
        );
    }
}

/// A prover who regenerates the last call's row from another counter or flags word than its
/// constant inputs hold, and claims the digest that row computes, keeps every constant gate and
/// satisfies every table's local constraints: the row is a true compression, and the witness
/// differs from the honest one only at the claimed outputs. The row pushes its counter and
/// flags limbs under the labels of those constant inputs, which no reader of the constants
/// matches, so the proof is refused.
#[test]
fn native_blake3_rows_bind_their_counter_and_flags_to_the_witness() {
    let (circuit, statement) = blake3_chain::<F>(3);
    let prepared = NativeBusCircuit::new(&circuit, "blake3").unwrap();
    let table = blake3_table(&prepared);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let honest = witness_values(&witness);
    assert!(tower_accepts(
        &prepared,
        prepared.public_values(&statement).unwrap()
    )(prepared.traces(&witness).unwrap()));

    let calls = blake3_calls(&circuit);
    let call = calls.len() - 1;
    let (inputs, outputs) = &calls[call];
    let limbs: Vec<u16> = inputs
        .iter()
        .map(|id| u16::try_from(honest[id.0 as usize].to_raw_coordinates()).unwrap())
        .collect();
    let words: [u32; BLAKE3_INPUT_WORDS] = limbs_to_words(&limbs).try_into().unwrap();
    // Input word 24 is the counter's low word and word 27 the flags.
    for word in [24, 27] {
        let mut forged_words = words;
        forged_words[word] ^= 1;
        let row = generate_binary_trace_rows::<F>(
            vec![Blake3CompressionInput {
                block: core::array::from_fn(|j| forged_words[j]),
                chaining_value: core::array::from_fn(|j| forged_words[16 + j]),
                counter: u64::from(forged_words[24]) | u64::from(forged_words[25]) << 32,
                block_len: forged_words[26],
                flags: forged_words[27],
            }],
            0,
        );
        let digest: Vec<F> = words_to_limbs(&blake3_compress(&forged_words)[..8])
            .into_iter()
            .map(limb_value)
            .collect();
        let mut values = honest.clone();
        for (id, &limb) in outputs.iter().zip(&digest) {
            values[id.0 as usize] = limb;
        }
        let claimed: Vec<F> = statement[..statement.len() - digest.len()]
            .iter()
            .chain(&digest)
            .copied()
            .collect();
        assert_ne!(claimed, statement);

        let public = prepared.public_values(&claimed).unwrap();
        let mut traces = prepared.traces(&WitnessTrace::new(values)).unwrap();
        traces[table].values[call * NUM_BLAKE3_BINARY_COLS..][..NUM_BLAKE3_BINARY_COLS]
            .copy_from_slice(&row.values);
        for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
            check_constraints(air, trace, public);
        }
        assert!(
            !tower_accepts(&prepared, public)(traces),
            "input word {word}"
        );
    }
}

/// The constant inputs of a call are fixed by constant gates. `hash` returns the BLAKE3 digest
/// units of a message of `bits`-wide units, here `prefix_bytes` constant bytes and three public
/// units, and the circuit binds them to public inputs. The message starts its last blocks from
/// precomputed chaining values and fixed counter, length and flags limbs. A prover who runs the
/// circuit with one other constant and claims the digest that follows satisfies every table but
/// that constant's gate, so the proof is refused. Each target is an input limb of a call, here
/// the first nonzero one of `candidates`, read by no other operation.
fn reject_forged_blake3_constants(
    bits: usize,
    hash: impl Fn(&mut CircuitBuilder<F>, &[ExprId]) -> Vec<ExprId>,
    prefix_bytes: usize,
    calls_expected: usize,
    targets: &[(usize, &[usize])],
) {
    let prefix = prefix_bytes * 8 / bits;
    let units: Vec<u16> = (0..prefix as u16 + 3)
        .map(|i| (i.wrapping_mul(0x9e37) ^ 0x5a5a) >> (16 - bits))
        .collect();
    let message: Vec<u8> = units
        .iter()
        .flat_map(|unit| unit.to_le_bytes().into_iter().take(bits / 8))
        .collect();
    // The digest units of sixteen low-first digest limbs.
    let digest = |limbs: &[u16]| -> Vec<u16> {
        if bits == 16 {
            limbs.to_vec()
        } else {
            limbs
                .iter()
                .flat_map(|limb| limb.to_le_bytes())
                .map(u16::from)
                .collect()
        }
    };
    let statement = |digest: &[u16]| -> Vec<F> {
        units[prefix..]
            .iter()
            .chain(digest)
            .map(|&unit| limb_value(unit))
            .collect()
    };
    let build = || {
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_blake3_compress().unwrap();
        let mut input: Vec<_> = units[..prefix]
            .iter()
            .map(|&unit| b.define_const(limb_value(unit)))
            .collect();
        input.extend(b.alloc_public_input_array::<3>("message suffix"));
        for unit in hash(&mut b, &input) {
            let expected = b.public_input();
            b.connect(unit, expected);
        }
        b.build().unwrap()
    };

    let circuit = build();
    let prepared = NativeBusCircuit::new(&circuit, "prefix").unwrap();
    let calls = blake3_calls(&circuit);
    assert_eq!(calls.len(), calls_expected);
    let honest_digest = digest(&bytes_to_limbs(&Blake3.hash_iter(message.iter().copied())));
    let honest = statement(&honest_digest);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&honest).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let accepts = tower_accepts(&prepared, prepared.public_values(&honest).unwrap());
    assert!(accepts(prepared.traces(&witness).unwrap()));

    let reads = |id: WitnessId| -> usize {
        circuit
            .ops
            .iter()
            .map(|op| match op {
                Op::Alu {
                    a,
                    b,
                    c,
                    intermediate_out,
                    ..
                } => [Some(*a), Some(*b), *c, *intermediate_out]
                    .into_iter()
                    .filter(|&read| read == Some(id))
                    .count(),
                Op::Hint { inputs, .. } => inputs.iter().filter(|&&read| read == id).count(),
                Op::NonPrimitiveOpWithExecutor { inputs, .. } => {
                    inputs.iter().flatten().filter(|&&read| read == id).count()
                }
                _ => 0,
            })
            .sum()
    };
    let value = |id: WitnessId| *witness.get_value(id).unwrap();
    let limb_of = |id: WitnessId| u16::try_from(value(id).to_raw_coordinates()).unwrap();
    let gates = prepared
        .airs()
        .iter()
        .position(|air| air.width() == 5)
        .unwrap();

    for &(call, candidates) in targets {
        let index = *candidates
            .iter()
            .find(|&&index| {
                let id = calls[call].0[index];
                limb_of(id) != 0 && reads(id) == 1
            })
            .expect("a constant limb that no other operation reads");
        let id = calls[call].0[index];
        let forged_limb = limb_of(id) ^ 1;

        // The digest that follows from the forged limb through every later call.
        let mut forged_limbs = HashMap::from([(id, forged_limb)]);
        for (inputs, outputs) in &calls {
            let limbs: Vec<u16> = inputs
                .iter()
                .map(|id| {
                    forged_limbs
                        .get(id)
                        .copied()
                        .unwrap_or_else(|| limb_of(*id))
                })
                .collect();
            let words: [u32; BLAKE3_INPUT_WORDS] = limbs_to_words(&limbs).try_into().unwrap();
            let output = words_to_limbs(&blake3_compress(&words)[..8]);
            forged_limbs.extend(outputs.iter().copied().zip(output));
        }
        let claimed_limbs: Vec<u16> = calls
            .last()
            .unwrap()
            .1
            .iter()
            .map(|id| forged_limbs[id])
            .collect();
        let claimed_digest = digest(&claimed_limbs);
        assert_ne!(claimed_digest, honest_digest);
        let claimed = statement(&claimed_digest);

        // The prover runs the same operations with that one constant changed, while
        // `prepared` keeps the circuit's constant gate.
        let mut forged_circuit = build();
        let position = forged_circuit
            .ops
            .iter()
            .position(|op| matches!(*op, Op::Const { out, .. } if out == id))
            .unwrap();
        forged_circuit.ops[position] = Op::Const {
            out: id,
            val: limb_value(forged_limb),
        };
        let mut runner = forged_circuit.runner();
        runner.set_public_inputs(&claimed).unwrap();
        let forged = runner.run().unwrap().witness_trace;

        let public = prepared.public_values(&claimed).unwrap();
        let traces = prepared.traces(&forged).unwrap();
        for (table, ((air, trace), public)) in
            prepared.airs().iter().zip(&traces).zip(&public).enumerate()
        {
            let local = catch_unwind(AssertUnwindSafe(|| check_constraints(air, trace, public)));
            assert_eq!(local.is_err(), table == gates, "table {table}");
        }
        assert!(
            !tower_accepts(&prepared, public)(traces),
            "input {index} of call {call}"
        );
    }
}

/// The second block of a message with a constant first block starts from the precomputed
/// chaining value, and carries the fixed block length and flags of its last block.
#[test]
fn native_product_buses_fix_the_precomputed_chaining_value_of_constant_blake3_words() {
    // Input limbs 32..48 are the chaining value, 52 the block length and 54 the flags.
    reject_forged_blake3_constants(
        16,
        |b, message| b.native_blake3_words(message).unwrap().to_vec(),
        64,
        1,
        &[(0, &(32..48).collect::<Vec<_>>()), (0, &[52]), (0, &[54])],
    );
}

/// A first block of constant bytes, folded pairwise into raw limbs, is compressed while
/// building: the second block starts from its precomputed chaining value, and carries the fixed
/// block length and flags of its last block.
#[test]
fn native_product_buses_fix_the_precomputed_chaining_value_of_constant_blake3_bytes() {
    // Input limbs 32..48 are the chaining value, 52 the block length and 54 the flags.
    reject_forged_blake3_constants(
        8,
        |b, message| b.native_blake3_bytes(message).unwrap().to_vec(),
        64,
        1,
        &[(0, &(32..48).collect::<Vec<_>>()), (0, &[52]), (0, &[54])],
    );
}

/// A constant first chunk is a precomputed child of the parent compression, whose block words
/// 0..16 are its chaining value; the second chunk's single block carries its chunk index.
#[test]
fn native_product_buses_fix_the_precomputed_child_and_counter_of_blake3_chunks() {
    // Input limb 48 is the low counter limb.
    reject_forged_blake3_constants(
        16,
        |b, message| b.native_blake3_words(message).unwrap().to_vec(),
        1024,
        2,
        &[(1, &(0..16).collect::<Vec<_>>()), (0, &[48])],
    );
}
