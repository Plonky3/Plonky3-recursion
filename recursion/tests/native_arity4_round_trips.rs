//! Native children whose WHIR commitments open four-digest Merkle trees, closed by
//! the recursive verifiers native recursion runs: dense Tower128, packed-bit Tower128
//! and Poly64, each with a cap of four roots.

use p3_binary_field::{BinaryField128, Poly64, TowerLevel};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, keccak_state_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit, NativeBusTrace};
use p3_field::Field;
use p3_keccak::KeccakF;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::artifact::{
    BinaryNativeMixedWhirAuthority, BinaryNativeMixedWhirPcsParameters,
    BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters, BinaryNativeVerifierSpec,
    BinaryNativeWhirAuthority, BinaryNativeWhirPcsParameters,
};
use p3_recursion::pcs::binary::MerkleArity;
use p3_recursion::verifier::VerifierLimits;
use p3_sumcheck::layout::Table;
use p3_symmetric::Permutation;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type H = NativeBinaryEncoding;

const HASH: ByteHash = ByteHash::Keccak256;
/// One four-digest level: four cap roots, each selected by two index bits.
const CAP_HEIGHT: usize = 1;

const fn protocol(folding: usize, rate: usize) -> ProtocolParameters {
    ProtocolParameters {
        security_level: 8,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(folding),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: rate,
    }
}

fn limits() -> VerifierLimits {
    VerifierLimits {
        max_rounds: 256,
        max_metadata_entries: 1 << 20,
        ..VerifierLimits::default()
    }
}

fn spec<P>(main: P, preprocessed: Option<P>) -> BinaryNativeVerifierSpec<P> {
    BinaryNativeVerifierSpec {
        main,
        preprocessed,
        transcript_hash: HASH,
        initial_bytes: b"native-arity-four".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 4,
    }
}

fn run<F: Field>(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

/// The verifier circuit accepts the child's statement and witness, and refuses a changed
/// statement value, a changed word of the first or second main cap root, or a changed last
/// witness value.
fn assert_closes<F: Field>(circuit: &Circuit<F>, public: &[F], private: &[F]) {
    assert!(run(circuit, public, private));
    let mut wrong = public.to_vec();
    wrong[1] += F::ONE;
    assert!(!run(circuit, &wrong, private));
    for index in [0, 16, private.len() - 1] {
        let mut wrong = private.to_vec();
        wrong[index] += F::ONE;
        assert!(!run(circuit, public, &wrong));
    }
}

/// The transcript the child's native proof starts from, rebuilt in the verifier circuit.
fn challenger<F>(b: &mut CircuitBuilder<F>, initial_bytes: &[u8]) -> BinaryTower128Challenger
where
    F: Field + Eq + core::hash::Hash,
    H: BinaryCircuitEncoding<F> + p3_circuit::ops::binary_host::BinaryCircuitHost<F>,
{
    let initial: Vec<ExprId> = initial_bytes
        .iter()
        .map(|&byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()))
        .collect();
    BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(b, HASH, &initial).unwrap()
}

/// `a * factor * a + constant` behind a native product bus, with preprocessing.
fn bus_circuit<F: Field + Eq + core::hash::Hash>(constant: F) -> Circuit<F> {
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let expected = b.public_input();
    let private = b.alloc_private_input("factor");
    let product = b.mul(input, private);
    let reused = b.mul(product, input);
    let c = b.define_const(constant);
    let out = b.add(reused, c);
    b.connect(out, expected);
    b.build().unwrap()
}

#[test]
fn dense_tower128_child_of_four_digest_trees_closes_natively() {
    type F = BinaryField128;
    let [a, factor, constant] = [0x8123456789abcdef, 0xfedcba9876543210, 0x8912].map(F::from_repr);
    let circuit = bus_circuit(constant);
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    let parameters = |arity| {
        move |n| {
            BinaryNativeWhirPcsParameters::<F>::with_limits(
                n,
                protocol(1, 2),
                HASH,
                arity,
                CAP_HEIGHT,
                &limits(),
            )
            .unwrap()
        }
    };
    let setup = |arity| {
        BinaryNativeWhirAuthority::<F, _>::setup(
            prepared.airs().to_vec(),
            prepared.log_heights().to_vec(),
            spec(
                parameters(arity)(prepared.main_variables()),
                prepared.preprocessed_variables().map(parameters(arity)),
            ),
            &limits(),
        )
        .unwrap()
    };
    let (prover, authority) = setup(MerkleArity::Four);
    let statement = [a, a * factor * a + constant];
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner.set_private_inputs(&[factor]).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let proof = prover.prove(&public, traces).unwrap();
    assert_eq!(proof.commitment.num_roots(), 4);
    let token = authority.verify_native(&proof, &public).unwrap();

    let verifier = authority.recursive_verifier();
    let shape = verifier.input_shape();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let expected: Vec<Vec<_>> = public
        .iter()
        .map(|values| {
            values
                .iter()
                .map(|_| {
                    let expression = b.public_input();
                    b.native_tower128_from_expr(expression)
                })
                .collect()
        })
        .collect();
    let targets = shape.allocate_native_targets(&mut b).unwrap();
    let ch = challenger(&mut b, authority.initial_bytes());
    verifier
        .verify_native(&mut b, ch, &expected, &targets)
        .unwrap();
    let recursive = b.build().unwrap();
    let private = token.native_input().private_native_values(&shape).unwrap();
    let flat: Vec<_> = public.iter().flatten().copied().collect();
    assert_closes(&recursive, &flat, &private);

    // A pairwise verifier of the same statement is another verifier.
    let (_, pairwise) = setup(MerkleArity::Two);
    assert_ne!(
        pairwise.canonical_verifier_bytes(),
        authority.canonical_verifier_bytes()
    );
    assert!(
        token
            .native_input()
            .private_native_values(&pairwise.recursive_verifier().input_shape())
            .is_err()
    );
}

#[test]
fn poly64_child_of_four_digest_trees_closes_natively() {
    type F = Poly64;
    let [a, factor, constant] = [0x8123456789abcdef, 0xfedcba9876543210, 0x8912].map(F::new);
    let circuit = bus_circuit(constant);
    let prepared = NativeBusCircuit::new(&circuit, "native").unwrap();
    let parameters = |n| {
        BinaryNativePolyWhirPcsParameters::with_limits(
            n,
            protocol(1, 2),
            HASH,
            MerkleArity::Four,
            CAP_HEIGHT,
            &limits(),
        )
        .unwrap()
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(
            parameters(prepared.main_variables()),
            prepared.preprocessed_variables().map(parameters),
        ),
        &limits(),
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
    let proof = prover.prove(&public, traces).unwrap();
    assert_eq!(proof.commitment.num_roots(), 4);
    let token = authority.verify_native(&proof, &public).unwrap();

    let verifier = authority.recursive_verifier();
    let shape = verifier.input_shape();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let expected: Vec<Vec<_>> = public
        .iter()
        .map(|values| values.iter().map(|_| b.public_input()).collect())
        .collect();
    let targets = shape.allocate_native_targets(&mut b).unwrap();
    let ch = challenger(&mut b, authority.initial_bytes());
    verifier
        .verify_native(&mut b, ch, &expected, &targets)
        .unwrap();
    let recursive = b.build().unwrap();
    let private = token.native_input().private_native_values(&shape).unwrap();
    let flat: Vec<_> = public.iter().flatten().copied().collect();
    assert_closes(&recursive, &flat, &private);
}

#[test]
fn packed_tower128_child_of_four_digest_trees_closes_natively() {
    type F = BinaryField128;
    const CALLS: usize = 3;
    const FOLDING: usize = 2;
    /// The row variables one field element of the packed commitment absorbs.
    const ABSORBED_VARIABLES: usize = 7;
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let mut state = builder.alloc_public_input_array::<100>("input").to_vec();
    for _ in 0..CALLS {
        state = builder.add_native_keccak_f1600(&state).unwrap().to_vec();
    }
    let output = builder.alloc_public_input_array::<100>("output");
    for (actual, expected) in state.iter().zip(output) {
        builder.connect(*actual, expected);
    }
    let circuit = builder.build().unwrap();
    let input: [u64; 25] =
        core::array::from_fn(|i| 0x8123456789abcdefu64.rotate_left(3 * i as u32));
    let mut permuted = input;
    for _ in 0..CALLS {
        KeccakF.permute_mut(&mut permuted);
    }
    let statement: Vec<F> = [input, permuted]
        .iter()
        .flat_map(keccak_state_to_limbs)
        .map(|limb| F::from_raw_coordinates(limb as u128).unwrap())
        .collect();

    let prepared = NativeBusCircuit::with_options(
        &circuit,
        "mixed",
        FOLDING,
        DirectCircuitLimits::default(),
        KeccakCommitment::Bits,
    )
    .unwrap();
    let whir = |n, rate| {
        BinaryNativeWhirPcsParameters::<F>::with_limits(
            n,
            ProtocolParameters {
                security_level: 32,
                ..protocol(FOLDING, rate)
            },
            HASH,
            MerkleArity::Four,
            CAP_HEIGHT,
            &limits(),
        )
        .unwrap()
    };
    let bits = prepared.packed_bit_variables().unwrap();
    let (prover, authority) = BinaryNativeMixedWhirAuthority::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        BinaryNativeVerifierSpec {
            security_bits: 16,
            ..spec(
                BinaryNativeMixedWhirPcsParameters::with_packed_table(
                    whir(prepared.main_variables(), 1),
                    whir(bits - ABSORBED_VARIABLES, 1),
                    prepared.keccak_table_index().unwrap(),
                    bits,
                )
                .unwrap(),
                prepared
                    .preprocessed_variables()
                    .map(|n| BinaryNativeMixedWhirPcsParameters::dense(whir(n, 1))),
            )
        },
        &limits(),
    )
    .unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let tables = prepared
        .trace_tables(&witness)
        .unwrap()
        .into_iter()
        .map(|trace| match trace {
            NativeBusTrace::Dense(matrix) => Table::new(matrix.transpose()),
            NativeBusTrace::PackedBits { words, log_height } => {
                Table::from_packed_bits(words, log_height)
            }
        })
        .collect();
    let proof = prover.prove_tables(&public, tables).unwrap();
    // Four dense roots, then four packed roots.
    assert_eq!(proof.commitment.num_roots(), 8);
    let token = authority.verify_native(&proof, &public).unwrap();

    let verifier = authority.recursive_verifier();
    let shape = verifier.input_shape();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let expected: Vec<Vec<_>> = public
        .iter()
        .map(|values| {
            values
                .iter()
                .map(|_| {
                    let expression = b.public_input();
                    b.native_tower128_from_expr(expression)
                })
                .collect()
        })
        .collect();
    let targets = shape.allocate_native_targets(&mut b).unwrap();
    let ch = challenger(&mut b, authority.initial_bytes());
    verifier
        .verify_native(&mut b, ch, &expected, &targets)
        .unwrap();
    let recursive = b.build().unwrap();
    let private = token.native_input().private_native_values(&shape).unwrap();
    let flat: Vec<_> = public.iter().flatten().copied().collect();
    assert_closes(&recursive, &flat, &private);
}
