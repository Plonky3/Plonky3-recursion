//! A packed-bit Keccak table committed over `Poly64` values with `Poly192` challenges.
//!
//! The table is the bus circuit's own packed output, opened at its current and next row.

use alloc::vec;
use alloc::vec::Vec;

use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirError, BooleanWhirPcs};
use p3_binary_pcs::{BooleanTraceCommitment, BooleanTraceCommitmentError};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::keccak_state_to_limbs;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit, NativeBusTrace};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_keccak_air::NUM_KECCAK_BINARY_COLS;
use p3_multilinear_util::point::Point;
use p3_sumcheck::layout::SuffixProver;
use p3_sumcheck::ring_switch::bits::{BitRingSwitchProofError, SuccessorTensors};
use p3_sumcheck::{
    OpeningBatch, OpeningEvals, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec,
};
use p3_symmetric::Permutation;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirProver};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use super::*;

type F = Poly64;
type E = Poly192;
type Challenger = BinaryNativeChallenger<F>;
type Backend = BooleanWhirPcs<F, E, BinaryWhirDomain<F>, NativeMmcs<F>, Challenger>;
type PackedPcs = BooleanTraceCommitment<E, Backend>;
type Proof = <PackedPcs as MultilinearPcs<E, Challenger>>::Proof;

const HASH: ByteHash = ByteHash::Keccak256;
const CAP_HEIGHT: usize = 1;
const FOLDING: usize = 2;
/// The row variables one `Poly64` element of the packed commitment absorbs.
const ABSORBED_VARIABLES: usize = 6;
const COLUMN_VARIABLES: usize = 11;

/// A chain of `calls` Keccak-f permutations from a public input state to a public output state.
fn keccak_chain(calls: usize) -> (Circuit<F>, Vec<F>) {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let mut state = builder.alloc_public_input_array::<100>("input").to_vec();
    for _ in 0..calls {
        state = builder.add_native_keccak_f1600(&state).unwrap().to_vec();
    }
    let expected = builder.alloc_public_input_array::<100>("output");
    for (actual, expected) in state.iter().zip(expected) {
        builder.connect(*actual, expected);
    }
    let mut lanes: [u64; 25] =
        core::array::from_fn(|i| 0x8123456789abcdefu64.rotate_left(5 * i as u32) ^ i as u64);
    let limbs = |lanes: &[u64; 25]| -> Vec<F> {
        keccak_state_to_limbs(lanes)
            .into_iter()
            .map(|word| F::from_raw_coordinates(u128::from(word)).unwrap())
            .collect()
    };
    let mut public = limbs(&lanes);
    for _ in 0..calls {
        KeccakF.permute_mut(&mut lanes);
    }
    public.extend(limbs(&lanes));
    (builder.build().unwrap(), public)
}

/// The bus circuit's packed Keccak words and the table's row variables.
struct Packed {
    words: Vec<u64>,
    log_height: usize,
    table: Table<F>,
}

fn packed_keccak(calls: usize) -> Packed {
    let (circuit, public) = keccak_chain(calls);
    let bus = NativeBusCircuit::with_options(
        &circuit,
        "poly-packed",
        1,
        DirectCircuitLimits::default(),
        KeccakCommitment::Bits,
    )
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let keccak = bus.keccak_table_index().unwrap();
    let trace = bus.trace_tables(&witness).unwrap().swap_remove(keccak);
    let NativeBusTrace::PackedBits { words, log_height } = trace else {
        panic!("the Keccak table is not packed");
    };
    assert_eq!(
        bus.packed_bit_variables(),
        Some(COLUMN_VARIABLES + log_height)
    );
    Packed {
        words: words.values.clone(),
        log_height,
        table: Table::from_packed_bits(words, log_height),
    }
}

fn challenger() -> Challenger {
    BinaryNativeChallenger::fresh(vec![5, 0, 9], HASH)
}

fn parameters() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 32,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(FOLDING),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}

fn backend(bit_variables: usize) -> Backend {
    let whir = BinaryNativePolyWhirPcsParameters::new(
        bit_variables - ABSORBED_VARIABLES,
        parameters(),
        HASH,
        CAP_HEIGHT,
    )
    .unwrap();
    let prover = WhirProver::<E, F, _, _, _, SuffixProver<F, E>>::new(
        whir.config,
        BinaryWhirDomain::<F>::default(),
        tree(HASH, CAP_HEIGHT),
    );
    BooleanWhirPcs::new(prover, bit_variables).unwrap()
}

fn pcs(bit_variables: usize) -> PackedPcs {
    BooleanTraceCommitment::from_commitment(backend(bit_variables))
}

fn protocol(log_height: usize) -> OpeningProtocol {
    let columns = (0..NUM_KECCAK_BINARY_COLS).collect::<Vec<_>>();
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(log_height, NUM_KECCAK_BINARY_COLS),
        vec![OpeningBatch::new(columns.clone(), columns)],
    )])
}

fn point(log_height: usize, seed: u64) -> Point<E> {
    let mut rng = SmallRng::seed_from_u64(seed);
    Point::new((0..log_height).map(|_| rng.random()).collect())
}

/// The equality weight of every row at `point`. Row bit `i` is the `i`-th point coordinate from
/// the last.
fn row_weights(point: &Point<E>) -> Vec<E> {
    point
        .as_slice()
        .iter()
        .rev()
        .fold(vec![E::ONE], |weights, &x| {
            // The rows below take the new bit clear, the rows above take it set.
            let clear = weights.iter().map(|&weight| weight * (E::ONE + x));
            let set = weights.iter().map(|&weight| weight * x);
            clear.chain(set).collect()
        })
}

/// Multilinear evaluation of the bit column `column`, `shift` rows ahead, under the row weights
/// of a point; the last row reads itself.
fn column_value(packed: &Packed, weights: &[E], column: usize, shift: usize) -> E {
    let height = weights.len();
    (0..height)
        .filter(|&row| {
            let source = (row + shift).min(height - 1);
            (packed.words[(source / 64) * NUM_KECCAK_BINARY_COLS + column] >> (source % 64)) & 1
                == 1
        })
        .fold(E::ZERO, |sum, row| sum + weights[row])
}

fn open(
    pcs: &PackedPcs,
    packed: &Packed,
) -> (MerkleCap<F, [u8; 32]>, Point<E>, OpeningProtocol, Proof) {
    let protocol = protocol(packed.log_height);
    let point = point(packed.log_height, 17);
    let (cap, data) = pcs
        .commit(vec![packed.table.clone()], &mut challenger())
        .unwrap();
    let mut prover = challenger();
    pcs.observe_commitment(&cap, &mut prover);
    let proof = pcs
        .open_at(data, &protocol, core::slice::from_ref(&point), &mut prover)
        .unwrap();
    (cap, point, protocol, proof)
}

/// Two calls fill exactly one element's rows, so the next row is read inside that element and the
/// reduction sends no carry or last; more calls outrun it and send both.
#[test]
fn poly_packed_keccak_opens_and_verifies() {
    for calls in [2, 3, 6] {
        let packed = packed_keccak(calls);
        let bits = COLUMN_VARIABLES + packed.log_height;
        let pcs = pcs(bits);
        let (cap, point, protocol, proof) = open(&pcs, &packed);
        assert_eq!(
            proof.opening.reduction.claims[0].successor.is_some(),
            packed.log_height > ABSORBED_VARIABLES,
            "{calls} calls"
        );
        if calls == 2 {
            assert_eq!(packed.log_height, ABSORBED_VARIABLES);
        }

        let mut verifier = challenger();
        pcs.observe_commitment(&cap, &mut verifier);
        let evals = pcs
            .verify_at(
                &cap,
                &proof,
                &protocol,
                core::slice::from_ref(&point),
                &mut verifier,
            )
            .unwrap();
        assert_eq!(evals.len(), 1);
        let (current, next) = (evals[0].current(), evals[0].next());
        assert_eq!(
            (current.len(), next.len()),
            (NUM_KECCAK_BINARY_COLS, NUM_KECCAK_BINARY_COLS)
        );
        let weights = row_weights(&point);
        for column in 0..NUM_KECCAK_BINARY_COLS {
            assert_eq!(
                current[column],
                column_value(&packed, &weights, column, 0),
                "column {column}"
            );
            assert_eq!(
                next[column],
                column_value(&packed, &weights, column, 1),
                "column {column}"
            );
        }
    }
}

/// Security terms are reported for the complete batch with its successor view: the base
/// opening, the bit ring-switch tensors and the column batch.
#[test]
fn poly_packed_security_terms_are_reported() {
    let packed = packed_keccak(3);
    let bits = COLUMN_VARIABLES + packed.log_height;
    let pcs = pcs(bits);
    let security = pcs
        .prescribed_security(&protocol(packed.log_height))
        .unwrap();
    // One claim draws no lambda, so there is no claim-batching term.
    assert_eq!(
        security
            .terms
            .iter()
            .map(|term| term.label)
            .collect::<Vec<_>>(),
        ["whir-opening", "bit-ring-switch", "column-batching"]
    );
    assert!(security.candidates().is_some());

    // The one reduction sends its tensor with carry and last.
    let backend = backend(bits);
    let readings = backend.readings_security(1, true).unwrap();
    assert_eq!(security.terms[..2], readings.terms[..]);
    assert_ne!(
        readings.terms,
        backend.readings_security(1, false).unwrap().terms
    );
    // Eight batching coordinates, alpha of degree two, and two per surviving variable, over the
    // 192 bits of a challenge and charged over every candidate.
    let surviving = bits - ABSORBED_VARIABLES;
    let ring_switch =
        192.0 - ((8 + 2 + 2 * surviving) as f64).log2() - security.log2_max_candidates;
    assert!(
        (security.terms[1].bits.bits() - ring_switch).abs() < 1e-9,
        "{:?} against {ring_switch}",
        security.terms[1]
    );

    // A protocol the scheme would refuse gets no assessment.
    assert!(
        pcs.prescribed_security(&protocol(packed.log_height + 1))
            .is_none()
    );
    // A protocol of incomplete batches takes the per-column route and is still assessed.
    let partial = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(packed.log_height, NUM_KECCAK_BINARY_COLS),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    assert!(pcs.prescribed_security(&partial).is_some());
}

/// A table of one element's rows reads its next row inside that element, so its reduction is
/// charged for the tensor alone.
#[test]
fn one_element_poly_packed_table_is_charged_no_successor_tensors() {
    let bits = COLUMN_VARIABLES + ABSORBED_VARIABLES;
    let security = pcs(bits)
        .prescribed_security(&protocol(ABSORBED_VARIABLES))
        .unwrap();
    assert_eq!(
        security.terms[..2],
        backend(bits).readings_security(1, false).unwrap().terms[..]
    );
}

/// Each forgery is absorbed before the draws after it, so a rejection follows a diverged
/// transcript as well as the check it names; only the prover-side test below isolates a binding.
#[test]
fn tampered_poly_packed_proofs_are_rejected() {
    let packed = packed_keccak(3);
    let bits = COLUMN_VARIABLES + packed.log_height;
    let pcs = pcs(bits);
    let (cap, point, protocol, proof) = open(&pcs, &packed);
    let bytes = postcard::to_allocvec(&proof).unwrap();
    let verify = |cap: &MerkleCap<F, [u8; 32]>, point: &Point<E>, proof: &Proof| {
        let mut verifier = challenger();
        pcs.observe_commitment(cap, &mut verifier);
        pcs.verify_at(
            cap,
            proof,
            &protocol,
            core::slice::from_ref(point),
            &mut verifier,
        )
        .map(|_| ())
    };
    verify(&cap, &point, &proof).unwrap();
    // The ring-switch reduction's verdict; it refuses every forgery below before the proximity
    // opening runs.
    let reduction = |cap: &MerkleCap<F, [u8; 32]>, point: &Point<E>, proof: &Proof| {
        let error = verify(cap, point, proof).unwrap_err();
        match error {
            BooleanTraceCommitmentError::Boolean(BooleanWhirError::ReductionProof(error)) => error,
            other => panic!("{other:?}"),
        }
    };
    let decoded = || -> Proof { postcard::from_bytes(&bytes).unwrap() };
    let tampered = |tamper: &dyn Fn(&mut Proof)| {
        let mut proof = decoded();
        tamper(&mut proof);
        reduction(&cap, &point, &proof)
    };
    // Bit 63 is the last of the element's 64 rows, the one row of `last` the successor reading
    // weighs.
    let last_row = F::from_raw_coordinates(1 << 63).unwrap();

    assert_eq!(
        tampered(&|proof| proof.values[0] += E::ONE),
        BitRingSwitchProofError::ClaimMismatch
    );
    // The next values are absorbed before the column point, so the current reading moves too.
    assert_eq!(
        tampered(&|proof| *proof.values.last_mut().unwrap() += E::ONE),
        BitRingSwitchProofError::ClaimMismatch
    );
    assert_eq!(
        tampered(&|proof| {
            proof.opening.reduction.claims[0]
                .tensor
                .add_exterior_product(E::ONE, F::ONE);
        }),
        BitRingSwitchProofError::ClaimMismatch
    );
    assert_eq!(
        tampered(&|proof| successor(proof).carry.add_exterior_product(E::ONE, F::ONE)),
        BitRingSwitchProofError::SuccessorClaimMismatch
    );
    assert_eq!(
        tampered(&|proof| successor(proof).last.add_exterior_product(E::ONE, last_row)),
        BitRingSwitchProofError::SuccessorClaimMismatch
    );
    // The rows of `last` the successor reading skips are bound by the sumcheck instead.
    assert_eq!(
        tampered(&|proof| successor(proof).last.add_exterior_product(E::ONE, F::ONE)),
        BitRingSwitchProofError::FinalCheck
    );

    let mut roots = cap.roots().to_vec();
    roots.reverse();
    assert_eq!(
        reduction(&MerkleCap::new(roots), &point, &decoded()),
        BitRingSwitchProofError::ClaimMismatch
    );

    let mut coordinates = point.as_slice().to_vec();
    coordinates[0] += E::ONE;
    assert_eq!(
        reduction(&cap, &Point::new(coordinates), &decoded()),
        BitRingSwitchProofError::ClaimMismatch
    );
}

/// The carry and last tensors of the one reduction.
fn successor(proof: &mut Proof) -> &mut SuccessorTensors<F, E> {
    proof.opening.reduction.claims[0]
        .successor
        .as_mut()
        .unwrap()
}

/// The multi-STARK prover supplies the zerocheck's values of the batch. The opening binds them
/// to the committed bits, so an honest value leaves the proof as an evaluating opening makes
/// it and a wrong one is refused.
#[test]
fn supplied_poly_packed_values_are_bound_by_the_opening() {
    let packed = packed_keccak(3);
    let bits = COLUMN_VARIABLES + packed.log_height;
    let pcs = pcs(bits);
    let protocol = protocol(packed.log_height);
    let point = point(packed.log_height, 23);
    let (_, data) = pcs.commit(vec![packed.table], &mut challenger()).unwrap();
    let points = core::slice::from_ref(&point);
    let evaluated = pcs
        .open_at(data.clone(), &protocol, points, &mut challenger())
        .unwrap();
    let (current, next) = evaluated.values.split_at(NUM_KECCAK_BINARY_COLS);
    let supplied =
        |current: &[E], next: &[E]| vec![Some(OpeningEvals::new(current.to_vec(), next.to_vec()))];

    let bound = pcs
        .open_at_known(
            data.clone(),
            &protocol,
            points,
            &supplied(current, next),
            &mut challenger(),
        )
        .unwrap();
    assert_eq!(
        postcard::to_allocvec(&bound).unwrap(),
        postcard::to_allocvec(&evaluated).unwrap()
    );

    let mut wrong = current.to_vec();
    wrong[0] += E::ONE;
    assert!(matches!(
        pcs.open_at_known(
            data.clone(),
            &protocol,
            points,
            &supplied(&wrong, next),
            &mut challenger()
        ),
        Err(BooleanTraceCommitmentError::ColumnBatchValueMismatch { .. })
    ));

    let mut wrong = next.to_vec();
    *wrong.last_mut().unwrap() += E::ONE;
    assert!(matches!(
        pcs.open_at_known(
            data,
            &protocol,
            points,
            &supplied(current, &wrong),
            &mut challenger()
        ),
        Err(BooleanTraceCommitmentError::ColumnBatchValueMismatch { .. })
    ));
}
