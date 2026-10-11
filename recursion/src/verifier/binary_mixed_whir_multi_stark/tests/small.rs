//! Small dense and Boolean tables, with the Boolean table between two dense ones so the split
//! and the merge must keep protocol order.

use core::ops::Range;

use p3_field::PrimeField64;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use super::*;

/// Above the seven row variables a field element absorbs, so the ring switch of a table read
/// one row ahead also sends the successor's carry and last tensors.
const BIT_VARIABLES: usize = 8;
const BITS: usize = 1;

fn dense_rows(first: F, second: F) -> Table<F> {
    let rows = 1 << DENSE_VARIABLES;
    let (mut a, mut b) = (vec![first], vec![second]);
    for (row, w) in weights().into_iter().enumerate().take(rows - 1) {
        a.push(b[row]);
        b.push(a[row] * b[row] + w);
    }
    Table::new(RowMajorMatrix::new([a, b].concat(), rows))
}

fn square_rows(first: F, log_height: usize) -> Table<F> {
    let mut rng = SmallRng::seed_from_u64(5);
    let a: Vec<F> = core::iter::once(first)
        .chain((1..1 << log_height).map(|_| rng.random()))
        .collect();
    let b = a.iter().map(|&a| a * a + F::ONE).collect::<Vec<_>>();
    Table::new(RowMajorMatrix::new([a, b].concat(), 1 << log_height))
}

/// Rows of the Boolean table, with a fresh random bit entering column 3 on every row.
fn bit_rows(log_height: usize) -> Table<F> {
    let mut rng = SmallRng::seed_from_u64(7);
    let mut row: Vec<bool> = (0..BIT_WIDTH).map(|_| rng.random()).collect();
    let mut cells = Vec::with_capacity(BIT_WIDTH << log_height);
    for _ in 0..1 << log_height {
        row[2] = row[0] & row[1];
        cells.extend(row.iter().map(|&bit| F::from_bool(bit)));
        let mut next = row.clone();
        next[0] = row[1];
        next[1] = row[0] | row[1];
        next[3] = rng.random();
        next[4..].copy_from_slice(&row[3..BIT_WIDTH - 1]);
        row = next;
    }
    Table::new(RowMajorMatrix::new(cells, BIT_WIDTH).transpose())
}

fn small_airs(next: Vec<usize>) -> Vec<TestAir> {
    vec![TestAir::Dense, TestAir::Bits { next }, TestAir::Dense]
}

/// Dense recurrences with a preprocessed column around a Boolean table read one row ahead.
fn small_proof() -> Mixed {
    let public = vec![
        vec![F::ONE, F::ONE + F::ONE + F::ONE],
        vec![],
        vec![F::ZERO, F::ONE],
    ];
    let tables = vec![
        dense_rows(public[0][0], public[0][1]),
        bit_rows(BIT_VARIABLES),
        dense_rows(public[2][0], public[2][1]),
    ];
    Mixed::prove(
        small_airs((0..BIT_WIDTH).collect()),
        vec![DENSE_VARIABLES, BIT_VARIABLES, DENSE_VARIABLES],
        public,
        BITS,
        tables,
    )
}

const SQUARE_VARIABLES: usize = FOLDING;
/// The row variables one field element absorbs.
const BOOLEAN_VARIABLES: usize = 7;

/// A first dense table, a Boolean table of `bit_variables` row variables read at one row only,
/// so the ring switch sends one tensor, and a square table. Only a [`TestAir::Dense`] first
/// table brings preprocessing.
fn minimal_proof_with(first: TestAir, bit_variables: usize) -> Mixed {
    let (first_public, first_rows, first_variables) = match first {
        TestAir::Square => {
            let public = vec![F::ONE + F::ONE];
            let rows = square_rows(public[0], SQUARE_VARIABLES);
            (public, rows, SQUARE_VARIABLES)
        }
        TestAir::Dense => {
            let public = vec![F::ONE, F::ONE + F::ONE + F::ONE];
            let rows = dense_rows(public[0], public[1]);
            (public, rows, DENSE_VARIABLES)
        }
        TestAir::Bus(_) | TestAir::Bits { .. } => unreachable!("the first table is dense"),
    };
    let public = vec![first_public, vec![], vec![F::ZERO]];
    let tables = vec![
        first_rows,
        bit_rows(bit_variables),
        square_rows(public[2][0], SQUARE_VARIABLES),
    ];
    Mixed::prove(
        vec![first, TestAir::Bits { next: vec![] }, TestAir::Square],
        vec![first_variables, bit_variables, SQUARE_VARIABLES],
        public,
        BITS,
        tables,
    )
}

/// The smallest mixed relation whose openings both send Merkle siblings, without
/// preprocessing. With fewer row variables the queries open every leaf of the packed
/// codeword's tree.
fn minimal_proof() -> Mixed {
    minimal_proof_with(TestAir::Square, BIT_VARIABLES)
}

/// Offsets of the dense and the packed opening's witnesses within the private inputs.
fn opening_offsets(
    input: &NativeBinaryMixedWhirMultiStarkInput,
    shape: &BinaryMixedWhirMultiStarkInputShape,
) -> (usize, usize) {
    assert!(input.bus.is_none() && input.indexed.is_none());
    let commitment = (2 << CAP_HEIGHT) * 16;
    let sumcheck = input
        .sumcheck
        .private_values::<BabyBear>(&shape.relation.sumcheck)
        .unwrap()
        .len();
    let dense = commitment + sumcheck;
    let packed = dense
        + input
            .dense
            .private_values::<BabyBear>(&shape.dense)
            .unwrap()
            .len();
    (dense, packed)
}

/// The positions of `needle` within `haystack[range]`.
fn occurrences(haystack: &[BabyBear], needle: &[BabyBear], range: Range<usize>) -> Vec<usize> {
    range
        .filter(|&i| haystack[i..].starts_with(needle))
        .collect()
}

/// A named change to the prime circuit's private inputs.
type WitnessTamper<'a> = (&'static str, &'a dyn Fn(&mut Vec<BabyBear>));

fn flip(value: &mut BabyBear) {
    *value = BabyBear::from_u64(value.as_canonical_u64() ^ 1);
}

/// The honest witness satisfies the prime circuit, and each tamper class, applied to the one
/// witness it names, makes witness generation fail.
fn assert_prime_circuit_accepts_and_refuses_tampers(mixed: &Mixed) {
    let verifier = mixed.verifier();
    let shape = verifier.input_shape();
    let (input, private) = mixed.honest_private_values(&verifier);
    let siblings = mixed.assert_tampers_refused_by_import(&verifier);

    let circuit = prime_circuit(&verifier);
    let public = mixed.public_limbs();
    assert!(accepts(&circuit, &private, &public));

    let (dense, packed) = opening_offsets(&input, &shape);
    let mut proof = mixed.proof_copy();
    // Tensor rows can repeat; a row whose value occurs once names its witness alone.
    let tensor_row = packed_opening(&mut proof).opening.reduction.claims[0]
        .tensor
        .rows()
        .iter()
        .find_map(|&row| {
            let row: Vec<_> = limbs(row).collect();
            match occurrences(&private, &row, packed..private.len()).as_slice() {
                &[position] => Some(position),
                _ => None,
            }
        })
        .unwrap();
    // A Merkle sibling enters the transcript nowhere, so the continuation is unchanged.
    let [dense_sibling, packed_sibling] = [0, 1].map(|i| {
        let mut values = siblings[i].private_values::<BabyBear>(&shape).unwrap();
        values.extend_from_slice(&private[private.len() - 8..]);
        values
    });
    // Each sibling tamper changes only the witnesses of the opening it names.
    assert_eq!(dense_sibling[..dense], private[..dense]);
    assert_eq!(dense_sibling[packed..], private[packed..]);
    assert_eq!(packed_sibling[..packed], private[..packed]);
    let roots = 16 << CAP_HEIGHT;
    let tampers: [WitnessTamper<'_>; 6] = [
        // Each opening's witnesses start with its opened values.
        ("packed opened value", &|private| flip(&mut private[packed])),
        ("dense opened value", &|private| flip(&mut private[dense])),
        ("ring-switch tensor row", &|private| {
            flip(&mut private[tensor_row]);
        }),
        ("cap with swapped halves", &|private| {
            private[..2 * roots].rotate_left(roots);
        }),
        ("dense WHIR Merkle sibling", &|private| {
            private.clone_from(&dense_sibling);
        }),
        ("packed WHIR Merkle sibling", &|private| {
            private.clone_from(&packed_sibling);
        }),
    ];
    for (name, tamper) in tampers {
        let mut tampered = private.clone();
        tamper(&mut tampered);
        assert_ne!(tampered, private);
        assert!(
            !accepts(&circuit, &tampered, &public),
            "the prime circuit accepted a tampered {name}"
        );
    }
}

#[test]
fn small_mixed_proof_imports_and_refuses_tampers() {
    let mixed = small_proof();
    let verifier = mixed.verifier();
    mixed.honest_private_values(&verifier);
    mixed.assert_tampers_refused_by_import(&verifier);
}

#[test]
fn minimal_mixed_proof_satisfies_the_prime_circuit_and_refuses_tampers() {
    assert_prime_circuit_accepts_and_refuses_tampers(&minimal_proof());
}

/// The preprocessing opening follows the packed one in the transcript, which the circuit's
/// continuation pins: a circuit verifying them in the other order refuses the honest witness.
#[test]
fn preprocessing_after_the_packed_opening_satisfies_the_prime_circuit() {
    let mixed = minimal_proof_with(TestAir::Dense, BOOLEAN_VARIABLES);
    assert!(mixed.proof.preprocessed_opening.is_some());
    let verifier = mixed.verifier();
    let (_, private) = mixed.honest_private_values(&verifier);
    let circuit = prime_circuit(&verifier);
    assert!(accepts(&circuit, &private, &mixed.public_limbs()));
}

/// The only prime-circuit test of the packed opening's successor route. The successor's carry
/// and last tensors nearly double a prime circuit: the minimal relation read one row ahead
/// grows from 24.1M to 42.3M operations. This one has 46.5M: 11.4 to 12.5 GB and about 250 s
/// in a debug build, and a 21.5 GB footprint with the circuit diagnostics of an all-features
/// build, above hosted runner memory.
#[test]
#[ignore = "builds a prime-field mixed verifier with successor tensors: about 12 GB in debug, 21.5 GB with circuit diagnostics; run explicitly"]
fn small_mixed_proof_satisfies_the_prime_circuit_and_refuses_tampers() {
    assert_prime_circuit_accepts_and_refuses_tampers(&small_proof());
}

#[test]
fn bit_committed_table_must_open_one_complete_batch() {
    let mixed = small_proof();
    for (next, complete) in [
        ((0..BIT_WIDTH).collect(), true),
        (vec![], true),
        (vec![0, 1], false),
    ] {
        let verifier = mixed.parameters.verifier(
            &small_airs(next),
            &mixed.heights,
            BITS,
            mixed.preprocessed_cap.clone(),
        );
        if complete {
            verifier.unwrap();
        } else {
            assert!(matches!(
                verifier,
                Err(VerificationError::InvalidProofShape(message))
                    if message == "binary mixed WHIR MultiStark packed table is not opened as one complete batch"
            ));
        }
    }
}

#[test]
fn identity_binds_the_bit_committed_table() {
    let mixed = small_proof();
    let identity = |shape: &BinaryMixedWhirMultiStarkInputShape| {
        let mut w = crate::artifact::wire::Writer::new(1 << 24);
        shape.write_identity(&mut w).unwrap();
        w.finish().unwrap()
    };
    let shape = mixed.verifier().input_shape();
    assert_eq!(identity(&shape), identity(&mixed.verifier().input_shape()));
    let mut moved = shape.clone();
    moved.packed_table = 0;
    assert_ne!(identity(&shape), identity(&moved));
}
