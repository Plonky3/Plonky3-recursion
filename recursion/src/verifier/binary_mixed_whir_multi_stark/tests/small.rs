//! Small dense and Boolean tables, with the Boolean table between two dense ones so the split
//! and the merge must keep protocol order.

use core::ops::Range;

use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use super::*;
use crate::pcs::binary::NativeBooleanWhirTraceProofTargets;

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
const ABSORBED_VARIABLES: usize = 7;

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

/// The positions of `needle` within `haystack[range]`.
fn occurrences<T: PartialEq>(haystack: &[T], needle: &[T], range: Range<usize>) -> Vec<usize> {
    range
        .filter(|&i| haystack[i..].starts_with(needle))
        .collect()
}

/// A named change to a circuit's private inputs.
type WitnessTamper<'a, T> = (&'static str, &'a dyn Fn(&mut Vec<T>));

/// One proof's honest import with the continued challenge both circuits pin, and its imports
/// with a tampered Merkle sibling, once the import has refused every other tamper class.
struct Imports {
    verifier: BinaryMixedWhirMultiStarkVerifier,
    honest: NativeBinaryMixedWhirMultiStarkInput,
    continued: F,
    siblings: Vec<NativeBinaryMixedWhirMultiStarkInput>,
}

impl Imports {
    fn new(mixed: &Mixed) -> Self {
        let verifier = mixed.verifier();
        let (honest, continued) = mixed.honest_import(&verifier);
        let siblings = mixed.assert_tampers_refused_by_import(&verifier);
        Self {
            verifier,
            honest,
            continued,
            siblings,
        }
    }
}

/// The honest witness satisfies `H`'s circuit, and each tamper class, applied to the one
/// witness it names, makes witness generation fail.
fn assert_circuit_accepts_and_refuses_tampers<H: Host>(mixed: &Mixed, imports: &Imports) {
    let shape = imports.verifier.input_shape();
    let private = private_inputs::<H>(&imports.honest, &shape, imports.continued);
    let circuit = H::circuit(&imports.verifier);
    let public = mixed.public_values::<H>();
    assert!(
        accepts(&circuit, &private, &public),
        "the {} circuit refused the honest witness",
        H::NAME
    );

    let (dense, packed) = opening_offsets::<H>(&imports.honest, &shape);
    let mut proof = mixed.proof_copy();
    // Tensor rows can repeat; a row whose value occurs once names its witness alone.
    let tensor_row = packed_opening(&mut proof).opening.reduction.claims[0]
        .tensor
        .rows()
        .iter()
        .find_map(|&row| {
            match occurrences(&private, &H::encode(row), packed..private.len()).as_slice() {
                &[position] => Some(position),
                _ => None,
            }
        })
        .unwrap();
    // A Merkle sibling enters the transcript nowhere, so the continuation is unchanged.
    let [dense_sibling, packed_sibling] = [0, 1].map(|i| {
        let mut values = H::witnesses(&imports.siblings[i], &shape);
        values.extend_from_slice(&private[values.len()..]);
        values
    });
    // Each sibling tamper changes only the witnesses of the opening it names.
    assert_eq!(dense_sibling[..dense], private[..dense]);
    assert_eq!(dense_sibling[packed..], private[packed..]);
    assert_eq!(packed_sibling[..packed], private[..packed]);
    let roots = 16 << CAP_HEIGHT;
    let tampers: [WitnessTamper<'_, H::CF>; 6] = [
        // Each opening's witnesses start with its opened values.
        ("packed opened value", &|private| {
            H::flip(&mut private[packed]);
        }),
        ("dense opened value", &|private| {
            H::flip(&mut private[dense]);
        }),
        ("ring-switch tensor row", &|private| {
            H::flip(&mut private[tensor_row]);
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
            "the {} circuit accepted a tampered {name}",
            H::NAME
        );
    }
}

#[test]
fn small_mixed_proof_imports_and_refuses_tampers() {
    Imports::new(&small_proof());
}

/// The prime and the native verifier agree on one proof: each circuit accepts the honest
/// import with the multi-stark verifier's continuation and refuses every tamper class.
#[test]
fn minimal_mixed_proof_satisfies_both_circuits_and_refuses_tampers() {
    let mixed = minimal_proof();
    let imports = Imports::new(&mixed);
    assert_circuit_accepts_and_refuses_tampers::<Prime>(&mixed, &imports);
    assert_circuit_accepts_and_refuses_tampers::<Native>(&mixed, &imports);
}

/// The preprocessing opening follows the packed one in the transcript, which the circuit's
/// continuation pins: a circuit verifying them in the other order refuses the honest witness.
#[test]
fn preprocessing_after_the_packed_opening_satisfies_the_prime_circuit() {
    let mixed = minimal_proof_with(TestAir::Dense, ABSORBED_VARIABLES);
    assert!(mixed.proof.preprocessed_opening.is_some());
    let verifier = mixed.verifier();
    let (_, private) = mixed.honest_private_values::<Prime>(&verifier);
    let circuit = prime_circuit(&verifier);
    assert!(accepts(&circuit, &private, &mixed.public_values::<Prime>()));
}

/// The only prime-circuit test of the packed opening's successor route. The successor's carry
/// and last tensors nearly double a prime circuit: the minimal relation read one row ahead
/// grows from 24.1M to 42.3M operations. This one has 46.5M: 11.4 to 12.5 GB and about 250 s
/// in a debug build, and a 21.5 GB footprint with the circuit diagnostics of an all-features
/// build, above hosted runner memory.
#[test]
#[ignore = "builds a prime-field mixed verifier with successor tensors: about 12 GB in debug, 21.5 GB with circuit diagnostics; run explicitly"]
fn small_mixed_proof_satisfies_the_prime_circuit_and_refuses_tampers() {
    let mixed = small_proof();
    assert_circuit_accepts_and_refuses_tampers::<Prime>(&mixed, &Imports::new(&mixed));
}

/// The successor route with its carry and last tensors, preprocessing, and the Boolean table
/// between two dense ones, in the native circuit.
#[test]
fn small_mixed_proof_satisfies_the_native_circuit_and_refuses_tampers() {
    let mixed = small_proof();
    assert_circuit_accepts_and_refuses_tampers::<Native>(&mixed, &Imports::new(&mixed));
}

/// The native verifier checks the packed opening's target shapes with the dense opening's,
/// before the transcript: refusing a malformed packed opening builds no more nodes than
/// refusing a malformed dense one.
#[test]
fn native_verifier_refuses_a_malformed_packed_opening_before_the_transcript() {
    let airs = [
        TestAir::Square,
        TestAir::Bits { next: vec![] },
        TestAir::Square,
    ];
    let heights = [SQUARE_VARIABLES, BIT_VARIABLES, SQUARE_VARIABLES];
    let parameters = Parameters::new(&airs, &heights, Some(BITS));
    let verifier = parameters
        .verifier(&airs, &heights, BITS, parameters.preprocessed_cap(&airs))
        .unwrap();
    let shape = verifier.input_shape();
    type Targets = BinaryMixedWhirMultiStarkProofTargets<
        NativeTower128Target,
        NativeBooleanWhirTraceProofTargets,
    >;
    let refusal = |malform: &dyn Fn(&mut Targets)| {
        let (mut b, public) = native_builder(shape.public_value_counts());
        let mut targets = shape.allocate_native_targets(&mut b).unwrap();
        malform(&mut targets);
        let ch = native_challenger(&mut b);
        let before = b.construction_usage().unwrap().expression_nodes;
        let Err(VerificationError::InvalidProofShape(message)) =
            verifier.verify_native(&mut b, ch, &public, &targets)
        else {
            panic!("the native verifier did not refuse malformed targets by their shape");
        };
        let nodes = b.construction_usage().unwrap().expression_nodes - before;
        (message, nodes)
    };
    let (dense, dense_nodes) = refusal(&|targets| {
        targets.dense.final_poly.pop();
    });
    let (packed, packed_nodes) = refusal(&|targets| {
        targets.packed.values.pop();
    });
    assert_eq!(dense, "binary WHIR target opening or proof shape mismatch");
    assert_eq!(packed, "binary trace row point or value count mismatch");
    assert_eq!(packed_nodes, dense_nodes);
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
