//! Native Poly64 bit-tensor readings and the Frobenius closing weight, checked
//! against the released bit ring switch over Poly64 values and Poly192
//! challenges.

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::ops::NativePoly192Target;
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError, CircuitConstructionLimits, ExprId};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_recursion::pcs::binary::{
    NativePolyBitTensorTarget, closing_weight_native_poly, poly64_trace_dual_basis,
};
use p3_sumcheck::ring_switch::bits::{BitRingSwitch, BitTensor, SuccessorTensors};

type F = Poly64;
type E = Poly192;
type Switch = BitRingSwitch<F, E>;
type Tensor = BitTensor<E, F>;

/// Coordinates one packed Poly64 element absorbs, indexing a column.
const ABSORBED: usize = 6;
/// Coordinates the batching point names, indexing a row.
const BATCHED: usize = 8;
/// Rows of a sent tensor, one per Poly192 coordinate.
const ROWS: usize = 192;
/// Columns of a sent tensor, one per Poly64 coordinate.
const COLUMNS: usize = 64;
/// The native Poly64 recursion's packed Keccak claim: 28 bit variables, 17 of
/// them rows, so 22 high coordinates of which 11 are kept rows.
const FIXED_HIGH: usize = 22;
const FIXED_KEPT: usize = 11;

/// Deterministic SplitMix64 stream of full-width field elements.
struct Sampler(u64);

impl Sampler {
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    const fn base(&mut self) -> F {
        F::new(self.next_u64())
    }

    fn bases(&mut self, count: usize) -> Vec<F> {
        (0..count).map(|_| self.base()).collect()
    }

    const fn ext(&mut self) -> E {
        E::new([self.base(), self.base(), self.base()])
    }

    fn exts(&mut self, count: usize) -> Vec<E> {
        (0..count).map(|_| self.ext()).collect()
    }
}

/// A native circuit under construction with its witness values. Private
/// inputs are allocated in call order, three Poly64 limbs per Poly192 value.
struct Native {
    b: CircuitBuilder<F>,
    public: Vec<F>,
    private: Vec<F>,
}

impl Native {
    fn new() -> Self {
        Self {
            b: CircuitBuilder::new(),
            public: Vec::new(),
            private: Vec::new(),
        }
    }

    /// A builder that rejects more than `nodes` expression nodes at its
    /// construction checkpoints, and limits nothing else.
    fn with_node_budget(nodes: usize) -> Self {
        let limits = CircuitConstructionLimits {
            max_expression_nodes: nodes,
            max_pending_connects: usize::MAX,
            max_non_primitive_calls: usize::MAX,
            max_non_primitive_slots: usize::MAX,
        };
        Self {
            b: CircuitBuilder::with_construction_limits(limits).unwrap(),
            public: Vec::new(),
            private: Vec::new(),
        }
    }

    fn base(&mut self, value: F) -> ExprId {
        self.private.push(value);
        self.b.alloc_private_input("native poly tensor test input")
    }

    fn ext(&mut self, value: E) -> NativePoly192Target {
        let limbs = value.coefficients().map(|limb| self.base(limb));
        self.b.native_poly192_from_coefficients(limbs)
    }

    fn exts(&mut self, values: &[E]) -> Vec<NativePoly192Target> {
        values.iter().map(|&value| self.ext(value)).collect()
    }

    fn tensor(&mut self, rows: &[F]) -> NativePolyBitTensorTarget {
        let rows = rows.iter().map(|&row| self.base(row)).collect();
        NativePolyBitTensorTarget::from_rows(rows).unwrap()
    }

    /// Constrains `actual` to the public value `expected`, limb by limb.
    fn expect(&mut self, actual: &NativePoly192Target, expected: E) {
        for (&actual, limb) in actual.coefficients().iter().zip(expected.coefficients()) {
            self.public.push(limb);
            let expected = self.b.public_input();
            let difference = self.b.sub(actual, expected);
            self.b.assert_zero(difference);
        }
    }

    fn nodes(&self) -> usize {
        self.b.construction_usage().unwrap().expression_nodes
    }

    fn connects(&self) -> usize {
        self.b.construction_usage().unwrap().pending_connects
    }

    fn build(self) -> (Circuit<F>, Vec<F>, Vec<F>) {
        (self.b.build().unwrap(), self.public, self.private)
    }
}

fn accepts(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

/// Every public limb is bound: changing any one of them is refused.
fn assert_bound(circuit: &Circuit<F>, public: &[F], private: &[F], indices: &[usize]) {
    assert!(accepts(circuit, public, private));
    for &index in indices {
        let mut wrong = public.to_vec();
        wrong[index] += F::ONE;
        assert!(!accepts(circuit, &wrong, private), "public limb {index}");
    }
}

const fn basis(v: usize) -> F {
    F::new(1 << v)
}

/// The absolute trace to `F_2`, by the definition `sum_m x^(2^m)`.
fn trace(x: F) -> F {
    let mut power = x;
    let mut sum = x;
    for _ in 1..64 {
        power = power.square();
        sum += power;
    }
    sum
}

fn tensor(rows: &[F]) -> Tensor {
    Tensor::try_from(rows.to_vec()).unwrap()
}

/// The released reduction's row reading of `tensor` at `batch`, which is its
/// starting sum without successor tensors.
fn released_rows(point: &Point<E>, batch: &[E], tensor: &Tensor) -> E {
    Switch::new(point)
        .unwrap()
        .batch(&Point::new(batch.to_vec()))
        .unwrap()
        .initial_sum(tensor, None)
}

/// The released verifier's closing weight for a claim at `high || low` whose
/// sumcheck survived at `survivor`. `successor` is `(kept_row_variables,
/// alpha)` for a successor view that sends carry and last tensors.
fn released_closing_weight(
    high: &[E],
    low: &[E],
    survivor: &[E],
    batch: &[E],
    successor: Option<(usize, E)>,
) -> E {
    let point = Point::new([high, low].concat());
    let batch = Point::new(batch.to_vec());
    let survivor = Point::new(survivor.to_vec());
    match successor {
        None => Switch::new(&point)
            .unwrap()
            .batch(&batch)
            .unwrap()
            .closing_weight(&survivor)
            .unwrap(),
        Some((kept, alpha)) => {
            let reduction = Switch::with_successor(&point, kept + ABSORBED).unwrap();
            assert!(reduction.sends_successor_tensors());
            reduction
                .batch_with_successor(&batch, alpha)
                .unwrap()
                .closing_weight(&survivor)
                .unwrap()
        }
    }
}

/// The released reduction runs over Poly64 values and Poly192 challenges with
/// six absorbed and eight batched coordinates, and 192 x 64 tensors.
#[test]
fn released_reduction_absorbs_six_and_batches_eight() {
    assert_eq!(Switch::ABSORBED, ABSORBED);
    assert_eq!(Switch::BATCHED, BATCHED);
    assert_eq!(Tensor::DIMENSION, ROWS);
    assert_eq!(tensor(&[F::ONE; ROWS]).columns().len(), COLUMNS);
}

#[test]
fn trace_dual_basis_reads_raw_coordinates() {
    let dual = poly64_trace_dual_basis();
    assert_eq!(dual.len(), COLUMNS);
    for (u, &delta) in dual.iter().enumerate() {
        for w in 0..COLUMNS {
            assert_eq!(
                trace(delta * basis(w)),
                F::from_bool(u == w),
                "Tr(delta_{u} * x^{w})"
            );
        }
    }
    let mut sampler = Sampler(0xd0a1);
    for x in sampler.bases(4) {
        for (u, &delta) in dual.iter().enumerate() {
            assert_eq!(trace(delta * x), F::from_bool(x.to_bits() >> u & 1 == 1));
        }
    }
}

/// Every reading of one tensor, its columns, and the carry and last columns
/// the successor claim reads, each bound to the released value. The batched
/// rows of all three tensors also combine into the released starting sum.
#[test]
fn readings_match_released_bit_ring_switch_claims() {
    let mut sampler = Sampler(0x7e45);
    for row_variables in [ABSORBED + 1, ABSORBED + 3] {
        let rows = sampler.bases(ROWS);
        let carry = sampler.bases(ROWS);
        let last = sampler.bases(ROWS);
        let high = sampler.exts(3);
        let low = sampler.exts(ABSORBED);
        let batch = sampler.exts(BATCHED);
        let alpha = sampler.ext();
        let successor = SuccessorTensors {
            carry: tensor(&carry),
            last: tensor(&last),
        };
        let current = tensor(&rows);
        let point = Point::new([high.as_slice(), &low].concat());
        let column_reading = Switch::new(&point).unwrap().incoming_claim(&current);
        let reduction = Switch::with_successor(&point, row_variables).unwrap();
        assert!(reduction.sends_successor_tensors());
        let successor_claim = reduction
            .successor_claim(&current, Some(&successor))
            .unwrap();
        let starting_sum = reduction
            .batch_with_successor(&Point::new(batch.clone()), alpha)
            .unwrap()
            .initial_sum(&current, Some(&successor));

        let mut n = Native::new();
        let mut tensor_t = n.tensor(&rows);
        let mut carry_t = n.tensor(&carry);
        let mut last_t = n.tensor(&last);
        let low_t = n.exts(&low);
        let batch_t = n.exts(&batch);
        let alpha_t = n.ext(alpha);
        let readings = [&tensor_t, &carry_t, &last_t].map(|t| t.evaluate_rows(&mut n.b, &batch_t));
        let [rows_t, carry_rows, last_rows] = readings.map(Result::unwrap);
        for (actual, element) in [
            (&rows_t, &current),
            (&carry_rows, &successor.carry),
            (&last_rows, &successor.last),
        ] {
            n.expect(actual, released_rows(&point, &batch, element));
        }
        let scaled = n.b.native_poly192_mul(&alpha_t, &last_rows);
        let inner = n.b.native_poly192_add(&carry_rows, &scaled);
        let outer = n.b.native_poly192_mul(&alpha_t, &inner);
        let sum = n.b.native_poly192_add(&rows_t, &outer);
        n.expect(&sum, starting_sum);
        let actual = tensor_t.evaluate_columns(&mut n.b, &low_t).unwrap();
        n.expect(&actual, column_reading);
        let actual = tensor_t
            .successor_reading(&mut n.b, &low_t, &mut carry_t, &mut last_t)
            .unwrap();
        n.expect(&actual, successor_claim);
        for v in [0, 1, 32, 63] {
            let actual = tensor_t.column(&mut n.b, v).unwrap();
            n.expect(&actual, current.column(v));
        }
        let actual = carry_t.column(&mut n.b, 0).unwrap();
        n.expect(&actual, successor.carry.column(0));
        let actual = last_t.column(&mut n.b, COLUMNS - 1).unwrap();
        n.expect(&actual, successor.last.column(COLUMNS - 1));
        // Trace columns of undecomposed tensors, one tensor per column, and of
        // the decomposed current tensor.
        for v in [0, 1, 32, 63] {
            let mut fresh = n.tensor(&rows);
            let actual = fresh.trace_column(&mut n.b, v).unwrap();
            n.expect(&actual, current.column(v));
            let actual = tensor_t.trace_column(&mut n.b, v).unwrap();
            n.expect(&actual, current.column(v));
        }
        let (circuit, public, private) = n.build();
        let every: Vec<usize> = (0..public.len()).collect();
        assert_bound(&circuit, &public, &private, &every);
    }
}

/// Batching indices 192 to 255 name no row. A batching point whose first two
/// coordinates are one weighs only those indices, so the row reading and the
/// closing weight are zero, as in the released reduction; one and zero select
/// the third limb's rows alone.
#[test]
fn padded_batching_indices_weigh_nothing() {
    let mut sampler = Sampler(0x9add);
    let rows = sampler.bases(ROWS);
    let current = tensor(&rows);
    let high = sampler.exts(4);
    let low = sampler.exts(ABSORBED);
    let survivor = sampler.exts(4);
    let alpha = sampler.ext();
    let point = Point::new([high.as_slice(), &low].concat());
    for leading in [[E::ONE, E::ONE], [E::ONE, E::ZERO]] {
        let batch = [leading.as_slice(), &sampler.exts(BATCHED - 2)].concat();
        let reading = released_rows(&point, &batch, &current);
        let weights = [None, Some((2, alpha))]
            .map(|successor| released_closing_weight(&high, &low, &survivor, &batch, successor));
        let padded = leading == [E::ONE, E::ONE];
        assert_eq!(reading == E::ZERO, padded);
        assert_eq!(weights.map(|weight| weight == E::ZERO), [padded; 2]);

        let mut n = Native::new();
        let tensor_t = n.tensor(&rows);
        let high_t = n.exts(&high);
        let survivor_t = n.exts(&survivor);
        let batch_t = n.exts(&batch);
        let alpha_t = n.ext(alpha);
        let actual = tensor_t.evaluate_rows(&mut n.b, &batch_t).unwrap();
        n.expect(&actual, reading);
        for (successor, expected) in [None, Some(2)].into_iter().zip(weights) {
            let actual = closing_weight_native_poly(
                &mut n.b,
                &high_t,
                &survivor_t,
                &batch_t,
                successor.map(|kept| (kept, &alpha_t)),
            )
            .unwrap();
            n.expect(&actual, expected);
        }
        let (circuit, public, private) = n.build();
        let every: Vec<usize> = (0..public.len()).collect();
        assert_bound(&circuit, &public, &private, &every);
    }
}

type Tamper = (usize, F);

#[derive(Clone, Copy, Debug)]
enum Reading {
    Rows,
    Columns,
    Successor,
}

/// Each reading alone rejects a tensor row changed in a coordinate it reads.
#[test]
fn tampered_rows_fail_the_bound_readings() {
    let mut sampler = Sampler(0x7a3e);
    let rows = sampler.bases(ROWS);
    let carry = sampler.bases(ROWS);
    let last = sampler.bases(ROWS);
    let low = sampler.exts(ABSORBED);
    let batch = sampler.exts(BATCHED);
    let current = tensor(&rows);
    let successor = SuccessorTensors {
        carry: tensor(&carry),
        last: tensor(&last),
    };
    let point = Point::new([sampler.exts(2).as_slice(), &low].concat());
    let successor_claim = Switch::with_successor(&point, ABSORBED + 2)
        .unwrap()
        .successor_claim(&current, Some(&successor))
        .unwrap();
    // Private inputs are the rows, then the carry rows, the last rows and the
    // point limbs. A tamper adds one coordinate basis vector to one row.
    let (row, high_limb_row, carry_row, last_row) = (37, 150, ROWS + 90, 2 * ROWS + 5);
    let readings: [(Reading, E, &[Tamper]); 3] = [
        (
            Reading::Rows,
            released_rows(&point, &batch, &current),
            &[(row, basis(17)), (high_limb_row, basis(0))],
        ),
        (
            Reading::Columns,
            Switch::new(&point).unwrap().incoming_claim(&current),
            &[(row, basis(0)), (high_limb_row, basis(63))],
        ),
        (
            Reading::Successor,
            successor_claim,
            &[
                (row, basis(1)),
                (high_limb_row, basis(63)),
                (carry_row, basis(0)),
                (last_row, basis(63)),
                (ROWS + 191, basis(0)),
                (2 * ROWS + 130, basis(63)),
            ],
        ),
    ];
    for (reading, expected, tampers) in readings {
        let mut n = Native::new();
        let mut tensor_t = n.tensor(&rows);
        let mut carry_t = n.tensor(&carry);
        let mut last_t = n.tensor(&last);
        let actual = match reading {
            Reading::Rows => {
                let batch_t = n.exts(&batch);
                tensor_t.evaluate_rows(&mut n.b, &batch_t)
            }
            Reading::Columns => {
                let low_t = n.exts(&low);
                tensor_t.evaluate_columns(&mut n.b, &low_t)
            }
            Reading::Successor => {
                let low_t = n.exts(&low);
                tensor_t.successor_reading(&mut n.b, &low_t, &mut carry_t, &mut last_t)
            }
        }
        .unwrap();
        n.expect(&actual, expected);
        let (circuit, public, private) = n.build();
        assert!(accepts(&circuit, &public, &private), "{reading:?}");
        for &(index, flip) in tampers {
            let mut tampered = private.clone();
            tampered[index] += flip;
            assert!(
                !accepts(&circuit, &public, &tampered),
                "{reading:?}: input {index} flipped by {flip:?}"
            );
        }
    }
}

/// Every high length up to four, without a successor and with every kept row
/// count, against the released closing weight.
#[test]
fn closing_weight_matches_released_weight() {
    let mut sampler = Sampler(0xc105);
    for len in 0..=4 {
        let high = sampler.exts(len);
        let low = sampler.exts(ABSORBED);
        let survivor = sampler.exts(len);
        let batch = sampler.exts(BATCHED);
        let alpha = sampler.ext();
        let mut n = Native::new();
        let high_t = n.exts(&high);
        let survivor_t = n.exts(&survivor);
        let batch_t = n.exts(&batch);
        let alpha_t = n.ext(alpha);
        for successor in core::iter::once(None).chain((1..=len).map(Some)) {
            let expected = released_closing_weight(
                &high,
                &low,
                &survivor,
                &batch,
                successor.map(|kept| (kept, alpha)),
            );
            let actual = closing_weight_native_poly(
                &mut n.b,
                &high_t,
                &survivor_t,
                &batch_t,
                successor.map(|kept| (kept, &alpha_t)),
            )
            .unwrap();
            n.expect(&actual, expected);
        }
        let (circuit, public, private) = n.build();
        let every: Vec<usize> = (0..public.len()).collect();
        assert_bound(&circuit, &public, &private, &every);
    }
}

/// The recursion fixed point, 22 high coordinates, without a successor and
/// with 11 or all 22 kept row coordinates.
#[test]
fn closing_weight_matches_released_weight_at_the_fixed_point() {
    let mut sampler = Sampler(0xf1e7);
    let high = sampler.exts(FIXED_HIGH);
    let low = sampler.exts(ABSORBED);
    let survivor = sampler.exts(FIXED_HIGH);
    let batch = sampler.exts(BATCHED);
    let alpha = sampler.ext();
    let mut n = Native::new();
    let high_t = n.exts(&high);
    let survivor_t = n.exts(&survivor);
    let batch_t = n.exts(&batch);
    let alpha_t = n.ext(alpha);
    for successor in [None, Some(FIXED_KEPT), Some(FIXED_HIGH)] {
        let expected = released_closing_weight(
            &high,
            &low,
            &survivor,
            &batch,
            successor.map(|kept| (kept, alpha)),
        );
        let actual = closing_weight_native_poly(
            &mut n.b,
            &high_t,
            &survivor_t,
            &batch_t,
            successor.map(|kept| (kept, &alpha_t)),
        )
        .unwrap();
        n.expect(&actual, expected);
    }
    let (circuit, public, private) = n.build();
    let every: Vec<usize> = (0..public.len()).collect();
    assert_bound(&circuit, &public, &private, &every);
}

/// The closing weight reads every input: a changed high, survivor, batching
/// or alpha limb changes it, so the honest value is refused.
#[test]
fn closing_weight_refuses_changed_inputs() {
    let (len, kept) = (5, 3);
    let mut sampler = Sampler(0x7a3f);
    let high = sampler.exts(len);
    let low = sampler.exts(ABSORBED);
    let survivor = sampler.exts(len);
    let batch = sampler.exts(BATCHED);
    let alpha = sampler.ext();
    let expected = released_closing_weight(&high, &low, &survivor, &batch, Some((kept, alpha)));
    let mut n = Native::new();
    let high_t = n.exts(&high);
    let survivor_t = n.exts(&survivor);
    let batch_t = n.exts(&batch);
    let alpha_t = n.ext(alpha);
    let actual = closing_weight_native_poly(
        &mut n.b,
        &high_t,
        &survivor_t,
        &batch_t,
        Some((kept, &alpha_t)),
    )
    .unwrap();
    n.expect(&actual, expected);
    let (circuit, public, private) = n.build();
    assert!(accepts(&circuit, &public, &private));
    // Limb offsets: high, then survivor, then batch, then alpha.
    let limb = |value: usize, limb: usize| 3 * value + limb;
    let (survivor_at, batch_at, alpha_at) = (len, 2 * len, 2 * len + BATCHED);
    let changed = [
        limb(0, 0),
        limb(len - 1, 2),
        limb(len - kept, 1),
        limb(survivor_at, 0),
        limb(survivor_at + len - 1, 1),
        limb(batch_at, 0),
        limb(batch_at + 1, 2),
        limb(batch_at + BATCHED - 1, 1),
        limb(alpha_at, 0),
    ];
    for index in changed {
        let mut tampered = private.clone();
        tampered[index] += F::ONE;
        assert!(
            !accepts(&circuit, &public, &tampered),
            "private limb {index}"
        );
    }
}

/// Node counts at the native recursion fixed point: 22 high coordinates, 11
/// kept row variables. Bounds are 1.2 times the measured counts.
///
/// Column readings are sound only because every row's bits are checked: each
/// bit is connected to its Boolean check and the row to its recomposition. A
/// tensor's first column therefore adds at least 65 connections per row. The
/// carry and last tensors are read in one column each by the trace, field
/// arithmetic on the rows with no hinted bit, so they add no connection, and
/// the two of them cost less than one checked column of a fresh tensor.
#[test]
fn node_counts_at_the_native_fixed_point() {
    const CHECKED_ROW_CONNECTS: usize = COLUMNS + 1;
    let mut sampler = Sampler(0x40de);
    let mut n = Native::new();
    let mut tensor = n.tensor(&sampler.bases(ROWS));
    let mut carry = n.tensor(&sampler.bases(ROWS));
    let mut last = n.tensor(&sampler.bases(ROWS));
    let low = n.exts(&sampler.exts(ABSORBED));
    let high = n.exts(&sampler.exts(FIXED_HIGH));
    let survivor = n.exts(&sampler.exts(FIXED_HIGH));
    let batch = n.exts(&sampler.exts(BATCHED));
    let alpha = n.ext(sampler.ext());
    let mut fresh = n.tensor(&sampler.bases(ROWS));

    let (start, start_connects) = (n.nodes(), n.connects());
    tensor.evaluate_columns(&mut n.b, &low).unwrap();
    let columns_and_current = n.nodes() - start;
    let column_connects = n.connects() - start_connects;
    let (start, start_connects) = (n.nodes(), n.connects());
    carry.trace_column(&mut n.b, 0).unwrap();
    last.trace_column(&mut n.b, COLUMNS - 1).unwrap();
    let carry_and_last = n.nodes() - start;
    let carry_and_last_connects = n.connects() - start_connects;
    let start = n.nodes();
    fresh.column(&mut n.b, 0).unwrap();
    let checked_column = n.nodes() - start;
    let start = n.nodes();
    tensor
        .successor_reading(&mut n.b, &low, &mut carry, &mut last)
        .unwrap();
    let successor = n.nodes() - start;
    let start = n.nodes();
    tensor.evaluate_rows(&mut n.b, &batch).unwrap();
    let first_rows = n.nodes() - start;
    let start = n.nodes();
    carry.evaluate_rows(&mut n.b, &batch).unwrap();
    last.evaluate_rows(&mut n.b, &batch).unwrap();
    let shared_rows = n.nodes() - start;
    let start = n.nodes();
    closing_weight_native_poly(
        &mut n.b,
        &high,
        &survivor,
        &batch,
        Some((FIXED_KEPT, &alpha)),
    )
    .unwrap();
    let closing = n.nodes() - start;
    println!(
        "native poly tensor nodes: columns + current reading {columns_and_current}, \
         successor reading {successor}, carry and last columns {carry_and_last}, \
         one checked column {checked_column}, \
         first row reading {first_rows}, two more row readings {shared_rows}, \
         closing weight (high {FIXED_HIGH}, kept {FIXED_KEPT}) {closing}; connections: \
         columns {column_connects}, carry and last columns {carry_and_last_connects}"
    );
    assert!(columns_and_current <= 60_193);
    assert!(successor <= 1_137);
    assert!(carry_and_last <= 29_947);
    assert!(first_rows <= 1_725);
    assert!(shared_rows <= 1_464);
    assert!(closing <= 126_322);
    // The later readings reuse the batching point's equality tables.
    assert!(shared_rows < first_rows);
    assert!(column_connects >= ROWS * CHECKED_ROW_CONNECTS);
    assert_eq!(carry_and_last_connects, 0);
    assert!(carry_and_last < checked_column);
}

#[test]
fn malformed_shapes_return_errors() {
    let mut n = Native::new();
    let zero = n.base(F::ZERO);
    let ext_zero = n.ext(E::ZERO);
    assert!(NativePolyBitTensorTarget::from_rows(vec![zero; ROWS - 1]).is_err());
    assert!(NativePolyBitTensorTarget::from_rows(vec![zero; ROWS + 64]).is_err());
    let mut tensor = NativePolyBitTensorTarget::from_rows(vec![zero; ROWS]).unwrap();
    let mut other = tensor.clone();
    let mut another = tensor.clone();
    let points = |len: usize| vec![ext_zero.clone(); len];
    assert!(
        tensor
            .evaluate_rows(&mut n.b, &points(BATCHED - 1))
            .is_err()
    );
    assert!(tensor.evaluate_rows(&mut n.b, &points(ABSORBED)).is_err());
    assert!(tensor.evaluate_columns(&mut n.b, &points(BATCHED)).is_err());
    assert!(
        tensor
            .successor_reading(&mut n.b, &[], &mut other, &mut another)
            .is_err()
    );
    assert!(tensor.column(&mut n.b, COLUMNS).is_err());
    assert!(tensor.trace_column(&mut n.b, COLUMNS).is_err());
    let batch = points(BATCHED);
    let one = points(1);
    let ext = &ext_zero;
    assert!(closing_weight_native_poly(&mut n.b, &one, &[], &batch, None).is_err());
    assert!(closing_weight_native_poly(&mut n.b, &one, &one, &batch[1..], None).is_err());
    assert!(closing_weight_native_poly(&mut n.b, &one, &one, &points(ABSORBED), None).is_err());
    assert!(closing_weight_native_poly(&mut n.b, &one, &one, &batch, Some((0, ext))).is_err());
    assert!(closing_weight_native_poly(&mut n.b, &one, &one, &batch, Some((2, ext))).is_err());
}

/// Column sums and the closing weight stop at their own construction
/// checkpoints, a bounded number of nodes past the budget, instead of
/// running on to the caller's next check.
#[test]
fn readings_stop_at_the_node_budget() {
    let budget_error = |result| {
        matches!(
            result,
            Err(CircuitBuilderError::ConstructionLimitExceeded { .. })
        )
    };
    let mut sampler = Sampler(0xb0d6);
    let rows = sampler.bases(ROWS);
    // The budget fits the row decomposition and the first column exactly, as
    // an unlimited builder measures them, and no further column.
    let mut n = Native::new();
    let mut tensor = n.tensor(&rows);
    tensor.column(&mut n.b, 0).unwrap();
    let mut n = Native::with_node_budget(n.nodes());
    let mut tensor = n.tensor(&rows);
    tensor.column(&mut n.b, 0).unwrap();
    assert!(budget_error(tensor.column(&mut n.b, 1)));

    // A trace column checks the budget after every row.
    let budget = 4096;
    let mut n = Native::with_node_budget(budget);
    let mut tensor = n.tensor(&rows);
    assert!(budget_error(tensor.trace_column(&mut n.b, 0)));
    assert!(n.nodes() <= budget + 64);

    // The fixed-point closing weight adds about 100k nodes. No stretch between
    // its checkpoints adds more than about a thousand.
    let budget = 4096;
    let mut n = Native::with_node_budget(budget);
    let high = n.exts(&sampler.exts(FIXED_HIGH));
    let survivor = n.exts(&sampler.exts(FIXED_HIGH));
    let batch = n.exts(&sampler.exts(BATCHED));
    let alpha = n.ext(sampler.ext());
    assert!(budget_error(closing_weight_native_poly(
        &mut n.b,
        &high,
        &survivor,
        &batch,
        Some((FIXED_KEPT, &alpha))
    )));
    assert!(n.nodes() <= budget + 1024);
}
