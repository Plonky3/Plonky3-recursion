//! Native Tower128 bit-tensor readings and the CRT closing weight, checked
//! against the released bit ring switch and the prime-host tensor gadget.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::ops::{BinaryTower128Target, NativeTower128Target};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_recursion::pcs::binary::{
    NativeBitTensorTarget, binary_tensor_closing_weight, binary128_trace_dual_basis,
    closing_weight_native,
};
use p3_sumcheck::ring_switch::bits::{BitRingSwitch, BitTensor, SuccessorTensors};

type F = BinaryField128;

/// Coordinates one packed Tower128 element absorbs.
const ABSORBED: usize = 7;

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

    fn field(&mut self) -> F {
        F::from_repr(u128::from(self.next_u64()) << 64 | u128::from(self.next_u64()))
    }

    fn fields(&mut self, count: usize) -> Vec<F> {
        (0..count).map(|_| self.field()).collect()
    }
}

/// A native circuit under construction with its witness values.
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

    fn input(&mut self, value: F) -> NativeTower128Target {
        self.private.push(value);
        let expression = self.b.alloc_private_input("native tensor test input");
        self.b.native_tower128_from_expr(expression)
    }

    fn inputs(&mut self, values: &[F]) -> Vec<NativeTower128Target> {
        values.iter().map(|&value| self.input(value)).collect()
    }

    fn tensor(&mut self, rows: &[F]) -> NativeBitTensorTarget {
        let rows = self.inputs(rows);
        NativeBitTensorTarget::from_rows(rows).unwrap()
    }

    /// Constrains `actual` to the public value `expected`.
    fn expect(&mut self, actual: &NativeTower128Target, expected: F) {
        self.public.push(expected);
        let expected = self.b.public_input();
        let difference = self.b.sub(actual.as_expr(), expected);
        self.b.assert_zero(difference);
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

fn basis(u: usize) -> F {
    F::from_repr(1 << u)
}

/// The absolute trace to `F_2`, by the definition `sum_j x^(2^j)`.
fn trace(x: F) -> F {
    let mut power = x;
    let mut sum = x;
    for _ in 1..128 {
        power = power.square();
        sum += power;
    }
    sum
}

fn weighted(values: &[F], point: &[F]) -> F {
    let weights = Poly::new_from_point(point, F::ONE);
    values
        .iter()
        .zip(weights.as_slice())
        .map(|(&value, &weight)| value * weight)
        .sum()
}

/// The released verifier's closing weight for a claim at `high || low` whose
/// sumcheck survived at `survivor`. `successor` is `(kept_row_variables,
/// alpha)` for a successor view that sends carry and last tensors.
fn released_closing_weight(
    high: &[F],
    low: &[F],
    survivor: &[F],
    batch: &[F],
    successor: Option<(usize, F)>,
) -> F {
    let point = Point::new([high, low].concat());
    let batch = Point::new(batch.to_vec());
    let survivor = Point::new(survivor.to_vec());
    match successor {
        None => BitRingSwitch::<F>::new(&point)
            .unwrap()
            .batch(&batch)
            .unwrap()
            .closing_weight(&survivor)
            .unwrap(),
        Some((kept, alpha)) => {
            let reduction = BitRingSwitch::<F>::with_successor(&point, kept + ABSORBED).unwrap();
            assert!(reduction.sends_successor_tensors());
            reduction
                .batch_with_successor(&batch, alpha)
                .unwrap()
                .closing_weight(&survivor)
                .unwrap()
        }
    }
}

/// Runs the prime-host tensor gadget over BabyBear on the same inputs, with
/// its output constrained to `expected`. Returns whether witness generation
/// accepts `expected`, then whether it accepts a perturbed value.
fn prime_closing_verdicts(
    high: &[F],
    survivor: &[F],
    batch: &[F],
    successor: Option<(usize, F)>,
    expected: F,
) -> [bool; 2] {
    let mut b = CircuitBuilder::<BabyBear>::new();
    let mut values = Vec::new();
    let mut input = |b: &mut CircuitBuilder<BabyBear>, value: F| -> BinaryTower128Target {
        let limbs = b.alloc_private_input_array::<8>("prime tensor test input");
        values.extend((0..8).map(|i| BabyBear::from_u16((value.to_repr() >> (16 * i)) as u16)));
        b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
    };
    let high: Vec<_> = high.iter().map(|&x| input(&mut b, x)).collect();
    let survivor: Vec<_> = survivor.iter().map(|&x| input(&mut b, x)).collect();
    let batch: Vec<_> = batch.iter().map(|&x| input(&mut b, x)).collect();
    let successor = successor.map(|(kept, alpha)| (kept, input(&mut b, alpha)));
    let expected = input(&mut b, expected);
    let actual = binary_tensor_closing_weight::<F, BabyBear>(
        &mut b,
        &high,
        &survivor,
        &batch,
        successor.as_ref().map(|(kept, alpha)| (*kept, alpha)),
    )
    .unwrap();
    for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
        let difference = b.sub(a, e);
        b.assert_zero(difference);
    }
    let circuit = b.build().unwrap();
    let mut perturbed = values.clone();
    // The expected value's lowest limb is the eighth from the end.
    let lowest_limb = perturbed.len() - 8;
    perturbed[lowest_limb] += BabyBear::ONE;
    [values, perturbed].map(|values| {
        let mut runner = circuit.runner();
        runner
            .set_private_inputs(&values)
            .and_then(|()| runner.run())
            .is_ok()
    })
}

#[test]
fn trace_dual_basis_reads_raw_coordinates() {
    let dual = binary128_trace_dual_basis();
    assert_eq!(dual.len(), 128);
    for (u, &delta) in dual.iter().enumerate() {
        for w in 0..128 {
            assert_eq!(
                trace(delta * basis(w)),
                F::from_bool(u == w),
                "Tr(delta_{u} * beta_{w})"
            );
        }
    }
    let mut sampler = Sampler(0xd0a1);
    for x in sampler.fields(4) {
        for (u, &delta) in dual.iter().enumerate() {
            assert_eq!(trace(delta * x), F::from_bool(x.to_repr() >> u & 1 == 1));
        }
    }
}

/// The three readings of one tensor, its columns, and the carry and last
/// columns the successor claim reads, each bound to the released value.
#[test]
fn readings_match_released_bit_ring_switch_claims() {
    let mut sampler = Sampler(0x7e45);
    for row_variables in [ABSORBED + 1, ABSORBED + 3] {
        let rows = sampler.fields(128);
        let carry = sampler.fields(128);
        let last = sampler.fields(128);
        let high = sampler.fields(3);
        let low = sampler.fields(ABSORBED);
        let tensor = BitTensor::try_from(rows.clone()).unwrap();
        let successor = SuccessorTensors {
            carry: BitTensor::try_from(carry.clone()).unwrap(),
            last: BitTensor::try_from(last.clone()).unwrap(),
        };
        let point = Point::new([high.as_slice(), &low].concat());
        let row_reading = weighted(tensor.rows(), &low);
        let column_reading = weighted(&tensor.columns(), &low);
        assert_eq!(
            column_reading,
            BitRingSwitch::<F>::new(&point)
                .unwrap()
                .incoming_claim(&tensor)
        );
        let reduction = BitRingSwitch::<F>::with_successor(&point, row_variables).unwrap();
        assert!(reduction.sends_successor_tensors());
        let successor_claim = reduction
            .successor_claim(&tensor, Some(&successor))
            .unwrap();

        let mut n = Native::new();
        let mut tensor_t = n.tensor(&rows);
        let mut carry_t = n.tensor(&carry);
        let mut last_t = n.tensor(&last);
        let low_t = n.inputs(&low);
        let actual = tensor_t.evaluate_rows(&mut n.b, &low_t).unwrap();
        n.expect(&actual, row_reading);
        let actual = tensor_t.evaluate_columns(&mut n.b, &low_t).unwrap();
        n.expect(&actual, column_reading);
        let actual = tensor_t
            .successor_reading(&mut n.b, &low_t, &mut carry_t, &mut last_t)
            .unwrap();
        n.expect(&actual, successor_claim);
        for v in [0, 1, 64, 127] {
            let actual = tensor_t.column(&mut n.b, v).unwrap();
            n.expect(&actual, tensor.column(v));
        }
        let actual = carry_t.column(&mut n.b, 0).unwrap();
        n.expect(&actual, successor.carry.column(0));
        let actual = last_t.column(&mut n.b, 127).unwrap();
        n.expect(&actual, successor.last.column(127));
        let (circuit, public, private) = n.build();
        assert!(accepts(&circuit, &public, &private));
        for index in 0..public.len() {
            let mut wrong = public.clone();
            wrong[index] += F::ONE;
            assert!(!accepts(&circuit, &wrong, &private), "binding {index}");
        }
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
    let rows = sampler.fields(128);
    let carry = sampler.fields(128);
    let last = sampler.fields(128);
    let low = sampler.fields(ABSORBED);
    let tensor = BitTensor::try_from(rows.clone()).unwrap();
    let successor = SuccessorTensors {
        carry: BitTensor::try_from(carry.clone()).unwrap(),
        last: BitTensor::try_from(last.clone()).unwrap(),
    };
    let point = Point::new([sampler.fields(2).as_slice(), &low].concat());
    let successor_claim = BitRingSwitch::<F>::with_successor(&point, ABSORBED + 2)
        .unwrap()
        .successor_claim(&tensor, Some(&successor))
        .unwrap();
    // Private inputs are the rows, then the carry rows, the last rows and the
    // point. A tamper adds one raw basis vector to one private input.
    let (row, carry_row, last_row) = (37, 128 + 90, 256 + 5);
    let readings: [(Reading, F, &[Tamper]); 3] = [
        (
            Reading::Rows,
            weighted(tensor.rows(), &low),
            &[(row, basis(77))],
        ),
        (
            Reading::Columns,
            weighted(&tensor.columns(), &low),
            &[(row, basis(0)), (row, basis(127))],
        ),
        (
            Reading::Successor,
            successor_claim,
            &[
                (row, basis(1)),
                (row, basis(127)),
                (carry_row, basis(0)),
                (last_row, basis(127)),
            ],
        ),
    ];
    for (reading, expected, tampers) in readings {
        let mut n = Native::new();
        let mut tensor_t = n.tensor(&rows);
        let mut carry_t = n.tensor(&carry);
        let mut last_t = n.tensor(&last);
        let low_t = n.inputs(&low);
        let actual = match reading {
            Reading::Rows => tensor_t.evaluate_rows(&mut n.b, &low_t),
            Reading::Columns => tensor_t.evaluate_columns(&mut n.b, &low_t),
            Reading::Successor => {
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

/// Every high length up to the native fixed point's 21, without a successor
/// and with every kept row count, against the released closing weight. The
/// prime-host gadget's BabyBear circuit is slow in debug builds (about ten
/// seconds at one high coordinate, thirty at two), so two cases also run it:
/// the identity tensor, and one coordinate with a successor, which exercises
/// the equality factor and both exterior products.
#[test]
fn closing_weight_matches_released_and_prime_weights() {
    const PRIME_CASES: [(usize, Option<usize>); 2] = [(0, None), (1, Some(1))];
    let mut sampler = Sampler(0xc105);
    for len in 0..=21 {
        let high = sampler.fields(len);
        let low = sampler.fields(ABSORBED);
        let survivor = sampler.fields(len);
        let batch = sampler.fields(ABSORBED);
        let alpha = sampler.field();
        let mut n = Native::new();
        let high_t = n.inputs(&high);
        let survivor_t = n.inputs(&survivor);
        let batch_t = n.inputs(&batch);
        let alpha_t = n.input(alpha);
        for successor in core::iter::once(None).chain((1..=len).map(Some)) {
            let expected = released_closing_weight(
                &high,
                &low,
                &survivor,
                &batch,
                successor.map(|kept| (kept, alpha)),
            );
            let actual = closing_weight_native(
                &mut n.b,
                &high_t,
                &survivor_t,
                &batch_t,
                successor.map(|kept| (kept, &alpha_t)),
            )
            .unwrap();
            n.expect(&actual, expected);
            if PRIME_CASES.contains(&(len, successor)) {
                let successor = successor.map(|kept| (kept, alpha));
                assert_eq!(
                    prime_closing_verdicts(&high, &survivor, &batch, successor, expected),
                    [true, false],
                    "prime closing weight, high {len}, successor {successor:?}"
                );
            }
        }
        let (circuit, public, private) = n.build();
        assert!(accepts(&circuit, &public, &private), "high {len}");
        for index in [0, public.len() - 1] {
            let mut wrong = public.clone();
            wrong[index] += F::ONE;
            assert!(
                !accepts(&circuit, &wrong, &private),
                "high {len}, binding {index}"
            );
        }
    }
}

/// Node counts at the native recursion fixed point: 21 high coordinates, ten
/// kept row variables. Bounds are 1.2 times the measured counts.
///
/// Column readings are sound only because every row's bits are checked: each
/// bit is connected to its Boolean check and the row to its recomposition. A
/// tensor's first column therefore adds at least 129 connections per row.
#[test]
fn node_counts_at_the_native_fixed_point() {
    const CHECKED_ROW_CONNECTS: usize = 128 + 1;
    let mut sampler = Sampler(0x40de);
    let mut n = Native::new();
    let mut tensor = n.tensor(&sampler.fields(128));
    let mut carry = n.tensor(&sampler.fields(128));
    let mut last = n.tensor(&sampler.fields(128));
    let low = n.inputs(&sampler.fields(ABSORBED));
    let high = n.inputs(&sampler.fields(21));
    let survivor = n.inputs(&sampler.fields(21));
    let batch = n.inputs(&sampler.fields(ABSORBED));
    let alpha = n.input(sampler.field());

    let (start, start_connects) = (n.nodes(), n.connects());
    tensor.evaluate_columns(&mut n.b, &low).unwrap();
    let columns_and_current = n.nodes() - start;
    let column_connects = n.connects() - start_connects;
    let (start, start_connects) = (n.nodes(), n.connects());
    carry.column(&mut n.b, 0).unwrap();
    last.column(&mut n.b, 127).unwrap();
    let carry_and_last = n.nodes() - start;
    let carry_and_last_connects = n.connects() - start_connects;
    let start = n.nodes();
    tensor
        .successor_reading(&mut n.b, &low, &mut carry, &mut last)
        .unwrap();
    let successor = n.nodes() - start;
    let start = n.nodes();
    closing_weight_native(&mut n.b, &high, &survivor, &batch, Some((10, &alpha))).unwrap();
    let closing = n.nodes() - start;
    println!(
        "native tensor nodes: columns + current reading {columns_and_current}, \
         successor reading {successor}, carry and last columns {carry_and_last}, \
         closing weight (high 21, kept 10) {closing}; connections: columns \
         {column_connects}, carry and last columns {carry_and_last_connects}"
    );
    assert!(columns_and_current <= 79_102);
    assert!(successor <= 306);
    assert!(carry_and_last <= 118_577);
    assert!(closing <= 48_879);
    assert!(column_connects >= 128 * CHECKED_ROW_CONNECTS);
    assert!(carry_and_last_connects >= 2 * 128 * CHECKED_ROW_CONNECTS);
}

#[test]
fn malformed_shapes_return_errors() {
    let mut n = Native::new();
    let zero = n.input(F::ZERO);
    assert!(NativeBitTensorTarget::from_rows(vec![zero; 127]).is_err());
    let mut tensor = NativeBitTensorTarget::from_rows(vec![zero; 128]).unwrap();
    let mut other = tensor.clone();
    let mut another = tensor.clone();
    assert!(tensor.evaluate_rows(&mut n.b, &[zero; 6]).is_err());
    assert!(tensor.evaluate_columns(&mut n.b, &[zero; 8]).is_err());
    assert!(
        tensor
            .successor_reading(&mut n.b, &[], &mut other, &mut another)
            .is_err()
    );
    assert!(tensor.column(&mut n.b, 128).is_err());
    let batch = [zero; ABSORBED];
    assert!(closing_weight_native(&mut n.b, &[zero], &[], &batch, None).is_err());
    assert!(closing_weight_native(&mut n.b, &[zero], &[zero], &batch[1..], None).is_err());
    assert!(closing_weight_native(&mut n.b, &[zero], &[zero], &batch, Some((0, &zero))).is_err());
    assert!(closing_weight_native(&mut n.b, &[zero], &[zero], &batch, Some((2, &zero))).is_err());
}
