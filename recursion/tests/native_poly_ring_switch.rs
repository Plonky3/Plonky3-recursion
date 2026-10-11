//! The native Poly64 bit ring switch, every sumcheck round run, checked
//! against released ring-switch proofs over Poly64 values and Poly192
//! challenges: the in-circuit transcript ends where the released one does, an
//! honest reduction is accepted, and every committed value is bound.

use p3_binary_field::{Poly64, Poly192};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NativePoly192Target};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_recursion::pcs::binary::{
    BinaryPolyBitRingVerifier, BinaryRingClaimSpec, NativePolyBitRingReading,
};
use p3_recursion::{BinaryTower128Challenger, VerificationError, VerifierLimits};
use p3_sumcheck::ring_switch::bits::{
    BitPacking, BitRingSwitch, BitRingSwitchClaims, BitRingSwitchClaimsProof,
};
use p3_test_utils::binary_field_params::keccak;

type F = Poly64;
type E = Poly192;
type H = NativeBinaryEncoding;
type Ch = keccak::LevelChallenger<F>;
type Proof = BitRingSwitchClaimsProof<F, E>;

/// Point coordinates one packed Poly64 element absorbs.
const ABSORBED: usize = 6;
/// Rows of a sent tensor, one per Poly192 coordinate.
const ROWS: usize = 192;
/// Poly64 cells of one Poly192 value.
const LIMBS: usize = 3;
/// Bytes every transcript here starts from, natively and in each circuit.
const INITIAL: [u8; 4] = [7, 19, 13, 29];

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

    const fn ext(&mut self) -> E {
        E::new([self.base(), self.base(), self.base()])
    }

    fn point(&mut self, variables: usize) -> Point<E> {
        Point::new((0..variables).map(|_| self.ext()).collect())
    }
}

const fn spec(current: bool, next_rows: Option<usize>) -> BinaryRingClaimSpec {
    BinaryRingClaimSpec { current, next_rows }
}

fn challenger() -> Ch {
    Ch::from_hasher(INITIAL.to_vec(), keccak::byte_hash())
}

fn native_challenger(b: &mut CircuitBuilder<F>) -> BinaryTower128Challenger {
    let initial = INITIAL.map(|byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()));
    BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(b, ByteHash::Keccak256, &initial)
        .unwrap()
}

fn public_value(b: &mut CircuitBuilder<F>) -> NativePoly192Target {
    let coefficients = core::array::from_fn(|_| b.public_input());
    b.native_poly192_from_coefficients(coefficients)
}

/// Constrains `actual` to the next three public limbs.
fn bind(b: &mut CircuitBuilder<F>, actual: &NativePoly192Target) {
    let expected = public_value(b);
    for (&actual, &expected) in actual.coefficients().iter().zip(expected.coefficients()) {
        let difference = b.sub(actual, expected);
        b.assert_zero(difference);
    }
}

/// The circuit transcript's next Poly192 draw, as the native transcript reads it.
fn native_sample(
    b: &mut CircuitBuilder<F>,
    ch: &mut BinaryTower128Challenger,
) -> NativePoly192Target {
    let bits = ch.sample_poly192_with_host::<H, F>(b).unwrap();
    b.native_poly192_from_bits(core::array::from_fn(|i| {
        bits.coefficients()[i / 64].bits()[i % 64]
    }))
    .unwrap()
}

fn accepts(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

/// Claims about one random packing of `2^(variables - 6)` Poly64 elements,
/// reduced by the released prover.
struct Switched {
    variables: usize,
    specs: Vec<BinaryRingClaimSpec>,
    verifier: BinaryPolyBitRingVerifier,
    points: Vec<Point<E>>,
    readings: Vec<(Option<E>, Option<E>)>,
    proof: Proof,
    survivor: Point<E>,
    value: E,
    /// The released prover's next challenge after the reduction.
    next: E,
}

impl Switched {
    fn new(variables: usize, specs: &[BinaryRingClaimSpec], seed: u64) -> Self {
        let mut sampler = Sampler(seed);
        let points = specs.iter().map(|_| sampler.point(variables)).collect();
        Self::at(variables, specs, points, seed)
    }

    fn at(
        variables: usize,
        specs: &[BinaryRingClaimSpec],
        points: Vec<Point<E>>,
        seed: u64,
    ) -> Self {
        let mut sampler = Sampler(seed ^ 0x9ac4);
        let packed: Vec<F> = (0..1usize << (variables - ABSORBED))
            .map(|_| sampler.base())
            .collect();
        let packing = BitPacking::<F>::from_packed(Poly::new(packed)).unwrap();
        let reductions = points
            .iter()
            .zip(specs)
            .map(|(point, spec)| {
                spec.next_rows
                    .map_or_else(
                        || BitRingSwitch::<F, E>::new(point),
                        |rows| BitRingSwitch::with_successor(point, rows),
                    )
                    .unwrap()
            })
            .collect();
        let claims = BitRingSwitchClaims::new(reductions).unwrap();
        let mut prover = challenger();
        let (proof, survivor, value) = claims.prove::<E, _, _>(&packing, &mut prover);
        assert_eq!(value, packing.poly().eval_base(&survivor));
        let readings = claims
            .reductions()
            .iter()
            .zip(&proof.claims)
            .zip(specs)
            .map(|((reduction, claim), spec)| {
                (
                    spec.current
                        .then(|| reduction.incoming_claim(&claim.tensor)),
                    spec.next_rows.map(|_| {
                        reduction
                            .successor_claim(&claim.tensor, claim.successor.as_ref())
                            .unwrap()
                    }),
                )
            })
            .collect();
        let next = prover.sample_algebra_element::<E>();
        Self {
            variables,
            specs: specs.to_vec(),
            verifier: BinaryPolyBitRingVerifier::new(variables, specs.to_vec()).unwrap(),
            points,
            readings,
            proof,
            survivor,
            value,
            next,
        }
    }

    const fn high(&self) -> usize {
        self.variables - ABSORBED
    }

    fn import(&self, proof: &Proof) -> Result<(Vec<F>, Point<E>, Ch), String> {
        let (input, point, challenger) = self
            .verifier
            .import_native(&self.points, &self.readings, proof, challenger())
            .map_err(|error| error.to_string())?;
        let values = input
            .private_native_values(&self.verifier.input_shape())
            .map_err(|error| error.to_string())?;
        Ok((values, point, challenger))
    }

    /// The honest witness. Its import lands on the released surviving point
    /// and leaves the native transcript where the released prover left it.
    fn private(&self) -> Vec<F> {
        let (values, point, mut rest) = self.import(&self.proof).unwrap();
        assert_eq!(point, self.survivor);
        assert_eq!(rest.sample_algebra_element::<E>(), self.next);
        values
    }

    /// Public inputs: every claim's point and readings, then, for a bound
    /// circuit, the surviving point, the surviving value and the next
    /// challenge.
    fn public(&self, bound: bool) -> Vec<F> {
        let mut values: Vec<E> = Vec::new();
        for (point, (current, next)) in self.points.iter().zip(&self.readings) {
            values.extend(point.iter().copied());
            values.extend(current.iter().chain(next.iter()).copied());
        }
        if bound {
            values.extend(self.survivor.iter().copied());
            values.push(self.value);
            values.push(self.next);
        }
        values.into_iter().flat_map(E::coefficients).collect()
    }

    /// The native verifier circuit. A bound circuit also constrains the
    /// surviving point and value and the next challenge to public inputs; an
    /// unbound circuit holds the verifier's own constraints only.
    fn circuit(&self, bound: bool) -> Circuit<F> {
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let readings: Vec<_> = self
            .specs
            .iter()
            .map(|spec| {
                let point = (0..self.variables).map(|_| public_value(&mut b)).collect();
                let current = spec.current.then(|| public_value(&mut b));
                let next = spec.next_rows.map(|_| public_value(&mut b));
                NativePolyBitRingReading {
                    point,
                    current,
                    next,
                }
            })
            .collect();
        let targets = self
            .verifier
            .input_shape()
            .allocate_native_targets(&mut b)
            .unwrap();
        let ch = native_challenger(&mut b);
        let output = self
            .verifier
            .verify_native(&mut b, ch, &readings, &targets)
            .unwrap();
        assert_eq!(output.point.len(), self.high());
        if bound {
            for coordinate in &output.point {
                bind(&mut b, coordinate);
            }
            bind(&mut b, &output.value);
            let mut ch = output.challenger;
            let next = native_sample(&mut b, &mut ch);
            bind(&mut b, &next);
        }
        b.build().unwrap()
    }
}

/// An honest reduction is accepted, its imported witness lands on the
/// released surviving point, and the circuit's transcript continues exactly
/// as the released one: the surviving point and value and the next challenge
/// drawn after the reduction are bound to the released ones. Covers a plain
/// claim, a successor spanning elements, one inside an element, one stepping
/// every coordinate, a successor reading alone, a point of one element with
/// no rounds, and batches of two and three claims under lambda, with and
/// without alpha.
#[test]
fn honest_reductions_replay_the_released_transcript() {
    let cases: [(usize, &[BinaryRingClaimSpec]); 9] = [
        (10, &[spec(true, None)]),
        (10, &[spec(true, Some(9))]),
        (10, &[spec(true, Some(5))]),
        (10, &[spec(true, Some(10))]),
        (10, &[spec(false, Some(9))]),
        (6, &[spec(true, Some(6))]),
        (9, &[spec(true, None), spec(true, None)]),
        (
            10,
            &[spec(true, None), spec(true, Some(4)), spec(true, Some(9))],
        ),
        (8, &[spec(true, Some(7)), spec(false, Some(8))]),
    ];
    for (i, (variables, specs)) in cases.into_iter().enumerate() {
        let switched = Switched::new(variables, specs, 0x2b17 + i as u64);
        let circuit = switched.circuit(true);
        let public = switched.public(true);
        let private = switched.private();
        assert!(accepts(&circuit, &public, &private), "{specs:?}");
        // The last limb of the next challenge and of the surviving value,
        // and of the first surviving coordinate when there is one.
        let survivor = public.len() - LIMBS * (switched.high() + 2);
        let mut indices = vec![public.len() - 1, public.len() - LIMBS - 1];
        if switched.high() > 0 {
            indices.push(survivor + 2);
        }
        for index in indices {
            let mut wrong = public.clone();
            wrong[index] += F::ONE;
            assert!(
                !accepts(&circuit, &wrong, &private),
                "{specs:?} public {index}"
            );
        }
    }
}

/// The imported witness is the proof's committed cells in allocation order:
/// every claim's tensor, carry and last rows, both values of every round's
/// message, then the surviving value, three limbs per Poly192 value.
#[test]
fn the_witness_is_the_proof_in_allocation_order() {
    let switched = Switched::new(10, &[spec(true, Some(9)), spec(true, None)], 0x51de);
    let private = switched.private();
    let claims = &switched.proof.claims;
    let successor = claims[0].successor.as_ref().unwrap();
    let mut expected: Vec<F> = claims[0].tensor.rows().to_vec();
    expected.extend(successor.carry.rows());
    expected.extend(successor.last.rows());
    expected.extend(claims[1].tensor.rows());
    for message in &switched.proof.sumcheck.polynomial_evaluations {
        expected.extend(message.iter().flat_map(|value| value.coefficients()));
    }
    expected.extend(switched.proof.final_eval.coefficients());
    assert_eq!(private, expected);
    assert_eq!(
        private.len(),
        4 * ROWS + 2 * LIMBS * switched.high() + LIMBS
    );
}

/// Every committed class is bound: in a circuit holding only the verifier's
/// constraints, changing a tensor, carry or last row, either value of a round
/// message, the surviving value, or a stated reading is refused. The
/// surviving value is absorbed after the last draw, so changing it fails the
/// closing check alone.
#[test]
fn every_committed_class_is_bound() {
    let switched = Switched::new(10, &[spec(true, Some(9)), spec(true, Some(5))], 0x7a3e);
    let circuit = switched.circuit(false);
    let public = switched.public(false);
    let private = switched.private();
    assert!(accepts(&circuit, &public, &private));
    let second = 3 * ROWS;
    let sumcheck = second + ROWS;
    let survivor = private.len() - LIMBS;
    for (class, index) in [
        ("tensor row", 5),
        ("carry row", ROWS + 7),
        ("last row", 2 * ROWS + 191),
        ("second claim's tensor row", second + 64),
        ("round h(0)", sumcheck + 1),
        ("round h(infinity)", sumcheck + LIMBS + 2),
        ("last round h(0)", survivor - 2 * LIMBS),
        ("surviving value", survivor),
        ("surviving value high limb", survivor + 2),
    ] {
        let mut wrong = private.clone();
        wrong[index] += F::new(1 << 41);
        assert!(!accepts(&circuit, &public, &wrong), "{class} at {index}");
    }
    let readings = switched.variables * LIMBS;
    for (class, index) in [
        ("first point coordinate", 0),
        ("current reading", readings),
        ("successor reading", readings + LIMBS + 1),
        ("second claim's successor reading", public.len() - 1),
    ] {
        let mut wrong = public.clone();
        wrong[index] += F::ONE;
        assert!(!accepts(&circuit, &wrong, &private), "{class} at {index}");
    }
}

/// The native verifier runs every round, so claims whose points share a
/// Boolean first coordinate, which the released reduction skips, are refused
/// by the import. Claims whose first coordinates are different bits share no
/// prefix, and neither does a successor stepping every coordinate, so those
/// are accepted with every round run.
#[test]
fn shared_boolean_prefixes_are_refused() {
    let with_firsts = |variables: usize, firsts: &[E], seed: u64| {
        let mut sampler = Sampler(seed);
        firsts
            .iter()
            .map(|&first| {
                let mut point = sampler.point(variables).as_slice().to_vec();
                point[0] = first;
                Point::new(point)
            })
            .collect::<Vec<_>>()
    };
    let refused: [(&[BinaryRingClaimSpec], &[E]); 4] = [
        (&[spec(true, None)], &[E::ZERO]),
        (&[spec(true, None)], &[E::ONE]),
        (&[spec(true, Some(9))], &[E::ONE]),
        (&[spec(true, None), spec(true, Some(5))], &[E::ONE, E::ONE]),
    ];
    for (specs, firsts) in refused {
        let switched = Switched::at(10, specs, with_firsts(10, firsts, 0x3c), 0x3c);
        assert!(switched.proof.sumcheck.polynomial_evaluations.len() < switched.high());
        let error = switched.import(&switched.proof).err().unwrap();
        assert!(
            error.contains("share a Boolean prefix"),
            "{specs:?}: {error}"
        );
    }
    let accepted: [(&[BinaryRingClaimSpec], &[E]); 2] = [
        (&[spec(true, None), spec(true, None)], &[E::ZERO, E::ONE]),
        (&[spec(true, Some(10))], &[E::ONE]),
    ];
    for (specs, firsts) in accepted {
        let switched = Switched::at(10, specs, with_firsts(10, firsts, 0x4d), 0x4d);
        assert_eq!(
            switched.proof.sumcheck.polynomial_evaluations.len(),
            switched.high()
        );
        assert!(accepts(
            &switched.circuit(true),
            &switched.public(true),
            &switched.private()
        ));
    }
}

/// The import refuses, with its own message, a proof carrying grinding
/// witnesses, missing a round or a successor element, or holding an extra
/// claim; points or readings whose count, width or presence differ from the
/// verifier's; and a tampered row, which the released replay rejects.
#[test]
fn malformed_proofs_and_readings_are_refused() {
    let switched = Switched::new(10, &[spec(true, Some(9))], 0x6f02);
    let refuse = |proof: &Proof, expected: &str| {
        let error = switched.import(proof).err().unwrap();
        assert!(error.contains(expected), "{expected}: {error}");
    };
    let mut ground = switched.proof.clone();
    ground.sumcheck.pow_witnesses.push(F::ZERO);
    refuse(&ground, "grinding witnesses");
    let mut short = switched.proof.clone();
    short.sumcheck.polynomial_evaluations.pop();
    refuse(&short, "structural mismatch");
    let mut bare = switched.proof.clone();
    bare.claims[0].successor = None;
    refuse(&bare, "structural mismatch");
    let mut doubled = switched.proof.clone();
    doubled.claims.push(doubled.claims[0].clone());
    refuse(&doubled, "structural mismatch");
    let mut tampered = switched.proof.clone();
    let mut rows = tampered.claims[0].tensor.rows().to_vec();
    rows[3] += F::ONE;
    tampered.claims[0].tensor = rows.try_into().unwrap();
    refuse(&tampered, "replay failed");

    let verifier = &switched.verifier;
    let import = |points: &[Point<E>], readings: &[(Option<E>, Option<E>)]| {
        verifier
            .import_native(points, readings, &switched.proof, challenger())
            .err()
            .unwrap()
            .to_string()
    };
    let narrow = Point::new(switched.points[0].as_slice()[1..].to_vec());
    for error in [
        import(&[], &[]),
        import(&[narrow], &switched.readings),
        import(&switched.points, &[(switched.readings[0].0, None)]),
        import(&switched.points, &[(None, switched.readings[0].1)]),
    ] {
        assert!(error.contains("claim shape mismatch"), "{error}");
    }
}

/// The verifier refuses geometry it cannot read and readings or targets that
/// do not match it, the latter before adding any expression.
#[test]
fn verifier_geometry_and_target_shapes_are_checked() {
    for (variables, specs) in [
        (5, vec![spec(true, None)]),
        (10, vec![]),
        (10, vec![spec(false, None)]),
        (10, vec![spec(true, Some(11))]),
    ] {
        let error = BinaryPolyBitRingVerifier::new(variables, specs).unwrap_err();
        assert!(error.to_string().contains("geometry is invalid"));
    }
    let limits = VerifierLimits {
        max_log_domain_or_degree: 9,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryPolyBitRingVerifier::with_limits(10, vec![spec(true, None)], &limits),
        Err(VerificationError::ResourceLimitExceeded { .. })
    ));
    let rounds = VerifierLimits {
        max_rounds: 3,
        ..VerifierLimits::default()
    };
    assert!(BinaryPolyBitRingVerifier::with_limits(10, vec![spec(true, None)], &rounds).is_err());
    assert!(BinaryPolyBitRingVerifier::with_limits(9, vec![spec(true, None)], &rounds).is_ok());

    let verifier = BinaryPolyBitRingVerifier::new(10, vec![spec(true, Some(9))]).unwrap();
    let other = BinaryPolyBitRingVerifier::new(10, vec![spec(true, None)]).unwrap();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let point: Vec<_> = (0..10).map(|_| public_value(&mut b)).collect();
    let current = Some(public_value(&mut b));
    let next = Some(public_value(&mut b));
    let targets = verifier
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap();
    let foreign = other.input_shape().allocate_native_targets(&mut b).unwrap();
    let ch = native_challenger(&mut b);
    let reading = |point: Vec<NativePoly192Target>, next: Option<NativePoly192Target>| {
        NativePolyBitRingReading {
            point,
            current: current.clone(),
            next,
        }
    };
    let before = b.construction_usage().unwrap();
    for (readings, targets) in [
        (vec![reading(point.clone(), None)], &targets),
        (vec![reading(point[1..].to_vec(), next.clone())], &targets),
        (vec![], &targets),
        (vec![reading(point, next)], &foreign),
    ] {
        let error = verifier
            .verify_native(&mut b, ch.clone(), &readings, targets)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("do not match the verifier shape")
        );
    }
    let after = b.construction_usage().unwrap();
    assert_eq!(after.expression_nodes, before.expression_nodes);
    assert_eq!(after.pending_connects, before.pending_connects);
}
