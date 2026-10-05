//! Complete native bit ring-switch transcripts, including dynamic Boolean prefixes.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryChallenger, BinaryField64, BinaryField128, TowerLevel};
use p3_blake3::Blake3;
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryBitRingVerifier, BinaryRingClaimSpec, BinaryRingProofTargets, NativeBinaryRingInput,
    RecursiveBinaryChallengeField,
};
use p3_sumcheck::ring_switch::bits::{
    BitPacking, BitRingSwitch, BitRingSwitchClaims, BitRingSwitchClaimsProof,
};
use p3_symmetric::CryptographicHasher;

type Native = BinaryField128;

fn val(i: u128) -> Native {
    Native::from_repr(0x21bade026a6ae768f2ed66ffdcc99396u128.wrapping_mul(i + 1))
}

struct Fixture<E> {
    imported: NativeBinaryRingInput<E>,
    hash: ByteHash,
    points: Vec<Vec<E>>,
    readings: Vec<(Option<E>, Option<E>)>,
    proof: BitRingSwitchClaimsProof<E>,
    survivor: Vec<E>,
    next_challenge: E,
}

fn native<E: RecursiveBinaryChallengeField>(
    specs: &[BinaryRingClaimSpec],
    high: Vec<Vec<E>>,
    seed: u128,
) -> Fixture<E> {
    native_hash(specs, high, seed, &Keccak256Hash, ByteHash::Keccak256)
}

fn native_hash<E, H>(
    specs: &[BinaryRingClaimSpec],
    high: Vec<Vec<E>>,
    seed: u128,
    hash: &H,
    circuit_hash: ByteHash,
) -> Fixture<E>
where
    E: RecursiveBinaryChallengeField,
    H: CryptographicHasher<u8, [u8; 32]> + Clone + Send + Sync,
{
    let h = high[0].len();
    let absorbed = E::RAW_BITS.ilog2() as usize;
    let val = |i| E::from_le_byte_iter(val(i).to_repr().to_le_bytes().into_iter());
    let points: Vec<_> = high
        .into_iter()
        .enumerate()
        .map(|(i, mut high)| {
            high.extend((0..absorbed).map(|j| val(30 + absorbed as u128 * i as u128 + j as u128)));
            high
        })
        .collect();
    let reductions: Vec<_> = points
        .iter()
        .zip(specs)
        .map(|(point, spec)| {
            let point = Point::new(point.clone());
            spec.next_rows
                .map_or_else(
                    || BitRingSwitch::new(&point),
                    |rows| BitRingSwitch::with_successor(&point, rows),
                )
                .unwrap()
        })
        .collect();
    let setup = BitRingSwitchClaims::new(reductions.clone()).unwrap();
    let packing = BitPacking::from_packed(Poly::new(
        (0..1usize << h)
            .map(|i| val(seed + i as u128))
            .collect::<Vec<_>>(),
    ))
    .unwrap();
    let make = || BinaryChallenger::<E, _>::from_hasher(vec![6; 3], hash.clone());
    let (proof, survivor, _) = setup.prove::<E, _, _>(&packing, &mut make());
    let readings = reductions
        .iter()
        .zip(specs)
        .zip(&proof.claims)
        .map(|((reduction, spec), claim)| {
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
        .collect::<Vec<_>>();
    let mut ch = make();
    let (restored, _) = setup.verify_readings(&proof, &readings, &mut ch).unwrap();
    assert_eq!(restored, survivor);
    let recursive = BinaryBitRingVerifier::<E>::new(h + absorbed, specs.to_vec()).unwrap();
    let native_points = points.iter().cloned().map(Point::new).collect::<Vec<_>>();
    let (imported, imported_point, mut imported_ch) = recursive
        .import_native(&native_points, &readings, &proof, make())
        .unwrap();
    assert_eq!(imported_point, survivor);
    let next_challenge = ch.sample_algebra_element();
    assert_eq!(imported_ch.sample_algebra_element::<E>(), next_challenge);
    Fixture {
        imported,
        hash: circuit_hash,
        points,
        readings,
        proof,
        survivor: survivor.as_slice().to_vec(),
        next_challenge,
    }
}

fn field<E: RecursiveBinaryChallengeField>(
    builder: &mut CircuitBuilder<BabyBear>,
    values: &mut Vec<BabyBear>,
    raw: E,
) -> BinaryTower128Target {
    let limbs = builder.alloc_private_input_array::<8>("ring field");
    values.extend((0..8).map(|i| BabyBear::from_u16((raw.raw_coordinates() >> (16 * i)) as u16)));
    builder.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}

fn build<E: RecursiveBinaryChallengeField>(
    specs: &[BinaryRingClaimSpec],
    fixture: &Fixture<E>,
) -> (Circuit<BabyBear>, Vec<BabyBear>) {
    let h = fixture.survivor.len();
    let verifier =
        BinaryBitRingVerifier::<E>::new(h + E::RAW_BITS.ilog2() as usize, specs.to_vec()).unwrap();
    let mut builder = CircuitBuilder::<BabyBear>::new();
    match fixture.hash {
        ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
    }
    let shape = verifier.input_shape();
    let mut values = fixture.imported.private_values::<BabyBear>(&shape).unwrap();
    let proof = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut builder)
        .unwrap();
    let initial = (0..3)
        .map(|_| builder.define_const(BabyBear::from_u8(6)))
        .collect::<Vec<_>>();
    let challenger = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
        &mut builder,
        fixture.hash,
        &initial,
    )
    .unwrap();
    let mut output = verifier
        .verify::<BabyBear, BabyBear>(&mut builder, challenger, &proof)
        .unwrap();
    let bytes = output
        .challenger
        .sample_bytes::<BabyBear, BabyBear>(&mut builder, E::RAW_BITS / 8)
        .unwrap();
    let mut bits = [ExprId::ZERO; 128];
    for (i, byte) in bytes.into_iter().enumerate() {
        bits[8 * i..8 * i + 8]
            .copy_from_slice(&builder.decompose_to_bits::<BabyBear>(byte, 8).unwrap());
    }
    let next_challenge = builder.binary128_from_bits(bits).unwrap();
    for (actual, expected) in output
        .point
        .iter()
        .zip(&fixture.survivor)
        .chain(core::iter::once((&next_challenge, &fixture.next_challenge)))
    {
        let expected = field(&mut builder, &mut values, *expected);
        for (&a, &b) in actual.bits().iter().zip(expected.bits()) {
            let difference = builder.sub(a, b);
            builder.assert_zero(difference);
        }
    }
    (builder.build().unwrap(), values)
}

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

#[test]
fn single_claim_prefix_round_counts_reuse_one_circuit() {
    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let first = native(&specs, vec![vec![val(1), val(2)]], 7);
    let (circuit, values) = build(&specs, &first);
    assert!(run(&circuit, &values));
    for high in [vec![Native::ONE, val(2)], vec![Native::ZERO, Native::ONE]] {
        let second = native(&specs, vec![high], 97);
        let (_, values) = build(&specs, &second);
        assert!(run(&circuit, &values));
        let mut wrong = values.clone();
        wrong[8 * (9 + 1 + 128) + 16] += BabyBear::ONE;
        assert!(
            !run(&circuit, &wrong),
            "unused sumcheck messages must be canonical zeros"
        );
    }
    let mut wrong = values;
    wrong[8 * 9] += BabyBear::ONE;
    assert!(!run(&circuit, &wrong), "claimed current reading");
}

#[test]
fn multiple_claims_match_native_common_and_individual_prefixes() {
    let specs = [
        BinaryRingClaimSpec {
            current: true,
            next_rows: Some(3),
        },
        BinaryRingClaimSpec {
            current: false,
            next_rows: Some(8),
        },
    ];
    let mut shared_circuit = None;
    for highs in [
        vec![vec![val(1), val(2)], vec![val(3), val(4)]],
        vec![vec![Native::ONE, val(2)], vec![Native::ONE, val(4)]],
        vec![vec![Native::ZERO, Native::ONE], vec![Native::ONE, val(4)]],
    ] {
        let fixture = native(&specs, highs, 7);
        let (circuit, values) = build(&specs, &fixture);
        let circuit = shared_circuit.get_or_insert(circuit);
        assert!(run(circuit, &values));
        let mut wrong = values.clone();
        wrong[values.len() / 2] += BabyBear::ONE;
        assert!(!run(circuit, &wrong));
    }
}

#[test]
fn zero_high_coordinates_and_zero_successor_rows_match_native() {
    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: Some(0),
    }];
    let fixture = native::<Native>(&specs, vec![vec![]], 7);
    let (circuit, values) = build(&specs, &fixture);
    assert!(run(&circuit, &values));
}

#[test]
fn invalid_geometry_and_proof_shapes_return_errors() {
    let current = BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    };
    assert!(BinaryBitRingVerifier::<Native>::new(6, vec![current]).is_err());
    assert!(BinaryBitRingVerifier::<Native>::new(7, vec![]).is_err());
    assert!(
        BinaryBitRingVerifier::<Native>::new(
            7,
            vec![BinaryRingClaimSpec {
                current: false,
                next_rows: None
            }]
        )
        .is_err()
    );
    assert!(
        BinaryBitRingVerifier::<Native>::new(
            7,
            vec![BinaryRingClaimSpec {
                current: false,
                next_rows: Some(8)
            }]
        )
        .is_err()
    );
    let limits = p3_recursion::verifier::VerifierLimits {
        max_total_scalar_elements: 0,
        ..Default::default()
    };
    assert!(BinaryBitRingVerifier::<Native>::with_limits(9, vec![current], &limits).is_err());
    let verifier = BinaryBitRingVerifier::<Native>::new(9, vec![current]).unwrap();
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let zero = builder.binary128_constant(0).unwrap();
    let malformed = BinaryRingProofTargets {
        claims: vec![],
        sumcheck: vec![],
        final_eval: zero,
    };
    assert!(
        verifier
            .verify::<BabyBear, BabyBear>(
                &mut builder,
                BinaryTower128Challenger::new(ByteHash::Keccak256),
                &malformed
            )
            .is_err()
    );
}

#[test]
fn eight_byte_challenges_and_dynamic_continuations_match_both_hashes() {
    let val = |i| BinaryField64::from_le_byte_iter(val(i).to_repr().to_le_bytes().into_iter());
    for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
        let specs = [BinaryRingClaimSpec {
            current: true,
            next_rows: None,
        }];
        let mut shared_circuit = None;
        for high in [vec![val(1)], vec![BinaryField64::ONE]] {
            let fixture = match hash {
                ByteHash::Keccak256 => native_hash(&specs, vec![high], 7, &Keccak256Hash, hash),
                ByteHash::Blake3 => native_hash(&specs, vec![high], 7, &Blake3, hash),
            };
            let (circuit, values) = build(&specs, &fixture);
            let circuit = shared_circuit.get_or_insert(circuit);
            assert!(run(circuit, &values));
            let mut wrong = values.clone();
            wrong[4] += BabyBear::ONE;
            assert!(!run(circuit, &wrong), "upper point coordinates");
        }
        let specs = [BinaryRingClaimSpec {
            current: true,
            next_rows: Some(7),
        }];
        let high = vec![vec![BinaryField64::ONE, val(2)]];
        let fixture = match hash {
            ByteHash::Keccak256 => native_hash(&specs, high, 7, &Keccak256Hash, hash),
            ByteHash::Blake3 => native_hash(&specs, high, 7, &Blake3, hash),
        };
        let (circuit, values) = build(&specs, &fixture);
        assert!(run(&circuit, &values));
    }
    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let fixture = native_hash(
        &specs,
        vec![vec![Native::from(val(1))]],
        7,
        &Blake3,
        ByteHash::Blake3,
    );
    let (circuit, values) = build(&specs, &fixture);
    assert!(run(&circuit, &values));
}

#[test]
fn native_import_rejects_noncanonical_and_mismatched_inputs() {
    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let fixture = native(&specs, vec![vec![Native::ONE, val(2)]], 7);
    let verifier = BinaryBitRingVerifier::<Native>::new(9, specs.to_vec()).unwrap();
    let points = fixture
        .points
        .iter()
        .cloned()
        .map(Point::new)
        .collect::<Vec<_>>();
    let make = || BinaryChallenger::<Native, _>::from_hasher(vec![6; 3], Keccak256Hash);
    let mut malformed = vec![fixture.proof.clone(); 4];
    malformed[0].sumcheck.pow_witnesses.push(Native::ZERO);
    malformed[1]
        .sumcheck
        .polynomial_evaluations
        .push([Native::ZERO; 2]);
    malformed[2].claims.clear();
    malformed[3].claims[0].successor = Some(p3_sumcheck::ring_switch::bits::SuccessorTensors {
        carry: malformed[3].claims[0].tensor.clone(),
        last: malformed[3].claims[0].tensor.clone(),
    });
    for proof in malformed {
        let mut ch = make();
        assert!(
            verifier
                .import_native(&points, &fixture.readings, &proof, &mut ch)
                .is_err()
        );
        assert_eq!(
            ch.sample_algebra_element::<Native>(),
            make().sample_algebra_element::<Native>(),
            "structural rejection must precede transcript replay"
        );
    }
    let mut wrong = fixture.readings.clone();
    wrong[0].0 = Some(wrong[0].0.unwrap() + Native::ONE);
    assert!(
        verifier
            .import_native(&points, &wrong, &fixture.proof, make())
            .is_err()
    );
    let other = BinaryBitRingVerifier::<Native>::new(
        9,
        vec![BinaryRingClaimSpec {
            current: true,
            next_rows: Some(0),
        }],
    )
    .unwrap();
    assert!(
        fixture
            .imported
            .private_values::<BabyBear>(&other.input_shape())
            .is_err()
    );
}
