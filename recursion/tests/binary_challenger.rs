//! Direct native differentials for the byte-hash binary tower challenger.

use core::hash::Hash as StdHash;

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryChallenger, BinaryField128, Gf2, TowerLevel};
use p3_blake3::Blake3;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, GrindingChallenger, HashChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitError, ExprId};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_symmetric::{CryptographicHasher, Hash};

type Native<H> = BinaryChallenger<BinaryField128, HashChallenger<u8, H, 32>>;
type BabyD4 = BinomialExtensionField<BabyBear, 4>;
type GoldD2 = BinomialExtensionField<Goldilocks, 2>;

const DENSE: u128 = 0x21bade026a6ae768f2ed66ffdcc99396;
const DIGEST: [u8; 32] = [
    0x03, 0x15, 0x27, 0x39, 0x4b, 0x5d, 0x6f, 0x71, 0x82, 0x94, 0xa6, 0xb8, 0xca, 0xdc, 0xee, 0xf0,
    0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f, 0x90, 0xa2, 0xb4, 0xc6, 0xd8, 0xea, 0xfc, 0x0e,
];

fn raw_limbs(raw: u128) -> [u16; 8] {
    core::array::from_fn(|i| (raw >> (16 * i)) as u16)
}

fn digest_limbs() -> [u16; 16] {
    core::array::from_fn(|i| u16::from_le_bytes([DIGEST[2 * i], DIGEST[2 * i + 1]]))
}

fn bind_raw<BF, EF>(builder: &mut CircuitBuilder<EF>, sample: &BinaryTower128Target, raw: u128)
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + StdHash,
{
    for (i, actual) in builder
        .binary128_to_limbs::<BF>(sample)
        .unwrap()
        .into_iter()
        .enumerate()
    {
        let expected = builder.define_const(EF::from(BF::from_u16((raw >> (16 * i)) as u16)));
        let difference = builder.sub(actual, expected);
        builder.assert_zero(difference);
    }
}

fn bind_bits<BF, EF>(builder: &mut CircuitBuilder<EF>, bits: &[ExprId], native: usize)
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + StdHash,
{
    for (i, &actual) in bits.iter().enumerate() {
        let expected = builder.define_const(EF::from(BF::from_bool(native & (1 << i) != 0)));
        let difference = builder.sub(actual, expected);
        builder.assert_zero(difference);
    }
}

fn draw_field<BF, EF, H>(
    builder: &mut CircuitBuilder<EF>,
    circuit: &mut BinaryTower128Challenger,
    native: &mut Native<H>,
) where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + StdHash,
    H: CryptographicHasher<u8, [u8; 32]>,
{
    let expected: BinaryField128 = native.sample();
    let sample = circuit.sample::<BF, EF>(builder).unwrap();
    bind_raw::<BF, EF>(builder, &sample, expected.to_repr());
}

fn draw_bits<BF, EF, H>(
    builder: &mut CircuitBuilder<EF>,
    circuit: &mut BinaryTower128Challenger,
    native: &mut Native<H>,
    width: usize,
) where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + StdHash,
    H: CryptographicHasher<u8, [u8; 32]>,
{
    let expected = native.sample_bits(width);
    let bits = circuit.sample_bits::<BF, EF>(builder, width).unwrap();
    assert_eq!(bits.len(), width);
    bind_bits::<BF, EF>(builder, &bits, expected);
}

fn differential_script<BF, EF, H>(hash: ByteHash, hasher: H)
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + StdHash,
    H: CryptographicHasher<u8, [u8; 32]> + Clone + Send + Sync,
{
    // Every observed limb is a private input; the two-byte order is observable.
    let initial = [0x1203u16, 0x4567, 0x89ab];
    let mut inputs: Vec<EF> = initial.iter().map(|&x| EF::from(BF::from_u16(x))).collect();
    let mut builder = CircuitBuilder::<EF>::new();
    match hash {
        ByteHash::Keccak256 => builder.enable_keccak_f1600::<BF>(),
        ByteHash::Blake3 => builder.enable_blake3_compress::<BF>(),
    }
    let initial_targets = builder.alloc_private_input_array::<3>("initial bytes");
    let mut circuit = BinaryTower128Challenger::with_initial_limbs::<BF, EF>(
        &mut builder,
        hash,
        &initial_targets,
    )
    .unwrap();
    let mut native = Native::<H>::from_hasher(
        initial.into_iter().flat_map(u16::to_le_bytes).collect(),
        hasher,
    );

    let raw_observations = [0, 1, DENSE];
    let mut observations = Vec::new();
    for raw in raw_observations {
        let target_limbs = builder.alloc_private_input_array::<8>("observed tower limbs");
        inputs.extend(raw_limbs(raw).map(|x| EF::from(BF::from_u16(x))));
        observations.push(builder.binary128_from_limbs::<BF>(target_limbs).unwrap());
        native.observe(BinaryField128::from_repr(raw));
    }
    circuit
        .observe_slice::<BF, EF>(&mut builder, &observations)
        .unwrap();
    circuit.observe_slice::<BF, EF>(&mut builder, &[]).unwrap();
    let digest_targets = builder.alloc_private_input_array::<16>("observed digest limbs");
    inputs.extend(digest_limbs().map(|x| EF::from(BF::from_u16(x))));
    circuit
        .observe_digest::<BF, EF>(&mut builder, &digest_targets)
        .unwrap();
    native.observe(Hash::<BinaryField128, u8, 32>::from(DIGEST));

    // Clone before first refill. Both branches draw the two halves, then chain.
    let mut circuit_clone = circuit.clone();
    let mut native_clone = native.clone();
    let mut cross = circuit.clone();
    let mut native_cross = native.clone();
    for _ in 0..3 {
        draw_field::<BF, EF, H>(&mut builder, &mut circuit, &mut native);
        draw_field::<BF, EF, H>(&mut builder, &mut circuit_clone, &mut native_clone);
    }

    // Three eight-byte draws leave eight bytes; the field draw spans a refill.
    for width in [0, 1, 7] {
        draw_bits::<BF, EF, H>(&mut builder, &mut cross, &mut native_cross, width);
    }
    draw_field::<BF, EF, H>(&mut builder, &mut cross, &mut native_cross);
    for width in [8, 31, 56, 63] {
        if width < usize::BITS as usize {
            draw_bits::<BF, EF, H>(&mut builder, &mut circuit, &mut native, width);
        }
    }

    // Empty observation keeps the stream; nonempty observation drops a remainder.
    draw_bits::<BF, EF, H>(&mut builder, &mut circuit, &mut native, 8);
    circuit.observe_slice::<BF, EF>(&mut builder, &[]).unwrap();
    draw_field::<BF, EF, H>(&mut builder, &mut circuit, &mut native);
    let mut partial_clone = circuit.clone();
    let mut native_partial_clone = native.clone();
    let later_raw = 0x0102030405060708090a0b0c0d0e0f10;
    let later_limbs = builder.alloc_private_input_array::<8>("later tower limbs");
    inputs.extend(raw_limbs(later_raw).map(|x| EF::from(BF::from_u16(x))));
    let later = builder.binary128_from_limbs::<BF>(later_limbs).unwrap();
    circuit.observe::<BF, EF>(&mut builder, &later).unwrap();
    native.observe(BinaryField128::from_repr(later_raw));
    draw_field::<BF, EF, H>(&mut builder, &mut circuit, &mut native);
    draw_field::<BF, EF, H>(&mut builder, &mut partial_clone, &mut native_partial_clone);

    // check_witness(0) leaves a shadow byte stream exactly unchanged.
    let mut zero_shadow = partial_clone.clone();
    let mut native_zero_shadow = native_partial_clone.clone();
    let zero_witness = builder.binary128_constant(0).unwrap();
    partial_clone
        .check_witness::<BF, EF>(&mut builder, 0, &zero_witness)
        .unwrap();
    assert!(native_partial_clone.check_witness(0, BinaryField128::from_repr(0)));
    draw_field::<BF, EF, H>(&mut builder, &mut partial_clone, &mut native_partial_clone);
    draw_field::<BF, EF, H>(&mut builder, &mut zero_shadow, &mut native_zero_shadow);
    draw_bits::<BF, EF, H>(&mut builder, &mut zero_shadow, &mut native_zero_shadow, 0);
    draw_field::<BF, EF, H>(&mut builder, &mut zero_shadow, &mut native_zero_shadow);

    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&inputs).unwrap();
    runner.run().unwrap();
}

#[test]
fn native_keccak_scripts_on_three_host_shapes() {
    differential_script::<BabyBear, BabyBear, _>(ByteHash::Keccak256, Keccak256Hash);
    differential_script::<BabyBear, BabyD4, _>(ByteHash::Keccak256, Keccak256Hash);
    differential_script::<Goldilocks, GoldD2, _>(ByteHash::Keccak256, Keccak256Hash);
}

#[test]
fn native_blake3_scripts_on_three_host_shapes() {
    differential_script::<BabyBear, BabyBear, _>(ByteHash::Blake3, Blake3);
    differential_script::<BabyBear, BabyD4, _>(ByteHash::Blake3, Blake3);
    differential_script::<Goldilocks, GoldD2, _>(ByteHash::Blake3, Blake3);
}

#[test]
fn empty_hash_vectors_pin_byte_order_and_chaining() {
    // Keccak-256(empty) and BLAKE3(empty), independently fixed digest vectors.
    for (hash, expected_digest) in [
        (
            ByteHash::Keccak256,
            [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70,
            ],
        ),
        (
            ByteHash::Blake3,
            [
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
                0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
                0xe4, 0x1f, 0x32, 0x62,
            ],
        ),
    ] {
        let actual_digest = match hash {
            ByteHash::Keccak256 => Keccak256Hash.hash_iter([]),
            ByteHash::Blake3 => Blake3.hash_iter([]),
        };
        assert_eq!(actual_digest, expected_digest);
        let mut builder = CircuitBuilder::<BabyBear>::new();
        match hash {
            ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
        }
        let mut challenger = BinaryTower128Challenger::new(hash);
        let first = challenger
            .sample::<BabyBear, BabyBear>(&mut builder)
            .unwrap();
        let second = challenger
            .sample::<BabyBear, BabyBear>(&mut builder)
            .unwrap();
        let third = challenger
            .sample::<BabyBear, BabyBear>(&mut builder)
            .unwrap();
        let first_raw = u128::from_be_bytes(expected_digest[16..32].try_into().unwrap());
        let second_raw = u128::from_be_bytes(expected_digest[0..16].try_into().unwrap());
        bind_raw::<BabyBear, BabyBear>(&mut builder, &first, first_raw);
        bind_raw::<BabyBear, BabyBear>(&mut builder, &second, second_raw);
        let chained_digest = match hash {
            ByteHash::Keccak256 => Keccak256Hash.hash_iter(expected_digest),
            ByteHash::Blake3 => Blake3.hash_iter(expected_digest),
        };
        bind_raw::<BabyBear, BabyBear>(
            &mut builder,
            &third,
            u128::from_be_bytes(chained_digest[16..32].try_into().unwrap()),
        );
        builder.build().unwrap().runner().run().unwrap();

        let first_eight = match hash {
            ByteHash::Keccak256 => 0x7bfad8045d85a470u64,
            ByteHash::Blake3 => 0x4c9a93cae41f3262u64,
        };
        let mut builder = CircuitBuilder::<BabyBear>::new();
        match hash {
            ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
        }
        let mut challenger = BinaryTower128Challenger::new(hash);
        let width = (usize::BITS as usize - 1).min(63);
        let bits = challenger
            .sample_bits::<BabyBear, BabyBear>(&mut builder, width)
            .unwrap();
        bind_bits::<BabyBear, BabyBear>(&mut builder, &bits, first_eight as usize);
        builder.build().unwrap().runner().run().unwrap();
    }
}

#[test]
fn independent_sample_limbs_reject_low_and_high_corruption() {
    let mut native = Native::<Keccak256Hash>::from_hasher(vec![], Keccak256Hash);
    let expected: BinaryField128 = native.sample();
    let expected_limbs = raw_limbs(expected.to_repr());
    let mut builder = CircuitBuilder::<BabyBear>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let supplied = builder.alloc_private_input_array::<8>("independent expected sample limbs");
    let mut challenger = BinaryTower128Challenger::new(ByteHash::Keccak256);
    let sample = challenger
        .sample::<BabyBear, BabyBear>(&mut builder)
        .unwrap();
    let actual = builder.binary128_to_limbs::<BabyBear>(&sample).unwrap();
    for (computed, independent) in actual.into_iter().zip(supplied) {
        let difference = builder.sub(computed, independent);
        builder.assert_zero(difference);
    }
    let built = builder.build().unwrap();
    let baseline: Vec<_> = expected_limbs.map(BabyBear::from_u16).into();
    let mut honest = built.runner();
    honest.set_private_inputs(&baseline).unwrap();
    honest.run().unwrap();
    for index in [0, 7] {
        let mut changed = baseline.clone();
        changed[index] += BabyBear::ONE;
        let mut runner = built.runner();
        runner.set_private_inputs(&changed).unwrap();
        assert!(matches!(
            runner.run(),
            Err(CircuitError::WitnessConflict { .. })
        ));
    }
}

#[test]
fn missing_hash_plugin_is_retryable_without_consuming_stream() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let mut circuit = BinaryTower128Challenger::new(ByteHash::Keccak256);
    assert!(matches!(
        circuit.sample::<BabyBear, BabyBear>(&mut builder),
        Err(CircuitBuilderError::OpNotAllowed { .. })
    ));
    builder.enable_keccak_f1600::<BabyBear>();
    let mut native = Native::<Keccak256Hash>::from_hasher(vec![], Keccak256Hash);
    draw_field::<BabyBear, BabyBear, _>(&mut builder, &mut circuit, &mut native);
    draw_field::<BabyBear, BabyBear, _>(&mut builder, &mut circuit, &mut native);
    builder.build().unwrap().runner().run().unwrap();
}

#[test]
fn invalid_width_is_rejected_before_stream_mutation() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let mut circuit = BinaryTower128Challenger::new(ByteHash::Keccak256);
    let error = circuit.sample_bits::<BabyBear, BabyBear>(&mut builder, usize::BITS as usize);
    assert!(matches!(
        error,
        Err(CircuitBuilderError::BinaryDecompositionTooManyBits { expected, n_bits })
            if expected == usize::BITS as usize - 1 && n_bits == usize::BITS as usize
    ));
    let witness = builder.binary128_constant(0).unwrap();
    let error =
        circuit.check_witness::<BabyBear, BabyBear>(&mut builder, usize::BITS as usize, &witness);
    assert!(matches!(
        error,
        Err(CircuitBuilderError::BinaryDecompositionTooManyBits { .. })
    ));
    let mut native = Native::<Keccak256Hash>::from_hasher(vec![], Keccak256Hash);
    draw_field::<BabyBear, BabyBear, _>(&mut builder, &mut circuit, &mut native);
    builder.build().unwrap().runner().run().unwrap();
}

#[test]
fn characteristic_two_is_rejected_before_hashing() {
    let mut builder = CircuitBuilder::<Gf2>::new();
    assert!(matches!(
        BinaryTower128Challenger::with_initial_limbs::<Gf2, Gf2>(
            &mut builder,
            ByteHash::Keccak256,
            &[]
        ),
        Err(CircuitBuilderError::CharacteristicTwoUnsupported { .. })
    ));
    let mut challenger = BinaryTower128Challenger::new(ByteHash::Keccak256);
    assert!(matches!(
        challenger.sample_bits::<Gf2, Gf2>(&mut builder, 0),
        Err(CircuitBuilderError::CharacteristicTwoUnsupported { .. })
    ));
}

#[test]
fn malformed_initial_and_digest_limbs_are_rejected() {
    for bad_initial in [true, false] {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        builder.enable_keccak_f1600::<BabyBear>();
        let initial = builder.alloc_private_input("initial limb");
        let mut circuit = BinaryTower128Challenger::with_initial_limbs::<BabyBear, BabyBear>(
            &mut builder,
            ByteHash::Keccak256,
            &[initial],
        )
        .unwrap();
        let digest = builder.alloc_private_input_array::<16>("digest limbs");
        circuit
            .observe_digest::<BabyBear, BabyBear>(&mut builder, &digest)
            .unwrap();
        let mut native = Native::<Keccak256Hash>::from_hasher(vec![0, 0], Keccak256Hash);
        native.observe(Hash::<BinaryField128, u8, 32>::from(DIGEST));
        draw_field::<BabyBear, BabyBear, _>(&mut builder, &mut circuit, &mut native);
        let built = builder.build().unwrap();
        let mut values = vec![BabyBear::ZERO];
        values.extend(digest_limbs().map(BabyBear::from_u16));
        let mut honest = built.runner();
        honest.set_private_inputs(&values).unwrap();
        honest.run().unwrap();
        values[if bad_initial { 0 } else { 1 }] = BabyBear::from_u32(65_536);
        let mut malformed = built.runner();
        malformed.set_private_inputs(&values).unwrap();
        assert!(matches!(
            malformed.run(),
            Err(CircuitError::WitnessConflict { .. })
        ));
    }
}

#[test]
fn nonbase_extension_transcript_limb_is_rejected() {
    let nonbase = BabyD4::from_basis_coefficients_slice(&[
        BabyBear::ZERO,
        BabyBear::ONE,
        BabyBear::ZERO,
        BabyBear::ZERO,
    ])
    .unwrap();
    assert!(!<BabyD4 as ExtensionField<BabyBear>>::is_in_basefield(
        &nonbase
    ));
    for bad_initial in [true, false] {
        let mut builder = CircuitBuilder::<BabyD4>::new();
        builder.enable_keccak_f1600::<BabyBear>();
        let initial = builder.alloc_private_input("initial limb");
        let mut circuit = BinaryTower128Challenger::with_initial_limbs::<BabyBear, BabyD4>(
            &mut builder,
            ByteHash::Keccak256,
            &[initial],
        )
        .unwrap();
        let digest = builder.alloc_private_input_array::<16>("digest limbs");
        circuit
            .observe_digest::<BabyBear, BabyD4>(&mut builder, &digest)
            .unwrap();
        let mut native = Native::<Keccak256Hash>::from_hasher(vec![0, 0], Keccak256Hash);
        native.observe(Hash::<BinaryField128, u8, 32>::from(DIGEST));
        draw_field::<BabyBear, BabyD4, _>(&mut builder, &mut circuit, &mut native);
        let built = builder.build().unwrap();
        let mut values = vec![BabyD4::ZERO];
        values.extend(digest_limbs().map(|x| BabyD4::from(BabyBear::from_u16(x))));
        let mut honest = built.runner();
        honest.set_private_inputs(&values).unwrap();
        honest.run().unwrap();
        values[if bad_initial { 0 } else { 1 }] = nonbase;
        let mut malformed = built.runner();
        malformed.set_private_inputs(&values).unwrap();
        assert!(matches!(
            malformed.run(),
            Err(CircuitError::WitnessConflict { .. })
        ));
    }
}

#[test]
fn native_generated_witness_is_accepted_and_native_rejected_candidate_fails() {
    let difficulty = 5;
    let initial = [0x22u16, 0x4433];
    let initial_bytes: Vec<u8> = initial.into_iter().flat_map(u16::to_le_bytes).collect();
    let mut base = Native::<Keccak256Hash>::from_hasher(initial_bytes, Keccak256Hash);
    let good = base.clone().grind(difficulty);
    assert!(base.clone().check_witness(difficulty, good));
    let mut bad_raw = good.to_repr().wrapping_add(1);
    while base
        .clone()
        .check_witness(difficulty, BinaryField128::from_repr(bad_raw))
    {
        bad_raw = bad_raw.wrapping_add(1);
    }
    let bad = BinaryField128::from_repr(bad_raw);
    assert!(!base.check_witness(difficulty, bad));

    for (candidate, should_pass) in [(good, true), (bad, false)] {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        builder.enable_keccak_f1600::<BabyBear>();
        let initial_targets = builder.alloc_private_input_array::<2>("initial limbs");
        let witness_limbs = builder.alloc_private_input_array::<8>("candidate limbs");
        let witness = builder
            .binary128_from_limbs::<BabyBear>(witness_limbs)
            .unwrap();
        let mut circuit = BinaryTower128Challenger::with_initial_limbs::<BabyBear, BabyBear>(
            &mut builder,
            ByteHash::Keccak256,
            &initial_targets,
        )
        .unwrap();
        circuit
            .check_witness::<BabyBear, BabyBear>(&mut builder, difficulty, &witness)
            .unwrap();
        let built = builder.build().unwrap();
        let values: Vec<_> = initial
            .into_iter()
            .chain(raw_limbs(candidate.to_repr()))
            .map(BabyBear::from_u16)
            .collect();
        let mut runner = built.runner();
        runner.set_private_inputs(&values).unwrap();
        if should_pass {
            runner.run().unwrap();
        } else {
            assert!(matches!(
                runner.run(),
                Err(CircuitError::WitnessConflict { .. })
            ));
        }
    }
}
