//! Exact native Poly64/Poly192 byte boundaries across partial digest refills.

use core::hash::Hash;

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryChallenger, Poly64, Poly192};
use p3_blake3::Blake3;
use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, HashChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{BinaryPoly192Target, ByteHash};
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_symmetric::CryptographicHasher;

fn bind<BF, EF>(b: &mut CircuitBuilder<EF>, actual: &BinaryPoly192Target, expected: Poly192)
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
{
    let native = expected.coefficients();
    for (i, limb) in b
        .binary_poly192_to_limbs::<BF>(actual)
        .unwrap()
        .into_iter()
        .enumerate()
    {
        let expected = b.define_const(EF::from_u16(
            (native[i / 4].to_bits() >> (16 * (i % 4))) as u16,
        ));
        let difference = b.sub(limb, expected);
        b.assert_zero(difference);
    }
}

fn check<BF, EF, H>(hash: ByteHash, hasher: H)
where
    BF: PrimeField64,
    EF: ExtensionField<BF> + Eq + Hash,
    H: CryptographicHasher<u8, [u8; 32]> + Send + Sync,
{
    let initial = [1u8, 219, 37, 129, 3];
    let mut native = BinaryChallenger::<Poly64, HashChallenger<u8, H, 32>>::from_hasher(
        initial.to_vec(),
        hasher,
    );
    let mut b = CircuitBuilder::<EF>::new();
    match hash {
        ByteHash::Keccak256 => b.enable_keccak_f1600::<BF>(),
        ByteHash::Blake3 => b.enable_blake3_compress::<BF>(),
    }
    let initial = initial.map(|byte| b.define_const(EF::from_u8(byte)));
    let mut ch =
        BinaryTower128Challenger::with_initial_bytes::<BF, EF>(&mut b, hash, &initial).unwrap();
    // Consecutive 24-byte samples cross both partial and empty digest buffers.
    for _ in 0..5 {
        let expected = native.sample_algebra_element::<Poly192>();
        let actual = ch.sample_poly192::<BF, EF>(&mut b).unwrap();
        bind::<BF, EF>(&mut b, &actual, expected);
    }
    for bits in [0, 31, 63, 7] {
        let expected = native.sample_bits(bits);
        let actual = ch.sample_bits::<BF, EF>(&mut b, bits).unwrap();
        for (i, actual) in actual.into_iter().enumerate() {
            let expected = b.define_const(EF::from_bool(expected >> i & 1 != 0));
            let difference = b.sub(actual, expected);
            b.assert_zero(difference);
        }
        let observed = Poly192::new([
            Poly64::new(0x80123456789abcde),
            Poly64::new(0x57a983b1de021365),
            Poly64::new(0xfefdfcfbfaf9f8f7),
        ]);
        for coefficient in observed.coefficients() {
            native.observe(coefficient);
        }
        let target = b
            .binary_poly192_constant(observed.coefficients().map(Poly64::to_bits))
            .unwrap();
        ch.observe_poly192::<BF, EF>(&mut b, &target).unwrap();
        let expected = native.sample_algebra_element::<Poly192>();
        let actual = ch.sample_poly192::<BF, EF>(&mut b).unwrap();
        bind::<BF, EF>(&mut b, &actual, expected);
        let observed = Poly64::new(0x91fedcba01234567);
        native.observe(observed);
        let target = b.binary_poly64_constant(observed.to_bits()).unwrap();
        ch.observe_poly64::<BF, EF>(&mut b, &target).unwrap();
        let expected = native.sample_algebra_element::<Poly192>();
        let actual = ch.sample_poly192::<BF, EF>(&mut b).unwrap();
        bind::<BF, EF>(&mut b, &actual, expected);
    }
    b.build().unwrap().runner().run().unwrap();
}

#[test]
fn polynomial_transcript_matches_keccak_and_blake3_over_baby_bear() {
    check::<BabyBear, BabyBear, _>(ByteHash::Keccak256, Keccak256Hash);
    check::<BabyBear, BabyBear, _>(ByteHash::Blake3, Blake3);
}

#[test]
fn polynomial_transcript_matches_native_over_prime_extension_circuits() {
    check::<BabyBear, BinomialExtensionField<BabyBear, 4>, _>(ByteHash::Blake3, Blake3);
    check::<Goldilocks, BinomialExtensionField<Goldilocks, 2>, _>(
        ByteHash::Keccak256,
        Keccak256Hash,
    );
}
