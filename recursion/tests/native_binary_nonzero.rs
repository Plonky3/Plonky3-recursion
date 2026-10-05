//! Native carriers retain nonzero samples, their tails and the resumed transcript.

use p3_binary_field::{BinaryChallenger, BinaryField32, BinaryField64, BinaryField128, Poly64};
use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_field::ExtensionField;
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryNonzeroChallengePlan, BinaryNonzeroChallengeTailPlan, RecursiveBinaryChallengeField,
    RecursiveBinaryTowerField,
};

type H = NativeBinaryEncoding;

fn run<CF: BinaryCoordinateField>(circuit: &Circuit<CF>, public: &[CF]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.run())
        .is_ok()
}

fn differential<F, E, CF>(tail: bool)
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
    CF: BinaryCoordinateField,
{
    let initial = [129u8, 3, 251, 7, 19, 241, 83];
    let mut native = BinaryChallenger::<F, _>::from_hasher(initial.to_vec(), Keccak256Hash);
    let mut b = CircuitBuilder::<CF>::new();
    b.enable_native_keccak_f1600().unwrap();
    let input = b.alloc_public_input_array::<7>("initial bytes");
    let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, CF>(
        &mut b,
        ByteHash::Keccak256,
        &input,
    )
    .unwrap();
    let (mut actual, mut expected, continuation) = if tail {
        let plan = BinaryNonzeroChallengeTailPlan::<E>::new(2, 4, 2).unwrap();
        let (mut expected, following) = plan.sample_native::<F, _>(&mut native).unwrap();
        expected.extend(following);
        let output = plan.sample_with_host::<H, CF>(&mut b, ch).unwrap();
        let mut actual = output.values;
        actual.extend(output.following);
        (actual, expected, output.continuation)
    } else {
        let plan = BinaryNonzeroChallengePlan::<E>::new(2, 4).unwrap();
        let expected = plan.sample_native::<F, _>(&mut native).unwrap();
        let output = plan.sample_with_host::<H, CF>(&mut b, ch).unwrap();
        (output.values, expected, output.continuation)
    };
    let observation: Vec<_> = (0..F::RAW_BITS / 8)
        .map(|i| if i == 0 { 193u8 } else { 0 })
        .collect();
    native.observe(F::from_le_byte_iter(observation.iter().copied()));
    let observation: Vec<_> = observation
        .into_iter()
        .map(|byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()))
        .collect();
    let mut ch = continuation
        .resume_with_observation_with_host::<H, CF>(&mut b, &observation)
        .unwrap();
    expected.push(native.sample_algebra_element::<E>());
    let bytes = ch
        .sample_bytes_with_host::<H, CF>(&mut b, E::RAW_BITS / 8)
        .unwrap();
    let mut bits = [ExprId::ZERO; 128];
    for (i, byte) in bytes.into_iter().enumerate() {
        bits[8 * i..8 * i + 8].copy_from_slice(&H::decompose_word(&mut b, byte, 8).unwrap());
    }
    actual.push(b.binary128_from_bits(bits).unwrap());
    let next_bits = native.sample_bits(23);
    let actual_bits = ch.sample_bits_with_host::<H, CF>(&mut b, 23).unwrap();
    let mut public: Vec<CF> = initial
        .map(|byte| H::encode_u16(u16::from(byte)).unwrap())
        .to_vec();
    for (value, native) in actual.iter().zip(expected) {
        bind_words(&mut b, value, native.raw_coordinates(), &mut public);
    }
    let mut padded_bits = [ExprId::ZERO; 128];
    padded_bits[..23].copy_from_slice(&actual_bits);
    let value = b.binary128_from_bits(padded_bits).unwrap();
    bind_words(&mut b, &value, next_bits as u128, &mut public);
    let circuit = b.build().unwrap();
    assert!(run(&circuit, &public));
    let next_offset = 7 + (if tail { 4 } else { 2 }) * 8;
    for offset in [7, next_offset, public.len() - 8] {
        let mut wrong = public.clone();
        wrong[offset] += CF::ONE;
        assert!(!run(&circuit, &wrong));
    }
    if E::RAW_BITS == 64 {
        let mut wrong = public;
        wrong[11] = CF::ONE;
        assert!(!run(&circuit, &wrong));
    }
}

fn bind_words<CF: BinaryCoordinateField>(
    b: &mut CircuitBuilder<CF>,
    value: &BinaryTower128Target,
    raw: u128,
    public: &mut Vec<CF>,
) {
    let words = b.alloc_public_input_array::<8>("expected native coordinates");
    for (i, word) in words.into_iter().enumerate() {
        let bits = H::decompose_word(b, word, 16).unwrap();
        for (&actual, expected) in value.bits()[16 * i..16 * i + 16].iter().zip(bits) {
            b.connect(actual, expected);
        }
        public.push(H::encode_u16((raw >> (16 * i)) as u16).unwrap());
    }
}

#[test]
fn native_prefix_matches_both_widths_and_carriers() {
    differential::<BinaryField128, BinaryField128, BinaryField128>(false);
    differential::<BinaryField32, BinaryField64, Poly64>(false);
}

#[test]
fn native_tail_matches_following_words_and_next_observation() {
    differential::<BinaryField128, BinaryField128, BinaryField128>(true);
    differential::<BinaryField32, BinaryField64, Poly64>(true);
}
