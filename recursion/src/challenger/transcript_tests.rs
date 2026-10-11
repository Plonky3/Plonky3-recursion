//! Random transcripts replayed by p3's native byte challenger and the circuit challenger.
//!
//! The native reference is `HashChallenger<u8, Keccak256Hash, 32>` behind
//! `BinaryChallenger`, which pops sampled bytes from the end of each digest and
//! re-absorbs the retained digest from its start. The circuit draws through a
//! native carrier, whose refills read the digest's byte-swapped limbs.

use alloc::vec::Vec;

use p3_binary_field::{
    BinaryChallenger, BinaryField8, BinaryField128, Poly64, Poly192, TowerLevel,
};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, HashChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_keccak::Keccak256Hash;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use crate::verifier::binary_field_policy::{
    BinaryProtocolPolicy, NativePoly64Relation, NativeTower128Relation,
};
use crate::{BinaryQueryContinuation, BinaryTower128Challenger};

type H = NativeBinaryEncoding;
type Native = BinaryChallenger<BinaryField8, HashChallenger<u8, Keccak256Hash, 32>>;

/// Draws one field challenge in the circuit and binds it to the native transcript's next one.
type Draw<F> = fn(&mut CircuitBuilder<F>, &mut BinaryTower128Challenger, &mut Native);

const INITIAL: [u8; 5] = [7, 0, 251, 19, 3];

fn byte(native: &mut Native) -> u8 {
    let byte: BinaryField8 = native.sample();
    byte.to_repr()
}

fn bind<F: BinaryCoordinateField>(b: &mut CircuitBuilder<F>, actual: ExprId, raw: u16) {
    let expected = b.define_const(H::encode_u16(raw).unwrap());
    b.connect(actual, expected);
}

/// `count` random public units of `width` bytes each, which the native transcript observes
/// as their little-endian bytes.
fn observed<F: BinaryCoordinateField>(
    b: &mut CircuitBuilder<F>,
    native: &mut Native,
    public: &mut Vec<F>,
    rng: &mut SmallRng,
    (count, width): (usize, usize),
) -> Vec<ExprId> {
    let targets = (0..count).map(|_| b.public_input()).collect();
    for _ in 0..count {
        let unit: u16 = if width == 1 {
            rng.random::<u8>().into()
        } else {
            rng.random()
        };
        let bytes: Vec<_> = unit.to_le_bytes()[..width]
            .iter()
            .map(|&byte| BinaryField8::from_repr(byte))
            .collect();
        native.observe_slice(&bytes);
        public.push(H::encode_u16(unit).unwrap());
    }
    targets
}

/// A circuit of `steps` random observations and draws from [`INITIAL`], ending with a field
/// draw, and its public inputs: every observed unit. Each draw is bound to the native
/// transcript's value, so the circuit accepts exactly the observed public inputs.
fn random_transcript<F: BinaryCoordinateField>(
    seed: u64,
    steps: usize,
    draw: Draw<F>,
) -> (Circuit<F>, Vec<F>) {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut native = Native::from_hasher(INITIAL.to_vec(), Keccak256Hash);
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let initial = INITIAL.map(|unit| b.define_const(H::encode_u16(unit.into()).unwrap()));
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
        &mut b,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    let mut public = Vec::new();
    for _ in 0..steps {
        match rng.random_range(0..8) {
            0 => {
                let count = rng.random_range(0..10);
                let bytes = observed(&mut b, &mut native, &mut public, &mut rng, (count, 1));
                ch.observe_bytes_with_host::<H, F>(&mut b, &bytes).unwrap();
            }
            1 => {
                let count = rng.random_range(0..13);
                let words = observed(&mut b, &mut native, &mut public, &mut rng, (count, 2));
                ch.observe_words_with_host::<H, F>(&mut b, &words).unwrap();
            }
            2 => {
                let count = rng.random_range(1..8);
                for actual in ch.sample_bytes_with_host::<H, F>(&mut b, count).unwrap() {
                    let expected = byte(&mut native);
                    bind(&mut b, actual, expected.into());
                }
            }
            3 => {
                let bits = rng.random_range(0..41);
                let expected = native.sample_bits(bits);
                let actual = ch.sample_bits_with_host::<H, F>(&mut b, bits).unwrap();
                assert_eq!(actual.len(), bits);
                for (i, bit) in actual.into_iter().enumerate() {
                    bind(&mut b, bit, (expected >> i & 1) as u16);
                }
            }
            4 => {
                let count = rng.random_range(1..6);
                for actual in ch.sample_words_with_host::<H, F>(&mut b, count).unwrap() {
                    let expected = u16::from_le_bytes([byte(&mut native), byte(&mut native)]);
                    bind(&mut b, actual, expected);
                }
            }
            5 => {
                let count = rng.random_range(1..6);
                let actual = ch
                    .sample_byte_bits_with_host::<H, F>(&mut b, count)
                    .unwrap();
                for bits in actual.chunks(8) {
                    let expected = byte(&mut native);
                    for (i, &bit) in bits.iter().enumerate() {
                        bind(&mut b, bit, (expected >> i & 1).into());
                    }
                }
            }
            6 => draw(&mut b, &mut ch, &mut native),
            _ => {
                // A draw retains its digest, and a nonempty observation resumes from it.
                draw(&mut b, &mut ch, &mut native);
                let (hash, digest) = ch.retained_query_digest().unwrap();
                let token = BinaryQueryContinuation::from_digest(hash, digest);
                let count = rng.random_range(1..6);
                let bytes = observed(&mut b, &mut native, &mut public, &mut rng, (count, 1));
                ch = token
                    .resume_with_observation_with_host::<H, F>(&mut b, &bytes)
                    .unwrap();
            }
        }
    }
    draw(&mut b, &mut ch, &mut native);
    (b.build().unwrap(), public)
}

fn draw_tower(
    b: &mut CircuitBuilder<BinaryField128>,
    ch: &mut BinaryTower128Challenger,
    native: &mut Native,
) {
    type P = NativeTower128Relation;
    let expected: BinaryField128 = native.sample();
    let actual = P::sample::<H>(b, ch).unwrap();
    let constant = b.native_tower128_constant(expected.to_repr());
    P::assert_equal(b, &actual, &constant);
}

fn draw_poly(
    b: &mut CircuitBuilder<Poly64>,
    ch: &mut BinaryTower128Challenger,
    native: &mut Native,
) {
    type P = NativePoly64Relation;
    let raw = core::array::from_fn(|_| u64::from_le_bytes(core::array::from_fn(|_| byte(native))));
    let actual = P::sample::<H>(b, ch).unwrap();
    let constant = b.native_poly192_constant(raw);
    P::assert_equal(b, &actual, &constant);
}

/// A random Tower128 transcript over the native `BinaryField128` carrier.
pub(crate) fn tower_transcript(
    seed: u64,
    steps: usize,
) -> (Circuit<BinaryField128>, Vec<BinaryField128>) {
    random_transcript(seed, steps, draw_tower)
}

/// A random Poly64 transcript, with Poly192 field draws, over the native `Poly64` carrier.
pub(crate) fn poly_transcript(seed: u64, steps: usize) -> (Circuit<Poly64>, Vec<Poly64>) {
    random_transcript(seed, steps, draw_poly)
}

/// The circuit accepts the observed inputs and refuses any one of them changed in its
/// lowest coordinate, which changes every later refill and so the final field draw.
fn accepts_exactly_the_transcript<F: BinaryCoordinateField>(circuit: &Circuit<F>, public: &[F]) {
    let runs = |public: &[F]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    assert!(runs(public));
    for i in [0, public.len() / 2, public.len().saturating_sub(1)] {
        if let Some(&value) = public.get(i) {
            let mut wrong = public.to_vec();
            wrong[i] = value + F::ONE;
            assert!(!runs(&wrong), "changed observation {i}");
        }
    }
}

#[test]
fn random_tower_transcripts_match_the_native_byte_challenger() {
    for seed in 0..12 {
        let (circuit, public) = tower_transcript(seed, 24);
        accepts_exactly_the_transcript(&circuit, &public);
    }
}

#[test]
fn random_poly_transcripts_match_the_native_byte_challenger() {
    // The Poly192 decoding above is p3's `BinaryChallenger<Poly64, _>` draw.
    let mut bytes = Native::from_hasher(INITIAL.to_vec(), Keccak256Hash);
    let mut poly = BinaryChallenger::<Poly64, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
        INITIAL.to_vec(),
        Keccak256Hash,
    );
    for _ in 0..3 {
        let raw: [u64; 3] = core::array::from_fn(|_| {
            u64::from_le_bytes(core::array::from_fn(|_| byte(&mut bytes)))
        });
        let expected = poly.sample_algebra_element::<Poly192>();
        let coefficients: &[Poly64] = expected.as_basis_coefficients_slice();
        assert_eq!(coefficients, raw.map(Poly64::new));
    }
    for seed in 0..12 {
        let (circuit, public) = poly_transcript(seed, 24);
        accepts_exactly_the_transcript(&circuit, &public);
    }
}

/// A random Poly64 transcript's traces prove and verify through the native bus with the
/// Keccak table committed densely, and the proof does not verify for a changed observation.
#[test]
fn random_poly_transcript_circuit_proves() {
    use p3_circuit_prover::native_bus::NativeBusCircuit;
    use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

    use crate::artifact::{
        BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters, BinaryNativeVerifierSpec,
    };
    use crate::verifier::VerifierLimits;

    let (circuit, statement) = poly_transcript(7, 24);
    let prepared = NativeBusCircuit::new(&circuit, "poly-transcript").unwrap();
    let parameters = |variables| {
        BinaryNativePolyWhirPcsParameters::new(
            variables,
            ProtocolParameters {
                starting_log_inv_rate: 2,
                round_log_inv_rates: alloc::vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                security_level: 24,
                pow_bits: 0,
            },
            ByteHash::Keccak256,
            0,
        )
        .unwrap()
    };
    let spec = BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables()),
        preprocessed: prepared.preprocessed_variables().map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"poly-transcript".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 16,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec,
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let proof = prover.prove(&public, traces).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let mut wrong = statement;
    wrong[0] += Poly64::ONE;
    let wrong = prepared.public_values(&wrong).unwrap();
    assert!(authority.verify_native(&proof, &wrong).is_err());
}
