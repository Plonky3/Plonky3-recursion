//! Pins for the dense native WHIR identity and proof encoding.
//!
//! The constants fix the canonical verifier bytes and the encoded proof bytes of
//! the dense format. They are intentionally updatable only for deliberate
//! format changes.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::BinaryField128;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit_prover::native_bus::NativeBusCircuit;
use p3_keccak::Keccak256Hash;
use p3_recursion::artifact::{
    BinaryNativeVerifierSpec, BinaryNativeWhirAuthority, BinaryNativeWhirPcsParameters,
};
use p3_recursion::verifier::VerifierLimits;
use p3_symmetric::CryptographicHasher;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = BinaryField128;

const TINY_AIR_IDENTITY_DIGEST: &str =
    "b1260b9a33fcffe81446dbda6a8a9b5a0b7614739843f1f8afa4f7a8c649fb3a";
const NATIVE_BUS_IDENTITY_DIGEST: &str =
    "47541409752fc16e3b766041f3a740e4b9feb047333630dc7011c7b97a71fee7";
const NATIVE_BUS_PROOF_DIGEST: &str =
    "8c1e46f686992f059080fd7e6cf29c93e9179506ba46edd26adc3f60a32ca04c";

fn digest(bytes: &[u8]) -> String {
    Keccak256Hash
        .hash_iter(bytes.iter().copied())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct ConstantAir;
impl BaseAir<F> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for ConstantAir {
    fn eval(&self, b: &mut AB) {
        b.assert_eq(b.main().current_slice()[0], b.public_values()[0]);
    }
}

const fn protocol() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 24,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(1),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 2,
    }
}

fn spec(
    variables: usize,
    preprocessed: Option<usize>,
) -> BinaryNativeVerifierSpec<BinaryNativeWhirPcsParameters<F>> {
    let parameters =
        |n| BinaryNativeWhirPcsParameters::<F>::new(n, protocol(), ByteHash::Keccak256, 0).unwrap();
    BinaryNativeVerifierSpec {
        main: parameters(variables),
        preprocessed: preprocessed.map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"dense-format-pin".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 16,
    }
}

fn tiny_air_identity() -> String {
    let (_, authority) = BinaryNativeWhirAuthority::<F, _>::setup(
        vec![ConstantAir],
        vec![3],
        spec(3, None),
        &VerifierLimits::default(),
    )
    .unwrap();
    digest(authority.canonical_verifier_bytes())
}

/// Identity digest and encoded proof for a circuit with three Keccak-f calls.
fn native_bus_pins() -> (String, Vec<u8>) {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let message = b.alloc_public_input_array::<3>("message");
    let mut state = message.to_vec();
    for _ in 0..3 {
        state = b.native_keccak256_bytes(&state).unwrap().to_vec();
    }
    let expected = b.alloc_public_input_array::<32>("digest");
    for (actual, expected) in state.iter().zip(expected) {
        b.connect(*actual, expected);
    }
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "pin").unwrap();

    let mut bytes = b"abc".to_vec();
    for _ in 0..3 {
        bytes = Keccak256Hash.hash_iter(bytes.iter().copied()).to_vec();
    }
    let statement: Vec<_> = b"abc"
        .iter()
        .chain(&bytes)
        .map(|&byte| F::from_raw_coordinates(byte as u128).unwrap())
        .collect();
    let (prover, authority) = BinaryNativeWhirAuthority::<F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(prepared.main_variables(), prepared.preprocessed_variables()),
        &VerifierLimits {
            max_rounds: 256,
            max_metadata_entries: 1 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let proof = prover.prove(&public, traces).unwrap();
    authority.verify_native(&proof, &public).unwrap();
    let encoded = authority.encode_native_proof(&proof, &public).unwrap();
    (digest(authority.canonical_verifier_bytes()), encoded)
}

#[test]
fn dense_whir_identity_pin_tiny_air() {
    assert_eq!(tiny_air_identity(), TINY_AIR_IDENTITY_DIGEST);
}

#[test]
fn dense_whir_nativebus_identity_and_proof_pins() {
    let (identity, proof) = native_bus_pins();
    assert_eq!(identity, NATIVE_BUS_IDENTITY_DIGEST);
    assert_eq!(digest(&proof), NATIVE_BUS_PROOF_DIGEST);
}

#[test]
fn dense_whir_proof_is_deterministic() {
    let (first_identity, first) = native_bus_pins();
    let (second_identity, second) = native_bus_pins();
    assert_eq!(first_identity, second_identity);
    assert_eq!(first, second);
}
