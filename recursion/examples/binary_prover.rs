//! Hybrid example: native binary-field proving followed by prime-field recursion.
//!
//! Prove seven successive squarings in Poly64 using additive WHIR with Poly192
//! challenges and a BLAKE3 transcript, then recursively verify the native proof
//! in a BabyBear circuit proved with Poseidon2/FRI.
//!
//! For binary-field proving and binary-field recursion, run either native example:
//! ```sh
//! cargo run -p p3-recursion --profile optimized --features parallel \
//!     --example native_binary_recursion -- --layers 1
//! cargo run -p p3-recursion --profile optimized --features parallel \
//!     --example native_poly_recursion -- --layers 1
//! ```
//!
//! Run from the workspace root:
//! ```sh
//! cargo run -p p3-recursion --release --example binary_prover
//! ```
//!
//! The small security parameters below are for demonstration only.

use std::error::Error;
use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::Poly64;
use p3_circuit::ops::ByteHash;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::ProveNextLayerParams;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    BinaryNativeVerifierSpec,
};
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2BinaryConfig, FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary,
};
use p3_recursion::prepared::PreparedBinaryPolyWhirMultiStarkLayer;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

const LOG_HEIGHT: usize = 3;
const HEIGHT: usize = 1 << LOG_HEIGHT;

/// One trace column: x, x^2, x^4, ... . Public values bind the first and last rows.
struct SquaringAir;

impl BaseAir<Poly64> for SquaringAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        2
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![0]
    }
}

impl<AB: AirBuilder<F = Poly64>> Air<AB> for SquaringAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current = main.current_slice()[0];
        let next = main.next_slice()[0];
        let initial = builder.public_values()[0];
        let final_value = builder.public_values()[1];
        builder.when_first_row().assert_eq(current, initial);
        builder.when_transition().assert_eq(next, current * current);
        builder.when_last_row().assert_eq(current, final_value);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Poly64::new interprets these bits in the binary field's polynomial basis.
    let seed = Poly64::new(0xfedc_ba98_7654_3210);
    let mut values = Vec::with_capacity(HEIGHT);
    let mut value = seed;
    for _ in 0..HEIGHT {
        values.push(value);
        value *= value;
    }
    let result = values[HEIGHT - 1];
    let public = vec![vec![seed, result]];
    let trace = RowMajorMatrix::new(values, 1);
    println!(
        "Poly64: {} squarings, input = {:#018x}, output = {:#018x}",
        HEIGHT - 1,
        seed.to_bits(),
        result.to_bits(),
    );

    let limits = ArtifactLimits::default();
    let spec = BinaryNativeVerifierSpec {
        // A single column with 2^LOG_HEIGHT rows needs LOG_HEIGHT variables.
        main: BinaryNativePolyWhirPcsParameters::new(
            LOG_HEIGHT,
            ProtocolParameters {
                starting_log_inv_rate: 2,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                security_level: 24,
                pow_bits: 0,
            },
            ByteHash::Blake3,
            0,
        )?,
        preprocessed: None,
        transcript_hash: ByteHash::Blake3,
        initial_bytes: b"binary-prover-example-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 16,
    };
    // The authority retains the AIR, verification key, and native parameters.
    // Heights passed to setup are logarithmic.
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup_with_artifact_limits(
        vec![SquaringAir],
        vec![LOG_HEIGHT],
        spec,
        limits,
    )?;

    println!("Proving and verifying the native Poly64/Poly192 WHIR proof...");
    let start = Instant::now();
    let native_proof = prover.prove(&public, vec![trace])?;
    // Only successful native verification against the expected public values
    // can produce this checked token for the prepared recursion layer.
    let checked = authority.verify_native(&native_proof, &public)?;
    println!("Native proof verified in {:.2?}", start.elapsed());

    let output_config = baby_bear_d4_poseidon2_binary(
        &FriConfigV1::new(
            SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
            1, // log_blowup
            0, // log_final_poly_len
            2, // max_log_arity
            2, // num_queries (demonstration only)
            0, // commit_pow_bits
            0, // query_pow_bits
            0, // input_cap_height
            0, // commit_cap_height
            0, // num_random_codewords
            0, // salt_elements
        ),
        &limits.verifier,
    )?;
    println!("Preparing, proving, and verifying the BabyBear recursion layer...");
    let start = Instant::now();
    let layer = PreparedBinaryPolyWhirMultiStarkLayer::<BabyBearD4Poseidon2BinaryConfig, 4>::from_native_authority(
        &authority,
        output_config,
        ProveNextLayerParams::default(),
    )?;
    let recursive_output = layer.prove_verified(&checked)?;
    // Each Poly64 public value is packed into four 16-bit BabyBear limbs.
    // Pack the caller's expected statement independently of the proof.
    let statement = layer.statement_layout().pack::<BabyBear>(&public)?;
    layer.verifier().verify(&recursive_output.0, &statement)?;
    println!("Recursive proof verified in {:.2?}", start.elapsed());
    Ok(())
}
