//! Native Poly64 proving and recursion with Poly192 challenges.
//!
//! cargo run -p p3-recursion --profile optimized --features parallel \
//!     --example native_poly_recursion -- --layers 3
//!
//! The defaults (WHIR security level 32 with 24 grinding bits, Merkle cap height 4) keep every
//! layer within the default limits. When a layer exceeds one anyway, the error names the flag
//! that raises it and a value to start from.
//!
//! Measured without any limit flag on a 14-core Apple M-series machine with 48 GB (time of the
//! last layer; wall time, maximum resident set and peak memory footprint of the whole run):
//!
//! | --layers | witnesses | codeword cells | last layer | wall   | resident | footprint |
//! |----------|-----------|----------------|------------|--------|----------|-----------|
//! | 2        | 1,521,969 | 402,653,184    | 6.9 s      | 8.3 s  | 15.2 GB  | 14.7 GB   |
//! | 3        | 1,948,639 | 671,088,640    | 10.9 s     | 20.1 s | 25.5 GB  | 23.7 GB   |
//!
//! Layer 1 takes 0.48 s with 17,921 witnesses and 5,242,880 codeword cells. From layer 3 on,
//! more than 2,621 Keccak-f calls (25 trace rows each) give the Keccak table 2^17 rows instead
//! of 2^16; hence the default limits of 2^29 trace cells and 2^30 codeword cells, 4 GiB and
//! 8 GiB of Poly64 cells.
//!
//! Requests four bits of composed security and uses non-hiding proofs. Limits count field cells
//! or graph entries, not bytes.

use std::error::Error;
use std::time::Instant;

use clap::Parser;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::Poly64;
use p3_circuit::CircuitConstructionLimits;
use p3_circuit::ops::ByteHash;
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    BinaryNativeVerifierSpec,
};
use p3_recursion::prepared::{NativeBinaryRecursionOptions, PreparedNativeBinaryPolyWhirLayer};
use p3_recursion::verifier::VerifierLimits;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

#[path = "common/limit_hint.rs"]
mod limit_hint;
use limit_hint::at_layer;

/// Freed codewords and traces go back to the OS promptly, which keeps peak footprint near
/// the live working set between the large proving buffers.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

type F = Poly64;
#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 1)]
    layers: usize,
    #[arg(long, default_value_t = 1 << 22)]
    max_witnesses: usize,
    #[arg(long, default_value_t = 1 << 22)]
    max_operations: usize,
    #[arg(long, default_value_t = 1 << 22)]
    max_expression_nodes: usize,
    /// Maximum retained wiring equalities during construction.
    #[arg(long, default_value_t = 1 << 22)]
    max_pending_connects: usize,
    /// Maximum retained non-primitive calls during construction.
    #[arg(long, default_value_t = 1 << 20)]
    max_non_primitive_calls: usize,
    /// Maximum retained non-primitive input and output slots during construction.
    #[arg(long, default_value_t = 1 << 27)]
    max_non_primitive_slots: usize,
    /// Maximum combined trace, preprocessing, and temporary field cells.
    #[arg(long, default_value_t = 1 << 29)]
    max_trace_cells: usize,
    /// Maximum combined initial main and preprocessing codeword cells.
    #[arg(long, default_value_t = 1 << 30)]
    max_pcs_codeword_cells: usize,
    /// Maximum aggregate verifier rounds in each recursive output authority. It bounds the
    /// work of verifying an untrusted output proof, not prover memory.
    #[arg(long, default_value_t = 1024)]
    max_verifier_rounds: usize,
    /// WHIR security level per opening; composed security still requires four bits.
    #[arg(long, default_value_t = 32)]
    pcs_security_level: usize,
    /// Merkle cap height for the recursive output proofs.
    #[arg(long, default_value_t = 4)]
    cap_height: usize,
    /// WHIR grinding bits per recursive opening; queries cover the rest of the security level.
    #[arg(long, default_value_t = 24)]
    pow_bits: usize,
}
struct SquaringAir;
impl BaseAir<F> for SquaringAir {
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
impl<AB: AirBuilder<F = F>> Air<AB> for SquaringAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let current = main.current_slice()[0];
        let next = main.next_slice()[0];
        let initial = b.public_values()[0];
        let expected = b.public_values()[1];
        b.when_first_row().assert_eq(current, initial);
        b.when_transition().assert_eq(next, current * current);
        b.when_last_row().assert_eq(current, expected);
    }
}
const fn protocol() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 8,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(1),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}
fn recursive_protocol(security_level: usize, pow_bits: usize) -> ProtocolParameters {
    ProtocolParameters {
        security_level,
        pow_bits,
        folding_factor: FoldingFactor::Constant(4),
        ..protocol()
    }
}
fn options(depth: usize, args: &Args) -> NativeBinaryRecursionOptions {
    NativeBinaryRecursionOptions {
        main: recursive_protocol(args.pcs_security_level, args.pow_bits),
        preprocessed: recursive_protocol(args.pcs_security_level, args.pow_bits),
        cap_height: args.cap_height,
        initial_bytes: format!("native-poly-recursion-layer-{depth}").into_bytes(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 4,
        max_pcs_codeword_cells: args.max_pcs_codeword_cells,
        artifact_limits: ArtifactLimits {
            verifier: VerifierLimits {
                max_rounds: args.max_verifier_rounds,
                max_metadata_entries: 1 << 20,
                ..Default::default()
            },
            ..Default::default()
        },
    }
}
fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if args.layers == 0 {
        return Err("--layers must be positive".into());
    }
    if args.pow_bits >= args.pcs_security_level {
        return Err("--pow-bits must be below --pcs-security-level".into());
    }
    let input = F::new(0xfedcba9876543210);
    let mut values = vec![input];
    for _ in 0..3 {
        let value = *values.last().unwrap();
        values.push(value * value);
    }
    let output = *values.last().unwrap();
    let mut expected = vec![vec![input, output]];
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePolyWhirPcsParameters::new(2, protocol(), ByteHash::Keccak256, 0)?,
        preprocessed: None,
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-poly-recursion-source-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        vec![SquaringAir],
        vec![2],
        spec,
        &VerifierLimits::default(),
    )?;
    let proof = prover.prove(&expected, vec![RowMajorMatrix::new(values, 1)])?;
    let mut checked = authority.verify_native(&proof, &expected)?;
    println!(
        "Poly64 source verified: {:#018x} -> {:#018x}",
        input.to_bits(),
        output.to_bits()
    );
    let limits = DirectCircuitLimits {
        max_witnesses: args.max_witnesses,
        max_operations: args.max_operations,
        max_trace_cells: args.max_trace_cells,
    };
    let construction_limits = CircuitConstructionLimits {
        max_expression_nodes: args.max_expression_nodes,
        max_pending_connects: args.max_pending_connects,
        max_non_primitive_calls: args.max_non_primitive_calls,
        max_non_primitive_slots: args.max_non_primitive_slots,
    };
    println!("Preparing native recursion layer 1...");
    let mut layer =
        PreparedNativeBinaryPolyWhirLayer::from_native_authority_with_construction_limits(
            &authority,
            options(1, &args),
            &limits,
            &construction_limits,
        )
        .map_err(at_layer(1))?;
    drop(prover);
    for depth in 1..=args.layers {
        let start = Instant::now();
        println!(
            "Layer {depth}: {} witnesses, {} initial codeword cells",
            layer.circuit().witness_count,
            layer.initial_codeword_cells()
        );
        let next_expected = layer
            .output_public_values(&expected)
            .map_err(at_layer(depth))?;
        let recursive = layer.prove_verified(&checked).map_err(at_layer(depth))?;
        checked = layer
            .verify(&recursive, &expected)
            .map_err(at_layer(depth))?;
        println!(
            "Native Poly64/Poly192 layer {depth} proved and verified in {:.2?}",
            start.elapsed()
        );
        expected = next_expected;
        if depth < args.layers {
            println!("Preparing native recursion layer {}...", depth + 1);
            let authority = layer.into_authority();
            layer =
                PreparedNativeBinaryPolyWhirLayer::from_native_authority_with_construction_limits(
                    &authority,
                    options(depth + 1, &args),
                    &limits,
                    &construction_limits,
                )
                .map_err(at_layer(depth + 1))?;
        }
    }
    Ok(())
}
