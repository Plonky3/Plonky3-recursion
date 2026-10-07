//! Native Tower128 proving followed by native Tower128 recursion. `--pcs
//! folding|whir` selects the polynomial commitment of the source proof and of
//! every recursion layer.
//!
//! cargo run -p p3-recursion --profile optimized --features parallel \
//!     --example native_binary_recursion -- --layers 2
//!
//! The defaults (WHIR security level 32 with 24 grinding bits, Merkle cap
//! height 4) keep every layer within the default limits. The recursive verifier
//! levels off from layer 4: about 983k witnesses, 2,595 Keccak-f calls and
//! 335,544,320 initial codeword cells (5 GiB) per layer.
//!
//! Measured with the defaults on a 14-core Apple M-series machine with 48 GB
//! (fastest observed time of the last layer; peak memory footprint and maximum
//! resident set of the whole run):
//!
//! | --layers | last layer | footprint | resident |
//! |----------|------------|-----------|----------|
//! | 1        | 1.6 s      | 0.3 GB    | 0.3 GB   |
//! | 2        | 35 s       | 11.6 GB   | 13.8 GB  |
//! | 3        | 45 s       | 13.4 GB   | 17.8 GB  |
//! | 4        | 45 s       | 13.5 GB   | 19.6 GB  |
//!
//! Other jobs on the machine slowed layer 1 by up to 4.5x and later layers by
//! up to 1.8x. Grinding takes most of layer 1 and 1.5-6 s of each later layer.
//! With `--pow-bits 20`, layer 2 takes 40-46 s (15.5 GB resident) but layer 3
//! needs 603,979,776 codeword cells. With `--cap-height 0 --pow-bits 0`, layer
//! 2 takes 95 s (24 GB resident) and needs
//! `--max-pcs-codeword-cells 1073741824`.
//!
//! Requests four bits of composed security and uses non-hiding proofs. Limits
//! count field cells or graph entries, not bytes.

use std::error::Error;
use std::time::Instant;

use clap::Parser;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::CircuitConstructionLimits;
use p3_circuit::ops::ByteHash;
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
    BinaryNativeWhirAuthority, BinaryNativeWhirPcsParameters,
};
use p3_recursion::prepared::{
    NativeBinaryFoldingRecursionOptions, NativeBinaryRecursionOptions, PreparedNativeBinaryLayer,
    PreparedNativeBinaryWhirLayer,
};
use p3_recursion::verifier::VerifierLimits;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

/// Freed codewords and traces go back to the OS promptly, which keeps peak footprint near
/// the live working set between the large proving buffers.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

type F = BinaryField128;
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Pcs {
    Whir,
    Folding,
}
#[derive(Parser)]
struct Args {
    /// Polynomial commitment for the source proof and every recursion layer.
    #[arg(long, value_enum, default_value_t = Pcs::Whir)]
    pcs: Pcs,
    /// Log folding factor of the recursive output PCS (both WHIR and folding).
    #[arg(long, default_value_t = 4)]
    fold_arity: usize,
    /// Log inverse rate of the recursive output PCS (both WHIR and folding).
    #[arg(long, default_value_t = 1)]
    log_inv_rate: usize,
    /// Extra in-circuit query candidates beyond each folding PCS's query count.
    #[arg(long, default_value_t = 8)]
    query_draw_slack: usize,
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
    /// Maximum combined trace, preprocessing, and temporary field cells.
    #[arg(long, default_value_t = 1 << 28)]
    max_trace_cells: usize,
    /// Maximum combined initial main and preprocessing codeword cells.
    #[arg(long, default_value_t = 1 << 29)]
    max_pcs_codeword_cells: usize,
    /// Maximum aggregate verifier rounds in each recursive output authority.
    #[arg(long, default_value_t = 256)]
    max_verifier_rounds: usize,
    /// PCS security level per opening; composed security still requires four bits.
    #[arg(long, default_value_t = 32)]
    pcs_security_level: usize,
    /// Merkle cap height for the recursive output proofs.
    #[arg(long, default_value_t = 4)]
    cap_height: usize,
    /// Grinding bits per recursive opening (both WHIR and folding); queries cover the rest
    /// of the security level.
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
fn recursive_protocol(args: &Args) -> ProtocolParameters {
    ProtocolParameters {
        security_level: args.pcs_security_level,
        pow_bits: args.pow_bits,
        folding_factor: FoldingFactor::Constant(args.fold_arity),
        starting_log_inv_rate: args.log_inv_rate,
        ..protocol()
    }
}
fn options(depth: usize, args: &Args) -> NativeBinaryRecursionOptions {
    NativeBinaryRecursionOptions {
        main: recursive_protocol(args),
        preprocessed: recursive_protocol(args),
        cap_height: args.cap_height,
        initial_bytes: format!("native-binary-recursion-layer-{depth}").into_bytes(),
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
    match args.pcs {
        Pcs::Whir => run_whir(&args),
        Pcs::Folding => run_folding(&args),
    }
}
fn folding_options(depth: usize, args: &Args) -> NativeBinaryFoldingRecursionOptions {
    let params = BinaryPcsParams {
        log_inv_rate: args.log_inv_rate,
        pow_bits: args.pow_bits,
        security_level: args.pcs_security_level,
    };
    NativeBinaryFoldingRecursionOptions {
        main: params,
        preprocessed: params,
        log_folding_factor: args.fold_arity,
        cap_height: args.cap_height,
        query_draw_slack: args.query_draw_slack,
        initial_bytes: format!("native-binary-recursion-layer-{depth}").into_bytes(),
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
const fn circuit_limits(args: &Args) -> (DirectCircuitLimits, CircuitConstructionLimits) {
    (
        DirectCircuitLimits {
            max_witnesses: args.max_witnesses,
            max_operations: args.max_operations,
            max_trace_cells: args.max_trace_cells,
        },
        CircuitConstructionLimits {
            max_expression_nodes: args.max_expression_nodes,
            max_pending_connects: args.max_pending_connects,
            max_non_primitive_calls: 1 << 20,
            max_non_primitive_slots: 1 << 27,
        },
    )
}
fn source_trace() -> (F, F, Vec<F>) {
    let input = F::from_repr(0xfedcba98765432108123456789abcdef);
    let mut values = vec![input];
    for _ in 0..3 {
        let value = *values.last().unwrap();
        values.push(value * value);
    }
    let output = *values.last().unwrap();
    (input, output, values)
}
fn run_whir(args: &Args) -> Result<(), Box<dyn Error>> {
    let (input, output, values) = source_trace();
    let mut expected = vec![vec![input, output]];
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativeWhirPcsParameters::<F>::new(2, protocol(), ByteHash::Keccak256, 0)?,
        preprocessed: None,
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-binary-recursion-source-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeWhirAuthority::<F, _>::setup(
        vec![SquaringAir],
        vec![2],
        spec,
        &VerifierLimits::default(),
    )?;
    let proof = prover.prove(&expected, vec![RowMajorMatrix::new(values, 1)])?;
    let mut checked = authority.verify_native(&proof, &expected)?;
    println!(
        "Tower128 source verified: {:#034x} -> {:#034x}",
        input.to_repr(),
        output.to_repr()
    );
    let (limits, construction_limits) = circuit_limits(args);
    println!("Preparing native recursion layer 1...");
    let mut layer = PreparedNativeBinaryWhirLayer::from_native_authority_with_construction_limits(
        &authority,
        options(1, args),
        &limits,
        &construction_limits,
    )?;
    drop(prover);
    for depth in 1..=args.layers {
        let start = Instant::now();
        println!(
            "Layer {depth}: {} witnesses, {} initial codeword cells",
            layer.circuit().witness_count,
            layer.initial_codeword_cells()
        );
        let next_expected = layer.output_public_values(&expected)?;
        let recursive = layer.prove_verified(&checked)?;
        checked = layer.verify(&recursive, &expected)?;
        println!(
            "Native Tower128 layer {depth} proved and verified in {:.2?}",
            start.elapsed()
        );
        let bytes = match layer
            .authority()
            .encode_native_proof(&recursive, &next_expected)
        {
            Ok(bytes) => bytes.len().to_string(),
            Err(error) => format!("unavailable ({error:?})"),
        };
        println!("Layer {depth} proof bytes: {bytes}");
        expected = next_expected;
        if depth < args.layers {
            println!("Preparing native recursion layer {}...", depth + 1);
            let authority = layer.into_authority();
            layer = PreparedNativeBinaryWhirLayer::from_native_authority_with_construction_limits(
                &authority,
                options(depth + 1, args),
                &limits,
                &construction_limits,
            )?;
        }
    }
    Ok(())
}

fn run_folding(args: &Args) -> Result<(), Box<dyn Error>> {
    let (input, output, values) = source_trace();
    let mut expected = vec![vec![input, output]];
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePcsParameters {
            config: BinaryPcsConfig::try_new::<F, F>(
                2,
                BinaryPcsParams {
                    log_inv_rate: 1,
                    pow_bits: 0,
                    security_level: 8,
                },
            )?,
            hash: ByteHash::Keccak256,
            cap_height: 0,
            max_query_draws: 64,
        },
        preprocessed: None,
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-binary-recursion-source-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        vec![SquaringAir],
        vec![2],
        spec,
        &VerifierLimits::default(),
    )?;
    let proof = prover.prove(&expected, vec![RowMajorMatrix::new(values, 1)])?;
    let mut checked = authority.verify_native(&proof, &expected)?;
    println!(
        "Tower128 source verified: {:#034x} -> {:#034x}",
        input.to_repr(),
        output.to_repr()
    );
    let (limits, construction_limits) = circuit_limits(args);
    println!("Preparing native recursion layer 1...");
    let mut layer = PreparedNativeBinaryLayer::from_native_authority_with_construction_limits(
        &authority,
        folding_options(1, args),
        &limits,
        &construction_limits,
    )?;
    drop(prover);
    for depth in 1..=args.layers {
        let start = Instant::now();
        println!(
            "Layer {depth}: {} witnesses, {} initial codeword cells",
            layer.circuit().witness_count,
            layer.initial_codeword_cells()
        );
        let next_expected = layer.output_public_values(&expected)?;
        let recursive = layer.prove_verified(&checked)?;
        checked = layer.verify(&recursive, &expected)?;
        println!(
            "Native Tower128 layer {depth} proved and verified in {:.2?}",
            start.elapsed()
        );
        let bytes = match layer
            .authority()
            .encode_native_proof(&recursive, &next_expected)
        {
            Ok(bytes) => bytes.len().to_string(),
            Err(error) => format!("unavailable ({error:?})"),
        };
        println!("Layer {depth} proof bytes: {bytes}");
        expected = next_expected;
        if depth < args.layers {
            println!("Preparing native recursion layer {}...", depth + 1);
            let authority = layer.into_authority();
            layer = PreparedNativeBinaryLayer::from_native_authority_with_construction_limits(
                &authority,
                folding_options(depth + 1, args),
                &limits,
                &construction_limits,
            )?;
        }
    }
    Ok(())
}
