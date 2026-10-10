//! Native Tower128 proving followed by native Tower128 recursion.
//!
//! cargo run -p p3-recursion --profile optimized --features parallel \
//!     --example native_binary_recursion -- --layers 3
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
//! | 1        | 3-7 s      | 0.3 GB    | 0.3 GB   |
//! | 2        | 35 s       | 11.6 GB   | 13.8 GB  |
//! | 3        | 45 s       | 13.4 GB   | 17.8 GB  |
//! | 4        | 48 s       | 13.5 GB   | 19.6 GB  |
//!
//! Other jobs on the machine slowed layers by up to 1.8x. Grinding takes most
//! of layer 1 and 1.5-6 s of each later layer. With `--pow-bits 20`, layer 2
//! takes 40-46 s (15.5 GB resident) but layer 3 needs 603,979,776 codeword
//! cells. With `--cap-height 0 --pow-bits 0`, layer 2 takes 95 s (24 GB
//! resident) and needs `--max-pcs-codeword-cells 1073741824`.
//!
//! Requests four bits of composed security and uses non-hiding proofs. Limits
//! count field cells or graph entries, not bytes.

use std::error::Error;
use std::time::Instant;

use clap::Parser;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::CircuitConstructionLimits;
use p3_circuit::ops::ByteHash;
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
    BinaryNativeWhirPcsParameters,
};
use p3_recursion::prepared::{NativeBinaryRecursionOptions, PreparedNativeBinaryWhirLayer};
use p3_recursion::verifier::VerifierLimits;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

/// Freed codewords and traces go back to the OS promptly, which keeps peak footprint near
/// the live working set between the large proving buffers.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

type F = BinaryField128;
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
    /// Maximum combined trace, preprocessing, and temporary field cells.
    #[arg(long, default_value_t = 1 << 28)]
    max_trace_cells: usize,
    /// Maximum combined initial main and preprocessing codeword cells.
    #[arg(long, default_value_t = 1 << 29)]
    max_pcs_codeword_cells: usize,
    /// Maximum aggregate verifier rounds in each recursive output authority.
    #[arg(long, default_value_t = 256)]
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
    let input = F::from_repr(0xfedcba98765432108123456789abcdef);
    let mut values = vec![input];
    for _ in 0..3 {
        let value = *values.last().unwrap();
        values.push(value * value);
    }
    let output = *values.last().unwrap();
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
    let limits = DirectCircuitLimits {
        max_witnesses: args.max_witnesses,
        max_operations: args.max_operations,
        max_trace_cells: args.max_trace_cells,
    };
    let construction_limits = CircuitConstructionLimits {
        max_expression_nodes: args.max_expression_nodes,
        max_pending_connects: args.max_pending_connects,
        max_non_primitive_calls: 1 << 20,
        max_non_primitive_slots: 1 << 27,
    };
    println!("Preparing native recursion layer 1...");
    let mut layer = PreparedNativeBinaryWhirLayer::from_native_authority_with_construction_limits(
        &authority,
        options(1, &args),
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
        expected = next_expected;
        if depth < args.layers {
            println!("Preparing native recursion layer {}...", depth + 1);
            let authority = layer.into_authority();
            layer = PreparedNativeBinaryWhirLayer::from_native_authority_with_construction_limits(
                &authority,
                options(depth + 1, &args),
                &limits,
                &construction_limits,
            )?;
        }
    }
    Ok(())
}
