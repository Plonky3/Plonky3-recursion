//! Native Poly64 proving and recursion with Poly192 challenges. `--keccak-commitment
//! packed|dense` selects how every layer commits its Keccak table: as packed bits, 64 per field
//! element, beside a dense commitment of every other table, or as field elements like every
//! other table. `--merkle-arity 4|2` selects four-digest or pairwise Merkle trees for every
//! layer's commitments. `--hash keccak|blake3` selects the hash of every commitment and
//! transcript; the default Merkle arity is 4 under Keccak and 2 under Blake3.
//!
//! cargo run -p p3-recursion --profile optimized --features parallel \
//!     --example native_poly_recursion -- --layers 3
//!
//! The defaults (packed Keccak tables, WHIR security level 32 with 24 grinding bits,
//! four-digest Merkle trees under a cap of 2 levels) keep every layer within the default
//! limits. When a layer exceeds one anyway, the error names the flag that raises it and a value
//! to start from.
//!
//! Measured without any limit flag on a 14-core Apple M-series machine with 48 GB (time of the
//! last layer; wall time, maximum resident set and peak memory footprint of the whole run;
//! arity is `--merkle-arity`, Keccak is `--keccak-commitment`, with packed log inverse rate 3):
//!
//! | arity | Keccak | --layers | witnesses | codeword cells | last layer | wall   | resident | footprint |
//! |-------|--------|----------|-----------|----------------|------------|--------|----------|-----------|
//! | 4     | packed | 2        | 857,033   | 117,440,512    | 4.8 s      | 6.4 s  | 6.5 GB   | 5.7 GB    |
//! | 4     | packed | 3        | 1,145,424 | 117,440,512    | 4.6 s      | 10.2 s | 6.5 GB   | 6.0 GB    |
//! | 4     | dense  | 2        | 1,049,178 | 335,544,320    | 6.1 s      | 8.1 s  | 12.2 GB  | 11.1 GB   |
//! | 4     | dense  | 3        | 1,362,313 | 335,544,320    | 7.0 s      | 17.1 s | 14.5 GB  | 12.3 GB   |
//! | 2     | dense  | 2        | 1,057,676 | 335,544,320    | 6.5 s      | 7.8 s  | 12.8 GB  | 12.5 GB   |
//! | 2     | dense  | 3        | 1,380,220 | 603,979,776    | 10.9 s     | 19.1 s | 23.5 GB  | 21.9 GB   |
//!
//! At arity 4, layer 1 has 8,284 witnesses and 1,048,576 codeword cells when packed and
//! 4,718,592 when dense, and takes 0.8 to 1.2 s either way. Layers 2 and 3 pad the witness
//! table to 2^22 rows and the gates table to 2^20 rows either way, so the packed layers stay
//! clear of the 2^21 gates cliff.
//!
//! A four-digest node absorbs one Keccak-f block, as a pairwise node does, and an opening walks
//! half as many levels. At arity 4, layer 2 takes 1,602 Keccak-f calls when packed and 1,781
//! when dense, and layer 3 takes 2,143 when packed and 2,227 when dense, against 2,798 for a
//! dense layer 3 at arity 2. More than 2,621 calls (25 trace rows each) give the Keccak table
//! 2^17 rows instead of 2^16, so with dense Keccak tables only at `--merkle-arity 2` does layer
//! 3 need the default limit of 2^30 codeword cells, 8 GiB of Poly64 cells; at arity 4, layers 1
//! to 3 stay within 2^29.
//!
//! `--hash blake3` measured against `--hash keccak` at `--layers 3` with `--keccak-commitment
//! dense` on the same machine. Each run also takes the row's `--hash` and `--merkle-arity`. A
//! hash call is one Keccak-f or one Blake3 compression. Of the last layer's gate rows, AIR check
//! counts those that check the hash table's constraints and column batch those that observe and
//! batch the opened values of the commitment holding the table. Resident is the largest maximum
//! resident set of the runs:
//!
//! | hash   | arity | witnesses | hash calls | gate rows | AIR check | column batch | codeword cells | resident |
//! |--------|-------|-----------|------------|-----------|-----------|--------------|----------------|----------|
//! | keccak | 4     | 1,362,313 | 2,227      | 1,047,133 | 124,003   | 467,541      | 335,544,320    | 15.1 GB  |
//! | blake3 | 2     | 3,316,725 | 7,000      | 3,022,401 | 483,498   | 2,172,182    | 536,870,912    | 19.2 GB  |
//! | blake3 | 4     | 3,359,011 | 7,033      | 3,053,855 | 483,498   | 2,172,187    | 536,870,912    | 18.5 GB  |
//!
//! The Blake3 table holds 2^13 rows at layer 3, but the verifier opens its 11,536 columns
//! densely over Poly192. Observing and batching their values takes 2.17M gate rows, 1.80M of
//! them weighting each column, against 0.47M under Keccak, and the AIR check 0.48M against
//! 0.12M. The layer has 2.4 times the witnesses and 2.9 times the gate rows of the Keccak
//! layer, which pads the fanout to 2^24 rows and the gate table to 2^22.
//!
//! Other jobs shared the machine, so times are not compared here. The user CPU time of a
//! whole run was 118 to 125 s under Keccak and 109 to 124 s under Blake3 at either arity, and
//! grinding takes 0.8 to 1.1 s of the last layer under either hash.
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
    BinaryNativeVerifierSpec, VerifiedBinaryNativePolyMixedWhirProof,
    VerifiedBinaryNativePolyWhirProof,
};
use p3_recursion::pcs::binary::MerkleArity;
use p3_recursion::prepared::{
    NativeBinaryMixedRecursionOptions, NativeBinaryPolyMixedRecursiveProof,
    NativeBinaryRecursionOptions, PreparedNativeBinaryPolyMixedWhirLayer,
    PreparedNativeBinaryPolyWhirLayer,
};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

#[path = "common/limit_hint.rs"]
mod limit_hint;
use limit_hint::at_layer;

/// Freed codewords and traces go back to the OS promptly, which keeps peak footprint near
/// the live working set between the large proving buffers.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

type F = Poly64;
/// Default cap height of pairwise trees, in levels: 16 roots.
const DEFAULT_CAP_HEIGHT: usize = 4;
/// Default cap height of four-digest trees, in levels: 16 roots.
const DEFAULT_FOUR_DIGEST_CAP_HEIGHT: usize = 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum KeccakCommitment {
    /// The Keccak table as packed bits, beside a dense commitment of every other table.
    Packed,
    /// Every table as field elements.
    Dense,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Hash {
    /// Keccak-256.
    Keccak,
    /// Blake3.
    Blake3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Arity {
    /// Pairwise nodes.
    #[value(name = "2")]
    Two,
    /// Four-digest nodes, each one Keccak-f block like a pairwise node, over half the levels.
    #[value(name = "4")]
    Four,
}
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
    /// With a packed Keccak commitment the packed codeword counts too.
    #[arg(long, default_value_t = 1 << 30)]
    max_pcs_codeword_cells: usize,
    /// Maximum aggregate verifier rounds in each recursive output authority. It bounds the
    /// work of verifying an untrusted output proof, not prover memory.
    #[arg(long, default_value_t = 1024)]
    max_verifier_rounds: usize,
    /// WHIR security level per opening; composed security still requires four bits.
    #[arg(long, default_value_t = 32)]
    pcs_security_level: usize,
    /// Commitment of every recursion layer's Keccak table.
    #[arg(long, value_enum, default_value_t = KeccakCommitment::Packed)]
    keccak_commitment: KeccakCommitment,
    /// Log inverse rate of the packed Keccak commitment; ignored unless the Keccak commitment
    /// is packed.
    #[arg(long, default_value_t = 3)]
    packed_log_inv_rate: usize,
    /// Hash of the source proof's commitments and transcript; every layer inherits it.
    #[arg(long, value_enum, default_value_t = Hash::Keccak)]
    hash: Hash,
    /// Digests per Merkle tree node of every recursive output commitment. Defaults to `4`
    /// under Keccak and `2` under Blake3.
    #[arg(long, value_enum)]
    merkle_arity: Option<Arity>,
    /// Merkle cap height of the recursive output proofs, in tree levels: `h` levels hold `2^h`
    /// roots of pairwise trees or `4^h` of four-digest trees. Defaults to 16 roots, 2 levels at
    /// `--merkle-arity 4` and 4 at `--merkle-arity 2`.
    #[arg(long)]
    cap_height: Option<usize>,
    /// WHIR grinding bits per recursive opening; queries cover the rest of the security level.
    #[arg(long, default_value_t = 24)]
    pow_bits: usize,
}
impl Args {
    const fn byte_hash(&self) -> ByteHash {
        match self.hash {
            Hash::Keccak => ByteHash::Keccak256,
            Hash::Blake3 => ByteHash::Blake3,
        }
    }
    const fn arity(&self) -> Arity {
        match (self.merkle_arity, self.hash) {
            (Some(arity), _) => arity,
            (None, Hash::Keccak) => Arity::Four,
            (None, Hash::Blake3) => Arity::Two,
        }
    }
    const fn merkle_arity(&self) -> MerkleArity {
        match self.arity() {
            Arity::Two => MerkleArity::Two,
            Arity::Four => MerkleArity::Four,
        }
    }
    /// `--cap-height`, or the default for the selected arity.
    fn cap_height(&self) -> usize {
        self.cap_height.unwrap_or_else(|| match self.arity() {
            Arity::Two => DEFAULT_CAP_HEIGHT,
            Arity::Four => DEFAULT_FOUR_DIGEST_CAP_HEIGHT,
        })
    }
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
        arity: args.merkle_arity(),
        cap_height: args.cap_height(),
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
fn mixed_options(depth: usize, args: &Args) -> NativeBinaryMixedRecursionOptions {
    NativeBinaryMixedRecursionOptions {
        base: options(depth, args),
        packed: ProtocolParameters {
            starting_log_inv_rate: args.packed_log_inv_rate,
            ..recursive_protocol(args.pcs_security_level, args.pow_bits)
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
    let expected = vec![vec![input, output]];
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePolyWhirPcsParameters::new(2, protocol(), args.byte_hash(), 0)?,
        preprocessed: None,
        transcript_hash: args.byte_hash(),
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
    let checked = authority.verify_native(&proof, &expected)?;
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
    drop(prover);
    match args.keccak_commitment {
        KeccakCommitment::Dense => run_dense(
            &args,
            &authority,
            checked,
            expected,
            &limits,
            &construction_limits,
        ),
        KeccakCommitment::Packed => run_mixed(
            &args,
            &authority,
            &checked,
            &expected,
            &limits,
            &construction_limits,
        ),
    }
}

/// Every layer commits every table as field elements.
fn run_dense(
    args: &Args,
    source: &BinaryNativePolyWhirAuthority<SquaringAir>,
    mut checked: VerifiedBinaryNativePolyWhirProof,
    mut expected: Vec<Vec<F>>,
    limits: &DirectCircuitLimits,
    construction_limits: &CircuitConstructionLimits,
) -> Result<(), Box<dyn Error>> {
    println!("Preparing native recursion layer 1...");
    let mut layer =
        PreparedNativeBinaryPolyWhirLayer::from_native_authority_with_construction_limits(
            source,
            options(1, args),
            limits,
            construction_limits,
        )
        .map_err(at_layer(1))?;
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
                    options(depth + 1, args),
                    limits,
                    construction_limits,
                )
                .map_err(at_layer(depth + 1))?;
        }
    }
    Ok(())
}

/// The next expected statement and the checked output of one packed-Keccak layer.
type MixedOutput = (Vec<Vec<F>>, VerifiedBinaryNativePolyMixedWhirProof);
/// Proves layer `depth` from `prove`, verifies it against the expected child statement, and
/// returns the next expected statement with the checked output.
fn prove_mixed<S>(
    depth: usize,
    layer: &PreparedNativeBinaryPolyMixedWhirLayer<S>,
    expected: &[Vec<F>],
    prove: impl FnOnce(
        &PreparedNativeBinaryPolyMixedWhirLayer<S>,
    ) -> Result<NativeBinaryPolyMixedRecursiveProof, VerificationError>,
) -> Result<MixedOutput, Box<dyn Error>> {
    let start = Instant::now();
    println!(
        "Layer {depth}: {} witnesses, {} initial codeword cells",
        layer.circuit().witness_count,
        layer.initial_codeword_cells()
    );
    let next_expected = layer
        .output_public_values(expected)
        .map_err(at_layer(depth))?;
    let recursive = prove(layer).map_err(at_layer(depth))?;
    let checked = layer
        .verify(&recursive, expected)
        .map_err(at_layer(depth))?;
    println!(
        "Native Poly64/Poly192 layer {depth} proved and verified in {:.2?}",
        start.elapsed()
    );
    Ok((next_expected, checked))
}

/// Every layer commits its Keccak table as packed bits. The first layer verifies the dense
/// source; every later layer verifies a packed-Keccak child.
fn run_mixed(
    args: &Args,
    source: &BinaryNativePolyWhirAuthority<SquaringAir>,
    checked: &VerifiedBinaryNativePolyWhirProof,
    expected: &[Vec<F>],
    limits: &DirectCircuitLimits,
    construction_limits: &CircuitConstructionLimits,
) -> Result<(), Box<dyn Error>> {
    println!("Preparing native recursion layer 1...");
    let first =
        PreparedNativeBinaryPolyMixedWhirLayer::from_native_authority_with_construction_limits(
            source,
            mixed_options(1, args),
            limits,
            construction_limits,
        )
        .map_err(at_layer(1))?;
    let (mut expected, mut checked) =
        prove_mixed(1, &first, expected, |layer| layer.prove_verified(checked))?;
    let mut authority = first.authority().clone();
    drop(first);
    for depth in 2..=args.layers {
        println!("Preparing native recursion layer {depth}...");
        let layer =
            PreparedNativeBinaryPolyMixedWhirLayer::from_mixed_authority_with_construction_limits(
                &authority,
                mixed_options(depth, args),
                limits,
                construction_limits,
            )
            .map_err(at_layer(depth))?;
        (expected, checked) = prove_mixed(depth, &layer, &expected, |layer| {
            layer.prove_verified(&checked)
        })?;
        authority = layer.authority().clone();
    }
    Ok(())
}
