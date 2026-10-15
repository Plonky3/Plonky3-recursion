//! Native Tower128 proving followed by native Tower128 recursion. `--pcs whir|folding`
//! selects the polynomial commitment of the source proof and of every recursion layer. Under
//! WHIR, `--hash blake3|keccak` selects the hash of every commitment and transcript (default
//! Blake3; `--pcs folding` supports only Keccak and defaults to it),
//! `--hash-commitment packed|dense` (alias `--keccak-commitment`) selects how every layer
//! commits its hash table: as packed bits, 128 per field element, beside a dense commitment of
//! every other table, or as field elements like every other table, and `--merkle-arity 4|2`
//! selects four-digest or pairwise Merkle trees for every layer's commitments (default 2, and 4
//! under Keccak, since under Blake3 a four-digest tree saves no compressions). With
//! `--pcs folding`, which commits every table densely, `--leaves coset|symbol` selects whether
//! each Merkle leaf is one fold coset or one codeword symbol.
//!
//! cargo run -p p3-recursion --profile optimized --features parallel \
//!     --example native_binary_recursion -- --layers 3
//!
//! The defaults (WHIR with Blake3 and packed hash tables at log inverse rate 3 and every other
//! table at rate 1, PCS security level 32 with 24 grinding bits, pairwise Merkle trees under a
//! cap of 4 levels) keep every layer within the default limits. When a layer exceeds one
//! anyway, the error names the flag that raises it and a value to start from.
//!
//! Measured at `--layers 3` without any limit flag on a 14-core Apple M-series machine with
//! 48 GB (time of the last layer; wall time, maximum resident set and peak memory footprint of
//! the whole run; arity is `--merkle-arity`). The first row is the default configuration, the
//! second ran under `--hash keccak` and the third under `--merkle-arity 4`, each once on an
//! otherwise idle machine:
//!
//! | Command                       | arity | witnesses | codeword cells | proof bytes |
//! |-------------------------------|-------|-----------|----------------|-------------|
//! | `--layers 3`                  | 2     | 558,865   | 33,554,432     | 262,491     |
//! | `--hash keccak --layers 3`    | 4     | 566,758   | 50,331,648     | 155,691     |
//! | `--merkle-arity 4 --layers 3` | 4     | 622,197   | 33,554,432     | 279,739     |
//!
//! | Command                       | arity | last layer | wall   | resident | footprint |
//! |-------------------------------|-------|------------|--------|----------|-----------|
//! | `--layers 3`                  | 2     | 3.1 s      | 8.6 s  | 2.5 GB   | 2.3 GB    |
//! | `--hash keccak --layers 3`    | 4     | 9.1 s      | 16.0 s | 3.9 GB   | 3.7 GB    |
//! | `--merkle-arity 4 --layers 3` | 4     | 3.0 s      | 7.4 s  | 2.5 GB   | 2.3 GB    |
//!
//! Blake3 proves the last layer in a third of the time of Keccak with less memory, and its
//! proofs are 69% larger. A four-digest node costs two Blake3 compressions, so under Blake3 a
//! four-digest tree saves no compressions over half the levels while it opens three siblings
//! per level: it proves the last layer in about the same time as arity 2, with larger proofs.
//!
//! The user CPU time of a whole run was 68 s under the default against 155 s under `--hash
//! keccak --layers 3`. Layer 1 has 4,501 witnesses and takes 0.4 s under the default, and
//! 7,800 witnesses and 0.8 s under `--hash keccak`. The default codeword-cell limit is 2^29 at
//! `--log-inv-rate 1`, doubled for each further rate bit and for `--pcs folding`, which
//! multiplies every dense codeword.
//!
//! Under Keccak, a four-digest node absorbs one Keccak-f block, as a pairwise node does, and an
//! opening walks half as many levels, so a packed layer takes fewer Keccak-f calls and its
//! bridge table fewer rows, at the price of a larger proof.
//!
//! `--pcs folding` takes the same security level and grinding bits. Its coset leaves default to
//! cap height 1.
//!
//! Each layer prints the security report of its output statement. Without
//! `--security-target`, every output requires four bits of composed security and the defaults
//! give about 29. The binary-bus term caps the composed security whatever the PCS level, so a
//! `--security-target` above the cap is refused. Proofs are non-hiding. Limits count field
//! cells or graph entries, not bytes.

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
use p3_multi_stark::MultiStarkSecurityReport;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeAuthority, BinaryNativeGroupedAuthority,
    BinaryNativeGroupedPcsParameters, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
    BinaryNativeWhirAuthority, BinaryNativeWhirPcsParameters, VerifiedBinaryNativeMixedWhirProof,
    VerifiedBinaryNativeWhirProof,
};
use p3_recursion::pcs::binary::{BinaryCodewordGrouping, MerkleArity};
use p3_recursion::prepared::{
    NativeBinaryFoldingRecursionOptions, NativeBinaryMixedRecursionOptions,
    NativeBinaryMixedRecursiveProof, NativeBinaryProverBackend, NativeBinaryRecursionOptions,
    PreparedNativeBinaryGroupedLayer, PreparedNativeBinaryLayer,
    PreparedNativeBinaryMixedWhirLayer, PreparedNativeBinaryWhirLayer,
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

type F = BinaryField128;
/// Default cap height of pairwise trees, in levels: 16 roots.
const DEFAULT_CAP_HEIGHT: usize = 4;
/// Default cap height of four-digest trees, in levels: 16 roots.
const DEFAULT_FOUR_DIGEST_CAP_HEIGHT: usize = 2;
/// Composed security bits each recursive output statement requires without `--security-target`.
const SECURITY_BITS: usize = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Pcs {
    Whir,
    Folding,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum HashCommitment {
    /// The hash table as packed bits, beside a dense commitment of every other table.
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
    /// Four-digest nodes over half the levels; a node is one Keccak-f block, like a pairwise
    /// node, or two Blake3 compressions.
    #[value(name = "4")]
    Four,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Leaves {
    /// One Merkle leaf per fold coset.
    Coset,
    /// One Merkle leaf per codeword symbol.
    Symbol,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ProverBackend {
    Generic,
    Repr,
    ReprLate,
    BooleanTensor,
}
impl From<ProverBackend> for NativeBinaryProverBackend {
    fn from(value: ProverBackend) -> Self {
        match value {
            ProverBackend::Generic => Self::Generic,
            ProverBackend::Repr => Self::Repr,
            ProverBackend::ReprLate => Self::ReprLate,
            ProverBackend::BooleanTensor => Self::BooleanTensor,
        }
    }
}
#[derive(Parser)]
struct Args {
    /// Zerocheck backend for recursive output proofs.
    #[arg(long, value_enum, default_value_t = ProverBackend::ReprLate)]
    prover_backend: ProverBackend,
    /// Polynomial commitment for the source proof and every recursion layer.
    #[arg(long, value_enum, default_value_t = Pcs::Whir)]
    pcs: Pcs,
    /// Merkle leaves of every folding commitment; ignored by `--pcs whir`.
    /// `coset` requires a cap height at most `--log-inv-rate`, since the
    /// smallest coset-leaf tree has `2^log_inv_rate` leaves.
    #[arg(long, value_enum, default_value_t = Leaves::Coset)]
    leaves: Leaves,
    /// Hash of the source proof's commitments and transcript; every layer inherits it.
    /// Defaults to `blake3` with `--pcs whir` and `keccak` with `--pcs folding`, which supports
    /// only `keccak`.
    #[arg(long, value_enum)]
    hash: Option<Hash>,
    /// Commitment of every recursion layer's hash table. Defaults to `packed` with
    /// `--pcs whir` and `dense` with `--pcs folding`, which supports only `dense`.
    #[arg(long, value_enum, alias = "keccak-commitment")]
    hash_commitment: Option<HashCommitment>,
    /// Digests per Merkle tree node of every recursive output commitment. Defaults to `2`, and to
    /// `4` with `--pcs whir` under Keccak. `--pcs folding` supports only `2`.
    #[arg(long, value_enum)]
    merkle_arity: Option<Arity>,
    /// Log inverse rate of the packed hash-table commitment; ignored unless the hash table is
    /// committed as packed bits.
    #[arg(long, default_value_t = 3)]
    packed_log_inv_rate: usize,
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
    /// Maximum retained non-primitive calls during construction.
    #[arg(long, default_value_t = 1 << 20)]
    max_non_primitive_calls: usize,
    /// Maximum retained non-primitive input and output slots during construction.
    #[arg(long, default_value_t = 1 << 27)]
    max_non_primitive_slots: usize,
    /// Maximum combined trace, preprocessing, and temporary field cells.
    #[arg(long, default_value_t = 1 << 28)]
    max_trace_cells: usize,
    /// Maximum combined initial main, packed hash-table and preprocessing codeword cells. Defaults
    /// to 2^29 for WHIR at `--log-inv-rate 1`, doubled for each further rate bit and for
    /// `--pcs folding`, since each multiplies every dense codeword. The packed hash-table
    /// codeword stores 128 bits per cell, so with `--packed-log-inv-rate` at most 6 above
    /// `--log-inv-rate` it is smaller than the dense hash-table codeword it replaces.
    #[arg(long)]
    max_pcs_codeword_cells: Option<usize>,
    /// Maximum aggregate verifier rounds in each recursive output authority. It bounds the
    /// work of verifying an untrusted output proof, not prover memory.
    #[arg(long, default_value_t = 1024)]
    max_verifier_rounds: usize,
    /// PCS security level per opening; composed security still requires four bits.
    #[arg(long, default_value_t = 32)]
    pcs_security_level: usize,
    /// Composed security bits every recursive output statement requires (`--pcs whir` only).
    /// Each layer then uses the smallest PCS security level from the target up, shared by all
    /// of its commitments, whose composed security meets the target.
    #[arg(long, conflicts_with = "pcs_security_level")]
    security_target: Option<usize>,
    /// Merkle cap height of the recursive output proofs, in tree levels: `h` levels hold `2^h`
    /// roots of pairwise trees or `4^h` of four-digest trees. Defaults to 16 roots, 2 levels at
    /// `--merkle-arity 4` and 4 at `--merkle-arity 2`, or to at most `--log-inv-rate` with
    /// `--pcs folding --leaves coset`.
    #[arg(long)]
    cap_height: Option<usize>,
    /// Grinding bits per recursive opening (both WHIR and folding); queries cover the rest
    /// of the security level.
    #[arg(long, default_value_t = 24)]
    pow_bits: usize,
}
impl Args {
    /// `--max-pcs-codeword-cells`, or the default for the selected commitment and rate.
    fn max_pcs_codeword_cells(&self) -> usize {
        self.max_pcs_codeword_cells.unwrap_or_else(|| {
            let folding = u32::from(self.pcs == Pcs::Folding);
            let rate = u32::try_from(self.log_inv_rate.saturating_sub(1)).unwrap_or(u32::MAX);
            1usize
                .checked_shl(29u32.saturating_add(rate).saturating_add(folding))
                .unwrap_or(usize::MAX)
        })
    }
    /// `--hash-commitment`, or the default for the selected commitment.
    fn hash_commitment(&self) -> HashCommitment {
        self.hash_commitment.unwrap_or(match self.pcs {
            Pcs::Whir => HashCommitment::Packed,
            Pcs::Folding => HashCommitment::Dense,
        })
    }
    /// `--hash`, or the default for the selected commitment.
    fn hash(&self) -> Hash {
        self.hash.unwrap_or(match self.pcs {
            Pcs::Whir => Hash::Blake3,
            Pcs::Folding => Hash::Keccak,
        })
    }
    /// The selected hash as a circuit hash.
    fn byte_hash(&self) -> ByteHash {
        match self.hash() {
            Hash::Keccak => ByteHash::Keccak256,
            Hash::Blake3 => ByteHash::Blake3,
        }
    }
    /// `--merkle-arity`, or the default for the selected commitment and hash.
    fn merkle_arity(&self) -> MerkleArity {
        let arity = self
            .merkle_arity
            .unwrap_or_else(|| match (self.pcs, self.hash()) {
                (Pcs::Whir, Hash::Keccak) => Arity::Four,
                (Pcs::Whir, Hash::Blake3) | (Pcs::Folding, _) => Arity::Two,
            });
        match arity {
            Arity::Two => MerkleArity::Two,
            Arity::Four => MerkleArity::Four,
        }
    }
    /// `--cap-height`, or the default for the selected commitment, leaves and arity.
    fn cap_height(&self) -> usize {
        self.cap_height
            .unwrap_or_else(|| match (self.pcs, self.leaves, self.merkle_arity()) {
                (Pcs::Folding, Leaves::Coset, _) => DEFAULT_CAP_HEIGHT.min(self.log_inv_rate),
                (_, _, MerkleArity::Four) => DEFAULT_FOUR_DIGEST_CAP_HEIGHT,
                (_, _, MerkleArity::Two) => DEFAULT_CAP_HEIGHT,
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
/// PCS security level of every commitment of one recursion layer, and the composed security
/// bits its output statement requires.
#[derive(Clone, Copy)]
struct Security {
    level: usize,
    bits: usize,
}
fn recursive_protocol(args: &Args, level: usize) -> ProtocolParameters {
    ProtocolParameters {
        security_level: level,
        pow_bits: args.pow_bits,
        folding_factor: FoldingFactor::Constant(args.fold_arity),
        starting_log_inv_rate: args.log_inv_rate,
        ..protocol()
    }
}
fn options(depth: usize, args: &Args, security: Security) -> NativeBinaryRecursionOptions {
    NativeBinaryRecursionOptions {
        main: recursive_protocol(args, security.level),
        preprocessed: recursive_protocol(args, security.level),
        arity: args.merkle_arity(),
        cap_height: args.cap_height(),
        // An even-length label keeps the words observed after it at even offsets,
        // where they enter the hash whole.
        initial_bytes: format!("native-binary-recursion-layer-{depth:02}").into_bytes(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: security.bits,
        max_pcs_codeword_cells: args.max_pcs_codeword_cells(),
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
fn mixed_options(
    depth: usize,
    args: &Args,
    security: Security,
) -> NativeBinaryMixedRecursionOptions {
    NativeBinaryMixedRecursionOptions {
        base: options(depth, args, security),
        packed: ProtocolParameters {
            starting_log_inv_rate: args.packed_log_inv_rate,
            ..recursive_protocol(args, security.level)
        },
    }
}
/// Builds recursion layer `depth` at `--pcs-security-level`, requiring four composed bits; or,
/// with `--security-target`, at the smallest PCS security level from the target up whose
/// composed security, in the `report` of the layer's output authority, meets the target, which
/// the layer then requires. Probe layers require one composed bit, so their reports decide the
/// search.
fn with_security<L>(
    depth: usize,
    args: &Args,
    build: impl Fn(Security) -> Result<L, VerificationError>,
    report: impl Fn(&L) -> MultiStarkSecurityReport,
    require: impl Fn(L, usize) -> Result<L, VerificationError>,
) -> Result<L, Box<dyn Error>> {
    let Some(target) = args.security_target else {
        return build(Security {
            level: args.pcs_security_level,
            bits: SECURITY_BITS,
        })
        .map_err(at_layer(depth));
    };
    // Each WHIR opening's term union-composes rounds that each target the level, so in
    // practice it does not exceed the level and no level below the target meets it.
    let mut level = target.max(args.pow_bits + 1);
    let layer = loop {
        let layer = build(Security { level, bits: 1 }).map_err(at_layer(depth))?;
        let report = report(&layer);
        let composed = report.security_bits().ok_or_else(|| {
            format!(
                "layer {depth} security is unassessed: {:?}",
                report.unassessed_components()
            )
        })?;
        if composed >= target as f64 {
            break layer;
        }
        let ceiling = composed_without_whir(&report);
        if ceiling < target as f64 {
            return Err(format!(
                "--security-target {target} is out of reach for layer {depth}: its terms \
                 other than the WHIR openings compose to {ceiling:.1} bits"
            )
            .into());
        }
        level += 1;
    };
    println!("Layer {depth} PCS security level: {level}");
    require(layer, target).map_err(at_layer(depth))
}
/// Composed security of every term of `report` but the WHIR openings', the only terms the PCS
/// security level raises.
fn composed_without_whir(report: &MultiStarkSecurityReport) -> f64 {
    -report
        .terms()
        .iter()
        .filter(|term| term.label != "whir-opening")
        .map(|term| (-term.bits.bits()).exp2())
        .sum::<f64>()
        .log2()
}
fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if args.layers == 0 {
        return Err("--layers must be positive".into());
    }
    if args.security_target.is_none() && args.pow_bits >= args.pcs_security_level {
        return Err("--pow-bits must be below --pcs-security-level".into());
    }
    if args.pcs == Pcs::Folding && args.hash() == Hash::Blake3 {
        return Err("--hash blake3 requires --pcs whir".into());
    }
    if args.pcs == Pcs::Folding && args.hash_commitment() == HashCommitment::Packed {
        return Err("--hash-commitment packed requires --pcs whir".into());
    }
    if args.pcs == Pcs::Folding && args.merkle_arity() == MerkleArity::Four {
        return Err("--merkle-arity 4 requires --pcs whir".into());
    }
    if args.pcs == Pcs::Folding && args.security_target.is_some() {
        return Err("--security-target requires --pcs whir".into());
    }
    match args.pcs {
        Pcs::Whir => match args.hash_commitment() {
            HashCommitment::Packed => run_mixed(&args),
            HashCommitment::Dense => run_whir(&args),
        },
        Pcs::Folding => match args.leaves {
            Leaves::Coset => run_grouped_folding(&args),
            Leaves::Symbol => run_folding(&args),
        },
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
        cap_height: args.cap_height(),
        query_draw_slack: args.query_draw_slack,
        // An even-length label keeps the words observed after it at even offsets,
        // where they enter the hash whole.
        initial_bytes: format!("native-binary-recursion-layer-{depth:02}").into_bytes(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: SECURITY_BITS,
        max_pcs_codeword_cells: args.max_pcs_codeword_cells(),
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
            max_non_primitive_calls: args.max_non_primitive_calls,
            max_non_primitive_slots: args.max_non_primitive_slots,
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
/// The WHIR source statement, its authority and its checked proof.
type WhirSource = (
    Vec<Vec<F>>,
    BinaryNativeWhirAuthority<F, SquaringAir>,
    VerifiedBinaryNativeWhirProof<F>,
);
fn whir_source(args: &Args) -> Result<WhirSource, Box<dyn Error>> {
    let (input, output, values) = source_trace();
    let expected = vec![vec![input, output]];
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativeWhirPcsParameters::<F>::new(2, protocol(), args.byte_hash(), 0)?,
        preprocessed: None,
        transcript_hash: args.byte_hash(),
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
    let checked = authority.verify_native(&proof, &expected)?;
    println!(
        "Tower128 source verified: {:#034x} -> {:#034x}",
        input.to_repr(),
        output.to_repr()
    );
    Ok((expected, authority, checked))
}
/// Prints the composed security of a layer's output statement and each of its terms.
fn print_security(depth: usize, report: &MultiStarkSecurityReport) {
    match report.security_bits() {
        Some(bits) => println!("Layer {depth} composed security: {bits:.1} bits"),
        None => println!(
            "Layer {depth} composed security: unassessed ({:?})",
            report.unassessed_components()
        ),
    }
    for term in report.terms() {
        let component = term
            .component
            .map_or_else(String::new, |component| format!(" [{component}]"));
        println!(
            "  {:>6.1} bits: {}{component}",
            term.bits.bits(),
            term.label
        );
    }
}
fn run_whir(args: &Args) -> Result<(), Box<dyn Error>> {
    let (mut expected, authority, mut checked) = whir_source(args)?;
    let (limits, construction_limits) = circuit_limits(args);
    println!("Preparing native recursion layer 1...");
    let start = Instant::now();
    let mut layer = with_security(
        1,
        args,
        |security| {
            PreparedNativeBinaryWhirLayer::from_native_authority_with_construction_limits(
                &authority,
                options(1, args, security),
                &limits,
                &construction_limits,
            )
        },
        |layer| layer.authority().security_report().clone(),
        |layer, bits| layer.with_security_bits(bits),
    )?
    .with_prover_backend(args.prover_backend.into());
    println!("Layer 1 prepared in {:.2?}", start.elapsed());
    for depth in 1..=args.layers {
        print_security(depth, layer.authority().security_report());
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
            let start = Instant::now();
            let authority = layer.into_authority();
            layer = with_security(
                depth + 1,
                args,
                |security| {
                    PreparedNativeBinaryWhirLayer::from_native_authority_with_construction_limits(
                        &authority,
                        options(depth + 1, args, security),
                        &limits,
                        &construction_limits,
                    )
                },
                |layer| layer.authority().security_report().clone(),
                |layer, bits| layer.with_security_bits(bits),
            )?
            .with_prover_backend(args.prover_backend.into());
            println!("Layer {} prepared in {:.2?}", depth + 1, start.elapsed());
        }
    }
    Ok(())
}

/// The next expected statement and the checked output of one packed hash-table layer.
type MixedOutput = (Vec<Vec<F>>, VerifiedBinaryNativeMixedWhirProof);
/// Proves layer `depth` from `prove`, verifies it against the expected child statement, and
/// returns the next expected statement with the checked output.
fn prove_mixed<S>(
    depth: usize,
    layer: &PreparedNativeBinaryMixedWhirLayer<F, S>,
    expected: &[Vec<F>],
    prove: impl FnOnce(
        &PreparedNativeBinaryMixedWhirLayer<F, S>,
    ) -> Result<NativeBinaryMixedRecursiveProof, VerificationError>,
) -> Result<MixedOutput, Box<dyn Error>> {
    print_security(depth, layer.authority().security_report());
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
    Ok((next_expected, checked))
}

/// Every layer commits its hash table as packed bits. The first layer verifies the dense
/// source; every later layer verifies a packed hash-table child.
fn run_mixed(args: &Args) -> Result<(), Box<dyn Error>> {
    let (expected, authority, source) = whir_source(args)?;
    let (limits, construction_limits) = circuit_limits(args);
    println!("Preparing native recursion layer 1...");
    let start = Instant::now();
    let first = with_security(
        1,
        args,
        |security| {
            PreparedNativeBinaryMixedWhirLayer::from_native_authority_with_construction_limits(
                &authority,
                mixed_options(1, args, security),
                &limits,
                &construction_limits,
            )
        },
        |layer| layer.authority().security_report().clone(),
        |layer, bits| layer.with_security_bits(bits),
    )?
    .with_prover_backend(args.prover_backend.into());
    println!("Layer 1 prepared in {:.2?}", start.elapsed());
    let (mut expected, mut checked) =
        prove_mixed(1, &first, &expected, |layer| layer.prove_verified(&source))?;
    let mut authority = first.authority().clone();
    drop(first);
    for depth in 2..=args.layers {
        println!("Preparing native recursion layer {depth}...");
        let start = Instant::now();
        let layer = with_security(
            depth,
            args,
            |security| {
                PreparedNativeBinaryMixedWhirLayer::from_mixed_authority_with_construction_limits(
                    &authority,
                    mixed_options(depth, args, security),
                    &limits,
                    &construction_limits,
                )
            },
            |layer| layer.authority().security_report().clone(),
            |layer, bits| layer.with_security_bits(bits),
        )?
        .with_prover_backend(args.prover_backend.into());
        println!("Layer {depth} prepared in {:.2?}", start.elapsed());
        (expected, checked) = prove_mixed(depth, &layer, &expected, |layer| {
            layer.prove_verified(&checked)
        })?;
        authority = layer.authority().clone();
    }
    Ok(())
}

fn folding_source_pcs() -> Result<BinaryNativePcsParameters, Box<dyn Error>> {
    Ok(BinaryNativePcsParameters {
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
    })
}

fn run_folding(args: &Args) -> Result<(), Box<dyn Error>> {
    let (input, output, values) = source_trace();
    let mut expected = vec![vec![input, output]];
    let spec = BinaryNativeVerifierSpec {
        main: folding_source_pcs()?,
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
    )
    .map_err(at_layer(1))?
    .with_prover_backend(args.prover_backend.into());
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
            )
            .map_err(at_layer(depth + 1))?
            .with_prover_backend(args.prover_backend.into());
        }
    }
    Ok(())
}

fn run_grouped_folding(args: &Args) -> Result<(), Box<dyn Error>> {
    let (input, output, values) = source_trace();
    let mut expected = vec![vec![input, output]];
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativeGroupedPcsParameters {
            pcs: folding_source_pcs()?,
            base_grouping: BinaryCodewordGrouping::Folding,
            round_grouping: BinaryCodewordGrouping::Folding,
        },
        preprocessed: None,
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-binary-recursion-source-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeGroupedAuthority::<F, F, _>::setup(
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
    let mut layer =
        PreparedNativeBinaryGroupedLayer::from_native_authority_with_construction_limits(
            &authority,
            folding_options(1, args),
            &limits,
            &construction_limits,
        )
        .map_err(at_layer(1))?
        .with_prover_backend(args.prover_backend.into());
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
            layer =
                PreparedNativeBinaryGroupedLayer::from_native_authority_with_construction_limits(
                    &authority,
                    folding_options(depth + 1, args),
                    &limits,
                    &construction_limits,
                )
                .map_err(at_layer(depth + 1))?
                .with_prover_backend(args.prover_backend.into());
        }
    }
    Ok(())
}
