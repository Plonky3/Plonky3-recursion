//! WHIR-backed recursive Fibonacci proof verification example.
//!
//! This example mirrors `recursive_fibonacci.rs` (the FRI-backed example) but drives the
//! [`WhirRecursionBackend`] instead. It demonstrates:
//! 1. **Base proof**: prove a Fibonacci trace with a WHIR-backed `StarkGenericConfig`.
//! 2. **Recursion layer**: build a verifier circuit for that proof and prove it, again under a
//!    WHIR-backed config, through the shared `recursion.rs` pipeline.
//!
//! ## Current scope
//!
//! Unlike `recursive_fibonacci.rs`, this example proves exactly **one** recursion layer.
//! `WhirRecursionBackend` only supports [`RecursionInput::UniStark`] today (see
//! `WhirRecursionBackendForExt`'s `PcsRecursionBackend` impl in `recursion/src/backend/whir.rs`);
//! it returns an error on [`RecursionInput::BatchStark`], which is what
//! `RecursionOutput::into_recursion_input` produces for chaining a second layer. So the base
//! proof here is a raw `p3_uni_stark` proof over `FibonacciAir` (matching the pattern proven in
//! `recursion/tests/whir_recursion_backend.rs`), not the `CircuitBuilder`-based Fibonacci circuit
//! `recursive_fibonacci.rs` uses for its own layer 0. Consequently `--n` here is the base proof's
//! trace length (must be a power of two), not a Fibonacci index.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --release --example recursive_fibonacci_whir -- --field baby-bear --n 1024
//! cargo run --release --example recursive_fibonacci_whir -- --field koala-bear --n 4096
//! ```

mod common;
use common::whir::*;
use common::*;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_recursion::backend::whir::WhirRecursionBackend;
use p3_uni_stark::{prove, verify};

/// Base field / WHIR configuration to run the example with.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum WhirField {
    /// BabyBear with the D=4 Poseidon2 challenger/MMCS shape.
    BabyBear,
    /// KoalaBear with the D=4 Poseidon2 challenger/MMCS shape.
    KoalaBear,
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "WHIR-backed recursive Fibonacci proof verification example"
)]
struct Args {
    /// Trace length for the base Fibonacci proof (must be a power of two).
    #[arg(short, long, default_value_t = 1024)]
    n: usize,

    /// Base field for the WHIR-backed base proof and recursion layer.
    #[arg(short, long, ignore_case = true, value_enum, default_value_t = WhirField::BabyBear)]
    field: WhirField,
}

fn main() {
    init_logger();

    let args = Args::parse();

    info!(
        "Recursively proving a Fibonacci trace of length {} with field {:?} via WHIR",
        args.n, args.field
    );

    match args.field {
        WhirField::BabyBear => baby_bear::run(args.n),
        WhirField::KoalaBear => koala_bear::run(args.n),
    }
}

/// Expands to a `run(n)` that proves and verifies a WHIR-backed Fibonacci base proof of trace
/// length `n`, then builds, proves and verifies one WHIR-backed recursion layer over it.
macro_rules! define_whir_field_module {
    ($mod_name:ident, $field:ty, $ef:ty, $config_fn:path, $poseidon2_config:expr) => {
        mod $mod_name {
            use super::*;

            fn fibonacci_output(n: usize) -> $field {
                let mut a = <$field as PrimeCharacteristicRing>::ZERO;
                let mut b = <$field as PrimeCharacteristicRing>::ONE;
                for _ in 1..n {
                    let next = a + b;
                    a = b;
                    b = next;
                }
                b
            }

            /// Prove and verify a WHIR-backed Fibonacci base proof of trace length `n`, then
            /// build, prove and verify one WHIR-backed recursion layer over it.
            pub fn run(n: usize) {
                assert!(
                    n.is_power_of_two(),
                    "--n must be a power of two (trace length), got {n}"
                );

                let trace = generate_trace_rows::<$field>(0, 1, n);
                let pis = vec![
                    <$field as PrimeCharacteristicRing>::ZERO,
                    <$field as PrimeCharacteristicRing>::ONE,
                    fibonacci_output(n),
                ];
                let air = FibonacciAir {};
                let config = $config_fn(vec![]);

                let proof = prove(&config, &air, trace, &pis);
                verify(&config, &air, &proof, &pis).expect("Failed to verify base proof");
                report_proof_size(&proof);
                info!("Base WHIR Fibonacci proof verified successfully");

                let recursion_input = RecursionInput::UniStark {
                    proof: &proof,
                    air: &air,
                    public_inputs: pis,
                    preprocessed_commit: None,
                };

                let backend = WhirRecursionBackend::<16, 8>::new($poseidon2_config)
                    .for_extension_degree::<4>();
                let params = ProveNextLayerParams::default();

                let output =
                    build_and_prove_next_layer(&recursion_input, &config, &backend, &params)
                        .expect("Failed to prove the WHIR recursion layer");
                report_proof_size(&output.0);

                let mut prover =
                    BatchStarkProver::new(config).with_table_packing(params.table_packing);
                prover.register_poseidon2_table::<4>($poseidon2_config.for_challenger());
                prover.register_poseidon2_table::<4>($poseidon2_config);
                prover.register_recompose_table::<4>(true);
                prover
                    .verify_all_tables::<$ef>(&output.0)
                    .expect("Failed to verify the WHIR recursion layer proof");

                info!("Recursive proof verified successfully");
            }
        }
    };
}

define_whir_field_module!(
    baby_bear,
    BbF,
    BbEF,
    bb_whir_config,
    Poseidon2Config::BABY_BEAR_D4_W16
);
define_whir_field_module!(
    koala_bear,
    KbF,
    KbEF,
    kb_whir_config,
    Poseidon2Config::KOALA_BEAR_D4_W16
);
