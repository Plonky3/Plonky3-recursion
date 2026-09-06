//! WHIR-backed 2-to-1 proof aggregation example (binary tree).
//!
//! This example mirrors `recursive_aggregation.rs` (the FRI-backed example) but drives the
//! [`WhirRecursionBackend`] instead:
//! 1. **Leaves**: `2^tree_depth` uni-STARK Fibonacci proofs, each of a distinct trace length, each
//!    proved directly via `p3_uni_stark::prove` (the same base proof `recursive_fibonacci_whir.rs`
//!    uses for its own single layer).
//! 2. **Levels 1..tree_depth+1**: pairwise 2-to-1 aggregation up the tree, via
//!    [`build_and_prove_aggregation_layer`], until a single root proof remains. Level 1 aggregates
//!    pairs of uni-STARK leaves; every level after that aggregates pairs of the *previous* level's
//!    own batch-STARK output (`RecursionOutput::into_recursion_input::<BatchOnly>`).
//!
//! `--num-recursive-layers` sets `tree_depth` (default 2, i.e. 4 base proofs / 2 aggregation
//! levels), so the default run already chains multiple WHIR recursion layers.
//!
//! ## What this proves
//!
//! The root proof attests that every base proof in the tree is valid. Every leaf has a distinct
//! trace length, so no two leaves are identical proofs.
//!
//! ## Scope
//!
//! `recursive_aggregation.rs`'s leaves are themselves batch-STARK proofs of a trivial
//! `CircuitBuilder` dummy circuit that registers no non-primitive (Poseidon2 / recompose) table.
//! [`WhirRecursionBackend`]'s `RecursionInput::BatchStark` support only verifies batch-STARK
//! proofs that used the *same* non-primitive tables its own recursion layers do -- see
//! `whir_recursion_backend_proves_a_batch_stark_next_layer` in
//! `recursion/tests/whir_recursion_backend.rs`, which notes batch-STARK support means exactly
//! "verify a previous recursion layer's own output", not an arbitrary hand-built batch-STARK
//! proof. A dummy circuit like `recursive_aggregation.rs`'s, with zero non-primitive tables, does
//! not qualify. So this example's leaves are uni-STARK proofs instead (`RecursionInput::UniStark`,
//! which carries no such requirement), and only level 2 onward chains batch-STARK-to-batch-STARK.
//!
//! Every layer, base or aggregated, is also proved and verified under the same single WHIR-backed
//! `StarkGenericConfig` -- there is no cross-config aggregation
//! (`prove_aggregation_layer_cross`/an `OutSC` distinct from the input config) here, unlike some
//! of `recursive_aggregation.rs`'s own field/arity variants. It also does not expose the FRI
//! example's `--arity4`, `--quintic`, `--hash`, `--zk`, or `--profile` knobs, mirroring how
//! `recursive_fibonacci_whir.rs` simplified `recursive_fibonacci.rs`'s CLI surface for WHIR.
//!
//! ## Usage
//!
//! ```bash
//! # 4 base proofs, 2 aggregation levels (default)
//! cargo run --release --example recursive_aggregation_whir -- --field baby-bear
//!
//! # 8 base proofs, 3 aggregation levels
//! cargo run --release --example recursive_aggregation_whir -- \
//!     --field koala-bear \
//!     --num-recursive-layers 3
//! ```

mod common;
use common::whir::*;
use common::*;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit_prover::BatchStarkProof;
use p3_recursion::backend::whir::WhirRecursionBackend;
use p3_uni_stark::{Proof, prove, verify};

/// Base field / WHIR configuration to run the example with.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum WhirField {
    /// BabyBear with the D=4 Poseidon2 challenger/MMCS shape.
    BabyBear,
    /// KoalaBear with the D=4 Poseidon2 challenger/MMCS shape.
    KoalaBear,
}

#[derive(Parser, Debug)]
#[command(version, about = "WHIR-backed 2-to-1 proof aggregation example")]
struct Args {
    /// Tree depth (total base proofs = 2^(tree_depth)).  (1 = single pair, 2 = 4 leaves, …)
    #[arg(
        long,
        default_value_t = 2,
        help = "Tree depth (total base proofs = 2^(tree_depth))"
    )]
    num_recursive_layers: usize,

    /// Base field for the WHIR-backed base proofs and every aggregation layer.
    #[arg(short, long, ignore_case = true, value_enum, default_value_t = WhirField::BabyBear)]
    field: WhirField,
}

fn main() {
    init_logger();

    let args = Args::parse();
    assert!(args.num_recursive_layers >= 1);

    info!(
        "WHIR-backed 2-to-1 aggregation with field {:?}, {} aggregation levels",
        args.field, args.num_recursive_layers
    );

    match args.field {
        WhirField::BabyBear => baby_bear::run(args.num_recursive_layers),
        WhirField::KoalaBear => koala_bear::run(args.num_recursive_layers),
    }
}

/// Expands to a `run(tree_depth)` that proves `2^tree_depth` distinct WHIR-backed Fibonacci base
/// proofs, then aggregates them pairwise up a binary tree of `tree_depth` WHIR recursion layers,
/// verifying every aggregated proof along the way.
macro_rules! define_whir_aggregation_module {
    ($mod_name:ident, $field:ty, $ef:ty, $config_ty:ty, $config_fn:path, $poseidon2_config:expr) => {
        mod $mod_name {
            use super::*;

            /// The value `generate_trace_rows::<$field>(0, 1, n)`'s last row claims as its
            /// output, i.e. `F(n)` for the sequence started at `F(0) = 0`, `F(1) = 1`.
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

            /// Proves and verifies a WHIR-backed uni-STARK Fibonacci base proof of trace length
            /// `n`.
            fn prove_base(
                n: usize,
                config: &$config_ty,
            ) -> (Proof<$config_ty>, FibonacciAir, Vec<$field>) {
                let trace = generate_trace_rows::<$field>(0, 1, n);
                let pis = vec![
                    <$field as PrimeCharacteristicRing>::ZERO,
                    <$field as PrimeCharacteristicRing>::ONE,
                    fibonacci_output(n),
                ];
                let air = FibonacciAir {};
                let proof = prove(config, &air, trace, &pis);
                verify(config, &air, &proof, &pis).expect("Failed to verify base proof");
                report_proof_size(&proof);
                (proof, air, pis)
            }

            /// Verifies one WHIR aggregation-layer proof by registering the same non-primitive
            /// tables [`WhirRecursionBackend`] used against a fresh [`BatchStarkProver`].
            fn verify_layer(
                config: &$config_ty,
                table_packing: &TablePacking,
                proof: &BatchStarkProof<$config_ty>,
            ) {
                let mut verifier =
                    BatchStarkProver::new(config.clone()).with_table_packing(table_packing.clone());
                verifier.register_poseidon2_table::<4>($poseidon2_config.for_challenger());
                verifier.register_poseidon2_table::<4>($poseidon2_config);
                verifier.register_recompose_table::<4>(true);
                verifier
                    .verify_all_tables::<$ef>(proof)
                    .expect("Failed to verify the WHIR aggregation layer proof");
            }

            /// Proves `2^tree_depth` distinct base proofs and aggregates them pairwise up a
            /// binary tree of `tree_depth` WHIR recursion layers.
            pub fn run(tree_depth: usize) {
                // An empty round schedule lets each WHIR commit derive its own round count from
                // the size of the polynomial being committed, which one config serving base
                // proofs of several distinct trace lengths plus every aggregation layer's own
                // commit requires.
                let config = $config_fn(vec![]);
                let backend = WhirRecursionBackend::<16, 8>::new($poseidon2_config)
                    .for_extension_degree::<4>();
                let agg_params = ProveNextLayerParams::default();

                let num_leaves = 1usize << tree_depth;
                info!(
                    "WHIR binary aggregation tree: {num_leaves} base proofs, {tree_depth} levels"
                );

                // Every leaf gets its own trace length, so no two base proofs are identical.
                // `10` is the smallest trace length this WHIR protocol configuration's query
                // count (driven by `security_level` and `starting_log_inv_rate` in
                // `bb_whir_protocol_params`/`kb_whir_protocol_params`) supports; a smaller trace
                // folds down to a domain too small for the number of queries the security level
                // demands.
                let base_log_n = 10;
                let base_proofs: Vec<(Proof<$config_ty>, FibonacciAir, Vec<$field>)> = (0
                    ..num_leaves)
                    .map(|i| {
                        let n = 1usize << (base_log_n + i);
                        info!("Base proof {i} (Fibonacci trace length {n})");
                        prove_base(n, &config)
                    })
                    .collect();

                // Level 1: aggregate uni-STARK leaf pairs into batch-STARK proofs.
                let pairs_l1 = num_leaves / 2;
                let mut proofs: Vec<RecursionOutput<$config_ty>> = Vec::with_capacity(pairs_l1);
                for pair_idx in 0..pairs_l1 {
                    let (proof_l, air_l, pis_l) = &base_proofs[pair_idx * 2];
                    let (proof_r, air_r, pis_r) = &base_proofs[pair_idx * 2 + 1];
                    let left = RecursionInput::UniStark {
                        proof: proof_l,
                        air: air_l,
                        public_inputs: pis_l.clone(),
                        preprocessed_commit: None,
                    };
                    let right = RecursionInput::UniStark {
                        proof: proof_r,
                        air: air_r,
                        public_inputs: pis_r.clone(),
                        preprocessed_commit: None,
                    };

                    let out = build_and_prove_aggregation_layer::<
                        $config_ty,
                        FibonacciAir,
                        FibonacciAir,
                        _,
                        4,
                    >(&left, &right, &config, &backend, &agg_params, None)
                    .unwrap_or_else(|e| panic!("Failed at level 1, pair {pair_idx}: {e:?}"));

                    report_proof_size(&out.0);
                    verify_layer(&config, &agg_params.table_packing, &out.0);
                    proofs.push(out);
                }
                info!(
                    "Aggregation level 1: {num_leaves} base proofs -> {}",
                    proofs.len()
                );

                // Levels 2..tree_depth: aggregate batch-STARK pairs from the previous level.
                let mut level = 1u32;
                while proofs.len() > 1 {
                    level += 1;
                    let pairs = proofs.len() / 2;
                    info!(
                        "Aggregation level {level}: {} proofs -> {pairs}",
                        proofs.len()
                    );

                    let mut next_level = Vec::with_capacity(pairs);
                    for pair_idx in 0..pairs {
                        let li = pair_idx * 2;
                        let left = proofs[li].into_recursion_input::<BatchOnly>();
                        let right = proofs[li + 1].into_recursion_input::<BatchOnly>();

                        let out = build_and_prove_aggregation_layer::<$config_ty, _, _, _, 4>(
                            &left,
                            &right,
                            &config,
                            &backend,
                            &agg_params,
                            None,
                        )
                        .unwrap_or_else(|e| {
                            panic!("Failed at level {level}, pair {pair_idx}: {e:?}")
                        });

                        report_proof_size(&out.0);
                        verify_layer(&config, &agg_params.table_packing, &out.0);
                        next_level.push(out);
                    }
                    proofs = next_level;
                }

                info!("All levels verified successfully");
            }
        }
    };
}

define_whir_aggregation_module!(
    baby_bear,
    BbF,
    BbEF,
    BbWhirConfig,
    bb_whir_config,
    Poseidon2Config::BABY_BEAR_D4_W16
);
define_whir_aggregation_module!(
    koala_bear,
    KbF,
    KbEF,
    KbWhirConfig,
    kb_whir_config,
    Poseidon2Config::KOALA_BEAR_D4_W16
);
