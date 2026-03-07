//! Recursive Keccak proof verification example.
//!
//! This example demonstrates end-to-end multi-layer recursive verification:
//! 1. **Layer 0 (Base)**: Create a Keccak AIR proof with Plonky3 STARK
//! 2. **Layer 1+ (Recursive)**: Build verification circuits that check the previous layer's proof,
//!    then prove each verification circuit itself
//!
//! ## What this proves
//!
//! The final proof attests that:
//! - The Keccak hash computation was performed correctly
//! - All intermediate Plonky3 STARK verifications succeeded
//! - The recursive proof chain is valid
//!
//! ## Multi-layer recursion
//!
//! This example supports configurable recursion depth via `--num-recursive-layers`.
//! Each recursive layer verifies the previous layer's proof, creating a chain of proofs.
//!
//! ## Note on Performance
//!
//! The Keccak AIR produces a large verification circuit due to the complexity of Keccak
//! constraints (~2600 columns) and hence may require either additional recursive layers
//! or more aggressive recursion parameters.
//!
//! ## Usage
//!
//! ```bash
//! # Basic usage with default parameters (3 recursive layers)
//! cargo run --release --example recursive_keccak -- --field koala-bear --num-hashes 1000
//!
//! # With custom FRI parameters and recursion depth
//! cargo run --release --example recursive_keccak -- \
//!     --field koala-bear \
//!     --num-hashes 1000 \
//!     --num-recursive-layers 5 \
//!     --log-blowup 3 \
//!     --max-log-arity 4 \
//!     --log-final-poly-len 5 \
//!     --query-pow-bits 16
//! ```

#[macro_use]
mod common;
use common::*;
use p3_keccak_air::KeccakAir;
use p3_uni_stark::{prove, verify};
#[cfg(target_family = "unix")]
use tikv_jemallocator::Jemalloc;

#[cfg(target_family = "unix")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser, Debug)]
#[command(version, about = "Recursive Keccak proof verification example")]
struct Args {
    /// Number of Keccak permutations to prove.
    #[arg(short, long, default_value_t = 4)]
    num_hashes: usize,

    /// Number of recursive verification layers (1 = verify base once, 3 = base + 3 recursive layers).
    #[arg(
        long,
        default_value_t = 3,
        help = "Number of recursive verification layers"
    )]
    num_recursive_layers: usize,

    #[command(flatten)]
    common: CommonArgs,
}

fn main() {
    init_logger();

    let args = Args::parse();
    let fri_params = args.common.to_fri_params();
    let table_packing = args.common.table_packing();

    if args.num_recursive_layers < 1 {
        panic!("Number of recursive layers should be at least 1");
    }

    info!(
        "Recursively proving {} Keccak hashes with field {:?}",
        args.num_hashes, args.common.field
    );

    match args.common.field {
        FieldOption::KoalaBear => koala_bear::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.common.security_level,
            args.common.zk,
        ),
        FieldOption::BabyBear => baby_bear::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.common.security_level,
            args.common.zk,
        ),
        FieldOption::Goldilocks => goldilocks::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.common.security_level,
            args.common.zk,
        ),
    }
}

macro_rules! define_field_module {
    (
        $mod_name:ident,
        $field:ty,
        $perm:ty,
        $default_perm:path,
        $poseidon2_config:expr,
        $poseidon2_circuit_config:ty,
        $d:expr,
        $width:expr,
        $rate:expr,
        $digest_elems:expr,
        $enable_poseidon2_fn:ident,
        $register_poseidon2_fn:ident,
        $default_perm_circuit:path,
        $poseidon2_air_builders_fn:ident,
        $backend_ctor:ident,
        $backend_width:expr,
        $backend_rate:expr
    ) => {
        mod $mod_name {
            use super::*;

            define_field_module_types!(
                $field,
                $perm,
                $default_perm,
                $poseidon2_config,
                $poseidon2_circuit_config,
                $d,
                $width,
                $rate,
                $digest_elems,
                $enable_poseidon2_fn,
                $register_poseidon2_fn,
                $default_perm_circuit,
                $poseidon2_air_builders_fn,
                $backend_ctor,
                $backend_width,
                $backend_rate
            );

            pub fn run(
                num_hashes: usize,
                num_recursive_layers: usize,
                fri_params: &FriParams,
                table_packing: &TablePacking,
                security_level: usize,
                zk: bool,
            ) {
                let keccak_air = KeccakAir {};
                let min_trace_rows: usize =
                    1 << (fri_params.log_final_poly_len + fri_params.log_blowup + 1);
                let min_keccak_hashes = min_trace_rows.div_ceil(p3_keccak_air::NUM_ROUNDS);
                let effective_num_hashes = num_hashes.max(min_keccak_hashes);
                if effective_num_hashes != num_hashes {
                    tracing::warn!("Number of equivalent Keccak hashes after mandatory padding: {effective_num_hashes}");
                }
                let trace =
                    keccak_air.generate_trace_rows(effective_num_hashes, fri_params.log_blowup);

                // The base Keccak layer always uses non-ZK uni-stark (p3-uni-stark has no ZK support).
                let config_0 = config_with_fri_params(fri_params, security_level);
                let pis: Vec<F> = vec![];

                let proof_0 = prove(&config_0, &keccak_air, trace, &pis);
                report_proof_size(&proof_0);

                verify(&config_0, &keccak_air, &proof_0, &pis)
                    .expect("Failed to verify Keccak proof natively");

                if num_recursive_layers < 1 {
                    return;
                }

                let backend =
                    FriRecursionBackend::<$backend_width, $backend_rate>::$backend_ctor($poseidon2_config);

                if zk {
                    // The Keccak base proof is always non-ZK (p3-uni-stark has no ZK support).
                    // Since the recursive chain's config must match the proof being verified,
                    // all recursive layers here use ConfigWithFriParams. The --zk flag has no
                    // effect for recursive_keccak; use recursive_fibonacci for full ZK recursion.
                    tracing::warn!(
                        "--zk is not applicable to recursive_keccak: the Keccak base proof \
                         uses p3-uni-stark which has no ZK support. All recursive layers will \
                         use non-ZK config."
                    );
                }

                let mut output: Option<RecursionOutput<ConfigWithFriParams>> = None;

                for layer in 1..=num_recursive_layers {
                    let layer_table_packing = if layer == 1 {
                        TablePacking::new(1, 2)
                    } else {
                        table_packing.clone()
                    }
                    .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                    let params = ProveNextLayerParams {
                        table_packing: layer_table_packing,
                        use_npos_in_circuit: true,
                        constraint_profile: ConstraintProfile::Standard,
                    };
                    let config = config_with_fri_params(fri_params, security_level);

                    let out = if layer == 1 {
                        let input = RecursionInput::UniStark {
                            proof: &proof_0,
                            air: &keccak_air,
                            public_inputs: pis.clone(),
                            preprocessed_commit: None,
                        };
                        build_and_prove_next_layer::<ConfigWithFriParams, _, _, D>(
                            &input,
                            &config,
                            &backend,
                            &params,
                        )
                    } else {
                        let input = output.as_ref().unwrap().into_recursion_input::<BatchOnly>();
                        build_and_prove_next_layer::<ConfigWithFriParams, _, _, D>(
                            &input,
                            &config,
                            &backend,
                            &params,
                        )
                    }
                    .unwrap_or_else(|e| panic!("Failed to prove layer {layer}: {e:?}"));

                    report_proof_size(&out.0);
                    let mut prover = BatchStarkProver::new(config.clone())
                        .with_table_packing(params.table_packing);
                    prover.$register_poseidon2_fn($poseidon2_config);
                    prover
                        .verify_all_tables(&out.0, out.1.common_data())
                        .unwrap_or_else(|e| panic!("Failed to verify layer {layer}: {e:?}"));

                    output = Some(out);
                }

                info!("Recursive proof verified successfully");
            }
        }
    };
}

define_field_module!(
    koala_bear,
    p3_koala_bear::KoalaBear,
    p3_koala_bear::Poseidon2KoalaBear<16>,
    p3_koala_bear::default_koalabear_poseidon2_16,
    Poseidon2Config::KoalaBearD4Width16,
    p3_poseidon2_circuit_air::KoalaBearD4Width16,
    4,
    16,
    8,
    8,
    enable_poseidon2_perm,
    register_poseidon2_table,
    p3_koala_bear::default_koalabear_poseidon2_16,
    poseidon2_air_builders_d4,
    new_d4,
    16,
    8
);

define_field_module!(
    baby_bear,
    p3_baby_bear::BabyBear,
    p3_baby_bear::Poseidon2BabyBear<16>,
    p3_baby_bear::default_babybear_poseidon2_16,
    Poseidon2Config::BabyBearD4Width16,
    p3_poseidon2_circuit_air::BabyBearD4Width16,
    4,
    16,
    8,
    8,
    enable_poseidon2_perm,
    register_poseidon2_table,
    p3_baby_bear::default_babybear_poseidon2_16,
    poseidon2_air_builders_d4,
    new_d4,
    16,
    8
);

define_field_module!(
    goldilocks,
    p3_goldilocks::Goldilocks,
    p3_goldilocks::Poseidon2Goldilocks<8>,
    default_goldilocks_poseidon2_8,
    Poseidon2Config::GoldilocksD2Width8,
    p3_circuit::ops::GoldilocksD2Width8,
    2,
    8,
    4,
    4,
    enable_poseidon2_perm_width_8,
    register_poseidon2_table_d2,
    default_goldilocks_poseidon2_8,
    poseidon2_air_builders_d2,
    new_d2,
    8,
    4
);
