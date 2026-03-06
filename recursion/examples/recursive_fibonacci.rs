//! Recursive Fibonacci proof verification example.
//!
//! This example demonstrates end-to-end multi-layer recursive verification:
//! 1. **Layer 0 (Base)**: Create a Fibonacci(n) circuit and prove it with Plonky3 STARK
//! 2. **Layer 1+ (Recursive)**: Build verification circuits that check the previous layer's proof,
//!    then prove each verification circuit itself
//!
//! ## What this proves
//!
//! The final proof attests that:
//! - The original Fibonacci(n) computation was performed correctly
//! - All intermediate Plonky3 STARK verifications succeeded
//! - The recursive proof chain is valid
//!
//! ## Multi-layer recursion
//!
//! This example supports configurable recursion depth via `--num-recursive-layers`.
//! Each recursive layer verifies the previous layer's proof, creating a chain of proofs.
//!
//! ## Usage
//!
//! ```bash
//! # Basic usage with default parameters (3 recursive layers)
//! cargo run --release --example recursive_fibonacci -- --field koala-bear --n 10000
//!
//! # With custom FRI parameters and recursion depth
//! cargo run --release --example recursive_fibonacci -- \
//!     --field koala-bear \
//!     --n 10000 \
//!     --num-recursive-layers 5 \
//!     --log-blowup 3 \
//!     --max-log-arity 4 \
//!     --log-final-poly-len 5 \
//!     --query-pow-bits 16
//! ```

#[macro_use]
mod common;
use common::*;

#[derive(Parser, Debug)]
#[command(version, about = "Recursive Fibonacci proof verification example")]
struct Args {
    /// The Fibonacci index to compute (F(n)).
    #[arg(short, long, default_value_t = 100)]
    n: usize,

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

    if args.common.zk {
        eprintln!(
            "error: --zk is not supported for recursive_fibonacci yet.\n\
             Awaiting upstream P3 changes to have HidingFriPcs support Sync."
        );
        std::process::exit(1);
    }

    let fri_params = args.common.to_fri_params();
    let table_packing = args.common.table_packing();

    if args.num_recursive_layers < 1 {
        panic!("Number of recursive layers should be at least 1");
    }

    info!(
        "Recursively proving {} Fibonacci iterations with field {:?}",
        args.n, args.common.field
    );

    match args.common.field {
        FieldOption::KoalaBear => koala_bear::run(
            args.n,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.common.security_level,
        ),
        FieldOption::BabyBear => baby_bear::run(
            args.n,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.common.security_level,
        ),
        FieldOption::Goldilocks => goldilocks::run(
            args.n,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.common.security_level,
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
            use p3_batch_stark::ProverData;

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
                n: usize,
                num_recursive_layers: usize,
                fri_params: &FriParams,
                table_packing: &TablePacking,
                security_level: usize,
            ) {
                let mut builder = CircuitBuilder::new();
                let expected_result = builder.alloc_public_input("expected_result");

                let mut a = builder.alloc_const(F::ZERO, "F(0)");
                let mut b = builder.alloc_const(F::ONE, "F(1)");

                for _ in 2..=n {
                    let next = builder.add(a, b);
                    a = b;
                    b = next;
                }

                builder.connect(b, expected_result);

                let base_circuit = builder.build().unwrap();
                let table_packing_0 = TablePacking::new(1, 1)
                    .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);

                let config_0 = config_with_fri_params(fri_params, security_level);
                let (airs_degrees_0, preprocessed_columns_0) =
                    get_airs_and_degrees_with_prep::<ConfigWithFriParams, F, 1>(
                        &base_circuit,
                        table_packing_0,
                        &[],
                        &[],
                        ConstraintProfile::Standard,
                    )
                    .unwrap();
                let (mut airs_0, degrees_0): (Vec<_>, Vec<usize>) = airs_degrees_0.into_iter().unzip();

                let mut runner_0 = base_circuit.runner();
                let expected_fib = compute_fibonacci(n);
                runner_0.set_public_inputs(&[expected_fib]).unwrap();

                let traces_0 = runner_0.run().unwrap();
                let prover_data_0 =
                    ProverData::from_airs_and_degrees(&config_0, &mut airs_0, &degrees_0);
                let circuit_prover_data_0 =
                    CircuitProverData::new(prover_data_0, preprocessed_columns_0);
                let common_0 = circuit_prover_data_0.common_data();
                let prover_0 =
                    BatchStarkProver::new(config_0.clone()).with_table_packing(table_packing_0);
                let proof_0 = prover_0
                    .prove_all_tables(&traces_0, &circuit_prover_data_0)
                    .expect("Failed to prove base circuit");
                report_proof_size(&proof_0);

                prover_0
                    .verify_all_tables(&proof_0, &common_0)
                    .expect("Failed to verify base proof");

                if num_recursive_layers == 0 {
                    info!("Recursive proof verified successfully");
                    return;
                }

                let backend = FriRecursionBackend::<$backend_width, $backend_rate>::$backend_ctor(
                    $poseidon2_config,
                );
                let mut output = RecursionOutput(proof_0, Rc::new(circuit_prover_data_0));

                for layer in 1..=num_recursive_layers {
                    let params = ProveNextLayerParams {
                        table_packing: table_packing
                            .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup),
                        use_npos_in_circuit: true,
                        constraint_profile: ConstraintProfile::Standard,
                    };
                    let config = config_with_fri_params(fri_params, security_level);

                    let input = output.into_recursion_input::<BatchOnly>();
                    let out = build_and_prove_next_layer::<ConfigWithFriParams, _, _, D>(
                        &input, &config, &backend, &params,
                    )
                    .unwrap_or_else(|e| panic!("Failed to prove layer {layer}: {e:?}"));

                    report_proof_size(&out.0);
                    let mut prover = BatchStarkProver::new(config.clone())
                        .with_table_packing(params.table_packing);
                    prover.$register_poseidon2_fn($poseidon2_config);
                    prover
                        .verify_all_tables(&out.0, out.1.common_data())
                        .unwrap_or_else(|e| panic!("Failed to verify layer {layer}: {e:?}"));

                    output = out;
                }

                info!("Recursive proof verified successfully");
            }

            fn compute_fibonacci(n: usize) -> F {
                if n == 0 {
                    return F::ZERO;
                }
                if n == 1 {
                    return F::ONE;
                }
                let mut a = F::ZERO;
                let mut b = F::ONE;
                for _ in 2..=n {
                    let next = a + b;
                    a = b;
                    b = next;
                }
                b
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
