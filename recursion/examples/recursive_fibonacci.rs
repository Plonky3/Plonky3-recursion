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

    #[arg(short, long, ignore_case = true, value_enum, default_value_t = FieldOption::KoalaBear)]
    pub field: FieldOption,

    #[arg(
        long,
        default_value_t = 2,
        help = "Logarithmic blowup factor for the LDE"
    )]
    pub log_blowup: usize,

    #[arg(
        long,
        default_value_t = 3,
        help = "Maximum arity allowed during FRI folding phases"
    )]
    pub max_log_arity: usize,

    #[arg(long, default_value_t = 2, help = "Height of the Merkle cap to open")]
    pub cap_height: usize,

    #[arg(
        long,
        default_value_t = 5,
        help = "Log size of final polynomial after FRI folding"
    )]
    pub log_final_poly_len: usize,

    #[arg(
        long,
        default_value_t = 0,
        help = "PoW grinding bits during FRI commit phase"
    )]
    pub commit_pow_bits: usize,

    #[arg(
        long,
        default_value_t = 18,
        help = "PoW grinding bits during FRI query phase"
    )]
    pub query_pow_bits: usize,

    #[arg(
        long,
        default_value_t = 1,
        help = "Number of public lanes for the table packing in recursive layers"
    )]
    pub public_lanes: usize,

    #[arg(
        long,
        default_value_t = 3,
        help = "Number of ALU lanes for the table packing in recursive layers"
    )]
    pub alu_lanes: usize,

    // TODO: Update once https://github.com/Plonky3/Plonky3/pull/1329 lands
    #[arg(
        long,
        default_value_t = 124,
        help = "Targeted security level (conjectured)"
    )]
    pub security_level: usize,

    #[arg(long, default_value_t = false, help = "Enable ZK mode (HidingFriPcs)")]
    pub zk: bool,
}

impl Args {
    pub const fn to_fri_params(&self) -> FriParams {
        FriParams {
            log_blowup: self.log_blowup,
            max_log_arity: self.max_log_arity,
            cap_height: self.cap_height,
            log_final_poly_len: self.log_final_poly_len,
            commit_pow_bits: self.commit_pow_bits,
            query_pow_bits: self.query_pow_bits,
        }
    }

    pub fn table_packing(&self) -> TablePacking {
        TablePacking::new(self.public_lanes, self.alu_lanes)
    }
}

fn main() {
    init_logger();

    let args = Args::parse();
    let fri_params = args.to_fri_params();
    let table_packing = args.table_packing();

    if args.num_recursive_layers < 1 {
        panic!("Number of recursive layers should be at least 1");
    }

    info!(
        "Recursively proving {} Fibonacci iterations with field {:?}",
        args.n, args.field
    );

    match args.field {
        FieldOption::KoalaBear => koala_bear::run(
            args.n,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
        ),
        FieldOption::BabyBear => baby_bear::run(
            args.n,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
        ),
        FieldOption::Goldilocks => goldilocks::run(
            args.n,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
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
                $backend_rate,
                noop_enable_recompose
            );

            pub fn run(
                n: usize,
                num_recursive_layers: usize,
                fri_params: &FriParams,
                table_packing: &TablePacking,
                security_level: usize,
                zk: bool,
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

                let expected_fib = compute_fibonacci(n);
                let traces_0 = {
                    let mut runner_0 = base_circuit.clone().runner();
                    runner_0.set_public_inputs(&[expected_fib]).unwrap();
                    runner_0.run().unwrap()
                };

                let backend = FriRecursionBackend::<$backend_width, $backend_rate>::$backend_ctor(
                    $poseidon2_config,
                );

                macro_rules! run_layers {
                    ($cfg_type:ident, $cfg_fn:expr) => {{
                        let config_0: $cfg_type = $cfg_fn(0);
                        let (airs_degrees_0, preprocessed_columns_0) =
                            get_airs_and_degrees_with_prep::<$cfg_type, F, 1>(
                                &base_circuit,
                                table_packing_0,
                                &[],
                                &[],
                                ConstraintProfile::Standard,
                            )
                            .unwrap();
                        let (mut airs_0, degrees_0): (Vec<_>, Vec<usize>) =
                            airs_degrees_0.into_iter().unzip();
                        let ext_degrees_0: Vec<usize> =
                            degrees_0.iter().map(|&d| d + config_0.is_zk()).collect();
                        let prover_data_0 = ProverData::from_airs_and_degrees(
                            &config_0,
                            &mut airs_0,
                            &ext_degrees_0,
                        );
                        let circuit_prover_data_0 =
                            CircuitProverData::new(prover_data_0, preprocessed_columns_0);
                        let common_0 = circuit_prover_data_0.common_data();
                        let prover_0 = BatchStarkProver::new(config_0.clone())
                            .with_table_packing(table_packing_0);
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

                        let mut output = RecursionOutput(proof_0, Rc::new(circuit_prover_data_0));

                        // The verifier circuit grows until the proof size stabilises (fixed point).
                        // Track consecutive identical proof witness counts to detect this.
                        let mut prev_witness_count: Option<u32> = None;
                        let mut stable_prep: Option<NextLayerPrepCache<$cfg_type>> = None;
                        // Seed used when the circuit first stabilised; all cached layers reuse
                        // this seed so that the cached PCS commitment stays valid.
                        let mut stable_seed: Option<u64> = None;

                        for layer in 1..=num_recursive_layers {
                            let params = ProveNextLayerParams {
                                table_packing: table_packing.with_fri_params(
                                    fri_params.log_final_poly_len,
                                    fri_params.log_blowup,
                                ),
                                constraint_profile: ConstraintProfile::Standard,
                            };
                            let seed = stable_seed.unwrap_or(layer as u64);
                            let config: $cfg_type = $cfg_fn(seed);

                            let input = output.into_recursion_input::<BatchOnly>();

                            let (verification_circuit, verifier_result) =
                                build_next_layer_circuit::<$cfg_type, BatchOnly, _, D>(
                                    &input, &config, &backend,
                                )
                                .unwrap_or_else(|e| {
                                    panic!("Failed to build circuit layer {layer}: {e:?}")
                                });

                            let current_witness_count = verification_circuit.witness_count;
                            let is_stable = prev_witness_count == Some(current_witness_count);
                            prev_witness_count = Some(current_witness_count);

                            if is_stable && stable_prep.is_none() {
                                stable_seed = Some(seed);
                                stable_prep = Some(
                                    build_next_layer_prep::<$cfg_type, BatchOnly, _, D>(
                                        &verification_circuit,
                                        &config,
                                        &backend,
                                        &params,
                                    )
                                    .unwrap_or_else(|e| {
                                        panic!("Failed to build prep cache: {e:?}")
                                    }),
                                );
                            }

                            let out = prove_next_layer::<$cfg_type, BatchOnly, _, D>(
                                &input,
                                verification_circuit,
                                &verifier_result,
                                &config,
                                &backend,
                                &params,
                                stable_prep.as_ref(),
                            )
                            .unwrap_or_else(|e| panic!("Failed to prove layer {layer}: {e:?}"));

                            report_proof_size(&out.0);
                            let mut prover = BatchStarkProver::new(config.clone())
                                .with_table_packing(params.table_packing);
                            prover.$register_poseidon2_fn($poseidon2_config);
                            prover
                                .verify_all_tables(&out.0, out.1.common_data())
                                .unwrap_or_else(|e| {
                                    panic!("Failed to verify layer {layer}: {e:?}")
                                });

                            output = out;
                        }
                    }};
                }

                if zk {
                    run_layers!(ConfigWithFriParamsZk, |seed| {
                        config_with_fri_params_zk(fri_params, security_level, seed)
                    });
                } else {
                    run_layers!(ConfigWithFriParams, |_seed| {
                        config_with_fri_params(fri_params, security_level, true)
                    });
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
