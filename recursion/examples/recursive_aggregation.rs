//! 2-to-1 proof aggregation example (binary tree).
//!
//! Builds a full binary aggregation tree from distinct base proofs:
//! 1. **Leaves**: `2^(N+1)` dummy circuits (each a single distinct constant),
//!    each proved independently with batch STARK.
//! 2. **Levels 1..N+1**: Pairwise 2-to-1 aggregation up the tree until a
//!    single root proof remains.
//!
//! `N` is the `--num-recursive-layers` argument (default 1).
//!
//! ## What this proves
//!
//! The root proof attests that every base proof in the tree is valid.  All
//! base proofs are genuinely distinct (different constant values) so the
//! circuit optimizer cannot collapse the two verifications inside an
//! aggregation node.
//!
//! ## Usage
//!
//! ```bash
//! # 4 base proofs, 2 aggregation levels (default)
//! cargo run --release --example recursive_aggregation -- --field koala-bear
//!
//! # 8 base proofs, 3 aggregation levels, custom FRI parameters
//! cargo run --release --example recursive_aggregation -- \
//!     --field koala-bear \
//!     --num-recursive-layers 2 \
//!     --log-blowup 3 \
//!     --max-log-arity 4 \
//!     --log-final-poly-len 5 \
//!     --query-pow-bits 16
//! ```

#[macro_use]
mod common;
use common::*;

#[derive(Parser, Debug)]
#[command(version, about = "2-to-1 proof aggregation example")]
struct Args {
    /// Tree depth (total base proofs = 2^(tree_depth)).  (1 = single pair, 2 = 4 leaves, …)
    #[arg(
        long,
        default_value_t = 1,
        help = "Tree depth (total base proofs = 2^(tree_depth))"
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

    assert!(args.num_recursive_layers >= 1);

    info!(
        "2-to-1 aggregation with field {:?}, {} aggregation recursive layers",
        args.common.field, args.num_recursive_layers
    );

    match args.common.field {
        FieldOption::KoalaBear => koala_bear::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.common.security_level,
            args.common.zk,
        ),
        FieldOption::BabyBear => baby_bear::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.common.security_level,
            args.common.zk,
        ),
        FieldOption::Goldilocks => goldilocks::run(
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

            /// Build a dummy circuit with a single constant and prove it (non-ZK).
            fn prove_dummy_circuit(
                constant_value: u32,
                config: &ConfigWithFriParams,
                table_packing: TablePacking,
            ) -> RecursionOutput<ConfigWithFriParams> {
                let mut builder = CircuitBuilder::new();
                let c = builder.alloc_const(F::from_u32(constant_value), "dummy_const");
                let expected = builder.alloc_public_input("expected");
                builder.connect(c, expected);
                let circuit = builder.build().unwrap();
                let (airs_degrees, preprocessed_columns) =
                    get_airs_and_degrees_with_prep::<ConfigWithFriParams, F, 1>(
                        &circuit,
                        table_packing,
                        &[],
                        &[],
                        ConstraintProfile::Standard,
                    )
                    .unwrap();
                let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&[F::from_u32(constant_value)])
                    .unwrap();
                let traces = runner.run().unwrap();
                let ext_degrees: Vec<usize> =
                    degrees.iter().map(|&d| d + config.is_zk()).collect();
                let prover_data =
                    ProverData::from_airs_and_degrees(config, &mut airs, &ext_degrees);
                let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
                let prover =
                    BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
                let proof = prover
                    .prove_all_tables(&traces, &circuit_prover_data)
                    .expect("Failed to prove dummy circuit");
                report_proof_size(&proof);
                prover
                    .verify_all_tables(&proof, circuit_prover_data.common_data())
                    .expect("Failed to verify dummy proof");
                RecursionOutput(proof, Rc::new(circuit_prover_data))
            }

            /// Build a dummy circuit with a single constant and prove it (ZK).
            fn prove_dummy_circuit_zk(
                constant_value: u32,
                config: &ConfigWithFriParamsZk,
                table_packing: TablePacking,
            ) -> RecursionOutput<ConfigWithFriParamsZk> {
                let mut builder = CircuitBuilder::new();
                let c = builder.alloc_const(F::from_u32(constant_value), "dummy_const");
                let expected = builder.alloc_public_input("expected");
                builder.connect(c, expected);
                let circuit = builder.build().unwrap();
                let (airs_degrees, preprocessed_columns) =
                    get_airs_and_degrees_with_prep::<ConfigWithFriParamsZk, F, 1>(
                        &circuit,
                        table_packing,
                        &[],
                        &[],
                        ConstraintProfile::Standard,
                    )
                    .unwrap();
                let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&[F::from_u32(constant_value)])
                    .unwrap();
                let traces = runner.run().unwrap();
                let ext_degrees: Vec<usize> =
                    degrees.iter().map(|&d| d + config.is_zk()).collect();
                let prover_data =
                    ProverData::from_airs_and_degrees(config, &mut airs, &ext_degrees);
                let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
                let prover =
                    BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
                let proof = prover
                    .prove_all_tables(&traces, &circuit_prover_data)
                    .expect("Failed to prove dummy circuit (ZK)");
                report_proof_size(&proof);
                prover
                    .verify_all_tables(&proof, circuit_prover_data.common_data())
                    .expect("Failed to verify dummy proof (ZK)");
                RecursionOutput(proof, Rc::new(circuit_prover_data))
            }

            pub fn run(
                num_recursive_layers: usize,
                fri_params: &FriParams,
                table_packing: &TablePacking,
                security_level: usize,
                zk: bool,
            ) {
                let base_table_packing = TablePacking::new(1, 1)
                    .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                let backend = FriRecursionBackend::<$backend_width, $backend_rate>::$backend_ctor(
                    $poseidon2_config,
                );

                let tree_depth = num_recursive_layers;
                let num_leaves = 1usize << tree_depth;
                info!("Binary aggregation tree: {num_leaves} base proofs, {tree_depth} levels");

                macro_rules! run_aggregation {
                    ($cfg_type:ident, $cfg_fn:expr, $prove_base_fn:ident) => {{
                        let config: $cfg_type = $cfg_fn(0);
                        let mut proofs: Vec<RecursionOutput<$cfg_type>> = (0..num_leaves)
                            .map(|i| {
                                let val = (i + 1) as u32;
                                info!("Base proof {i} (const = {val})");
                                $prove_base_fn(val, &config, base_table_packing)
                            })
                            .collect();

                        let mut level = 0u32;
                        while proofs.len() > 1 {
                            level += 1;
                            let pairs = proofs.len() / 2;
                            info!(
                                "Aggregation level {level}: {} proofs -> {pairs}",
                                proofs.len()
                            );

                            let agg_params = ProveNextLayerParams {
                                table_packing: if level == 1 {
                                    TablePacking::new(2, 2)
                                } else {
                                    table_packing.clone()
                                }
                                .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup),
                                use_npos_in_circuit: true,
                                constraint_profile: ConstraintProfile::Standard,
                            };
                            let agg_config: $cfg_type = $cfg_fn(level as u64);

                            let mut next_level = Vec::with_capacity(pairs);
                            let mut prep_cache: Option<AggregationPrepCache<$cfg_type>> = None;
                            for pair_idx in 0..pairs {
                                let li = pair_idx * 2;
                                let left = proofs[li].into_recursion_input::<BatchOnly>();
                                let right = proofs[li + 1].into_recursion_input::<BatchOnly>();

                                let out = build_and_prove_aggregation_layer::<$cfg_type, _, _, _, D>(
                                    &left, &right, &agg_config, &backend, &agg_params,
                                    Some(&mut prep_cache),
                                )
                                .unwrap_or_else(|e| {
                                    panic!("Failed at level {level}, pair {pair_idx}: {e:?}")
                                });

                                report_proof_size(&out.0);
                                let mut verifier = BatchStarkProver::new(agg_config.clone())
                                    .with_table_packing(agg_params.table_packing);
                                verifier.$register_poseidon2_fn($poseidon2_config);
                                verifier
                                    .verify_all_tables(&out.0, out.1.common_data())
                                    .unwrap_or_else(|e| {
                                        panic!("Verification failed at level {level}, pair {pair_idx}: {e:?}")
                                    });
                                next_level.push(out);
                            }
                            proofs = next_level;
                        }
                    }};
                }

                if zk {
                    run_aggregation!(
                        ConfigWithFriParamsZk,
                        |seed| config_with_fri_params_zk(fri_params, security_level, seed),
                        prove_dummy_circuit_zk
                    );
                } else {
                    run_aggregation!(
                        ConfigWithFriParams,
                        |_seed| config_with_fri_params(fri_params, security_level),
                        prove_dummy_circuit
                    );
                }

                info!("All levels verified successfully");
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
