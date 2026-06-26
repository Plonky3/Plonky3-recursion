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
//! # KoalaBear with quintic challenge extension (D = 5)
//! cargo run --release --example recursive_aggregation -- --field koala-bear --quintic
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
use p3_batch_stark::ProverData;

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

    #[arg(short, long, ignore_case = true, value_enum, default_value_t = FieldOption::KoalaBear)]
    pub field: FieldOption,

    /// Use quintic (D = 5) challenge extension (KoalaBear only; incompatible with baby-bear / goldilocks).
    #[arg(long, default_value_t = false)]
    pub quintic: bool,

    /// Hash backing the recursive challenger/MMCS.
    #[arg(long, value_enum, ignore_case = true, default_value_t = HashOption::Poseidon2)]
    pub hash: HashOption,

    #[arg(
        long,
        default_value_t = 2,
        help = "Logarithmic blowup factor for the LDE"
    )]
    pub log_blowup: usize,

    #[arg(
        long,
        default_value_t = 2,
        help = "Maximum arity allowed during FRI folding phases"
    )]
    pub max_log_arity: usize,

    #[arg(long, default_value_t = 0, help = "Height of the Merkle cap to open")]
    pub cap_height: usize,

    #[arg(
        long,
        default_value_t = 6,
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
        default_value_t = 15,
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

    /// Pack this many consecutive HornerAcc steps (same `b`) per ALU row on lane 0 (must be >= 2).
    #[arg(
        long,
        default_value_t = 4,
        help = "Pack this many consecutive HornerAcc steps (same `b`) per ALU row on lane 0 (must be >= 2)"
    )]
    pub horner_packed_steps: usize,

    #[arg(
        long,
        default_value_t = 1,
        help = "Number of recompose lanes for the table packing in recursive layers"
    )]
    pub recompose_lanes: usize,

    // TODO: Update once https://github.com/Plonky3/Plonky3/pull/1329 lands
    #[arg(
        long,
        default_value_t = 124,
        help = "Targeted security level (conjectured)"
    )]
    pub security_level: usize,

    #[arg(long, default_value_t = false, help = "Enable ZK mode (HidingFriPcs)")]
    pub zk: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Disable recompose NPO (use only Poseidon2 perm)"
    )]
    pub disable_recompose_npo: bool,

    /// Use the mixed-config arity-4 (4-to-1) native MMCS for recursive layers (level >= 1).
    ///
    /// Base proofs (level 0) always commit with arity-2; the flag only changes how aggregation
    /// layers commit and verify. The Fiat-Shamir challenger stays on the W16 Poseidon2 table while
    /// the leaf hash and 4-to-1 compression run on a W32 table. Only supported for non-ZK KoalaBear
    /// with `--hash poseidon2` (binomial `D=4` or `--quintic` `D=5`).
    #[arg(long, default_value_t = false)]
    pub arity4: bool,
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
            .with_horner_pack_k(self.horner_packed_steps)
            .with_npo_lanes(NpoTypeId::recompose(), self.recompose_lanes)
    }
}

fn main() {
    init_logger();

    let args = Args::parse();
    let fri_params = args.to_fri_params();
    let table_packing = args.table_packing();

    assert!(args.num_recursive_layers >= 1);

    assert_quintic_field(args.field, args.quintic);
    assert_arity4_supported(args.arity4, args.field, args.hash);

    info!(
        "2-to-1 aggregation with field {:?}, quintic {}, hash {:?}, arity4 {}, {} aggregation recursive layers",
        args.field, args.quintic, args.hash, args.arity4, args.num_recursive_layers
    );

    if args.arity4 {
        assert!(
            !args.zk,
            "--arity4 is not yet wired with --zk in recursive_aggregation"
        );
        match (args.field, args.quintic) {
            (FieldOption::KoalaBear, true) => koala_bear_quintic_arity4::run(
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
                args.disable_recompose_npo,
            ),
            (FieldOption::KoalaBear, false) => koala_bear_arity4::run(
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
                args.disable_recompose_npo,
            ),
            (FieldOption::BabyBear, _) => baby_bear_arity4::run(
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
                args.disable_recompose_npo,
            ),
            (FieldOption::Goldilocks, _) => goldilocks_arity4::run(
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
                args.disable_recompose_npo,
            ),
        }
        return;
    }

    match (args.hash, args.field, args.quintic) {
        (HashOption::Poseidon2, FieldOption::KoalaBear, true) => koala_bear_quintic::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
        ),
        (HashOption::Poseidon2, FieldOption::KoalaBear, false) => koala_bear::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
        ),
        (HashOption::Poseidon2, FieldOption::BabyBear, _) => baby_bear::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
        ),
        (HashOption::Poseidon2, FieldOption::Goldilocks, _) => goldilocks::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
        ),
        (HashOption::Poseidon1, FieldOption::KoalaBear, true) => koala_bear_quintic_poseidon1::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
        ),
        (HashOption::Poseidon1, FieldOption::KoalaBear, false) => koala_bear_poseidon1::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
        ),
        (HashOption::Poseidon1, FieldOption::BabyBear, _) => baby_bear_poseidon1::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
        ),
        (HashOption::Poseidon1, FieldOption::Goldilocks, _) => goldilocks_poseidon1::run(
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
        ),
    }
}

/// KoalaBear quintic extension (`D = 5`) variant of [`define_field_module`] for aggregation.
macro_rules! define_field_module_aggregation_quintic {
    (
        $mod_name:ident,
        $field:ty,
        $perm:ty,
        $default_perm:path,
        $poseidon2_config:expr,
        $poseidon2_circuit_config:ty,
        $width:expr,
        $rate:expr,
        $digest_elems:expr,
        $backend_width:expr,
        $backend_rate:expr,
        $register_fn:ident,
        $enable_fn:ident,
        $gen_trace:ident,
        $params_trait:path
    ) => {
        mod $mod_name {
            use p3_batch_stark::ProverData;

            use super::*;

            define_field_module_types_quintic!(
                $field,
                $perm,
                $default_perm,
                $poseidon2_config,
                $poseidon2_circuit_config,
                $width,
                $rate,
                $digest_elems,
                || ::p3_test_utils::LiftPermToQuintic::<$field, $perm, $width>::new(
                    $default_perm()
                ),
                $backend_width,
                $backend_rate,
                $enable_fn,
                $gen_trace,
                $params_trait
            );

            fn prove_dummy_circuit(
                constant_value: u32,
                config: &ConfigWithFriParams,
                table_packing: &TablePacking,
            ) -> RecursionOutput<ConfigWithFriParams> {
                let mut builder = CircuitBuilder::new();
                let c = builder.alloc_const(F::from_u32(constant_value), "dummy_const");
                let expected = builder.alloc_public_input("expected");
                builder.connect(c, expected);
                let circuit = builder.build().unwrap();
                let (airs_degrees, primitive_columns, non_primitive_columns) =
                    get_airs_and_degrees_with_prep::<ConfigWithFriParams, F, 1>(
                        &circuit,
                        &table_packing,
                        &[],
                        &[],
                        ConstraintProfile::Standard,
                    )
                    .unwrap();
                let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&[F::from_u32(constant_value)])
                    .unwrap();
                let traces = runner.run().unwrap();
                let ext_degrees: Vec<usize> =
                    degrees.iter().map(|&d| d + config.is_zk()).collect();
                let prover_data =
                    ProverData::from_airs_and_degrees(config, &airs, &ext_degrees);
                let circuit_prover_data = CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
                let prover =
                    BatchStarkProver::new(config.clone()).with_table_packing(table_packing.clone());
                let proof = prover
                    .prove_all_tables(&traces, &circuit_prover_data)
                    .expect("Failed to prove dummy circuit");
                report_proof_size(&proof);
                prover
                    .verify_all_tables::<F>(&proof)
                    .expect("Failed to verify dummy proof");
                RecursionOutput(proof, Rc::new(circuit_prover_data))
            }

            pub fn run(
                num_recursive_layers: usize,
                fri_params: &FriParams,
                table_packing: &TablePacking,
                security_level: usize,
                zk: bool,
                disable_recompose_npo: bool,
            ) {
                if zk {
                    tracing::warn!(
                        "--zk is not yet supported for KoalaBear quintic in recursive_aggregation; \
                         using non-ZK config for all layers."
                    );
                }

                let base_table_packing = TablePacking::new(1, 1)
                    .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                let backend = FriRecursionBackend::<$backend_width, $backend_rate, _>::new_d5(
                    $poseidon2_config,
                );

                let tree_depth = num_recursive_layers;
                let num_leaves = 1usize << tree_depth;
                info!("Binary aggregation tree: {num_leaves} base proofs, {tree_depth} levels");

                macro_rules! run_aggregation {
                    ($cfg_type:ident, $config_base:expr, $config_agg:expr, $prove_base_fn:ident) => {{
                        let config_base: $cfg_type = $config_base;
                        let mut proofs: Vec<RecursionOutput<$cfg_type>> = (0..num_leaves)
                            .map(|i| {
                                let val = (i + 1) as u32;
                                info!("Base proof {i} (const = {val})");
                                $prove_base_fn(val, &config_base, &base_table_packing)
                            })
                            .collect();

                        let mut prep_cache: Option<AggregationPrepCache<$cfg_type>> = None;
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
                                .with_fri_params(
                                    fri_params.log_final_poly_len,
                                    fri_params.log_blowup,
                                ),
                                constraint_profile: ConstraintProfile::Standard,
                            };
                            let agg_config: $cfg_type = $config_agg(level as u64);

                            let mut next_level = Vec::with_capacity(pairs);
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
                                    .with_table_packing(agg_params.table_packing.clone());
                                verifier.$register_fn::<D>($poseidon2_config);
                                if !disable_recompose_npo {
                                    verifier.register_recompose_table::<D>($poseidon2_config.d() != D);
                                }
                                verifier
                                    .verify_all_tables::<Challenge>(&out.0)
                                    .unwrap_or_else(|e| {
                                        panic!("Verification failed at level {level}, pair {pair_idx}: {e:?}")
                                    });
                                next_level.push(out);
                            }
                            proofs = next_level;
                        }
                    }};
                }

                run_aggregation!(
                    ConfigWithFriParams,
                    config_with_fri_params(fri_params, security_level, true),
                    |_lvl| config_with_fri_params(
                        fri_params,
                        security_level,
                        disable_recompose_npo,
                    ),
                    prove_dummy_circuit
                );

                info!("All levels verified successfully");
            }
        }
    };
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
        $default_perm_circuit:path,
        $backend_width:expr,
        $backend_rate:expr,
        $register_fn:ident,
        $gen_trace:ident,
        $params_trait:path
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
                $default_perm_circuit,
                $backend_width,
                $backend_rate,
                enable_recompose,
                $gen_trace,
                $params_trait
            );

            /// Build a dummy circuit with a single constant and prove it (non-ZK).
            fn prove_dummy_circuit(
                constant_value: u32,
                config: &ConfigWithFriParams,
                table_packing: &TablePacking,
            ) -> RecursionOutput<ConfigWithFriParams> {
                let mut builder = CircuitBuilder::new();
                let c = builder.alloc_const(F::from_u32(constant_value), "dummy_const");
                let expected = builder.alloc_public_input("expected");
                builder.connect(c, expected);
                let circuit = builder.build().unwrap();
                let (airs_degrees, primitive_columns, non_primitive_columns) =
                    get_airs_and_degrees_with_prep::<ConfigWithFriParams, F, 1>(
                        &circuit,
                        &table_packing,
                        &[],
                        &[],
                        ConstraintProfile::Standard,
                    )
                    .unwrap();
                let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&[F::from_u32(constant_value)])
                    .unwrap();
                let traces = runner.run().unwrap();
                let ext_degrees: Vec<usize> =
                    degrees.iter().map(|&d| d + config.is_zk()).collect();
                let prover_data =
                    ProverData::from_airs_and_degrees(config, &airs, &ext_degrees);
                let circuit_prover_data = CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
                let prover =
                    BatchStarkProver::new(config.clone()).with_table_packing(table_packing.clone());
                let proof = prover
                    .prove_all_tables(&traces, &circuit_prover_data)
                    .expect("Failed to prove dummy circuit");
                report_proof_size(&proof);
                prover
                    .verify_all_tables::<F>(&proof)
                    .expect("Failed to verify dummy proof");
                RecursionOutput(proof, Rc::new(circuit_prover_data))
            }

            /// Build a dummy circuit with a single constant and prove it (ZK).
            fn prove_dummy_circuit_zk(
                constant_value: u32,
                config: &ConfigWithFriParamsZk,
                table_packing: &TablePacking,
            ) -> RecursionOutput<ConfigWithFriParamsZk> {
                let mut builder = CircuitBuilder::new();
                let c = builder.alloc_const(F::from_u32(constant_value), "dummy_const");
                let expected = builder.alloc_public_input("expected");
                builder.connect(c, expected);
                let circuit = builder.build().unwrap();
                let (airs_degrees, primitive_columns, non_primitive_columns) =
                    get_airs_and_degrees_with_prep::<ConfigWithFriParamsZk, F, 1>(
                        &circuit,
                        &table_packing,
                        &[],
                        &[],
                        ConstraintProfile::Standard,
                    )
                    .unwrap();
                let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&[F::from_u32(constant_value)])
                    .unwrap();
                let traces = runner.run().unwrap();
                let ext_degrees: Vec<usize> =
                    degrees.iter().map(|&d| d + config.is_zk()).collect();
                let prover_data =
                    ProverData::from_airs_and_degrees(config, &airs, &ext_degrees);
                let circuit_prover_data = CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
                let prover =
                    BatchStarkProver::new(config.clone()).with_table_packing(table_packing.clone());
                let proof = prover
                    .prove_all_tables(&traces, &circuit_prover_data)
                    .expect("Failed to prove dummy circuit (ZK)");
                report_proof_size(&proof);
                prover
                    .verify_all_tables::<F>(&proof)
                    .expect("Failed to verify dummy proof (ZK)");
                RecursionOutput(proof, Rc::new(circuit_prover_data))
            }

            pub fn run(
                num_recursive_layers: usize,
                fri_params: &FriParams,
                table_packing: &TablePacking,
                security_level: usize,
                zk: bool,
                disable_recompose_npo: bool,
            ) {
                let base_table_packing = TablePacking::new(1, 1)
                    .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                let backend = FriRecursionBackend::<$backend_width, $backend_rate, _>::new(
                    $poseidon2_config,
                )
                .for_extension_degree::<$d>();

                let tree_depth = num_recursive_layers;
                let num_leaves = 1usize << tree_depth;
                info!("Binary aggregation tree: {num_leaves} base proofs, {tree_depth} levels");

                macro_rules! run_aggregation {
                    ($cfg_type:ident, $config_base:expr, $config_agg:expr, $prove_base_fn:ident) => {{
                        let config_base: $cfg_type = $config_base;
                        let mut proofs: Vec<RecursionOutput<$cfg_type>> = (0..num_leaves)
                            .map(|i| {
                                let val = (i + 1) as u32;
                                info!("Base proof {i} (const = {val})");
                                $prove_base_fn(val, &config_base, &base_table_packing)
                            })
                            .collect();

                        let mut prep_cache: Option<AggregationPrepCache<$cfg_type>> = None;
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
                                .with_fri_params(
                                    fri_params.log_final_poly_len,
                                    fri_params.log_blowup,
                                ),
                                constraint_profile: ConstraintProfile::Standard,
                            };
                            let agg_config: $cfg_type = $config_agg(level as u64);

                            let mut next_level = Vec::with_capacity(pairs);
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
                                    .with_table_packing(agg_params.table_packing.clone());
                                verifier.$register_fn::<$d>($poseidon2_config);
                                if !disable_recompose_npo {
                                    verifier.register_recompose_table::<$d>($poseidon2_config.d() != $d);
                                }
                                verifier
                                    .verify_all_tables::<Challenge>(&out.0)
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
                        config_with_fri_params_zk(fri_params, security_level, true, 0),
                        |lvl| config_with_fri_params_zk(
                            fri_params,
                            security_level,
                            disable_recompose_npo,
                            lvl,
                        ),
                        prove_dummy_circuit_zk
                    );
                } else {
                    run_aggregation!(
                        ConfigWithFriParams,
                        config_with_fri_params(fri_params, security_level, true),
                        |_lvl| config_with_fri_params(
                            fri_params,
                            security_level,
                            disable_recompose_npo,
                        ),
                        prove_dummy_circuit
                    );
                }

                info!("All levels verified successfully");
            }
        }
    };
}

define_field_module_aggregation_quintic!(
    koala_bear_quintic,
    p3_koala_bear::KoalaBear,
    p3_koala_bear::Poseidon2KoalaBear<16>,
    p3_koala_bear::default_koalabear_poseidon2_16,
    Poseidon2Config::KOALA_BEAR_D1_W16,
    p3_poseidon2_circuit_air::KoalaBearD1Width16,
    16,
    8,
    8,
    16,
    8,
    register_poseidon2_table,
    enable_poseidon2_perm_base,
    generate_poseidon2_trace,
    p3_circuit::ops::Poseidon2Params
);

define_field_module_aggregation_quintic!(
    koala_bear_quintic_poseidon1,
    p3_koala_bear::KoalaBear,
    p3_koala_bear::Poseidon1KoalaBear<16>,
    p3_koala_bear::default_koalabear_poseidon1_16,
    p3_circuit::ops::Poseidon1Config::KOALA_BEAR_D1_W16,
    p3_circuit::ops::poseidon1_perm::KoalaBearD1Width16,
    16,
    8,
    8,
    16,
    8,
    register_poseidon1_table,
    enable_poseidon1_perm_base,
    generate_poseidon1_trace,
    p3_circuit::ops::Poseidon1Params
);

define_field_module!(
    koala_bear,
    p3_koala_bear::KoalaBear,
    p3_koala_bear::Poseidon2KoalaBear<16>,
    p3_koala_bear::default_koalabear_poseidon2_16,
    Poseidon2Config::KOALA_BEAR_D4_W16,
    p3_poseidon2_circuit_air::KoalaBearD4Width16,
    4,
    16,
    8,
    8,
    enable_poseidon2_perm,
    p3_koala_bear::default_koalabear_poseidon2_16,
    16,
    8,
    register_poseidon2_table,
    generate_poseidon2_trace,
    p3_circuit::ops::Poseidon2Params
);

define_field_module!(
    koala_bear_poseidon1,
    p3_koala_bear::KoalaBear,
    p3_koala_bear::Poseidon1KoalaBear<16>,
    p3_koala_bear::default_koalabear_poseidon1_16,
    p3_circuit::ops::Poseidon1Config::KOALA_BEAR_D4_W16,
    p3_circuit::ops::poseidon1_perm::KoalaBearD4Width16,
    4,
    16,
    8,
    8,
    enable_poseidon1_perm,
    p3_koala_bear::default_koalabear_poseidon1_16,
    16,
    8,
    register_poseidon1_table,
    generate_poseidon1_trace,
    p3_circuit::ops::Poseidon1Params
);

define_field_module!(
    baby_bear,
    p3_baby_bear::BabyBear,
    p3_baby_bear::Poseidon2BabyBear<16>,
    p3_baby_bear::default_babybear_poseidon2_16,
    Poseidon2Config::BABY_BEAR_D4_W16,
    p3_poseidon2_circuit_air::BabyBearD4Width16,
    4,
    16,
    8,
    8,
    enable_poseidon2_perm,
    p3_baby_bear::default_babybear_poseidon2_16,
    16,
    8,
    register_poseidon2_table,
    generate_poseidon2_trace,
    p3_circuit::ops::Poseidon2Params
);

define_field_module!(
    baby_bear_poseidon1,
    p3_baby_bear::BabyBear,
    p3_baby_bear::Poseidon1BabyBear<16>,
    p3_baby_bear::default_babybear_poseidon1_16,
    p3_circuit::ops::Poseidon1Config::BABY_BEAR_D4_W16,
    p3_circuit::ops::poseidon1_perm::BabyBearD4Width16,
    4,
    16,
    8,
    8,
    enable_poseidon1_perm,
    p3_baby_bear::default_babybear_poseidon1_16,
    16,
    8,
    register_poseidon1_table,
    generate_poseidon1_trace,
    p3_circuit::ops::Poseidon1Params
);

define_field_module!(
    goldilocks,
    p3_goldilocks::Goldilocks,
    p3_goldilocks::Poseidon2Goldilocks<8>,
    default_goldilocks_poseidon2_8,
    Poseidon2Config::GOLDILOCKS_D2_W8,
    p3_circuit::ops::GoldilocksD2Width8,
    2,
    8,
    4,
    4,
    enable_poseidon2_perm_width_8,
    default_goldilocks_poseidon2_8,
    8,
    4,
    register_poseidon2_table,
    generate_poseidon2_trace,
    p3_circuit::ops::Poseidon2Params
);

define_field_module!(
    goldilocks_poseidon1,
    p3_goldilocks::Goldilocks,
    p3_goldilocks::poseidon1::Poseidon1Goldilocks<8>,
    p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8,
    p3_circuit::ops::Poseidon1Config::GOLDILOCKS_D2_W8,
    p3_circuit::ops::poseidon1_perm::GoldilocksD2Width8,
    2,
    8,
    4,
    4,
    enable_poseidon1_perm_width_8,
    p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8,
    8,
    4,
    register_poseidon1_table,
    generate_poseidon1_trace,
    p3_circuit::ops::Poseidon1Params
);

/// Emits the mixed-config arity-4 recursive verifier config (W16 challenger + W32 MMCS) plus its
/// `create_config` / `config_with_fri_params` helpers. Requires the base
/// [`define_field_module_types!`]/[`define_quintic_poseidon_perm_lift_and_types!`] and
/// [`define_field_module_types_arity4!`] aliases to already be in scope.
macro_rules! arity4_mixed_config_impl {
    (
        $poseidon2_config_arity4:expr,
        $digest_elems:expr,
        $default_perm:path,
        $default_perm_arity4:path,
        $challenger_enable_fn:ident,
        $challenger_circuit_config:ty,
        $challenger_perm:expr,
        $mmcs_enable_fn:ident,
        $mmcs_circuit_config:ty,
        $mmcs_perm:expr
    ) => {
        type MyConfigArity4 = StarkConfig<MyPcsArity4, Challenge, Challenger>;

        #[derive(Clone)]
        struct ConfigWithFriParamsArity4 {
            config: Arc<MyConfigArity4>,
            fri_verifier_params: FriVerifierParams,
            disable_recompose_npo: bool,
        }

        impl core::ops::Deref for ConfigWithFriParamsArity4 {
            type Target = MyConfigArity4;
            fn deref(&self) -> &MyConfigArity4 {
                &self.config
            }
        }

        impl StarkGenericConfig for ConfigWithFriParamsArity4 {
            type Challenge = Challenge;
            type Challenger = Challenger;
            type Pcs = MyPcsArity4;
            fn pcs(&self) -> &MyPcsArity4 {
                self.config.pcs()
            }
            fn initialise_challenger(&self) -> Challenger {
                self.config.initialise_challenger()
            }
        }

        impl FriRecursionConfig for ConfigWithFriParamsArity4
        where
            MyPcsArity4: RecursivePcs<
                    ConfigWithFriParamsArity4,
                    InputProofTargets<F, Challenge, RecInputMmcsArity4>,
                    InnerFriArity4,
                    MerkleCapTargets<F, $digest_elems>,
                    <MyPcsArity4 as Pcs<Challenge, Challenger>>::Domain,
                >,
        {
            type Commitment = MerkleCapTargets<F, $digest_elems>;
            type InputProof = InputProofTargets<F, Challenge, RecInputMmcsArity4>;
            type OpeningProof = InnerFriArity4;
            type RawOpeningProof = <MyPcsArity4 as Pcs<Challenge, Challenger>>::Proof;
            const DIGEST_ELEMS: usize = $digest_elems;

            fn with_fri_opening_proof<'a, A, R>(
                prev: &RecursionInput<'a, Self, A>,
                f: impl FnOnce(&Self::RawOpeningProof) -> R,
            ) -> R
            where
                A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
            {
                match prev {
                    RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
                    RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
                }
            }

            fn prepare_circuit_for_verification(
                &self,
                circuit: &mut CircuitBuilder<Challenge>,
            ) -> Result<(), VerificationError> {
                circuit.$challenger_enable_fn::<$challenger_circuit_config, _>(
                    generate_poseidon2_trace::<Challenge, $challenger_circuit_config>,
                    $challenger_perm,
                );
                circuit.$mmcs_enable_fn::<$mmcs_circuit_config, _>(
                    generate_poseidon2_trace::<Challenge, $mmcs_circuit_config>,
                    $mmcs_perm,
                );
                if self.disable_recompose_npo {
                    circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                } else {
                    circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                }
                if <$challenger_circuit_config as p3_circuit::ops::Poseidon2Params>::D == 1
                    && <Challenge as ::p3_field::BasedVectorSpace<F>>::DIMENSION > 1
                {
                    circuit.set_recompose_coeff_ctl_for_decompose_links(true);
                }
                Ok(())
            }

            fn pcs_verifier_params(
                &self,
            ) -> &<MyPcsArity4 as RecursivePcs<
                ConfigWithFriParamsArity4,
                InputProofTargets<F, Challenge, RecInputMmcsArity4>,
                InnerFriArity4,
                MerkleCapTargets<F, $digest_elems>,
                <MyPcsArity4 as Pcs<Challenge, Challenger>>::Domain,
            >>::VerifierParams {
                &self.fri_verifier_params
            }

            fn set_fri_private_data(
                runner: &mut CircuitRunner<'_, Challenge>,
                op_ids: &[NonPrimitiveOpId],
                opening_proof: &Self::RawOpeningProof,
            ) -> Result<(), &'static str> {
                set_fri_mmcs_private_data_arity4::<
                    F,
                    Challenge,
                    ChallengeMmcsArity4,
                    MyMmcsArity4,
                    $digest_elems,
                >(runner, op_ids, opening_proof, $poseidon2_config_arity4)
            }
        }

        fn create_config_arity4(fp: &FriParams, security_level: usize) -> MyConfigArity4 {
            let challenger_perm = $default_perm();
            let mmcs_perm = $default_perm_arity4();
            let hash = MyHashArity4::new(mmcs_perm.clone());
            let compress = MyCompressArity4::new(mmcs_perm.clone());
            let val_mmcs = MyMmcsArity4::new(hash, compress, fp.cap_height);
            let challenge_mmcs = ChallengeMmcsArity4::new(val_mmcs.clone());
            let dft = Dft::default();

            let num_queries = (security_level - fp.query_pow_bits) / fp.log_blowup;

            let fri_params = FriParameters {
                max_log_arity: fp.max_log_arity,
                log_blowup: fp.log_blowup,
                log_final_poly_len: fp.log_final_poly_len,
                num_queries,
                commit_proof_of_work_bits: fp.commit_pow_bits,
                query_proof_of_work_bits: fp.query_pow_bits,
                mmcs: challenge_mmcs,
            };
            let pcs = MyPcsArity4::new(dft, val_mmcs, fri_params);
            let challenger = Challenger::new(challenger_perm);
            MyConfigArity4::new(pcs, challenger)
        }

        fn create_fri_verifier_params_arity4(fp: &FriParams) -> FriVerifierParams {
            FriVerifierParams::with_mmcs(
                fp.log_blowup,
                fp.log_final_poly_len,
                fp.commit_pow_bits,
                fp.query_pow_bits,
                $poseidon2_config_arity4,
            )
        }

        fn config_with_fri_params_arity4(
            fp: &FriParams,
            security_level: usize,
            disable_recompose_npo: bool,
        ) -> ConfigWithFriParamsArity4 {
            ConfigWithFriParamsArity4 {
                config: Arc::new(create_config_arity4(fp, security_level)),
                fri_verifier_params: create_fri_verifier_params_arity4(fp),
                disable_recompose_npo,
            }
        }
    };
}

/// Emits the arity-2 base-proof dummy prover used to seed the aggregation tree.
macro_rules! arity4_base_dummy_prover {
    () => {
        fn prove_dummy_circuit(
            constant_value: u32,
            config: &ConfigWithFriParams,
            table_packing: &TablePacking,
        ) -> RecursionOutput<ConfigWithFriParams> {
            let mut builder = CircuitBuilder::new();
            let c = builder.alloc_const(F::from_u32(constant_value), "dummy_const");
            let expected = builder.alloc_public_input("expected");
            builder.connect(c, expected);
            let circuit = builder.build().unwrap();
            let (airs_degrees, primitive_columns, non_primitive_columns) =
                get_airs_and_degrees_with_prep::<ConfigWithFriParams, F, 1>(
                    &circuit,
                    &table_packing,
                    &[],
                    &[],
                    ConstraintProfile::Standard,
                )
                .unwrap();
            let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(&[F::from_u32(constant_value)])
                .unwrap();
            let traces = runner.run().unwrap();
            let ext_degrees: Vec<usize> = degrees.iter().map(|&d| d + config.is_zk()).collect();
            let prover_data = ProverData::from_airs_and_degrees(config, &airs, &ext_degrees);
            let circuit_prover_data =
                CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
            let prover =
                BatchStarkProver::new(config.clone()).with_table_packing(table_packing.clone());
            let proof = prover
                .prove_all_tables(&traces, &circuit_prover_data)
                .expect("Failed to prove dummy circuit");
            report_proof_size(&proof);
            prover
                .verify_all_tables::<F>(&proof)
                .expect("Failed to verify dummy proof");
            RecursionOutput(proof, Rc::new(circuit_prover_data))
        }
    };
}

/// Emits the mixed-config arity-4 aggregation `run`: arity-2 base proofs, a cross-config level-1
/// boundary that emits arity-4, and uniform arity-4 layers above.
macro_rules! arity4_run {
    (
        $poseidon2_config:expr,
        $poseidon2_config_arity4:expr,
        $backend:expr,
        $backend_arity4:expr
    ) => {
        pub fn run(
            num_recursive_layers: usize,
            fri_params: &FriParams,
            table_packing: &TablePacking,
            security_level: usize,
            disable_recompose_npo: bool,
        ) {
            let base_table_packing = TablePacking::new(1, 1)
                .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
            let backend = $backend;
            let backend_arity4 = $backend_arity4;

            let tree_depth = num_recursive_layers;
            let num_leaves = 1usize << tree_depth;
            info!(
                "Binary aggregation tree: {num_leaves} base proofs, {tree_depth} levels (arity-4)"
            );

            let agg_params_for_level = |level: u32| ProveNextLayerParams {
                table_packing: if level == 1 {
                    TablePacking::new(2, 2)
                } else {
                    table_packing.clone()
                }
                .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup),
                constraint_profile: ConstraintProfile::Standard,
            };

            let config_base = config_with_fri_params(fri_params, security_level, true);
            let base_proofs: Vec<RecursionOutput<ConfigWithFriParams>> = (0..num_leaves)
                .map(|i| {
                    let val = (i + 1) as u32;
                    info!("Base proof {i} (const = {val})");
                    prove_dummy_circuit(val, &config_base, &base_table_packing)
                })
                .collect();

            // Level 1: verify arity-2 base proofs, emit an arity-4 (mixed-config) proof.
            let mut level = 1u32;
            let pairs = base_proofs.len() / 2;
            info!(
                "Aggregation level {level}: {} proofs -> {pairs}",
                base_proofs.len()
            );
            let agg_params = agg_params_for_level(level);
            let input_config =
                config_with_fri_params(fri_params, security_level, disable_recompose_npo);
            let output_config =
                config_with_fri_params_arity4(fri_params, security_level, disable_recompose_npo);
            let mut boundary_prep_cache: Option<AggregationPrepCache<ConfigWithFriParamsArity4>> =
                None;
            let mut proofs: Vec<RecursionOutput<ConfigWithFriParamsArity4>> =
                Vec::with_capacity(pairs);
            for pair_idx in 0..pairs {
                let li = pair_idx * 2;
                let left = base_proofs[li].into_recursion_input::<BatchOnly>();
                let right = base_proofs[li + 1].into_recursion_input::<BatchOnly>();
                let out = build_and_prove_aggregation_layer_cross::<
                    ConfigWithFriParams,
                    ConfigWithFriParamsArity4,
                    _,
                    _,
                    _,
                    D,
                >(
                    &left,
                    &right,
                    &input_config,
                    &output_config,
                    &backend,
                    &agg_params,
                    Some(&mut boundary_prep_cache),
                )
                .unwrap_or_else(|e| panic!("Failed at level {level}, pair {pair_idx}: {e:?}"));
                report_proof_size(&out.0);
                let mut verifier = BatchStarkProver::new(output_config.clone())
                    .with_table_packing(agg_params.table_packing.clone());
                verifier.register_poseidon2_table::<D>($poseidon2_config);
                verifier.register_poseidon2_table::<D>($poseidon2_config_arity4);
                if !disable_recompose_npo {
                    verifier.register_recompose_table::<D>($poseidon2_config.d() != D);
                }
                verifier
                    .verify_all_tables::<Challenge>(&out.0)
                    .unwrap_or_else(|e| {
                        panic!("Verification failed at level {level}, pair {pair_idx}: {e:?}")
                    });
                proofs.push(out);
            }

            // Levels 2..: uniform arity-4 (mixed-config) aggregation.
            let mut prep_cache: Option<AggregationPrepCache<ConfigWithFriParamsArity4>> = None;
            while proofs.len() > 1 {
                level += 1;
                let pairs = proofs.len() / 2;
                info!(
                    "Aggregation level {level}: {} proofs -> {pairs}",
                    proofs.len()
                );
                let agg_params = agg_params_for_level(level);
                let agg_config = config_with_fri_params_arity4(
                    fri_params,
                    security_level,
                    disable_recompose_npo,
                );

                let mut next_level = Vec::with_capacity(pairs);
                for pair_idx in 0..pairs {
                    let li = pair_idx * 2;
                    let left = proofs[li].into_recursion_input::<BatchOnly>();
                    let right = proofs[li + 1].into_recursion_input::<BatchOnly>();
                    let out =
                        build_and_prove_aggregation_layer::<ConfigWithFriParamsArity4, _, _, _, D>(
                            &left,
                            &right,
                            &agg_config,
                            &backend_arity4,
                            &agg_params,
                            Some(&mut prep_cache),
                        )
                        .unwrap_or_else(|e| {
                            panic!("Failed at level {level}, pair {pair_idx}: {e:?}")
                        });
                    report_proof_size(&out.0);
                    let mut verifier = BatchStarkProver::new(agg_config.clone())
                        .with_table_packing(agg_params.table_packing.clone());
                    verifier.register_poseidon2_table::<D>($poseidon2_config);
                    verifier.register_poseidon2_table::<D>($poseidon2_config_arity4);
                    if !disable_recompose_npo {
                        verifier.register_recompose_table::<D>($poseidon2_config.d() != D);
                    }
                    verifier
                        .verify_all_tables::<Challenge>(&out.0)
                        .unwrap_or_else(|e| {
                            panic!("Verification failed at level {level}, pair {pair_idx}: {e:?}")
                        });
                    next_level.push(out);
                }
                proofs = next_level;
            }

            info!("All levels verified successfully");
        }
    };
}

mod koala_bear_arity4 {
    use super::*;

    define_field_module_types!(
        p3_koala_bear::KoalaBear,
        p3_koala_bear::Poseidon2KoalaBear<16>,
        p3_koala_bear::default_koalabear_poseidon2_16,
        Poseidon2Config::KOALA_BEAR_D4_W16,
        p3_poseidon2_circuit_air::KoalaBearD4Width16,
        4,
        16,
        8,
        8,
        enable_poseidon2_perm,
        p3_koala_bear::default_koalabear_poseidon2_16,
        16,
        8,
        enable_recompose,
        generate_poseidon2_trace,
        p3_circuit::ops::Poseidon2Params
    );
    define_field_module_types_arity4!(p3_koala_bear::Poseidon2KoalaBear<32>, 32, 24, 8);

    arity4_mixed_config_impl!(
        Poseidon2Config::KOALA_BEAR_D4_W32,
        8,
        p3_koala_bear::default_koalabear_poseidon2_16,
        p3_koala_bear::default_koalabear_poseidon2_32,
        enable_poseidon2_perm,
        p3_poseidon2_circuit_air::KoalaBearD4Width16,
        p3_koala_bear::default_koalabear_poseidon2_16(),
        enable_poseidon2_perm_width_32,
        p3_poseidon2_circuit_air::KoalaBearD4Width32,
        p3_koala_bear::default_koalabear_poseidon2_32()
    );
    arity4_base_dummy_prover!();
    arity4_run!(
        Poseidon2Config::KOALA_BEAR_D4_W16,
        Poseidon2Config::KOALA_BEAR_D4_W32,
        FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .for_extension_degree::<4>(),
        FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D4_W32)
            .for_extension_degree::<4>()
    );
}

mod koala_bear_quintic_arity4 {
    use super::*;

    define_quintic_poseidon_perm_lift_and_types!(
        p3_koala_bear::KoalaBear,
        p3_koala_bear::Poseidon2KoalaBear<16>,
        p3_koala_bear::default_koalabear_poseidon2_16,
        Poseidon2Config::KOALA_BEAR_D1_W16,
        p3_poseidon2_circuit_air::KoalaBearD1Width16,
        16,
        8,
        8,
        16,
        8
    );
    define_field_module_types_arity4!(p3_koala_bear::Poseidon2KoalaBear<32>, 32, 24, 8);

    arity4_mixed_config_impl!(
        Poseidon2Config::KOALA_BEAR_D1_W32,
        8,
        p3_koala_bear::default_koalabear_poseidon2_16,
        p3_koala_bear::default_koalabear_poseidon2_32,
        enable_poseidon2_perm_base,
        p3_poseidon2_circuit_air::KoalaBearD1Width16,
        ::p3_test_utils::LiftPermToQuintic::<F, p3_koala_bear::Poseidon2KoalaBear<16>, 16>::new(
            p3_koala_bear::default_koalabear_poseidon2_16()
        ),
        enable_poseidon2_perm_base_width_32,
        p3_poseidon2_circuit_air::KoalaBearD1Width32,
        ::p3_test_utils::LiftPermToQuintic::<F, p3_koala_bear::Poseidon2KoalaBear<32>, 32>::new(
            p3_koala_bear::default_koalabear_poseidon2_32()
        )
    );
    arity4_base_dummy_prover!();
    arity4_run!(
        Poseidon2Config::KOALA_BEAR_D1_W16,
        Poseidon2Config::KOALA_BEAR_D1_W32,
        FriRecursionBackend::<16, 8, _>::new_d5(Poseidon2Config::KOALA_BEAR_D1_W16),
        FriRecursionBackend::<16, 8, _>::new_d5(Poseidon2Config::KOALA_BEAR_D1_W16)
            .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D1_W32)
    );
}

mod goldilocks_arity4 {
    use super::*;

    define_field_module_types!(
        p3_goldilocks::Goldilocks,
        p3_goldilocks::Poseidon2Goldilocks<8>,
        default_goldilocks_poseidon2_8,
        Poseidon2Config::GOLDILOCKS_D2_W8,
        p3_circuit::ops::GoldilocksD2Width8,
        2,
        8,
        4,
        4,
        enable_poseidon2_perm_width_8,
        default_goldilocks_poseidon2_8,
        8,
        4,
        enable_recompose,
        generate_poseidon2_trace,
        p3_circuit::ops::Poseidon2Params
    );
    define_field_module_types_arity4!(p3_goldilocks::Poseidon2Goldilocks<16>, 16, 12, 4);

    arity4_mixed_config_impl!(
        Poseidon2Config::GOLDILOCKS_D2_W16,
        4,
        default_goldilocks_poseidon2_8,
        default_goldilocks_poseidon2_16,
        enable_poseidon2_perm_width_8,
        p3_circuit::ops::GoldilocksD2Width8,
        default_goldilocks_poseidon2_8(),
        enable_poseidon2_perm,
        p3_poseidon2_circuit_air::GoldilocksD2Width16,
        default_goldilocks_poseidon2_16()
    );
    arity4_base_dummy_prover!();
    arity4_run!(
        Poseidon2Config::GOLDILOCKS_D2_W8,
        Poseidon2Config::GOLDILOCKS_D2_W16,
        FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
            .for_extension_degree::<2>(),
        FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
            .with_extra_poseidon2_table(Poseidon2Config::GOLDILOCKS_D2_W16)
            .for_extension_degree::<2>()
    );
}

mod baby_bear_arity4 {
    use super::*;

    define_field_module_types!(
        p3_baby_bear::BabyBear,
        p3_baby_bear::Poseidon2BabyBear<16>,
        p3_baby_bear::default_babybear_poseidon2_16,
        Poseidon2Config::BABY_BEAR_D4_W16,
        p3_poseidon2_circuit_air::BabyBearD4Width16,
        4,
        16,
        8,
        8,
        enable_poseidon2_perm,
        p3_baby_bear::default_babybear_poseidon2_16,
        16,
        8,
        enable_recompose,
        generate_poseidon2_trace,
        p3_circuit::ops::Poseidon2Params
    );
    define_field_module_types_arity4!(p3_baby_bear::Poseidon2BabyBear<32>, 32, 24, 8);

    arity4_mixed_config_impl!(
        Poseidon2Config::BABY_BEAR_D4_W32,
        8,
        p3_baby_bear::default_babybear_poseidon2_16,
        p3_baby_bear::default_babybear_poseidon2_32,
        enable_poseidon2_perm,
        p3_poseidon2_circuit_air::BabyBearD4Width16,
        p3_baby_bear::default_babybear_poseidon2_16(),
        enable_poseidon2_perm_width_32,
        p3_poseidon2_circuit_air::BabyBearD4Width32,
        p3_baby_bear::default_babybear_poseidon2_32()
    );
    arity4_base_dummy_prover!();
    arity4_run!(
        Poseidon2Config::BABY_BEAR_D4_W16,
        Poseidon2Config::BABY_BEAR_D4_W32,
        FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::BABY_BEAR_D4_W16)
            .for_extension_degree::<4>(),
        FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::BABY_BEAR_D4_W16)
            .with_extra_poseidon2_table(Poseidon2Config::BABY_BEAR_D4_W32)
            .for_extension_degree::<4>()
    );
}
