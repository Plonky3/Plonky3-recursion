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
//! # KoalaBear with quintic challenge extension (D = 5)
//! cargo run --release --example recursive_keccak -- --field koala-bear --quintic --num-hashes 1000
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
use rand::RngExt;

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
    #[arg(long, default_value_t = 4)]
    pub horner_packed_steps: usize,

    #[arg(
        long,
        default_value_t = 1,
        help = "Number of recompose lanes for the table packing in recursive layers"
    )]
    pub recompose_lanes: usize,

    #[arg(
        long,
        default_value_t = false,
        help = "Disable recompose NPO (use only Poseidon2 perm)"
    )]
    pub disable_recompose_npo: bool,

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
        help = "Build/prove recursion layers >= 2 via a fixed RecursionLayerProfile instead of deriving shape from the previous proof"
    )]
    pub profile: bool,
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
    keep_freed_memory_mapped();
    init_logger();

    let args = Args::parse();
    let fri_params = args.to_fri_params();
    let table_packing = args.table_packing();

    if args.num_recursive_layers < 1 {
        panic!("Number of recursive layers should be at least 1");
    }

    assert_quintic_field(args.field, args.quintic);

    info!(
        "Recursively proving {} Keccak hashes with field {:?}, quintic {}, hash {:?}",
        args.num_hashes, args.field, args.quintic, args.hash
    );

    match (args.hash, args.field, args.quintic) {
        (HashOption::Poseidon2, FieldOption::KoalaBear, true) => koala_bear_quintic::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
            args.profile,
        ),
        (HashOption::Poseidon2, FieldOption::KoalaBear, false) => koala_bear::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
            args.profile,
        ),
        (HashOption::Poseidon2, FieldOption::BabyBear, _) => baby_bear::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
            args.profile,
        ),
        (HashOption::Poseidon2, FieldOption::Goldilocks, _) => goldilocks::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
            args.profile,
        ),
        (HashOption::Poseidon1, FieldOption::KoalaBear, true) => koala_bear_quintic_poseidon1::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
            args.profile,
        ),
        (HashOption::Poseidon1, FieldOption::KoalaBear, false) => koala_bear_poseidon1::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
            args.profile,
        ),
        (HashOption::Poseidon1, FieldOption::BabyBear, _) => baby_bear_poseidon1::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
            args.profile,
        ),
        (HashOption::Poseidon1, FieldOption::Goldilocks, _) => goldilocks_poseidon1::run(
            args.num_hashes,
            args.num_recursive_layers,
            &fri_params,
            &table_packing,
            args.security_level,
            args.zk,
            args.disable_recompose_npo,
            args.profile,
        ),
    }
}

/// KoalaBear quintic extension (`D = 5`) variant of [`define_field_module`] for Keccak recursion.
macro_rules! define_field_module_keccak_quintic {
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

            #[allow(clippy::too_many_arguments)]
            pub fn run(
                num_hashes: usize,
                num_recursive_layers: usize,
                fri_params: &FriParams,
                table_packing: &TablePacking,
                security_level: usize,
                zk: bool,
                disable_recompose_npo: bool,
                profile: bool,
            ) {
                let keccak_air = KeccakAir {};
                let min_trace_rows: usize =
                    1 << (fri_params.log_final_poly_len + fri_params.log_blowup + 1);
                let min_keccak_hashes = min_trace_rows.div_ceil(p3_keccak_air::NUM_ROUNDS);
                let effective_num_hashes = num_hashes.max(min_keccak_hashes);
                if effective_num_hashes != num_hashes {
                    tracing::warn!("Number of equivalent Keccak hashes after mandatory padding: {effective_num_hashes}");
                }
                let mut trace_rng = SmallRng::seed_from_u64(1);
                let keccak_inputs: Vec<[u64; 25]> = (0..effective_num_hashes)
                    .map(|_| trace_rng.random())
                    .collect();
                let trace = p3_keccak_air::generate_trace_rows::<F>(
                    keccak_inputs,
                    fri_params.log_blowup,
                );

                let config_0 = config_with_fri_params(fri_params, security_level, disable_recompose_npo);
                let pis: Vec<F> = vec![];

                let proof_0 = prove(&config_0, &keccak_air, trace, &pis).unwrap();
                report_proof_size(&proof_0);

                verify(&config_0, &keccak_air, &proof_0, &pis)
                    .expect("Failed to verify Keccak proof natively");

                if num_recursive_layers < 1 {
                    return;
                }

                let backend = FriRecursionBackend::<$backend_width, $backend_rate, _>::new_d5(
                    $poseidon2_config,
                );

                if zk {
                    tracing::warn!(
                        "--zk is not applicable to recursive_keccak: the Keccak base proof \
                         uses p3-uni-stark which has no ZK support. All recursive layers will \
                         use non-ZK config."
                    );
                }

                let mut output: Option<RecursionOutput<ConfigWithFriParams>> = None;

                let mut pending_owner: Option<PreparedLayer<'_, ConfigWithFriParams, KeccakAir, _, D>> = None;
                let mut stable_owner: Option<PreparedLayer<'_, ConfigWithFriParams, KeccakAir, _, D>> = None;

                // `--profile` path: a `RecursionLayerProfile` fixed point is searched for
                // starting from layer 1's proof, re-solving against each new layer's own output
                // until the profile stops changing (mirroring `solve_fixed_point`'s own
                // documented cross-layer contract: one call only fits the single proof it
                // solved against, so reaching a true fixed point requires solving again against
                // a layer actually proved under the candidate). Once a solve leaves the profile
                // unchanged, that layer's owner is retained and reused only after input checks.
                let mut profile_config: Option<ConfigWithFriParams> = None;
                let mut current_profile: Option<RecursionLayerProfile> = None;
                let mut profile_owner: Option<PreparedLayer<'_, ConfigWithFriParams, KeccakAir, _, D>> = None;

                for layer in 1..=num_recursive_layers {
                    if profile && layer >= 2 {
                        let config = profile_config.get_or_insert_with(|| {
                            config_with_fri_params(fri_params, security_level, disable_recompose_npo)
                        });
                        let previous = output.as_ref().unwrap();
                        let table_public_inputs = batch_table_public_inputs(previous);
                        let input = batch_prepared_input(previous, &table_public_inputs);
                        let recursion_input = previous.into_recursion_input::<BatchOnly>();

                        if let Some(owner) = profile_owner.as_ref() {
                            match owner.check_input(&input) {
                                Ok(()) => {
                                    let out = owner.prove(input).unwrap_or_else(|e| {
                                        panic!("Failed to prove layer {layer}: {e:?}")
                                    });
                                    report_proof_size(&out.0);
                                    let mut prover = BatchStarkProver::new(config.clone())
                                        .with_table_packing(owner.params().table_packing.clone());
                                        for table_config in $poseidon2_config.output_table_configs() {
                                            prover.$register_fn::<D>(table_config);
                                        }
                                    if !disable_recompose_npo {
                                        prover.register_recompose_table::<D>(true);
                                    }
                                    prover.verify_all_tables::<Challenge>(&out.0).unwrap_or_else(|e| {
                                        panic!("Failed to verify layer {layer}: {e:?}")
                                    });
                                    output = Some(out);
                                    continue;
                                }
                                Err(error) if is_prepared_input_mismatch(&error) => {}
                                Err(e) => panic!("Failed to validate layer {layer}: {e:?}"),
                            }
                        }

                        let seed = current_profile.clone().unwrap_or_else(|| RecursionLayerProfile {
                            table_packing: table_packing.clone().with_fri_params(
                                fri_params.log_final_poly_len,
                                fri_params.log_blowup,
                            ),
                            hash: HashProfile::default(),
                            transcript: TranscriptKind::BaseDuplex,
                            constraint_profile: ConstraintProfile::Standard,
                        });
                        let resolved = solve_fixed_point::<ConfigWithFriParams, BatchOnly, _, D>(
                            seed.clone(),
                            &recursion_input,
                            config,
                            &backend,
                            8,
                        )
                        .unwrap_or_else(|e| {
                            panic!("solve_fixed_point failed before layer {layer}: {e:?}")
                        });
                        let already_stable = current_profile.as_ref() == Some(&resolved);
                        current_profile = Some(resolved.clone());

                        let source = PreparedSource::BatchStark {
                            proof: &previous.0,
                            common_data: &previous.0.stark_common,
                            table_public_inputs: &table_public_inputs,
                        };
                        let owner = PreparedLayer::new_with_profile(
                            source,
                            config.clone(),
                            backend.clone(),
                            resolved.clone(),
                        )
                        .unwrap_or_else(|e| panic!("Failed to prepare layer {layer}: {e:?}"));
                        let out = owner.prove(input).unwrap_or_else(|e| {
                            panic!("Failed to prove layer {layer}: {e:?}")
                        });

                        report_proof_size(&out.0);
                        let mut prover = BatchStarkProver::new(config.clone())
                            .with_table_packing(resolved.table_packing.clone());
                            for table_config in $poseidon2_config.output_table_configs() {
                                prover.$register_fn::<D>(table_config);
                            }
                        if !disable_recompose_npo {
                            prover.register_recompose_table::<D>(true);
                        }
                        prover
                            .verify_all_tables::<Challenge>(&out.0)
                            .unwrap_or_else(|e| panic!("Failed to verify layer {layer}: {e:?}"));

                        output = Some(out);
                        if already_stable {
                            profile_owner = Some(owner);
                        }
                        continue;
                    }

                    let layer_table_packing = {
                        let p = if layer == 1 {
                            let mut p = TablePacking::new(1, 2)
                                .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                            if let Some(rl) = table_packing.npo_lanes(&NpoTypeId::recompose()) {
                                p = p.with_npo_lanes(NpoTypeId::recompose(), rl);
                            }
                            p
                        } else {
                            table_packing.clone()
                        }
                        .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                        p
                    };
                    let params = ProveNextLayerParams {
                        table_packing: layer_table_packing,
                        constraint_profile: ConstraintProfile::Standard,
                    };
                    let config =
                        config_with_fri_params(fri_params, security_level, disable_recompose_npo);

                    let out = if layer == 1 {
                        let input = PreparedInput::UniStark {
                            proof: &proof_0,
                            public_inputs: &pis,
                            preprocessed_commit: None,
                        };
                        let source = PreparedSource::UniStark {
                            air: &keccak_air,
                            proof: &proof_0,
                            public_inputs: &pis,
                            preprocessed_commit: None,
                        };
                        let owner = PreparedLayer::new(
                            source,
                            config.clone(),
                            backend.clone(),
                            params.clone(),
                        )
                        .unwrap_or_else(|e| panic!("Failed to prepare layer {layer}: {e:?}"));
                        let out = owner.prove(input);
                        pending_owner = Some(owner);
                        out
                    } else {
                        let previous = output.as_ref().unwrap();
                        let table_public_inputs = batch_table_public_inputs(previous);
                        let input = batch_prepared_input(previous, &table_public_inputs);
                        if let Some(owner) = stable_owner.as_ref() {
                            match owner.check_input(&input) {
                                Ok(()) => owner.prove(input),
                                Err(error) if is_prepared_input_mismatch(&error) => {
                                    let source = PreparedSource::BatchStark {
                                        proof: &previous.0,
                                        common_data: &previous.0.stark_common,
                                        table_public_inputs: &table_public_inputs,
                                    };
                                    let owner = PreparedLayer::new(
                                        source,
                                        config.clone(),
                                        backend.clone(),
                                        params.clone(),
                                    )
                                    .unwrap_or_else(|e| panic!("Failed to reprepare layer {layer}: {e:?}"));
                                    let out = owner.prove(input);
                                    stable_owner = Some(owner);
                                    out
                                }
                                Err(e) => panic!("Failed to validate layer {layer}: {e:?}"),
                            }
                        } else {
                            let source = PreparedSource::BatchStark {
                                proof: &previous.0,
                                common_data: &previous.0.stark_common,
                                table_public_inputs: &table_public_inputs,
                            };
                            let owner = PreparedLayer::new(
                                source,
                                config.clone(),
                                backend.clone(),
                                params.clone(),
                            )
                            .unwrap_or_else(|e| panic!("Failed to prepare layer {layer}: {e:?}"));
                            let matches_previous = match pending_owner.as_ref() {
                                Some(previous_owner) => match previous_owner.check_input(&input) {
                                    Ok(()) => true,
                                    Err(error) if is_prepared_input_mismatch(&error) => false,
                                    Err(e) => panic!("Failed to validate layer {layer}: {e:?}"),
                                },
                                None => false,
                            };
                            let out = owner.prove(input);
                            if matches_previous {
                                stable_owner = Some(owner);
                                pending_owner = None;
                            } else {
                                pending_owner = Some(owner);
                            }
                            out
                        }
                    }
                    .unwrap_or_else(|e| panic!("Failed to prove layer {layer}: {e:?}"));

                    report_proof_size(&out.0);
                    let mut prover = BatchStarkProver::new(config.clone())
                        .with_table_packing(params.table_packing.clone());
                        for table_config in $poseidon2_config.output_table_configs() {
                            prover.$register_fn::<D>(table_config);
                        }
                    if !disable_recompose_npo {
                        prover.register_recompose_table::<D>(true);
                    }
                    prover
                        .verify_all_tables::<Challenge>(&out.0)
                        .unwrap_or_else(|e| panic!("Failed to verify layer {layer}: {e:?}"));

                    output = Some(out);
                }

                info!("Recursive proof verified successfully");
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

            #[allow(clippy::too_many_arguments)]
            pub fn run(
                num_hashes: usize,
                num_recursive_layers: usize,
                fri_params: &FriParams,
                table_packing: &TablePacking,
                security_level: usize,
                zk: bool,
                disable_recompose_npo: bool,
                profile: bool,
            ) {
                let keccak_air = KeccakAir {};
                let min_trace_rows: usize =
                    1 << (fri_params.log_final_poly_len + fri_params.log_blowup + 1);
                let min_keccak_hashes = min_trace_rows.div_ceil(p3_keccak_air::NUM_ROUNDS);
                let effective_num_hashes = num_hashes.max(min_keccak_hashes);
                if effective_num_hashes != num_hashes {
                    tracing::warn!("Number of equivalent Keccak hashes after mandatory padding: {effective_num_hashes}");
                }
                let mut trace_rng = SmallRng::seed_from_u64(1);
                let keccak_inputs: Vec<[u64; 25]> = (0..effective_num_hashes)
                    .map(|_| trace_rng.random())
                    .collect();
                let trace = p3_keccak_air::generate_trace_rows::<F>(
                    keccak_inputs,
                    fri_params.log_blowup,
                );

                // The base Keccak layer always uses non-ZK uni-stark (p3-uni-stark has no ZK support).
                let config_0 = config_with_fri_params(fri_params, security_level, disable_recompose_npo);
                let pis: Vec<F> = vec![];

                let proof_0 = prove(&config_0, &keccak_air, trace, &pis).unwrap();
                report_proof_size(&proof_0);

                verify(&config_0, &keccak_air, &proof_0, &pis)
                    .expect("Failed to verify Keccak proof natively");

                if num_recursive_layers < 1 {
                    return;
                }

                let backend = FriRecursionBackend::<$backend_width, $backend_rate, _>::new(
                    $poseidon2_config,
                )
                .for_extension_degree::<$d>();

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

                let mut pending_owner: Option<PreparedLayer<'_, ConfigWithFriParams, KeccakAir, _, D>> = None;
                let mut stable_owner: Option<PreparedLayer<'_, ConfigWithFriParams, KeccakAir, _, D>> = None;

                // `--profile` path: a `RecursionLayerProfile` fixed point is searched for
                // starting from layer 1's proof, re-solving against each new layer's own output
                // until the profile stops changing (mirroring `solve_fixed_point`'s own
                // documented cross-layer contract: one call only fits the single proof it
                // solved against, so reaching a true fixed point requires solving again against
                // a layer actually proved under the candidate). Once a solve leaves the profile
                // unchanged, that layer's owner is retained and reused only after input checks.
                let mut profile_config: Option<ConfigWithFriParams> = None;
                let mut current_profile: Option<RecursionLayerProfile> = None;
                let mut profile_owner: Option<PreparedLayer<'_, ConfigWithFriParams, KeccakAir, _, D>> = None;

                for layer in 1..=num_recursive_layers {
                    if profile && layer >= 2 {
                        let config = profile_config.get_or_insert_with(|| {
                            config_with_fri_params(fri_params, security_level, disable_recompose_npo)
                        });
                        let previous = output.as_ref().unwrap();
                        let table_public_inputs = batch_table_public_inputs(previous);
                        let input = batch_prepared_input(previous, &table_public_inputs);
                        let recursion_input = previous.into_recursion_input::<BatchOnly>();

                        if let Some(owner) = profile_owner.as_ref() {
                            match owner.check_input(&input) {
                                Ok(()) => {
                                    let out = owner.prove(input).unwrap_or_else(|e| {
                                        panic!("Failed to prove layer {layer}: {e:?}")
                                    });
                                    report_proof_size(&out.0);
                                    let mut prover = BatchStarkProver::new(config.clone())
                                        .with_table_packing(owner.params().table_packing.clone());
                                        for table_config in $poseidon2_config.output_table_configs() {
                                            prover.$register_fn::<$d>(table_config);
                                        }
                                    if !disable_recompose_npo {
                                        prover.register_recompose_table::<$d>(true);
                                    }
                                    prover.verify_all_tables::<Challenge>(&out.0).unwrap_or_else(|e| {
                                        panic!("Failed to verify layer {layer}: {e:?}")
                                    });
                                    output = Some(out);
                                    continue;
                                }
                                Err(error) if is_prepared_input_mismatch(&error) => {}
                                Err(e) => panic!("Failed to validate layer {layer}: {e:?}"),
                            }
                        }

                        let seed = current_profile.clone().unwrap_or_else(|| RecursionLayerProfile {
                            table_packing: table_packing.clone().with_fri_params(
                                fri_params.log_final_poly_len,
                                fri_params.log_blowup,
                            ),
                            hash: HashProfile::default(),
                            transcript: TranscriptKind::BaseDuplex,
                            constraint_profile: ConstraintProfile::Standard,
                        });
                        let resolved = solve_fixed_point::<ConfigWithFriParams, BatchOnly, _, D>(
                            seed.clone(),
                            &recursion_input,
                            config,
                            &backend,
                            8,
                        )
                        .unwrap_or_else(|e| {
                            panic!("solve_fixed_point failed before layer {layer}: {e:?}")
                        });
                        let already_stable = current_profile.as_ref() == Some(&resolved);
                        current_profile = Some(resolved.clone());

                        let source = PreparedSource::BatchStark {
                            proof: &previous.0,
                            common_data: &previous.0.stark_common,
                            table_public_inputs: &table_public_inputs,
                        };
                        let owner = PreparedLayer::new_with_profile(
                            source,
                            config.clone(),
                            backend.clone(),
                            resolved.clone(),
                        )
                        .unwrap_or_else(|e| panic!("Failed to prepare layer {layer}: {e:?}"));
                        let out = owner.prove(input).unwrap_or_else(|e| {
                            panic!("Failed to prove layer {layer}: {e:?}")
                        });

                        report_proof_size(&out.0);
                        let mut prover = BatchStarkProver::new(config.clone())
                            .with_table_packing(resolved.table_packing.clone());
                            for table_config in $poseidon2_config.output_table_configs() {
                                prover.$register_fn::<$d>(table_config);
                            }
                        if !disable_recompose_npo {
                            prover.register_recompose_table::<$d>(true);
                        }
                        prover
                            .verify_all_tables::<Challenge>(&out.0)
                            .unwrap_or_else(|e| panic!("Failed to verify layer {layer}: {e:?}"));

                        output = Some(out);
                        if already_stable {
                            profile_owner = Some(owner);
                        }
                        continue;
                    }

                    let layer_table_packing = {
                        let p = if layer == 1 {
                            let mut p = TablePacking::new(1, 2)
                                .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                            if let Some(rl) = table_packing.npo_lanes(&NpoTypeId::recompose()) {
                                p = p.with_npo_lanes(NpoTypeId::recompose(), rl);
                            }
                            p
                        } else {
                            table_packing.clone()
                        }
                        .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                        p
                    };
                    let params = ProveNextLayerParams {
                        table_packing: layer_table_packing,
                        constraint_profile: ConstraintProfile::Standard,
                    };
                    let config =
                        config_with_fri_params(fri_params, security_level, disable_recompose_npo);

                    let out = if layer == 1 {
                        let input = PreparedInput::UniStark {
                            proof: &proof_0,
                            public_inputs: &pis,
                            preprocessed_commit: None,
                        };
                        let source = PreparedSource::UniStark {
                            air: &keccak_air,
                            proof: &proof_0,
                            public_inputs: &pis,
                            preprocessed_commit: None,
                        };
                        let owner = PreparedLayer::new(
                            source,
                            config.clone(),
                            backend.clone(),
                            params.clone(),
                        )
                        .unwrap_or_else(|e| panic!("Failed to prepare layer {layer}: {e:?}"));
                        let out = owner.prove(input);
                        pending_owner = Some(owner);
                        out
                    } else {
                        let previous = output.as_ref().unwrap();
                        let table_public_inputs = batch_table_public_inputs(previous);
                        let input = batch_prepared_input(previous, &table_public_inputs);
                        if let Some(owner) = stable_owner.as_ref() {
                            match owner.check_input(&input) {
                                Ok(()) => owner.prove(input),
                                Err(error) if is_prepared_input_mismatch(&error) => {
                                    let source = PreparedSource::BatchStark {
                                        proof: &previous.0,
                                        common_data: &previous.0.stark_common,
                                        table_public_inputs: &table_public_inputs,
                                    };
                                    let owner = PreparedLayer::new(
                                        source,
                                        config.clone(),
                                        backend.clone(),
                                        params.clone(),
                                    )
                                    .unwrap_or_else(|e| panic!("Failed to reprepare layer {layer}: {e:?}"));
                                    let out = owner.prove(input);
                                    stable_owner = Some(owner);
                                    out
                                }
                                Err(e) => panic!("Failed to validate layer {layer}: {e:?}"),
                            }
                        } else {
                            let source = PreparedSource::BatchStark {
                                proof: &previous.0,
                                common_data: &previous.0.stark_common,
                                table_public_inputs: &table_public_inputs,
                            };
                            let owner = PreparedLayer::new(
                                source,
                                config.clone(),
                                backend.clone(),
                                params.clone(),
                            )
                            .unwrap_or_else(|e| panic!("Failed to prepare layer {layer}: {e:?}"));
                            let matches_previous = match pending_owner.as_ref() {
                                Some(previous_owner) => match previous_owner.check_input(&input) {
                                    Ok(()) => true,
                                    Err(error) if is_prepared_input_mismatch(&error) => false,
                                    Err(e) => panic!("Failed to validate layer {layer}: {e:?}"),
                                },
                                None => false,
                            };
                            let out = owner.prove(input);
                            if matches_previous {
                                stable_owner = Some(owner);
                                pending_owner = None;
                            } else {
                                pending_owner = Some(owner);
                            }
                            out
                        }
                    }
                    .unwrap_or_else(|e| panic!("Failed to prove layer {layer}: {e:?}"));

                    report_proof_size(&out.0);
                    let mut prover = BatchStarkProver::new(config.clone())
                        .with_table_packing(params.table_packing.clone());
                        for table_config in $poseidon2_config.output_table_configs() {
                            prover.$register_fn::<$d>(table_config);
                        }
                    if !disable_recompose_npo {
                        prover.register_recompose_table::<$d>(true);
                    }
                    prover
                        .verify_all_tables::<Challenge>(&out.0)
                        .unwrap_or_else(|e| panic!("Failed to verify layer {layer}: {e:?}"));

                    output = Some(out);
                }

                info!("Recursive proof verified successfully");
            }
        }
    };
}

define_field_module_keccak_quintic!(
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

define_field_module_keccak_quintic!(
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
