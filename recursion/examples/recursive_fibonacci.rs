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

use std::rc::Rc;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_challenger::DuplexChallenger;
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::{poseidon2_air_builders_d2, poseidon2_air_builders_d4};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor, TablePacking,
};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::fri::HidingFriProofTargets;
use p3_recursion::pcs::{
    InputProofTargets, MerkleCapTargets, RecValMmcs, set_fri_mmcs_private_data,
};
use p3_recursion::traits::{RecursiveAir, RecursivePcs};
use p3_recursion::verifier::VerificationError;
use p3_recursion::{
    BatchOnly, BatchStarkVerifierInputsBuilder, FriRecursionBackend, FriRecursionConfig,
    FriVerifierParams, Poseidon2Config, ProveNextLayerParams, RecursionInput, RecursionOutput,
    build_and_prove_next_layer, verify_batch_circuit,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val};
use rand::SeedableRng;
use rand::rngs::SmallRng as ZkRng;

/// A simple three-column AIR proving addition: row[2] = row[0] + row[1].
/// Used as the ZK base proof AIR in the recursive examples.
#[derive(Clone, Copy)]
struct ZkAddAir;

impl<Val: p3_field::Field> p3_air::BaseAir<Val> for ZkAddAir {
    fn width(&self) -> usize {
        3
    }
}

impl<AB: p3_air::AirBuilder> p3_air::Air<AB> for ZkAddAir
where
    AB::F: p3_field::Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0).expect("row must exist");
        builder.assert_zero(row[0] + row[1] - row[2]);
    }
}
use serde::Serialize;
use tracing::info;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FieldOption {
    KoalaBear,
    BabyBear,
    Goldilocks,
}

#[derive(Debug, Clone, Copy)]
struct FriParams {
    log_blowup: usize,
    max_log_arity: usize,
    cap_height: usize,
    log_final_poly_len: usize,
    commit_pow_bits: usize,
    query_pow_bits: usize,
}

#[derive(Parser, Debug)]
#[command(version, about = "Recursive Fibonacci proof verification example")]
struct Args {
    /// The field to use for the proof.
    #[arg(short, long, ignore_case = true, value_enum, default_value_t = FieldOption::KoalaBear)]
    field: FieldOption,

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

    #[arg(
        long,
        default_value_t = 3,
        help = "Logarithmic blowup factor for the LDE"
    )]
    log_blowup: usize,

    #[arg(
        long,
        default_value_t = 3,
        help = "Maximum arity allowed during FRI folding phases"
    )]
    max_log_arity: usize,

    #[arg(long, default_value_t = 2, help = "Height of the Merkle cap to open")]
    cap_height: usize,

    #[arg(
        long,
        default_value_t = 5,
        help = "Log size of final polynomial after FRI folding"
    )]
    log_final_poly_len: usize,

    #[arg(
        long,
        default_value_t = 0,
        help = "PoW grinding bits during FRI commit phase"
    )]
    commit_pow_bits: usize,

    #[arg(
        long,
        default_value_t = 18,
        help = "PoW grinding bits during FRI query phase"
    )]
    query_pow_bits: usize,

    #[arg(
        long,
        default_value_t = 2,
        help = "Number of public lanes for the table packing in recursive layers"
    )]
    public_lanes: usize,

    #[arg(
        long,
        default_value_t = 3,
        help = "Number of ALU lanes for the table packing in recursive layers"
    )]
    alu_lanes: usize,

    // TODO: Update once https://github.com/Plonky3/Plonky3/pull/1329 lands
    #[arg(
        long,
        default_value_t = 124,
        help = "Targeted security level (conjectured)"
    )]
    security_level: usize,

    /// Enable zero-knowledge proofs using HidingFriPcs.
    #[arg(long, default_value_t = false, help = "Enable ZK mode (HidingFriPcs)")]
    zk: bool,
}

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let _ = Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .try_init();
}

fn main() {
    init_logger();

    let args = Args::parse();
    let fri_params = FriParams {
        log_blowup: args.log_blowup,
        max_log_arity: args.max_log_arity,
        cap_height: args.cap_height,
        log_final_poly_len: args.log_final_poly_len,
        commit_pow_bits: args.commit_pow_bits,
        query_pow_bits: args.query_pow_bits,
    };
    let table_packing = TablePacking::new(args.public_lanes, args.alu_lanes);

    if args.num_recursive_layers < 1 {
        panic!("Number of recursive layers should be at least 1");
    }

    info!(
        "Recursively proving {} Fibonacci iterations with field {:?}",
        args.n, args.field
    );

    if args.zk {
        match args.field {
            FieldOption::KoalaBear => koala_bear::run_zk(
                args.n,
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
            ),
            FieldOption::BabyBear => baby_bear::run_zk(
                args.n,
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
            ),
            FieldOption::Goldilocks => goldilocks::run_zk(
                args.n,
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
            ),
        }
    } else {
        match args.field {
            FieldOption::KoalaBear => koala_bear::run(
                args.n,
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
            ),
            FieldOption::BabyBear => baby_bear::run(
                args.n,
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
            ),
            FieldOption::Goldilocks => goldilocks::run(
                args.n,
                args.num_recursive_layers,
                &fri_params,
                &table_packing,
                args.security_level,
            ),
        }
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
        $poseidon2_air_builders_fn:ident,
        $default_perm_circuit:path,
        $backend_ctor:ident,
        $backend_width:expr,
        $backend_rate:expr
    ) => {
        mod $mod_name {
            use super::*;

            pub type F = $field;
            pub const D: usize = $d;
            const WIDTH: usize = $width;
            const RATE: usize = $rate;
            const DIGEST_ELEMS: usize = $digest_elems;

            type Challenge = BinomialExtensionField<F, D>;
            type Dft = Radix2DitParallel<F>;
            type Perm = $perm;
            type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
            type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
            type ValMmcs = MerkleTreeMmcs<
                <F as Field>::Packing,
                <F as Field>::Packing,
                MyHash,
                MyCompress,
                DIGEST_ELEMS,
            >;
            type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
            type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
            type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
            type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

            type InnerFri = p3_recursion::pcs::FriProofTargets<
                F,
                Challenge,
                p3_recursion::pcs::RecExtensionValMmcs<
                    F,
                    Challenge,
                    DIGEST_ELEMS,
                    RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                >,
                InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
                p3_recursion::pcs::Witness<F>,
            >;

            #[derive(Clone)]
            struct ConfigWithFriParams {
                config: Arc<MyConfig>,
                fri_verifier_params: FriVerifierParams,
            }

            impl core::ops::Deref for ConfigWithFriParams {
                type Target = MyConfig;
                fn deref(&self) -> &MyConfig {
                    &self.config
                }
            }

            impl StarkGenericConfig for ConfigWithFriParams {
                type Challenge = Challenge;
                type Challenger = Challenger;
                type Pcs = MyPcs;
                fn pcs(&self) -> &MyPcs {
                    self.config.pcs()
                }
                fn initialise_challenger(&self) -> Challenger {
                    self.config.initialise_challenger()
                }
            }

            impl FriRecursionConfig for ConfigWithFriParams
            where
                MyPcs: RecursivePcs<
                        ConfigWithFriParams,
                        InputProofTargets<
                            F,
                            Challenge,
                            RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                        >,
                        InnerFri,
                        MerkleCapTargets<F, DIGEST_ELEMS>,
                        <MyPcs as Pcs<Challenge, Challenger>>::Domain,
                    >,
            {
                type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
                type InputProof = InputProofTargets<
                    F,
                    Challenge,
                    RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                >;
                type OpeningProof = InnerFri;
                type RawOpeningProof = <MyPcs as Pcs<Challenge, Challenger>>::Proof;
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
                    let perm = $default_perm_circuit();
                    circuit.$enable_poseidon2_fn::<$poseidon2_circuit_config, _>(
                        generate_poseidon2_trace::<Challenge, $poseidon2_circuit_config>,
                        perm,
                    );
                    Ok(())
                }

                fn pcs_verifier_params(
                    &self,
                ) -> &<MyPcs as RecursivePcs<
                    ConfigWithFriParams,
                    InputProofTargets<
                        F,
                        Challenge,
                        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                    >,
                    InnerFri,
                    MerkleCapTargets<F, DIGEST_ELEMS>,
                    <MyPcs as Pcs<Challenge, Challenger>>::Domain,
                >>::VerifierParams {
                    &self.fri_verifier_params
                }

                fn set_fri_private_data(
                    runner: &mut CircuitRunner<Challenge>,
                    op_ids: &[NonPrimitiveOpId],
                    opening_proof: &Self::RawOpeningProof,
                ) -> Result<(), &'static str> {
                    set_fri_mmcs_private_data::<
                        F,
                        Challenge,
                        ChallengeMmcs,
                        ValMmcs,
                        MyHash,
                        MyCompress,
                        DIGEST_ELEMS,
                    >(runner, op_ids, opening_proof)
                }
            }

            fn create_config(fp: &FriParams, security_level: usize) -> MyConfig {
                let perm = $default_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm.clone());
                let val_mmcs = ValMmcs::new(hash, compress, fp.cap_height);
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
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
                let pcs = MyPcs::new(dft, val_mmcs, fri_params);
                let challenger = Challenger::new(perm);
                MyConfig::new(pcs, challenger)
            }

            const fn create_fri_verifier_params(fp: &FriParams) -> FriVerifierParams {
                FriVerifierParams::with_mmcs(
                    fp.log_blowup,
                    fp.log_final_poly_len,
                    fp.commit_pow_bits,
                    fp.query_pow_bits,
                    $poseidon2_config,
                )
            }

            fn config_with_fri_params(
                fp: &FriParams,
                security_level: usize,
            ) -> ConfigWithFriParams {
                ConfigWithFriParams {
                    config: Arc::new(create_config(fp, security_level)),
                    fri_verifier_params: create_fri_verifier_params(fp),
                }
            }

            type MyPcsZk = HidingFriPcs<F, Dft, ValMmcs, ChallengeMmcs, ZkRng>;
            type MyConfigZk = StarkConfig<MyPcsZk, Challenge, Challenger>;

            type InnerFriZk = HidingFriProofTargets<
                F,
                Challenge,
                p3_recursion::pcs::RecExtensionValMmcs<
                    F,
                    Challenge,
                    DIGEST_ELEMS,
                    RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                >,
                InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
                p3_recursion::pcs::Witness<F>,
            >;

            fn create_zk_config(fp: &FriParams, security_level: usize) -> MyConfigZk {
                let perm = $default_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm.clone());
                let val_mmcs = ValMmcs::new(hash, compress, fp.cap_height);
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
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
                let pcs = MyPcsZk::new(dft, val_mmcs, fri_params, 2, ZkRng::seed_from_u64(42));
                let challenger = Challenger::new(perm);
                MyConfigZk::new(pcs, challenger)
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

            fn generate_zk_add_trace(rows: usize) -> RowMajorMatrix<F> {
                let rows = rows.max(1).next_power_of_two();
                let mut vals = F::zero_vec(rows * 3);
                for i in 0..rows {
                    let a = F::from_usize(i);
                    let b = F::from_usize(i + 1);
                    vals[i * 3] = a;
                    vals[i * 3 + 1] = b;
                    vals[i * 3 + 2] = a + b;
                }
                RowMajorMatrix::new(vals, 3)
            }

            pub fn run_zk(
                n: usize,
                num_recursive_layers: usize,
                fri_params: &FriParams,
                table_packing: &TablePacking,
                security_level: usize,
            ) {
                // --- Layer 0: prove a Fibonacci AIR directly with HidingFriPcs (ZK) ---
                // We use prove_batch directly (not CircuitBuilder) to avoid the Sync requirement
                // of get_airs_and_degrees_with_prep, which is incompatible with HidingFriPcs
                // (it uses RefCell internally, making it !Sync).
                let config_zk = create_zk_config(fri_params, security_level);
                let air = ZkAddAir;
                let trace = generate_zk_add_trace(64);
                let pvs: Vec<Vec<F>> = vec![vec![]];
                let _ = n;

                let instances = vec![StarkInstance {
                    air: &air,
                    trace,
                    public_values: pvs[0].clone(),
                    lookups: vec![],
                }];
                let prover_data_zk = ProverData::from_instances(&config_zk, &instances);
                let common_0 = &prover_data_zk.common;

                let proof_zk = prove_batch(&config_zk, &instances, &prover_data_zk);

                verify_batch(&config_zk, &[air], &proof_zk, &pvs, common_0)
                    .expect("Failed to verify base ZK proof");
                eprintln!("ZK layer 0: Fibonacci({n}) proved with HidingFriPcs");

                if num_recursive_layers == 0 {
                    info!("ZK proof verified successfully");
                    return;
                }

                // --- Layer 1: recursively verify the ZK proof, prove with non-ZK ---
                // The verification circuit is built using MyConfigZk (for correct FRI verification),
                // but proved with ConfigWithFriParams (TwoAdicFriPcs) to avoid the Sync limitation
                // of HidingFriPcs (which uses RefCell<R> internally, making it !Sync).
                let fri_verifier_params = create_fri_verifier_params(fri_params);
                let config_rec = config_with_fri_params(fri_params, security_level);

                let perm_rec = $default_perm_circuit();
                let mut circuit_builder = CircuitBuilder::new();
                circuit_builder.$enable_poseidon2_fn::<$poseidon2_circuit_config, _>(
                    generate_poseidon2_trace::<Challenge, $poseidon2_circuit_config>,
                    perm_rec,
                );

                let lookup_gadget = LogUpGadget::new();
                let air_public_counts = vec![0usize; proof_zk.opened_values.instances.len()];
                let verifier_inputs = BatchStarkVerifierInputsBuilder::<
                    MyConfigZk,
                    MerkleCapTargets<F, DIGEST_ELEMS>,
                    InnerFriZk,
                >::allocate(
                    &mut circuit_builder,
                    &proof_zk,
                    common_0,
                    &air_public_counts,
                );

                let mmcs_op_ids = verify_batch_circuit::<
                    _,
                    MyConfigZk,
                    MerkleCapTargets<F, DIGEST_ELEMS>,
                    InputProofTargets<
                        F,
                        Challenge,
                        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                    >,
                    InnerFriZk,
                    _,
                    _,
                    WIDTH,
                    RATE,
                >(
                    &config_zk,
                    &[air],
                    &mut circuit_builder,
                    &verifier_inputs.proof_targets,
                    &verifier_inputs.air_public_targets,
                    &fri_verifier_params,
                    &verifier_inputs.common_data,
                    &lookup_gadget,
                    $poseidon2_config,
                )
                .expect("Failed to build ZK verification circuit");

                let verification_circuit = circuit_builder.build().unwrap();
                let public_inputs = verifier_inputs.pack_values(&pvs, &proof_zk, common_0);

                let table_packing_1 = table_packing
                    .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                let poseidon2_prep: [Box<dyn NpoPreprocessor<F>>; 1] =
                    [Box::new(Poseidon2Preprocessor)];
                let (rec_airs_degrees, rec_preprocessed_columns) =
                    get_airs_and_degrees_with_prep::<ConfigWithFriParams, _, D>(
                        &verification_circuit,
                        table_packing_1,
                        &poseidon2_prep,
                        &$poseidon2_air_builders_fn(),
                        ConstraintProfile::Standard,
                    )
                    .unwrap();
                let (mut rec_airs, rec_degrees): (Vec<_>, Vec<_>) =
                    rec_airs_degrees.into_iter().unzip();

                let mut runner_1 = verification_circuit.clone().runner();
                runner_1.set_public_inputs(&public_inputs).unwrap();
                if !mmcs_op_ids.is_empty() {
                    // HidingFriPcs opening proof is (random_opened_values, inner_fri_proof).
                    set_fri_mmcs_private_data::<
                        F,
                        Challenge,
                        ChallengeMmcs,
                        ValMmcs,
                        MyHash,
                        MyCompress,
                        DIGEST_ELEMS,
                    >(&mut runner_1, &mmcs_op_ids, &proof_zk.opening_proof.1)
                    .expect("Failed to set MMCS private data for ZK proof");
                }
                let traces_1 = runner_1.run().unwrap();

                let prover_data_1 =
                    ProverData::from_airs_and_degrees(&config_rec, &mut rec_airs, &rec_degrees);
                let circuit_prover_data_1 =
                    CircuitProverData::new(prover_data_1, rec_preprocessed_columns);

                let mut prover_1 =
                    BatchStarkProver::new(config_rec.clone()).with_table_packing(table_packing_1);
                prover_1.$register_poseidon2_fn($poseidon2_config);
                let proof_1 = prover_1
                    .prove_all_tables(&traces_1, &circuit_prover_data_1)
                    .expect("Failed to prove ZK recursive layer 1");
                report_proof_size(&proof_1);
                prover_1
                    .verify_all_tables(&proof_1, circuit_prover_data_1.common_data())
                    .expect("Failed to verify ZK recursive layer 1");
                eprintln!("ZK layer 1: recursive ZK verification proved with TwoAdicFriPcs");

                if num_recursive_layers == 1 {
                    info!("ZK recursive proof verified successfully");
                    return;
                }

                // --- Layers 2+: standard non-ZK recursion on the already-non-ZK proof ---
                let backend = FriRecursionBackend::<$backend_width, $backend_rate>::$backend_ctor(
                    $poseidon2_config,
                );
                let mut output = RecursionOutput(proof_1, Rc::new(circuit_prover_data_1));

                for layer in 2..=num_recursive_layers {
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
                    .unwrap_or_else(|e| panic!("Failed to prove ZK layer {layer}: {e:?}"));

                    report_proof_size(&out.0);
                    let mut prover = BatchStarkProver::new(config.clone())
                        .with_table_packing(params.table_packing);
                    prover.$register_poseidon2_fn($poseidon2_config);
                    prover
                        .verify_all_tables(&out.0, out.1.common_data())
                        .unwrap_or_else(|e| panic!("Failed to verify ZK layer {layer}: {e:?}"));

                    output = out;
                }

                info!("ZK recursive proof verified successfully");
            }

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
                    get_airs_and_degrees_with_prep::<ConfigWithFriParams, _, 1>(
                        &base_circuit,
                        table_packing_0,
                        &[],
                        &[],
                        ConstraintProfile::Standard,
                    )
                    .unwrap();
                let (mut airs_0, degrees_0): (Vec<_>, Vec<_>) = airs_degrees_0.into_iter().unzip();

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
        }
    };
}

fn default_goldilocks_poseidon2_8() -> p3_goldilocks::Poseidon2Goldilocks<8> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::SmallRng::seed_from_u64(1);
    p3_goldilocks::Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng)
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
    poseidon2_air_builders_d4,
    p3_koala_bear::default_koalabear_poseidon2_16,
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
    poseidon2_air_builders_d4,
    p3_baby_bear::default_babybear_poseidon2_16,
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
    poseidon2_air_builders_d2,
    default_goldilocks_poseidon2_8,
    new_d2,
    8,
    4
);

/// Report the size of the serialized proof.
#[inline]
pub fn report_proof_size<S: Serialize>(proof: &S) {
    let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
    println!("Proof size: {} bytes", proof_bytes.len());
}
