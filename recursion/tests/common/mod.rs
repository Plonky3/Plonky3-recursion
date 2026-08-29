#![allow(unused)]

use std::sync::Arc;

use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::ProverData;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProof, CircuitProverData, ConstraintProfile, TablePacking};
use p3_commit::Pcs;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::pcs::{
    FriProofTargets, InputProofTargets, MerkleCapTargets, RecExtensionValMmcs, RecValMmcs, Witness,
    set_fri_mmcs_private_data,
};
use p3_recursion::profile::{
    HashProfile, ProfilePrepCache, RecursionLayerProfile, TranscriptKind, build_layer_circuit,
    prove_layer, solve_fixed_point,
};
use p3_recursion::traits::{RecursiveAir, RecursivePcs};
use p3_recursion::verifier::VerificationError;
use p3_recursion::{
    BatchOnly, FriRecursionBackend, FriRecursionBackendForExt, FriRecursionConfig,
    FriVerifierParams, Poseidon2Config, ProveNextLayerParams, RecursionInput, RecursionOutput,
    build_next_layer_prep,
};
use p3_test_utils::koala_bear_params::*;
use p3_uni_stark::{StarkGenericConfig, Val};
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::SmallRng;
use rand::{Rng, RngExt, SeedableRng};

// Type of the `OpeningProof` used in the circuit for a `TwoAdicFriPcs`.
pub(crate) type InnerFriGeneric<MyConfig, MyHash, MyCompress, const DIGEST_ELEMS: usize> =
    FriProofTargets<
        Val<MyConfig>,
        <MyConfig as StarkGenericConfig>::Challenge,
        RecExtensionValMmcs<
            Val<MyConfig>,
            <MyConfig as StarkGenericConfig>::Challenge,
            DIGEST_ELEMS,
            RecValMmcs<Val<MyConfig>, DIGEST_ELEMS, MyHash, MyCompress>,
        >,
        InputProofTargets<
            Val<MyConfig>,
            <MyConfig as StarkGenericConfig>::Challenge,
            RecValMmcs<Val<MyConfig>, DIGEST_ELEMS, MyHash, MyCompress>,
        >,
        Witness<Val<MyConfig>>,
    >;

/// A test AIR that enforces multiplication constraints: `a^(degree-1) * b = c`
///
/// # Constraints
/// For each of REPETITIONS triples `(a, b, c)`:
/// 1. Multiplication: `a^(degree-1) * b = c`
/// 2. First row: `a^2 + 1 = b`
/// 3. Transition: `a' = a + REPETITIONS` (where `a'` is next row's `a`)
///
/// # Trace Layout
/// The trace has TRACE_WIDTH = REPETITIONS * 3 columns:
/// `[a_0, b_0, c_0, a_1, b_1, c_1, ..., a_19, b_19, c_19]`
#[derive(Clone, Copy)]
pub(crate) struct MulAir {
    /// Degree of the polynomial constraint `(a^(degree-1) * b = c)`
    pub(crate) degree: u64,
    pub(crate) rows: usize,
}

impl Default for MulAir {
    fn default() -> Self {
        Self {
            degree: 3,
            rows: 1 << 3,
        }
    }
}

/// Number of repetitions of the multiplication constraint (must be < 255 to fit in u8)
pub(crate) const REPETITIONS: usize = 20;

/// Total trace width: 3 columns per repetition (a, b, c)
pub(crate) const MAIN_TRACE_WIDTH: usize = REPETITIONS; // For c values
pub(crate) const PREP_WIDTH: usize = REPETITIONS * 2; // For a and b values

impl MulAir {
    /// Generate a random valid (or invalid) trace for testing. The trace consists of a main trace and a preprocessed trace.
    ///
    /// # Parameters
    /// - `rows`: Number of rows in the trace
    /// - `valid`: If true, generates a valid trace; if false, makes it invalid
    pub fn random_valid_trace<Val: Field>(
        &self,
        valid: bool,
    ) -> (RowMajorMatrix<Val>, RowMajorMatrix<Val>)
    where
        StandardUniform: Distribution<Val>,
    {
        let mut rng = SmallRng::seed_from_u64(1);
        let mut main_trace_values = Val::zero_vec(self.rows * MAIN_TRACE_WIDTH);
        let mut prep_trace_values = Val::zero_vec(self.rows * PREP_WIDTH);

        for (i, (a, b)) in prep_trace_values.iter_mut().tuples().enumerate() {
            let row = i / REPETITIONS;
            *a = Val::from_usize(i);

            // First row: b = a^2 + 1
            // Other rows: random b
            *b = if row == 0 {
                a.square() + Val::ONE
            } else {
                rng.random()
            };

            // Compute c = a^(degree-1) * b
            main_trace_values[i] = a.exp_u64(self.degree - 1) * *b;

            if !valid {
                // Make the trace invalid by corrupting c
                main_trace_values[i] *= Val::TWO;
            }
        }

        (
            RowMajorMatrix::new(main_trace_values, MAIN_TRACE_WIDTH),
            RowMajorMatrix::new(prep_trace_values, PREP_WIDTH),
        )
    }
}

impl<Val: Field> BaseAir<Val> for MulAir
where
    StandardUniform: Distribution<Val>,
{
    fn width(&self) -> usize {
        MAIN_TRACE_WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        PREP_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        Some(self.random_valid_trace(true).1)
    }
}

impl<AB: AirBuilder> Air<AB> for MulAir
where
    AB::F: Field,
    StandardUniform: Distribution<AB::F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice();

        let preprocessed = builder.preprocessed().clone();
        let preprocessed_local = preprocessed.current_slice();
        let preprocessed_next = preprocessed.next_slice();

        for (i, c) in main_local.iter().enumerate() {
            let prep_start = i * 2;
            let a = preprocessed_local[prep_start];
            let b = preprocessed_local[prep_start + 1];

            // Constraint 1: a^(degree-1) * b = c
            builder.assert_zero(a.into().exp_u64(self.degree - 1) * b - *c);

            // Constraint 2: On first row, b = a^2 + 1
            builder.when_first_row().assert_eq(a * a + AB::Expr::ONE, b);

            // Constraint 3: On transition rows, a' = a + REPETITIONS
            let next_a = preprocessed_next[prep_start];
            builder
                .when_transition()
                .assert_eq(a + AB::Expr::from_u8(REPETITIONS as u8), next_a);
        }
    }
}

/// `OpeningProof` type for a KoalaBear D4 `TwoAdicFriPcs` recursion-layer verifier circuit.
pub(crate) type KoalaBearD4InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;

/// FRI-recursion config for the standard KoalaBear D4 test STARK config
/// ([`p3_test_utils::koala_bear_params::MyConfig`]), holding the FRI verifier parameters a
/// recursion-layer verifier circuit needs. `Arc`-wrapped so cloning (required by
/// `build_next_layer_circuit`/`build_next_layer_prep`) is cheap.
#[derive(Clone)]
pub(crate) struct KoalaBearD4RecursionConfig {
    config: Arc<MyConfig>,
    fri_verifier_params: FriVerifierParams,
}

impl core::ops::Deref for KoalaBearD4RecursionConfig {
    type Target = MyConfig;
    fn deref(&self) -> &MyConfig {
        &self.config
    }
}

impl StarkGenericConfig for KoalaBearD4RecursionConfig {
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

impl FriRecursionConfig for KoalaBearD4RecursionConfig
where
    MyPcs: RecursivePcs<
            Self,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            KoalaBearD4InnerFri,
            MerkleCapTargets<F, DIGEST_ELEMS>,
            <MyPcs as Pcs<Challenge, Challenger>>::Domain,
        >,
{
    type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
    type InputProof =
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>;
    type OpeningProof = KoalaBearD4InnerFri;
    type RawOpeningProof = <MyPcs as Pcs<Challenge, Challenger>>::Proof;
    const DIGEST_ELEMS: usize = DIGEST_ELEMS;

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
        let perm = default_koalabear_poseidon2_16();
        circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
            perm,
        );
        circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
        Ok(())
    }

    fn pcs_verifier_params(
        &self,
    ) -> &<MyPcs as RecursivePcs<
        Self,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        KoalaBearD4InnerFri,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        <MyPcs as Pcs<Challenge, Challenger>>::Domain,
    >>::VerifierParams {
        &self.fri_verifier_params
    }

    fn set_fri_private_data(
        runner: &mut CircuitRunner<'_, Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
    ) -> Result<(), &'static str> {
        set_fri_mmcs_private_data::<
            F,
            Challenge,
            ChallengeMmcs,
            MyMmcs,
            MyHash,
            MyCompress,
            DIGEST_ELEMS,
        >(
            runner,
            op_ids,
            opening_proof,
            Poseidon2Config::KOALA_BEAR_D4_W16,
        )
    }
}

/// Backend type for a KoalaBear D4 recursion layer (spelled out so callers can turbofish it,
/// e.g. `build_next_layer_prep::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>`).
pub(crate) type KoalaBearD4Backend = FriRecursionBackendForExt<4, 16, 8, Poseidon2Config>;

/// Everything [`solve_fixed_point`](p3_recursion::solve_fixed_point) needs to build/probe a
/// first recursion layer over a KoalaBear D4 base batch-STARK proof.
pub(crate) struct KoalaBearD4FirstLayerFixture {
    pub(crate) layer_config: KoalaBearD4RecursionConfig,
    pub(crate) backend: KoalaBearD4Backend,
    pub(crate) base_proof: BatchStarkProof<KoalaBearD4RecursionConfig>,
}

impl KoalaBearD4FirstLayerFixture {
    /// Build the `RecursionInput::BatchStark` for this fixture's base proof.
    pub(crate) fn recursion_input(
        &self,
    ) -> RecursionInput<'_, KoalaBearD4RecursionConfig, BatchOnly> {
        let num_tables = self.base_proof.proof.opened_values.instances.len();
        RecursionInput::BatchStark {
            proof: &self.base_proof,
            common_data: &self.base_proof.stark_common,
            table_public_inputs: vec![vec![]; num_tables],
        }
    }
}

fn compute_fibonacci_classical(n: usize) -> F {
    if n == 0 {
        return F::ZERO;
    }
    if n == 1 {
        return F::ONE;
    }
    let mut a = F::ZERO;
    let mut b = F::ONE;
    for _i in 2..=n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}

/// Build a base KoalaBear D4 Fibonacci batch-STARK proof (mirroring
/// `fibonacci_batch_stark_prover.rs`'s base-proof setup) and wrap it as the fixture for a first
/// recursion layer: `solve_fixed_point` can build/probe a verifier circuit over it directly via
/// `[layer_config]`/`[backend]`/`[recursion_input]`.
pub(crate) fn build_koala_bear_d4_first_layer_input() -> KoalaBearD4FirstLayerFixture {
    build_koala_bear_d4_first_layer_input_with_pow_bits(test_fri_scalars().query_pow_bits)
}

/// Same as [`build_koala_bear_d4_first_layer_input`] but with explicit FRI PoW bits (applied to
/// both `commit_proof_of_work_bits` and `query_proof_of_work_bits`) instead of
/// `test_fri_scalars()`'s. Callers that need a deterministic `grind` -- e.g. comparing two
/// independently-produced proofs byte-for-byte -- can pass `pow_bits = 0`.
pub(crate) fn build_koala_bear_d4_first_layer_input_with_pow_bits(
    pow_bits: usize,
) -> KoalaBearD4FirstLayerFixture {
    let n: usize = 100;

    let mut builder = CircuitBuilder::new();
    let expected_result = builder.alloc_public_input("expected_result");
    let mut a = builder.alloc_const(F::ZERO, "F(0)");
    let mut b = builder.alloc_const(F::ONE, "F(1)");
    for _i in 2..=n {
        let next = builder.add(a, b);
        a = b;
        b = next;
    }
    builder.connect(b, expected_result);

    let table_packing = TablePacking::new(2, 4);

    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        pow_bits,
        pow_bits,
        scalars.num_queries,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    );
    let layer_config = KoalaBearD4RecursionConfig {
        config: Arc::new(make_test_config_with_pow_bits(pow_bits)),
        fri_verifier_params,
    };

    let circuit = builder.build().unwrap();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearD4RecursionConfig, _, 1>(
            &circuit,
            &table_packing,
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let expected_fib = compute_fibonacci_classical(n);
    runner.set_public_inputs(&[expected_fib]).unwrap();
    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&layer_config, &airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let prover = BatchStarkProver::new(layer_config.clone()).with_table_packing(table_packing);
    let base_proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    prover.verify_all_tables::<F>(&base_proof).unwrap();

    let backend = FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>();

    KoalaBearD4FirstLayerFixture {
        layer_config,
        backend,
        base_proof,
    }
}

/// A solved [`RecursionLayerProfile`] for a KoalaBear D4 first recursion layer, together with
/// the config/backend that solved it and the `RecursionInput` it was solved against.
///
/// The underlying fixture is leaked so the returned `RecursionInput` (which borrows from it)
/// can outlive this function; test processes are short-lived, so this is a one-shot leak per
/// call rather than something that accumulates across a long-running program.
pub(crate) fn solved_koala_bear_d4_profile() -> (
    KoalaBearD4RecursionConfig,
    KoalaBearD4Backend,
    RecursionInput<'static, KoalaBearD4RecursionConfig, BatchOnly>,
    RecursionLayerProfile,
) {
    // PoW bits pinned to 0 so `GrindingChallenger::grind` is deterministic: downstream
    // consumers of this profile compare independently-produced proofs byte-for-byte, which
    // requires every proof in the chain to grind to the same (trivial) witness.
    let fixture: &'static KoalaBearD4FirstLayerFixture = Box::leak(Box::new(
        build_koala_bear_d4_first_layer_input_with_pow_bits(0),
    ));
    let prev_input = fixture.recursion_input();

    // Same undersized seed as `profile_fixed_point.rs`: no per-table height overrides, so
    // convergence requires real iteration against this layer's actual table shapes.
    let seed = RecursionLayerProfile {
        table_packing: TablePacking::new(1, 3).with_horner_pack_k(4),
        hash: HashProfile::default(),
        transcript: TranscriptKind::default(),
        constraint_profile: ConstraintProfile::default(),
    };
    let profile = solve_fixed_point::<_, _, _, 4>(
        seed,
        &prev_input,
        &fixture.layer_config,
        &fixture.backend,
        8,
    )
    .expect(
        "solve_fixed_point should converge within 8 iterations for the KoalaBear D4 first layer",
    );

    (
        fixture.layer_config.clone(),
        fixture.backend.clone(),
        prev_input,
        profile,
    )
}

/// Build and prove one recursion layer entirely under `profile`: the verifier circuit is built
/// with [`build_layer_circuit`] and proved with [`prove_layer`] using a freshly built
/// [`ProfilePrepCache`], so both the circuit and the proof are self-consistent with `profile`.
/// Returns the layer's output together with the prep cache used to produce it.
pub(crate) fn prove_one_layer(
    profile: &RecursionLayerProfile,
    prev_input: &RecursionInput<'_, KoalaBearD4RecursionConfig, BatchOnly>,
    config: &KoalaBearD4RecursionConfig,
    backend: &KoalaBearD4Backend,
) -> (
    RecursionOutput<KoalaBearD4RecursionConfig>,
    ProfilePrepCache<KoalaBearD4RecursionConfig>,
) {
    let (circuit, verifier_result) =
        build_layer_circuit::<_, _, _, 4>(profile, prev_input, config, backend)
            .expect("build_layer_circuit should succeed");

    let inner =
        build_next_layer_prep::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &circuit,
            config,
            backend,
            &ProveNextLayerParams {
                table_packing: profile.table_packing.clone(),
                constraint_profile: ConstraintProfile::Standard,
            },
        )
        .expect("build_next_layer_prep should succeed for a profile-resolved table packing");

    let prep = ProfilePrepCache {
        profile: profile.clone(),
        inner,
    };

    let output = prove_layer::<_, _, _, 4>(
        profile,
        prev_input,
        &circuit,
        &verifier_result,
        config,
        backend,
        Some(&prep),
    )
    .expect("prove_layer should succeed under its own profile");

    (output, prep)
}
