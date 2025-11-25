//! Test for recursive STARK verification with a multiplication AIR.

use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_batch_stark::{CommonData, StarkInstance, prove_batch, verify_batch};
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::fri::{
    FriProofTargets, FriVerifierParams, HashTargets, InputProofTargets, RecExtensionValMmcs,
    RecValMmcs, Witness,
};
use p3_recursion::public_inputs::{BatchStarkVerifierInputsBuilder, StarkVerifierInputsBuilder};
use p3_recursion::{
    VerificationError, generate_batch_challenges, generate_challenges, verify_batch_circuit,
    verify_circuit,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    StarkConfig, StarkGenericConfig, Val, prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed,
};
use p3_util::log2_ceil_usize;
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

type F = BabyBear;
const D: usize = 4;
const RATE: usize = 8;
type Challenge = BinomialExtensionField<F, D>;
type Dft = Radix2DitParallel<F>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, RATE, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm, 16, RATE>;
type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

const DIGEST_ELEMS: usize = 8;

// Type of the `OpeningProof` used in the circuit for a `TwoAdicFriPcs`.
type InnerFri = FriProofTargets<
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

/// Enum to hold different AIR types for batch verification
#[derive(Clone, Copy)]
pub enum MixedAir {
    MulWithPreprocessed(MulAir),
    AddNoPreprocessed(AddAirNoPreprocessed),
    SubPartialPreprocessed(SubAirPartialPreprocessed),
}

impl<Val: Field> BaseAir<Val> for MixedAir
where
    StandardUniform: Distribution<Val>,
{
    fn width(&self) -> usize {
        match self {
            Self::MulWithPreprocessed(air) => BaseAir::<Val>::width(air),
            Self::AddNoPreprocessed(air) => BaseAir::<Val>::width(air),
            Self::SubPartialPreprocessed(air) => BaseAir::<Val>::width(air),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        match self {
            Self::MulWithPreprocessed(air) => BaseAir::<Val>::preprocessed_trace(air),
            Self::AddNoPreprocessed(air) => BaseAir::<Val>::preprocessed_trace(air),
            Self::SubPartialPreprocessed(air) => BaseAir::<Val>::preprocessed_trace(air),
        }
    }
}

impl<AB: PairBuilder> Air<AB> for MixedAir
where
    AB::F: Field,
    StandardUniform: Distribution<AB::F>,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::MulWithPreprocessed(air) => Air::<AB>::eval(air, builder),
            Self::AddNoPreprocessed(air) => Air::<AB>::eval(air, builder),
            Self::SubPartialPreprocessed(air) => Air::<AB>::eval(air, builder),
        }
    }
}

/// Number of repetitions of the multiplication constraint (must be < 255 to fit in u8)
const REPETITIONS: usize = 20;

/// Total trace width: 3 columns per repetition (a, b, c)
const MAIN_TRACE_WIDTH: usize = REPETITIONS; // For c values
const PREP_WIDTH: usize = REPETITIONS * 2; // For a and b values``

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
pub struct MulAir {
    /// Degree of the polynomial constraint `(a^(degree-1) * b = c)`
    degree: u64,
    rows: usize,
}

impl Default for MulAir {
    fn default() -> Self {
        Self {
            degree: 3,
            rows: 1 << 3,
        }
    }
}

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
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        Some(self.random_valid_trace(true).1)
    }
}

impl<AB: PairBuilder> Air<AB> for MulAir
where
    AB::F: Field,
    StandardUniform: Distribution<AB::F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.row_slice(0).expect("Matrix is empty?");

        let preprocessed = builder.preprocessed();
        let preprocessed_local = preprocessed
            .row_slice(0)
            .expect("Preprocessed matrix is empty?");
        let preprocessed_next = preprocessed
            .row_slice(1)
            .expect("Preprocessed matrix only has 1 row?");

        for i in 0..REPETITIONS {
            let prep_start = i * 2;
            let a = preprocessed_local[prep_start].clone();
            let b = preprocessed_local[prep_start + 1].clone();
            let c = main_local[i].clone();

            // Constraint 1: a^(degree-1) * b = c
            builder.assert_zero(a.clone().into().exp_u64(self.degree - 1) * b.clone() - c);

            // Constraint 2: On first row, b = a^2 + 1
            builder
                .when_first_row()
                .assert_eq(a.clone() * a.clone() + AB::Expr::ONE, b);

            // Constraint 3: On transition rows, a' = a + REPETITIONS
            let next_a = preprocessed_next[prep_start].clone();
            builder
                .when_transition()
                .assert_eq(a + AB::Expr::from_u8(REPETITIONS as u8), next_a);
        }
    }
}

/// AIR that doesn't have preprocessed columns - simple addition of two values
#[derive(Clone, Copy)]
pub struct AddAirNoPreprocessed {
    rows: usize,
}

impl Default for AddAirNoPreprocessed {
    fn default() -> Self {
        Self { rows: 1 << 3 }
    }
}

impl AddAirNoPreprocessed {
    pub fn random_valid_trace<Val: Field>(&self, valid: bool) -> RowMajorMatrix<Val>
    where
        StandardUniform: Distribution<Val>,
    {
        let width = 3; // [a, b, c] columns
        let mut main_trace_values = Val::zero_vec(self.rows * width);

        for row in 0..self.rows {
            let base_idx = row * width;
            let a = Val::from_usize(row);
            let b = Val::from_usize(row + 1);
            main_trace_values[base_idx] = a;
            main_trace_values[base_idx + 1] = b;

            // c = a + b
            main_trace_values[base_idx + 2] = if valid {
                a + b
            } else {
                a + b + Val::ONE // Make invalid
            };
        }

        RowMajorMatrix::new(main_trace_values, width)
    }
}

impl<Val: Field> BaseAir<Val> for AddAirNoPreprocessed
where
    StandardUniform: Distribution<Val>,
{
    fn width(&self) -> usize {
        3 // [a, b, c]
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        None // No preprocessed columns
    }
}

impl<AB: PairBuilder> Air<AB> for AddAirNoPreprocessed
where
    AB::F: Field,
    StandardUniform: Distribution<AB::F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.row_slice(0).expect("Matrix is empty?");

        let a = main_local[0].clone();
        let b = main_local[1].clone();
        let c = main_local[2].clone();

        // Constraint: a + b = c
        builder.assert_zero(a + b - c);
    }
}

/// AIR that has some preprocessed columns - subtraction with one preprocessed constant
#[derive(Clone, Copy)]
pub struct SubAirPartialPreprocessed {
    rows: usize,
}

impl Default for SubAirPartialPreprocessed {
    fn default() -> Self {
        Self { rows: 1 << 3 }
    }
}

impl SubAirPartialPreprocessed {
    pub fn random_valid_trace<Val: Field>(
        &self,
        valid: bool,
    ) -> (RowMajorMatrix<Val>, RowMajorMatrix<Val>)
    where
        StandardUniform: Distribution<Val>,
    {
        let main_width = 2; // [a, result] columns
        let prep_width = 1; // [constant] column

        let mut main_trace_values = Val::zero_vec(self.rows * main_width);
        let mut prep_trace_values = Val::zero_vec(self.rows * prep_width);

        for row in 0..self.rows {
            let main_base_idx = row * main_width;
            let prep_base_idx = row * prep_width;

            let a = Val::from_usize(row + 10);
            let constant = Val::from_usize(5); // Preprocessed constant

            main_trace_values[main_base_idx] = a;
            prep_trace_values[prep_base_idx] = constant;

            // result = a - constant
            main_trace_values[main_base_idx + 1] = if valid {
                a - constant
            } else {
                a - constant + Val::ONE // Make invalid
            };
        }

        (
            RowMajorMatrix::new(main_trace_values, main_width),
            RowMajorMatrix::new(prep_trace_values, prep_width),
        )
    }
}

impl<Val: Field> BaseAir<Val> for SubAirPartialPreprocessed
where
    StandardUniform: Distribution<Val>,
{
    fn width(&self) -> usize {
        2 // [a, result]
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        Some(self.random_valid_trace(true).1)
    }
}

impl<AB: PairBuilder> Air<AB> for SubAirPartialPreprocessed
where
    AB::F: Field,
    StandardUniform: Distribution<AB::F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.row_slice(0).expect("Matrix is empty?");

        let preprocessed = builder.preprocessed();
        let preprocessed_local = preprocessed
            .row_slice(0)
            .expect("Preprocessed matrix is empty?");

        let a = main_local[0].clone();
        let result = main_local[1].clone();
        let constant = preprocessed_local[0].clone();

        // Constraint: a - constant = result
        builder.assert_zero(a - constant - result);
    }
}

#[test]
fn test_mul_verifier_circuit() -> Result<(), VerificationError> {
    let mut rng = SmallRng::seed_from_u64(1);
    let n = 1 << 3;

    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let log_final_poly_len = 0;
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let pow_bits = fri_params.proof_of_work_bits;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![];

    // Create AIR and generate valid trace
    let air = MulAir { degree: 2, rows: n };
    let (trace, _) = air.random_valid_trace(true);

    // Setup preprocessed data
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed(&config, &air, log2_ceil_usize(trace.height())).unzip();
    // Generate and verify proof
    let proof = prove_with_preprocessed(
        &config,
        &air,
        trace,
        &pis,
        preprocessed_prover_data.as_ref(),
    );
    assert!(
        verify_with_preprocessed(&config, &air, &proof, &pis, preprocessed_vk.as_ref()).is_ok()
    );

    let mut circuit_builder = CircuitBuilder::new();

    // Allocate all targets
    let verifier_inputs =
        StarkVerifierInputsBuilder::<MyConfig, HashTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
            &mut circuit_builder,
            &proof,
            preprocessed_vk.as_ref().map(|vk| &vk.commitment),
            pis.len(),
        );

    // Add the verification circuit to the builder
    verify_circuit::<_, _, _, _, _, RATE>(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &verifier_inputs.preprocessed_commit,
        &fri_verifier_params,
    )?;

    // Build the circuit
    let (circuit, _) = circuit_builder.build()?;

    let mut runner = circuit.runner();
    // Generate all the challenge values
    let all_challenges = generate_challenges(
        &air,
        &config,
        &proof,
        &pis,
        Some(&[pow_bits, log_height_max]),
    )?;

    // Pack values using the same builder
    let num_queries = proof.opening_proof.query_proofs.len();
    let public_inputs = verifier_inputs.pack_values(
        &pis,
        &proof,
        &preprocessed_vk.map(|vk| vk.commitment),
        &all_challenges,
        num_queries,
    );

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}

#[test]
fn test_batch_verifier_with_mixed_preprocessed() -> Result<(), VerificationError> {
    let mut rng = SmallRng::seed_from_u64(42);
    let n = 1 << 3;

    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let log_final_poly_len = 0;
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let pow_bits = fri_params.proof_of_work_bits;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    let config = MyConfig::new(pcs, challenger);

    // Create three different AIRs with different preprocessed column configurations
    let air1 = MulAir { degree: 2, rows: n }; // Has preprocessed columns
    let air2 = AddAirNoPreprocessed { rows: n }; // No preprocessed columns  
    let air3 = SubAirPartialPreprocessed { rows: n }; // Some preprocessed columns

    // Generate valid traces for each AIR
    let trace1 = air1.random_valid_trace(true).0;
    let trace2 = air2.random_valid_trace(true);
    let trace3 = air3.random_valid_trace(true).0;

    // Each AIR has empty public inputs for this test
    let pvs = [vec![], vec![], vec![]];

    // Create MixedAir instances for batch proving
    let mixed_air1 = MixedAir::MulWithPreprocessed(air1);
    let mixed_air2 = MixedAir::AddNoPreprocessed(air2);
    let mixed_air3 = MixedAir::SubPartialPreprocessed(air3);

    // Create StarkInstances for batch proving
    let instances = vec![
        StarkInstance {
            air: &mixed_air1,
            trace: trace1,
            public_values: pvs[0].clone(),
        },
        StarkInstance {
            air: &mixed_air2,
            trace: trace2,
            public_values: pvs[1].clone(),
        },
        StarkInstance {
            air: &mixed_air3,
            trace: trace3,
            public_values: pvs[2].clone(),
        },
    ];

    let airs = [mixed_air1, mixed_air2, mixed_air3];

    // Generate common data and batch proof
    let common_data = CommonData::from_instances(&config, &instances);
    let batch_proof = prove_batch(&config, instances, &common_data);
    verify_batch(&config, &airs, &batch_proof, &pvs, &common_data).unwrap();

    // Create AIRs vector for verification circuit
    let airs = vec![mixed_air1, mixed_air2, mixed_air3];

    // The first and last AIRs have preprocessed columns, the second does not
    assert!(BaseAir::<F>::preprocessed_trace(&airs[0]).is_some());
    assert!(BaseAir::<F>::preprocessed_trace(&airs[1]).is_none());
    assert!(BaseAir::<F>::preprocessed_trace(&airs[2]).is_some());

    let mut circuit_builder = CircuitBuilder::new();

    // Allocate batch verifier inputs
    let air_public_counts = vec![0usize; batch_proof.opened_values.instances.len()];
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut circuit_builder,
        &batch_proof,
        &common_data,
        &air_public_counts,
    );

    // Create PCS verifier params from FRI verifier params
    let pcs_verifier_params = fri_verifier_params;

    // Add the batch verification circuit to the builder for the following AIRs:
    // 1. MulAir (has preprocessed columns)
    // 2. AddAirNoPreprocessed (no preprocessed columns)
    // 3. SubAirPartialPreprocessed (some preprocessed columns)
    verify_batch_circuit::<_, _, _, _, _, RATE>(
        &config,
        &airs,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &pcs_verifier_params,
        &verifier_inputs.preprocessed,
    )?;

    // Build the circuit
    let (circuit, _) = circuit_builder.build()?;

    let mut runner = circuit.runner();

    // Generate all the challenge values for batch proof
    let all_challenges = generate_batch_challenges(
        &airs,
        &config,
        &batch_proof,
        &pvs,
        Some(&[pow_bits, log_height_max]),
        &common_data,
    )?;

    // Pack values using the batch builder
    let public_inputs = verifier_inputs.pack_values(
        &pvs, // public inputs for each AIR
        &batch_proof,
        &common_data,
        &all_challenges,
    );

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
