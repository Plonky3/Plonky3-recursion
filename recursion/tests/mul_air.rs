//! Test for recursive STARK verification with a multiplication AIR.

use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_commit::{ExtensionMmcs, Pcs};
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
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{VerificationError, generate_challenges, verify_circuit};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val, prove, verify};
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
    let (trace, preprocessed) = air.random_valid_trace(true);

    // Commit to the preprocessed trace.
    let trace_domain = <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
        config.pcs(),
        trace.height(),
    );
    let (preprocessed_commit, _) =
        <MyPcs as Pcs<Challenge, Challenger>>::commit(config.pcs(), [(trace_domain, preprocessed)]);

    // Generate and verify proof
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());

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

    let mut circuit_builder = CircuitBuilder::new();

    // Allocate all targets
    let verifier_inputs =
        StarkVerifierInputsBuilder::<MyConfig, HashTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
            &mut circuit_builder,
            &proof,
            Some(preprocessed_commit),
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
        &Some(preprocessed_commit),
        &all_challenges,
        num_queries,
    );

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
