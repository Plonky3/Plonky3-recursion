#![allow(unused)]

use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::TwoAdicFriPcs;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::{
    FriProofTargets, InputProofTargets, RecExtensionValMmcs, RecValMmcs, Witness,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val};
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

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

/// Common parameters for the BabyBear field.
pub(crate) mod baby_bear_params {
    pub(crate) use p3_baby_bear::{BabyBear, Poseidon2BabyBear};

    use super::*;

    pub(crate) type F = BabyBear;
    pub(crate) const D: usize = 4;
    pub(crate) const RATE: usize = 8;
    pub(crate) const DIGEST_ELEMS: usize = 8;
    pub(crate) type Challenge = BinomialExtensionField<F, D>;
    pub(crate) type Dft = Radix2DitParallel<F>;
    pub(crate) type Perm = Poseidon2BabyBear<16>;
    pub(crate) type MyHash = PaddingFreeSponge<Perm, 16, RATE, 8>;
    pub(crate) type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    pub(crate) type ValMmcs =
        MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
    pub(crate) type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
    pub(crate) type Challenger = DuplexChallenger<F, Perm, 16, RATE>;
    pub(crate) type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
    pub(crate) type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

    pub(crate) type InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;
}

/// Common parameters for the KoalaBear field.
pub(crate) mod koala_bear_params {
    pub(crate) use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

    use super::*;

    pub(crate) type F = KoalaBear;
    pub(crate) const D: usize = 4;
    pub(crate) const RATE: usize = 8;
    pub(crate) const DIGEST_ELEMS: usize = 8;

    pub(crate) type Challenge = BinomialExtensionField<F, D>;
    pub(crate) type Dft = Radix2DitParallel<F>;
    pub(crate) type Perm = Poseidon2KoalaBear<16>;
    pub(crate) type MyHash = PaddingFreeSponge<Perm, 16, RATE, 8>;
    pub(crate) type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    pub(crate) type ValMmcs =
        MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
    pub(crate) type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
    pub(crate) type Challenger = DuplexChallenger<F, Perm, 16, RATE>;
    pub(crate) type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
    pub(crate) type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

    pub(crate) type InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;
}

/// Common parameters for the Goldilocks field.
pub(crate) mod goldilocks_params {
    pub(crate) use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};

    use super::*;

    pub(crate) type F = Goldilocks;
    pub(crate) const D: usize = 2;
    pub(crate) const RATE: usize = 4;
    pub(crate) const DIGEST_ELEMS: usize = 4;

    pub(crate) type Challenge = BinomialExtensionField<F, D>;
    pub(crate) type Dft = Radix2DitParallel<F>;
    pub(crate) type Perm = Poseidon2Goldilocks<8>;
    pub(crate) type MyHash = PaddingFreeSponge<Perm, 8, RATE, 4>;
    pub(crate) type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
    pub(crate) type ValMmcs =
        MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 4>;
    pub(crate) type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
    pub(crate) type Challenger = DuplexChallenger<F, Perm, 8, RATE>;
    pub(crate) type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
    pub(crate) type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

    pub(crate) type InnerFri = super::InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;
}

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
