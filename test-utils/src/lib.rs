//! Test utilities for Plonky3 recursion crates.

#![no_std]

extern crate alloc;

use core::marker::PhantomData;

/// Maximum allowed constraint degree for AIR constraints.
pub const MAX_TEST_CONSTRAINT_DEGREE: usize = 3;

/// Scalar FRI parameters matching [`FriParameters::new_testing`] with `log_final_poly_len = 0`.
///
/// Tests that need `FriVerifierParams` cannot get them from a `p3-test-utils` helper, because
/// `FriVerifierParams` lives in `p3-recursion`, which already depends on `p3-test-utils` (a
/// dependency cycle). This struct lets such tests derive `FriVerifierParams` from a single
/// canonical source without rebuilding the MMCS/PCS wiring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestFriScalars {
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub commit_pow_bits: usize,
    pub query_pow_bits: usize,
}

/// Returns the [`TestFriScalars`] used by the `make_test_config` helpers, read back from
/// [`FriParameters::new_testing`] so the two never drift.
pub fn test_fri_scalars() -> TestFriScalars {
    let params = FriParameters::<()>::new_testing((), 0);
    TestFriScalars {
        log_blowup: params.log_blowup,
        log_final_poly_len: params.log_final_poly_len,
        commit_pow_bits: params.commit_proof_of_work_bits,
        query_pow_bits: params.query_proof_of_work_bits,
    }
}

pub use p3_challenger::DuplexChallenger;
pub use p3_commit::ExtensionMmcs;
pub use p3_dft::Radix2DitParallel;
pub use p3_field::extension::BinomialExtensionField;
use p3_field::extension::{QuinticTrinomialExtendable, QuinticTrinomialExtensionField};
pub use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
pub use p3_fri::{FriParameters, TwoAdicFriPcs};
pub use p3_lookup::Lookups;
pub use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::Permutation;
pub use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
pub use p3_uni_stark::StarkConfig;

/// Lifts a base-field permutation to [`QuinticTrinomialExtensionField`] lanes: each lane is
/// permuted by reading its constant basis coefficient, applying the inner permutation on base
/// field words, then re-embedding with only that coefficient nonzero.
#[derive(Clone)]
pub struct LiftPermToQuintic<F, P, const W: usize> {
    perm: P,
    _base: PhantomData<F>,
}

impl<F, P, const W: usize> LiftPermToQuintic<F, P, W> {
    #[inline]
    pub const fn new(perm: P) -> Self {
        Self {
            perm,
            _base: PhantomData,
        }
    }

    #[inline]
    pub fn into_inner(self) -> P {
        self.perm
    }
}

impl<F, P, const W: usize> Permutation<[QuinticTrinomialExtensionField<F>; W]>
    for LiftPermToQuintic<F, P, W>
where
    F: PrimeCharacteristicRing + QuinticTrinomialExtendable,
    P: Permutation<[F; W]>,
{
    fn permute(
        &self,
        input: [QuinticTrinomialExtensionField<F>; W],
    ) -> [QuinticTrinomialExtensionField<F>; W] {
        let bases: [F; W] = core::array::from_fn(|i| {
            <QuinticTrinomialExtensionField<F> as BasedVectorSpace<F>>::as_basis_coefficients_slice(
                &input[i],
            )[0]
        });
        let out = self.perm.permute(bases);
        core::array::from_fn(|i| {
            QuinticTrinomialExtensionField::new([out[i], F::ZERO, F::ZERO, F::ZERO, F::ZERO])
        })
    }
}

/// Macro to generate a constraint degree test for an AIR.
///
/// Usage: `assert_air_constraint_degree!(air, "AirName");`
#[macro_export]
macro_rules! assert_air_constraint_degree {
    ($air:expr, $air_name:expr) => {{
        use p3_air::{AirLayout, BaseAir};
        use p3_batch_stark::symbolic::get_symbolic_constraints;
        use p3_lookup::Lookups;
        use p3_lookup::logup::LogUpGadget;

        type F = p3_baby_bear::BabyBear;
        type EF = p3_field::extension::BinomialExtensionField<F, 4>;
        let air = $air;

        let preprocessed_width = air.preprocessed_trace().map(|m| m.width()).unwrap_or(0);
        let lookups: Lookups<F> = Lookups::from_air::<EF, _>(&air);
        let lookup_gadget = LogUpGadget::new();
        let layout = AirLayout {
            preprocessed_width,
            main_width: BaseAir::<F>::width(&air),
            num_public_values: BaseAir::<F>::num_public_values(&air),
            permutation_width: 0,
            num_permutation_challenges: 0,
            num_permutation_values: 0,
            num_periodic_columns: 0,
        };

        let (base_constraints, extension_constraints) =
            get_symbolic_constraints::<F, EF, _, _>(&air, layout, &lookups, &lookup_gadget);

        for (i, constraint) in base_constraints.iter().enumerate() {
            let degree = constraint.degree_multiple();
            assert!(
                degree <= $crate::MAX_TEST_CONSTRAINT_DEGREE,
                "{} base constraint {} has degree {} which exceeds maximum of {}",
                $air_name,
                i,
                degree,
                $crate::MAX_TEST_CONSTRAINT_DEGREE
            );
        }

        for (i, constraint) in extension_constraints.iter().enumerate() {
            let degree = constraint.degree_multiple();
            assert!(
                degree <= $crate::MAX_TEST_CONSTRAINT_DEGREE,
                "{} extension constraint {} has degree {} which exceeds maximum of {}",
                $air_name,
                i,
                degree,
                $crate::MAX_TEST_CONSTRAINT_DEGREE
            );
        }
    }};
}

/// Single-AIR satisfaction helpers.
pub mod air_satisfaction {
    use alloc::string::String;
    use alloc::vec::Vec;

    use p3_air::{Air, BaseAir, DebugConstraintBuilder};
    use p3_field::{ExtensionField, Field};
    use p3_matrix::Matrix;
    use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
    use p3_matrix::stack::ViewPair;

    /// Run `air.eval` on every (row, row_next) pair and return the first row that violates a
    /// constraint, together with the formatted failure list.
    pub fn check_air_satisfies<F, EF, A>(
        air: &A,
        main: &RowMajorMatrix<F>,
        public_values: &[F],
    ) -> Result<(), (usize, String)>
    where
        F: Field,
        EF: ExtensionField<F>,
        A: BaseAir<F> + for<'a> Air<DebugConstraintBuilder<'a, F, EF>>,
    {
        let height = main.height();
        let preprocessed = air.preprocessed_trace();

        if let Some(prep) = preprocessed.as_ref() {
            assert_eq!(
                prep.height(),
                height,
                "preprocessed height ({}) must match main height ({})",
                prep.height(),
                height
            );
        }

        for row in 0..height {
            let next = (row + 1) % height;
            let local = main.row_slice(row).unwrap();
            let next_row = main.row_slice(next).unwrap();
            let main_pair = ViewPair::new(
                RowMajorMatrixView::new_row(&*local),
                RowMajorMatrixView::new_row(&*next_row),
            );

            let (prep_local, prep_next) = preprocessed.as_ref().map_or((None, None), |p| {
                (
                    Some(p.row_slice(row).unwrap()),
                    Some(p.row_slice(next).unwrap()),
                )
            });
            let prep_pair = match (prep_local.as_ref(), prep_next.as_ref()) {
                (Some(l), Some(n)) => ViewPair::new(
                    RowMajorMatrixView::new_row(&**l),
                    RowMajorMatrixView::new_row(&**n),
                ),
                _ => ViewPair::new(
                    RowMajorMatrixView::new(&[], 0),
                    RowMajorMatrixView::new(&[], 0),
                ),
            };

            let periodic_row = air.periodic_values(row);
            let perm_pair = ViewPair::<EF>::new(
                RowMajorMatrixView::new(&[], 0),
                RowMajorMatrixView::new(&[], 0),
            );
            let mut builder = DebugConstraintBuilder::<F, EF>::new_with_permutation(
                row,
                main_pair,
                prep_pair,
                public_values,
                F::from_bool(row == 0),
                F::from_bool(row == height - 1),
                F::from_bool(row != height - 1),
                perm_pair,
                &[],
                &[],
                &periodic_row,
            );
            air.eval(&mut builder);
            if builder.has_failures() {
                return Err((row, builder.formatted_failures()));
            }
        }
        Ok(())
    }

    /// Panicking convenience wrapper for satisfying-trace tests.
    pub fn assert_air_satisfies<F, EF, A>(air: &A, main: &RowMajorMatrix<F>)
    where
        F: Field,
        EF: ExtensionField<F>,
        A: BaseAir<F> + for<'a> Air<DebugConstraintBuilder<'a, F, EF>>,
    {
        if let Err((row, failures)) = check_air_satisfies::<F, EF, A>(air, main, &[]) {
            panic!("AIR constraint failed at row {row}: {failures}");
        }
    }

    /// Asserts that the AIR's `eval` rejects the given main trace on at least one row. Used
    /// for soundness tests where the trace is intentionally invalid.
    pub fn assert_air_rejects<F, EF, A>(air: &A, main: &RowMajorMatrix<F>)
    where
        F: Field,
        EF: ExtensionField<F>,
        A: BaseAir<F> + for<'a> Air<DebugConstraintBuilder<'a, F, EF>>,
    {
        let height = main.height();
        let preprocessed = air.preprocessed_trace();

        let mut any_failure = false;
        let mut rendered: Vec<(usize, String)> = Vec::new();

        for row in 0..height {
            let next = (row + 1) % height;
            let local = main.row_slice(row).unwrap();
            let next_row = main.row_slice(next).unwrap();
            let main_pair = ViewPair::new(
                RowMajorMatrixView::new_row(&*local),
                RowMajorMatrixView::new_row(&*next_row),
            );

            let (prep_local, prep_next) = preprocessed.as_ref().map_or((None, None), |p| {
                (
                    Some(p.row_slice(row).unwrap()),
                    Some(p.row_slice(next).unwrap()),
                )
            });
            let prep_pair = match (prep_local.as_ref(), prep_next.as_ref()) {
                (Some(l), Some(n)) => ViewPair::new(
                    RowMajorMatrixView::new_row(&**l),
                    RowMajorMatrixView::new_row(&**n),
                ),
                _ => ViewPair::new(
                    RowMajorMatrixView::new(&[], 0),
                    RowMajorMatrixView::new(&[], 0),
                ),
            };

            let periodic_row = air.periodic_values(row);
            let perm_pair = ViewPair::<EF>::new(
                RowMajorMatrixView::new(&[], 0),
                RowMajorMatrixView::new(&[], 0),
            );
            let mut builder = DebugConstraintBuilder::<F, EF>::new_with_permutation(
                row,
                main_pair,
                prep_pair,
                &[],
                F::from_bool(row == 0),
                F::from_bool(row == height - 1),
                F::from_bool(row != height - 1),
                perm_pair,
                &[],
                &[],
                &periodic_row,
            );
            air.eval(&mut builder);
            if builder.has_failures() {
                any_failure = true;
                rendered.push((row, builder.formatted_failures()));
            }
        }

        assert!(
            any_failure,
            "expected at least one constraint failure on the invalid trace, but every row satisfied the AIR ({} rows, formatted: {rendered:?})",
            height
        );
    }
}

/// Common parameters for the BabyBear field.
pub mod baby_bear_params {
    pub use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};

    pub use super::*;

    pub type F = BabyBear;
    pub const D: usize = 4;
    pub const WIDTH: usize = 16;
    pub const RATE: usize = 8;
    pub const DIGEST_ELEMS: usize = 8;
    pub type Challenge = BinomialExtensionField<F, D>;
    pub type Dft = Radix2DitParallel<F>;
    pub type Perm = Poseidon2BabyBear<WIDTH>;
    pub type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
    pub type MyMmcs = MerkleTreeMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        2,
        DIGEST_ELEMS,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
    pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
    pub type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
    pub type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

    /// Builds the standard test `MyConfig` (testing FRI params, default permutation).
    pub fn make_test_config() -> MyConfig {
        let perm = default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = MyMmcs::new(hash, compress, 0);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri_params = FriParameters::new_testing(challenge_mmcs, 0);
        let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
        MyConfig::new(pcs, Challenger::new(perm))
    }
}

/// Common parameters for the KoalaBear field.
pub mod koala_bear_params {
    pub use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};

    pub use super::*;

    pub type F = KoalaBear;
    pub const D: usize = 4;
    pub const WIDTH: usize = 16;
    pub const RATE: usize = 8;
    pub const DIGEST_ELEMS: usize = 8;

    pub type Challenge = BinomialExtensionField<F, D>;
    pub type Dft = Radix2DitParallel<F>;
    pub type Perm = Poseidon2KoalaBear<WIDTH>;
    pub type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
    pub type MyMmcs = MerkleTreeMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        2,
        DIGEST_ELEMS,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
    pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
    pub type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
    pub type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

    /// Builds the standard test `MyConfig` (testing FRI params, default permutation).
    pub fn make_test_config() -> MyConfig {
        let perm = default_koalabear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = MyMmcs::new(hash, compress, 0);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri_params = FriParameters::new_testing(challenge_mmcs, 0);
        let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
        MyConfig::new(pcs, Challenger::new(perm))
    }

    /// Builds a test `MyConfig` with an explicit FRI shape (`log_blowup`, `max_log_arity`),
    /// reusing `perm` for the Fiat-Shamir challenger. Used for aggregation tests that mix
    /// proofs with different FRI shapes.
    pub fn make_test_config_with_fri(
        perm: &Perm,
        log_blowup: usize,
        max_log_arity: usize,
    ) -> MyConfig {
        let query_proof_of_work_bits = 16;
        let num_queries = (100 - query_proof_of_work_bits) / log_blowup;
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = MyMmcs::new(hash, compress, 0);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri_params = FriParameters {
            max_log_arity,
            log_blowup,
            log_final_poly_len: 0,
            num_queries,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits,
            mmcs: challenge_mmcs,
        };
        let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
        MyConfig::new(pcs, Challenger::new(perm.clone()))
    }
}

/// KoalaBear with quintic trinomial challenge field (`D = 5`).
pub mod koala_bear_quintic_params {
    pub use p3_field::extension::QuinticTrinomialExtensionField;
    pub use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};

    pub use super::*;

    pub type F = KoalaBear;
    pub const D: usize = 5;
    pub const WIDTH: usize = 16;
    pub const RATE: usize = 8;
    pub const DIGEST_ELEMS: usize = 8;

    pub type Challenge = QuinticTrinomialExtensionField<F>;
    pub type Dft = Radix2DitParallel<F>;
    pub type Perm = Poseidon2KoalaBear<WIDTH>;
    pub type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
    pub type MyMmcs = MerkleTreeMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        2,
        DIGEST_ELEMS,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
    pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
    pub type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
    pub type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

    /// Base Poseidon2 permutation lifted to act on [`Challenge`] lanes (constant term only).
    pub type LiftKoalaPermForQuintic = super::LiftPermToQuintic<F, Perm, WIDTH>;

    /// Builds the standard test `MyConfig` (testing FRI params, default permutation).
    pub fn make_test_config() -> MyConfig {
        let perm = default_koalabear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let val_mmcs = MyMmcs::new(hash, compress, 0);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri_params = FriParameters::new_testing(challenge_mmcs, 0);
        let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
        MyConfig::new(pcs, Challenger::new(perm))
    }
}

/// Common parameters for the Goldilocks field.
pub mod goldilocks_params {
    pub use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};

    pub use super::*;

    pub type F = Goldilocks;
    pub const D: usize = 2;
    pub const WIDTH: usize = 8;
    pub const RATE: usize = 4;
    pub const DIGEST_ELEMS: usize = 4;

    pub type Challenge = BinomialExtensionField<F, D>;
    pub type Dft = Radix2DitParallel<F>;
    pub type Perm = Poseidon2Goldilocks<WIDTH>;
    pub type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
    pub type MyMmcs = MerkleTreeMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        2,
        DIGEST_ELEMS,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
    pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
    pub type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
    pub type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;
}
