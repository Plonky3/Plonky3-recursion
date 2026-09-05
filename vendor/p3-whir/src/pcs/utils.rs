use alloc::vec::Vec;

use p3_challenger::{CanSampleUniformBits, FieldChallenger};
use p3_field::Field;
use p3_util::log2_strict_usize;

/// Sample `t` STIR query indices uniformly from the transcript.
///
/// # Pipeline
///
/// ```text
///   transcript --> uniform draws
///                  [0, 2^k)
/// ```
///
/// with `k = log2(folded_domain_size)` and
/// `folded_domain_size = domain_size >> folding_factor`.
///
/// # Output
///
/// - length = `t = min(num_queries, folded_domain_size)`
/// - range  = `[0, folded_domain_size)`
/// - order  = transcript draw order; duplicates allowed
///
/// # Soundness
///
/// WHIR shift-query bound (Arnon-Chiesa-Fenzi-Yogev 2024, Thm 5.2):
///
/// ```text
///   eps_shift  <=  (1 - delta)^t
/// ```
///
/// `t` counts independent **uniformly-sampled** positions; distinctness
/// is not required (collisions waste opening work but do not weaken the
/// bound). This function therefore draws `t` independent samples with no
/// distinctness rejection and no sort: a fixed number of challenger draws
/// for a given `(domain_size, folding_factor, num_queries)`, independent of
/// the sampled values themselves. Per-draw uniformity is the only leak
/// closed here:
///
/// - **Biased draws** — bit-decomposing a uniform field element biases
///   each draw by `~ 2^bits / |F|`, which inflates `delta`. Routed
///   through `sample_uniform_bits` for exact uniformity.
///
/// # Saturation
///
/// `num_queries >= folded_domain_size` returns the full domain, in
/// ascending order, with **no challenger draws**: every position is opened,
/// so there is nothing left to decide. This is WHIR's final round: 1-4
/// folded positions vs. `final_queries` up to 75.
///
/// # Cost
///
/// ```text
///   per draw   | 1 field sample
///   common     | O(t)
///   saturated  | O(folded_domain_size), no challenger draws
/// ```
///
/// # Panics
///
/// `domain_size >> folding_factor` must be a power of two.
///
/// # Recursion-friendliness
///
/// A fixed-shape circuit's Fiat-Shamir sponge must make a fixed, known
/// number of challenger draws at this point in the transcript. Independent
/// sampling (this implementation) satisfies that: draw count depends only
/// on `(domain_size, folding_factor, num_queries)`, never on the sampled
/// values. Rejection-sampling-until-distinct does not: the draw count
/// depends on how many collisions the sampled values happen to produce, so
/// a circuit built for one draw count cannot replicate every proof's
/// transcript.
pub fn get_challenge_stir_queries<Challenger, F>(
    domain_size: usize,
    folding_factor: usize,
    num_queries: usize,
    challenger: &mut Challenger,
) -> Vec<usize>
where
    Challenger: FieldChallenger<F> + CanSampleUniformBits<F>,
    F: Field,
{
    // Phase 1: derive the addressable folded domain.
    //
    //   folded_domain_size = domain_size >> folding_factor
    //   k                  = log2(folded_domain_size)
    //
    // Each index fits in `k` bits.
    let folded_domain_size = domain_size >> folding_factor;
    let domain_size_bits = log2_strict_usize(folded_domain_size);

    // Phase 2: cap the request at the domain size.
    //
    //   num_queries <= folded_domain_size  ->  target = num_queries
    //   num_queries  > folded_domain_size  ->  target = folded_domain_size
    //                                          (open every position)
    let target = num_queries.min(folded_domain_size);

    // Phase 3: saturation opens every position; there is nothing left to
    // decide, so no challenger draws are made.
    if target == folded_domain_size {
        return (0..folded_domain_size).collect();
    }

    // Phase 4: draw `target` independent samples. Duplicates are allowed
    // and no ordering is imposed -- this is a fixed number of draws
    // regardless of the sampled values, which is what a fixed-shape
    // recursive circuit needs to replicate the transcript exactly.
    (0..target)
        .map(|_| {
            // RESAMPLE = true: the impl loops on field-side rejection internally.
            //
            // So the error arm is unreachable for every challenger in this workspace.
            challenger
                .sample_uniform_bits::<true>(domain_size_bits)
                .expect("RESAMPLE = true: rejection loops internally, never errors")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;

    use p3_challenger::{CanObserve, DuplexChallenger};
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use proptest::prelude::*;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;

    type F = KoalaBear;
    type Perm = Poseidon2KoalaBear<16>;
    type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;

    /// Build a deterministic duplex challenger from a seed.
    ///
    /// - Permutation: fixed across calls (seed-independent)
    /// - Transcript prefix: derived from `seed`
    ///
    /// Same seed -> byte-identical sample stream.
    fn challenger_with_seed(seed: u64) -> MyChallenger {
        // Permutation: deterministic across all test runs.
        let mut perm_rng = SmallRng::seed_from_u64(42);
        let perm = Perm::new_from_rng_128(&mut perm_rng);
        let mut challenger = MyChallenger::new(perm);

        // Transcript primer: 8 field elements derived from `seed`. This is
        // what makes two challengers with the same seed byte-identical.
        let mut transcript_rng = SmallRng::seed_from_u64(seed);
        let primer: Vec<F> = (0..8).map(|_| transcript_rng.random()).collect();
        challenger.observe_slice(&primer);
        challenger
    }

    /// Strategy for non-saturated `(domain_size, folding_factor, num_queries)`.
    ///
    /// ```text
    ///   log_folded     in [1, 8]   -> folded in [2, 256]
    ///   folding_factor in [0, 4]
    ///   num_queries    in [1, folded]
    /// ```
    ///
    /// Saturation (`num_queries > folded`) is covered by a dedicated test.
    fn arb_query_params() -> impl Strategy<Value = (usize, usize, usize)> {
        (1usize..=8, 0usize..=4).prop_flat_map(|(log_folded, folding_factor)| {
            let folded = 1usize << log_folded;
            let domain_size = folded << folding_factor;
            (1usize..=folded)
                .prop_map(move |num_queries| (domain_size, folding_factor, num_queries))
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn prop_get_challenge_stir_queries_invariants(
            (domain_size, folding_factor, num_queries) in arb_query_params(),
            seed in any::<u64>(),
        ) {
            // Three invariants, one challenger setup per case:
            // (1) length
            // (2) range
            // (3) deterministic replay
            //
            // Draws are independent, so duplicates are expected and no
            // ordering is guaranteed -- neither is asserted here.
            let folded_domain_size = domain_size >> folding_factor;

            // First run: seed -> queries_a.
            let mut challenger_a = challenger_with_seed(seed);
            let queries_a = get_challenge_stir_queries::<MyChallenger, F>(
                domain_size,
                folding_factor,
                num_queries,
                &mut challenger_a,
            );

            // (1) length == request.
            prop_assert_eq!(queries_a.len(), num_queries);

            // (2) every index in [0, folded_domain_size).
            for &q in &queries_a {
                prop_assert!(
                    q < folded_domain_size,
                    "out of range: {} not in [0, {})", q, folded_domain_size
                );
            }

            // (3) determinism: same seed -> byte-identical output.
            //     This is the prover/verifier Fiat-Shamir replay property.
            let mut challenger_b = challenger_with_seed(seed);
            let queries_b = get_challenge_stir_queries::<MyChallenger, F>(
                domain_size,
                folding_factor,
                num_queries,
                &mut challenger_b,
            );
            prop_assert_eq!(queries_a, queries_b);
        }

        #[test]
        fn prop_get_challenge_stir_queries_draws_can_repeat(
            seed in any::<u64>(),
        ) {
            // A small folded domain with more queries than the domain size
            // minus one forces duplicates with overwhelming probability
            // across the sampled seeds, without saturating (target stays
            // below folded_domain_size so the sampling branch, not the
            // exhaustive-enumeration branch, is exercised).
            let domain_size = 1usize << 6; // folded_domain_size = 32
            let folding_factor = 1usize;
            let folded_domain_size = domain_size >> folding_factor;
            let num_queries = folded_domain_size - 1; // 31 draws over 32 slots

            let mut challenger = challenger_with_seed(seed);
            let queries = get_challenge_stir_queries::<MyChallenger, F>(
                domain_size,
                folding_factor,
                num_queries,
                &mut challenger,
            );

            prop_assert_eq!(queries.len(), num_queries);
            for &q in &queries {
                prop_assert!(q < folded_domain_size);
            }
        }
    }

    #[test]
    fn duplicates_are_observed_across_many_draws() {
        // With independent sampling and no distinctness rejection, drawing
        // `folded_domain_size - 1` indices out of `folded_domain_size` slots
        // has probability `folded_domain_size! / folded_domain_size^(folded_domain_size - 1)`
        // of coming out all-distinct -- about 6e-12 at folded_domain_size =
        // 32, i.e. a near-certain duplicate for any single seed. Checking
        // several independent seeds makes this a statement about the
        // sampler, not a lucky draw. This directly falsifies a regression
        // back to rejection-sampling-until-distinct, which by construction
        // can never repeat an index within one call.
        let domain_size = 1usize << 6; // folded_domain_size = 32
        let folding_factor = 1usize;
        let folded_domain_size = domain_size >> folding_factor;
        let num_queries = folded_domain_size - 1; // 31, stays below saturation

        for seed in 0u64..8 {
            let mut challenger = challenger_with_seed(seed);
            let queries = get_challenge_stir_queries::<MyChallenger, F>(
                domain_size,
                folding_factor,
                num_queries,
                &mut challenger,
            );

            assert_eq!(queries.len(), num_queries);
            let unique: BTreeSet<usize> = queries.iter().copied().collect();
            assert!(
                unique.len() < queries.len(),
                "seed {seed}: expected at least one duplicate among {queries:?}, got all distinct"
            );
        }
    }

    #[test]
    fn saturates_when_num_queries_exceeds_domain() {
        // WHIR final-round regime: ask for more queries than positions.
        //
        //   folded_domain_size = 16 >> 2 = 4
        //   num_queries        = 75            (>> 4)
        //   expected           = [0, 1, 2, 3]  (full domain, ascending)
        let domain_size = 16usize;
        let folding_factor = 2usize;
        let folded_domain_size = domain_size >> folding_factor;
        let num_queries = 75usize;

        let mut challenger = challenger_with_seed(0xC0FFEE);
        let queries = get_challenge_stir_queries::<MyChallenger, F>(
            domain_size,
            folding_factor,
            num_queries,
            &mut challenger,
        );

        // Length capped at the domain; output is the full domain ascending.
        assert_eq!(queries.len(), folded_domain_size);
        assert_eq!(queries, (0..folded_domain_size).collect::<Vec<_>>());
    }

    #[test]
    fn empirical_uniformity_single_query() {
        // Histogram-based regression detector for uniform sampling.
        //
        //   N = 16 buckets, M = 4096 draws, expected = M/N = 256
        //
        // Hoeffding on the bucket indicator 1[q == k]:
        //
        //   Pr[ |count_k - 256| >= t ]  <=  2 * exp(-2 t^2 / M)
        //
        // With t = 160:
        //
        //   per-bucket    : 2  * exp(-12.5) ~ 7.4e-6
        //   union 16 bins : 32 * exp(-12.5) ~ 1.2e-4
        //
        // Cryptographic uniformity rests on the field-side rejection
        // primitive; this test only catches gross regressions.
        const FOLDED_DOMAIN_SIZE: usize = 16;
        const NUM_DRAWS: usize = 4096;
        const TOLERANCE: usize = 160;

        // Pick parameters so the folded domain has exactly 16 positions.
        let domain_size: usize = 64;
        let folding_factor: usize = 2;
        assert_eq!(domain_size >> folding_factor, FOLDED_DOMAIN_SIZE);

        // Histogram one draw per challenger seed.
        let mut counts = [0usize; FOLDED_DOMAIN_SIZE];
        // Histogram: one draw per seed.
        for seed in 0u64..NUM_DRAWS as u64 {
            let mut challenger = challenger_with_seed(seed);
            let q = get_challenge_stir_queries::<MyChallenger, F>(
                domain_size,
                folding_factor,
                1,
                &mut challenger,
            );
            assert_eq!(q.len(), 1);
            counts[q[0]] += 1;
        }

        // Each bucket within +/- TOLERANCE of expected count.
        let expected = NUM_DRAWS / FOLDED_DOMAIN_SIZE;
        for (bucket, &count) in counts.iter().enumerate() {
            let deviation = count.abs_diff(expected);
            assert!(
                deviation <= TOLERANCE,
                "bucket {bucket}: count {count} deviates from {expected} by {deviation} > {TOLERANCE}; counts = {counts:?}"
            );
        }
    }
}
