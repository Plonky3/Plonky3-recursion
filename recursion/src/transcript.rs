//! Domain-separator seeds of the native Fiat-Shamir transcripts.
//!
//! Since Plonky3 0.8 every native sub-protocol (uni-STARK, batch-STARK, the FRI PCS and its
//! low-degree test, WHIR, ...) opens its transcript by absorbing a domain-separator seed. The seed
//! is a pure function of the sub-protocol's static shape — its version, name, interaction pattern
//! and instance label — so it never depends on proof data.
//!
//! A recursive verifier therefore does not re-derive it in-circuit: it builds the same native
//! shape the native verifier would, records the base-field elements its seed absorbs, and absorbs
//! those as circuit constants at the matching transcript position. Off-circuit replays simply call
//! [`DomainSeparator::seed`] on their native challenger.

use alloc::vec::Vec;

use p3_challenger::fs::{DomainSeparator, FieldUnit};
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger,
};
use p3_field::{ExtensionField, PrimeField64};
use p3_lookup::LookupProtocol;
use p3_uni_stark::StarkShape;

use crate::traits::RecursiveAir;

/// A challenger stand-in that only records what it is asked to absorb.
struct SeedRecorder<F>(Vec<F>);

impl<F> CanObserve<F> for SeedRecorder<F> {
    fn observe(&mut self, value: F) {
        self.0.push(value);
    }
}

/// The base-field elements `separator` absorbs when it seeds a native challenger, in order.
#[must_use]
pub fn domain_separator_seed<F: PrimeField64>(separator: &DomainSeparator<FieldUnit<F>>) -> Vec<F> {
    let mut recorder = SeedRecorder(Vec::new());
    separator.seed(&mut recorder);
    recorder.0
}

/// A challenger that records what a native sub-protocol absorbs before its first sample.
///
/// Some native sub-transcripts (p3-sumcheck's layout claims and batching) keep their shapes
/// crate-private, so their domain-separator seeds cannot be built directly. Every seed is
/// self-delimiting — its first element is its byte length — so running the public native step on
/// this tap with dummy data and cutting the recorded prefix at that length recovers the seed
/// exactly, without restating upstream internals.
#[derive(Clone, Debug, Default)]
pub struct SeedTap<F> {
    observed: Vec<F>,
    sampled: bool,
}

impl<F: PrimeField64> SeedTap<F> {
    /// An empty tap.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            observed: Vec::new(),
            sampled: false,
        }
    }

    /// The domain-separator seed the recorded step opened with.
    ///
    /// # Panics
    /// Panics if the tap recorded no complete seed.
    #[must_use]
    pub fn seed(&self) -> Vec<F> {
        let bits = u64::BITS - F::ORDER_U64.leading_zeros();
        let bytes_per_element = ((bits as usize) - 1) / 8;
        let byte_len = self
            .observed
            .first()
            .expect("a native sub-transcript always opens with its seed")
            .as_canonical_u64() as usize;
        let len = 1 + byte_len.div_ceil(bytes_per_element);
        assert!(
            self.observed.len() >= len,
            "the tap recorded a truncated seed"
        );
        self.observed[..len].to_vec()
    }
}

impl<F: Clone> CanObserve<F> for SeedTap<F> {
    fn observe(&mut self, value: F) {
        if !self.sampled {
            self.observed.push(value);
        }
    }
}

impl<F: PrimeField64> CanSample<F> for SeedTap<F> {
    fn sample(&mut self) -> F {
        self.sampled = true;
        F::ZERO
    }
}

impl<F> CanSampleBits<usize> for SeedTap<F> {
    fn sample_bits(&mut self, _bits: usize) -> usize {
        self.sampled = true;
        0
    }
}

impl<F: PrimeField64> CanSampleUniformBits<F> for SeedTap<F> {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        _bits: usize,
    ) -> Result<usize, p3_challenger::ResamplingError> {
        self.sampled = true;
        Ok(0)
    }
}

impl<F: PrimeField64> FieldChallenger<F> for SeedTap<F> {}

impl<F: PrimeField64> GrindingChallenger for SeedTap<F> {
    type Witness = F;

    fn grind(&mut self, _bits: usize) -> F {
        F::ZERO
    }
}

/// The uni-STARK transcript shape `p3_uni_stark::verify` seeds its transcript from.
///
/// Mirrors [`StarkShape::new`], reading the AIR through [`RecursiveAir`] rather than `BaseAir`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn uni_stark_shape<F, EF, LG, A>(
    air: &A,
    preprocessed_width: usize,
    num_public_values: usize,
    log_ext_degree: usize,
    log_degree: usize,
    num_quotient_chunks: usize,
    has_randomization: bool,
    ood_pow_bits: usize,
) -> StarkShape
where
    F: PrimeField64,
    EF: ExtensionField<F>,
    LG: LookupProtocol,
    A: RecursiveAir<F, EF, LG> + ?Sized,
{
    StarkShape {
        log_ext_degree,
        log_degree,
        main_width: air.width(),
        preprocessed_width,
        num_public_values,
        num_periodic_columns: air.num_periodic_columns(),
        num_quotient_chunks,
        opens_main_next_row: air.opens_trace_next(),
        opens_preprocessed_next_row: air.opens_preprocessed_next(),
        has_randomization,
        ood_pow_bits,
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::{CanSample, DuplexChallenger};
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::PcsShape;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::*;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Perm = Poseidon2BabyBear<16>;

    #[test]
    fn recorded_seed_replays_the_native_seed() {
        let shape = PcsShape {
            claimed_evaluation_counts: alloc::vec![alloc::vec![alloc::vec![3, 1]]],
            batch_pow_bits: 0,
        };
        let separator = shape.domain_separator::<F, EF>();
        let perm = Perm::new_from_rng_128(&mut SmallRng::seed_from_u64(1));

        let mut native = DuplexChallenger::<F, Perm, 16, 8>::new(perm.clone());
        separator.seed(&mut native);

        let mut replay = DuplexChallenger::<F, Perm, 16, 8>::new(perm);
        replay.observe_slice(&domain_separator_seed(&separator));

        assert_eq!(
            CanSample::<F>::sample(&mut native),
            CanSample::<F>::sample(&mut replay)
        );
    }

    #[test]
    fn tapped_seed_matches_the_public_seed() {
        use p3_sumcheck::strategy::Basis;
        use p3_sumcheck::transcript::{SumcheckShape, VerifierTranscript};

        let shape = SumcheckShape::new(3, 0, Basis::Evaluation);
        let mut tap = SeedTap::<F>::new();
        let mut transcript = VerifierTranscript::<_, F, EF>::new(&mut tap, shape);
        let _ = transcript.round(EF::ONE, EF::TWO, None).unwrap();
        let _ = transcript.round(EF::ONE, EF::TWO, None).unwrap();
        let _ = transcript.round(EF::ONE, EF::TWO, None).unwrap();
        transcript.finish();

        assert_eq!(
            tap.seed(),
            domain_separator_seed(&shape.domain_separator::<F, EF>())
        );
    }
}
