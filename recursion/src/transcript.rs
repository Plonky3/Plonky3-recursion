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

use p3_challenger::fs::{DomainSeparator, FieldUnit, TranscriptField, TypeTag};
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger, GrindingChallenger,
};
use p3_field::{ExtensionField, Field, PrimeField64};
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
pub fn domain_separator_seed<F: TranscriptField>(
    separator: &DomainSeparator<FieldUnit<F>>,
) -> Vec<F> {
    let mut recorder = SeedRecorder(Vec::new());
    separator.seed(&mut recorder);
    recorder.0
}

/// A challenger that records what a native sub-protocol absorbs before its first sample.
///
/// Some native sub-transcripts (p3-sumcheck's layout claims and batching) keep their shapes
/// crate-private, so their domain-separator seeds cannot be built directly. Every seed is
/// self-delimiting, so running the public native step on this tap with dummy data and cutting
/// the recorded prefix at that length recovers the seed exactly, without restating upstream
/// internals. Prime alphabets use [`Self::seed`]; byte-aligned binary alphabets use
/// [`Self::binary_seed`], whose length prefix can span several narrow elements.
#[derive(Clone, Debug, Default)]
pub struct SeedTap<F> {
    observed: Vec<F>,
    sampled: bool,
}

impl<F> SeedTap<F> {
    /// An empty tap.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            observed: Vec::new(),
            sampled: false,
        }
    }
}

impl<F: PrimeField64> SeedTap<F> {
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

impl<F: TranscriptField> SeedTap<F> {
    /// The seed captured from a native byte-aligned binary alphabet.
    /// The native encoding places an eight-byte little-endian length first,
    /// padded to a whole number of alphabet elements, then its packed payload.
    ///
    /// # Panics
    /// Panics for another alphabet or if no complete native seed was recorded.
    #[must_use]
    pub fn binary_seed(&self) -> Vec<F> {
        assert!(
            matches!(
                F::algebra_tag(1, [0; 32]),
                TypeTag::BinaryTower { .. } | TypeTag::BinaryPolynomial { .. }
            ),
            "binary seed capture requires a native binary alphabet"
        );
        let width = F::wire_len();
        assert!(matches!(width, 1 | 2 | 4 | 8 | 16));
        let prefix_len = 8usize.div_ceil(width);
        assert!(
            self.observed.len() >= prefix_len,
            "the tap recorded a truncated binary length prefix"
        );
        // These native alphabets use big-endian wire encodings and raw
        // little-endian seed packing. Read the complete length prefix, even
        // when its low byte alone would wrap at a narrow tower level.
        let mut length_bytes = Vec::with_capacity(prefix_len * width);
        for element in &self.observed[..prefix_len] {
            let mut encoded = Vec::with_capacity(width);
            F::encode(element, &mut encoded);
            length_bytes.extend(encoded.into_iter().rev());
        }
        let byte_len = usize::try_from(u64::from_le_bytes(
            length_bytes[..8].try_into().expect("eight length bytes"),
        ))
        .expect("a recorded native seed length fits usize");
        let len = prefix_len
            .checked_add(byte_len.div_ceil(width))
            .expect("a recorded native seed length fits usize");
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

impl<F: Field> CanSample<F> for SeedTap<F> {
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

impl<F: Field> CanSampleUniformBits<F> for SeedTap<F> {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        _bits: usize,
    ) -> Result<usize, p3_challenger::ResamplingError> {
        self.sampled = true;
        Ok(0)
    }
}

impl<F: Field> FieldChallenger<F> for SeedTap<F> {}

impl<F: Field> GrindingChallenger for SeedTap<F> {
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

    #[test]
    fn tapped_binary_seeds_match_native_at_narrow_and_wide_levels() {
        use p3_binary_field::{BinaryField8, BinaryField128};
        use p3_sumcheck::strategy::Basis;
        use p3_sumcheck::transcript::{SumcheckShape, VerifierTranscript};

        fn check<F>()
        where
            F: p3_challenger::fs::TranscriptField + p3_field::AlgebraIdentity<F>,
        {
            let shape = SumcheckShape::new(1, 0, Basis::Evaluation);
            let mut tap = SeedTap::<F>::new();
            let mut transcript = VerifierTranscript::<_, F, F>::new(&mut tap, shape);
            let _ = transcript.round(F::ONE, F::ZERO, None).unwrap();
            transcript.finish();
            assert_eq!(
                tap.binary_seed(),
                domain_separator_seed(&shape.domain_separator::<F, F>())
            );
        }
        check::<BinaryField8>();
        check::<BinaryField128>();
    }

    #[test]
    fn binary_tap_reads_the_entire_eight_byte_length_prefix() {
        use p3_binary_field::{BinaryField8, TowerLevel};
        use p3_challenger::fs::TranscriptField;

        let mut tap = SeedTap::<BinaryField8>::new();
        BinaryField8::observe_seed(&mut tap, &alloc::vec![251; 1025]);
        tap.observe(BinaryField8::ONE);
        let seed = tap.binary_seed();
        assert_eq!(seed.len(), 8 + 1025);
        assert_eq!(seed[1], BinaryField8::from_repr(4));
    }
}
