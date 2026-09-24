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

use p3_challenger::CanObserve;
use p3_challenger::fs::{DomainSeparator, FieldUnit};
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
}
