//! Hash function configuration for circuit operations.
//!
//! Allows runtime selection of hash functions for HashAbsorb/HashSqueeze operations.

use core::marker::PhantomData;

/// Trait for hash function configurations used in circuits.
pub trait HashConfig {
    /// The field type
    type F;

    /// The width of the permutation state
    const WIDTH: usize;

    /// The rate (number of elements that can be absorbed/squeezed per permutation)
    const RATE: usize;

    /// The capacity (WIDTH - RATE)
    const CAPACITY: usize = Self::WIDTH - Self::RATE;
}

/// Poseidon2 hash configuration.
///
/// Generic over the field and permutation parameters.
/// Common configurations:
/// - Poseidon2-16: WIDTH=16, RATE=8 (CAPACITY=8)
/// - Poseidon2-24: WIDTH=24, RATE=16 (CAPACITY=8)
#[derive(Debug, Clone, Copy)]
pub struct Poseidon2Config<F, const WIDTH: usize, const RATE: usize> {
    _phantom: PhantomData<F>,
}

impl<F, const WIDTH: usize, const RATE: usize> HashConfig for Poseidon2Config<F, WIDTH, RATE> {
    type F = F;
    const WIDTH: usize = WIDTH;
    const RATE: usize = RATE;
}

impl<F, const WIDTH: usize, const RATE: usize> Poseidon2Config<F, WIDTH, RATE> {
    /// Create a new Poseidon2 configuration.
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F, const WIDTH: usize, const RATE: usize> Default for Poseidon2Config<F, WIDTH, RATE> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    type Poseidon2_16 = Poseidon2Config<BabyBear, 16, 8>;
    type Poseidon2_24 = Poseidon2Config<BabyBear, 24, 16>;

    #[test]
    fn test_poseidon2_16_params() {
        assert_eq!(Poseidon2_16::WIDTH, 16);
        assert_eq!(Poseidon2_16::RATE, 8);
        assert_eq!(Poseidon2_16::CAPACITY, 8);
    }

    #[test]
    fn test_poseidon2_24_params() {
        assert_eq!(Poseidon2_24::WIDTH, 24);
        assert_eq!(Poseidon2_24::RATE, 16);
        assert_eq!(Poseidon2_24::CAPACITY, 8);
    }
}
