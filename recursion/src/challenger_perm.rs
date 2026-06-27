//! Generic challenger permutation config for the recursion circuit.
//!
//! Allows the verifier and circuit challenger to be parameterised by a permutation
//! config without naming a specific hash (e.g. Poseidon2).

use p3_circuit::ops::{Poseidon1Config, Poseidon2Config};

/// Config for the permutation used by the in-circuit challenger.
///
/// Implemented by concrete permutation configs (e.g. Poseidon2); the recursion
/// verifier and [`crate::CircuitChallenger`] use this trait so they do not depend
/// on a specific hash by name.
pub trait ChallengerPermConfig: Send + Sync {
    /// Extension degree used by the in-circuit permutation NPO (`Poseidon2Config::d()`).
    ///
    /// This need not match the STARK challenge extension `EF::DIMENSION` (e.g. base
    /// width-16 Poseidon2 with `d() == 1` can pair with a quartic or quintic challenge).
    fn extension_degree(&self) -> usize;

    /// Poseidon2 config if this is a Poseidon2 permutation; `None` otherwise.
    fn as_poseidon2(&self) -> Option<&Poseidon2Config> {
        None
    }

    /// Poseidon1 config if this is a Poseidon1 permutation; `None` otherwise.
    fn as_poseidon1(&self) -> Option<&Poseidon1Config> {
        None
    }
}

impl ChallengerPermConfig for Poseidon2Config {
    fn extension_degree(&self) -> usize {
        Self::d(*self)
    }

    fn as_poseidon2(&self) -> Option<&Poseidon2Config> {
        Some(self)
    }
}

impl ChallengerPermConfig for Poseidon1Config {
    fn extension_degree(&self) -> usize {
        Self::d(*self)
    }

    fn as_poseidon1(&self) -> Option<&Poseidon1Config> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use p3_circuit::ops::{Poseidon1Config, Poseidon2Config};

    use super::*;

    #[test]
    fn test_poseidon2_extension_degree_d1() {
        assert_eq!(Poseidon2Config::BABY_BEAR_D1_W16.extension_degree(), 1);
    }

    #[test]
    fn test_poseidon2_extension_degree_d4() {
        assert_eq!(Poseidon2Config::BABY_BEAR_D4_W16.extension_degree(), 4);
    }

    #[test]
    fn test_poseidon1_extension_degree_d1() {
        assert_eq!(Poseidon1Config::BABY_BEAR_D1_W16.extension_degree(), 1);
    }

    #[test]
    fn test_poseidon1_extension_degree_d4() {
        assert_eq!(Poseidon1Config::BABY_BEAR_D4_W16.extension_degree(), 4);
    }

    #[test]
    fn test_poseidon2_as_poseidon2_some() {
        assert!(Poseidon2Config::BABY_BEAR_D1_W16.as_poseidon2().is_some());
    }

    #[test]
    fn test_poseidon2_as_poseidon1_none() {
        assert!(Poseidon2Config::BABY_BEAR_D1_W16.as_poseidon1().is_none());
    }

    #[test]
    fn test_poseidon1_as_poseidon1_some() {
        assert!(Poseidon1Config::BABY_BEAR_D1_W16.as_poseidon1().is_some());
    }

    #[test]
    fn test_poseidon1_as_poseidon2_none() {
        assert!(Poseidon1Config::BABY_BEAR_D1_W16.as_poseidon2().is_none());
    }

    #[test]
    fn test_poseidon2_returns_self_reference() {
        let cfg = Poseidon2Config::BABY_BEAR_D1_W16;
        assert_eq!(*cfg.as_poseidon2().unwrap(), cfg);
    }
}
