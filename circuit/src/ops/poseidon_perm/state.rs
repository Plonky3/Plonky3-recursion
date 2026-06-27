//! Execution state and private data shared by the Poseidon permutation operations.

use alloc::vec::Vec;
use core::fmt;

use p3_field::Field;

use super::PoseidonVariant;

/// Private data for a Poseidon permutation row.
///
/// Only used for Merkle mode operations. `sibling` holds extension limbs copied into the
/// capacity portion of the sponge state (length ≤ `capacity_ext` for the configured perm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoseidonPermPrivateData<F> {
    pub sibling: Vec<F>,
}

/// Execution state for Poseidon permutation operations.
///
/// The per-row trace type is selected by the [`PoseidonVariant`] marker.
pub(crate) struct PoseidonExecutionState<V: PoseidonVariant, F: Field> {
    pub last_output_normal: Option<Vec<F>>,
    pub last_output_merkle: Option<Vec<F>>,
    /// Circuit rows captured during execution.
    pub rows: Vec<V::Row<F>>,
}

impl<V: PoseidonVariant, F: Field> Default for PoseidonExecutionState<V, F> {
    fn default() -> Self {
        Self {
            last_output_normal: None,
            last_output_merkle: None,
            rows: Vec::new(),
        }
    }
}

impl<V: PoseidonVariant, F: Field> fmt::Debug for PoseidonExecutionState<V, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoseidonExecutionState")
            .field("last_output_normal", &self.last_output_normal)
            .field("last_output_merkle", &self.last_output_merkle)
            .field("rows", &self.rows)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use crate::ops::poseidon2_perm::state::Poseidon2PermPrivateData;

    #[test]
    fn test_private_data_debug() {
        let d = Poseidon2PermPrivateData::<BabyBear> {
            sibling: alloc::vec![],
        };
        let s = alloc::format!("{:?}", d);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_private_data_eq() {
        let a = Poseidon2PermPrivateData::<BabyBear> {
            sibling: alloc::vec![],
        };
        let b = Poseidon2PermPrivateData::<BabyBear> {
            sibling: alloc::vec![],
        };
        assert_eq!(a, b);
        let c = Poseidon2PermPrivateData::<BabyBear> {
            sibling: alloc::vec![BabyBear::ZERO],
        };
        assert_ne!(a, c);
    }

    #[test]
    fn test_private_data_empty_sibling() {
        let d = Poseidon2PermPrivateData::<BabyBear> {
            sibling: alloc::vec![],
        };
        assert!(d.sibling.is_empty());
    }
}
