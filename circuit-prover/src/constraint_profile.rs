use serde::{Deserialize, Serialize};

/// High-level constraint profiles used to instantiate AIR variants.
///
/// Profiles are selected per proof shape / recursion layer and must be
/// applied consistently across:
/// - circuit construction,
/// - native batch proving,
/// - recursive verification.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConstraintProfile {
    /// Existing behaviour: all AIRs keep their current low-degree constraints.
    #[default]
    Standard,
    /// Recursion-optimised profile.
    RecursionOptimized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_standard() {
        assert_eq!(ConstraintProfile::default(), ConstraintProfile::Standard);
    }

    #[test]
    fn test_equality() {
        assert_eq!(ConstraintProfile::Standard, ConstraintProfile::Standard);
        assert_eq!(
            ConstraintProfile::RecursionOptimized,
            ConstraintProfile::RecursionOptimized,
        );
        assert_ne!(
            ConstraintProfile::Standard,
            ConstraintProfile::RecursionOptimized
        );
    }

    #[test]
    fn test_clone() {
        assert_eq!(
            ConstraintProfile::Standard.clone(),
            ConstraintProfile::Standard
        );
        assert_eq!(
            ConstraintProfile::RecursionOptimized.clone(),
            ConstraintProfile::RecursionOptimized,
        );
    }

    #[test]
    fn test_copy() {
        let a = ConstraintProfile::Standard;
        let _b = a;
        let _c = a;
    }

    #[test]
    fn test_debug() {
        assert!(!alloc::format!("{:?}", ConstraintProfile::Standard).is_empty());
        assert!(!alloc::format!("{:?}", ConstraintProfile::RecursionOptimized).is_empty());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        use postcard::{from_bytes, to_allocvec};
        let original = ConstraintProfile::RecursionOptimized;
        let bytes = to_allocvec(&original).unwrap();
        let decoded: ConstraintProfile = from_bytes(&bytes).unwrap();
        assert_eq!(decoded, original);
    }
}
