//! Closed, versioned registry and native factories for portable verifier suites.
//!
//! This module deliberately enumerates the configurations that the repository
//! implements today.  A suite identifier is not a bag of freely-combinable
//! field, hash, arity, and hiding switches.

mod fri;
mod registry;
mod whir;

pub use fri::*;
pub use registry::{
    BuiltinConfigDescriptorV1, BuiltinConfigError, FieldFamilyV1, FriConfigV1, HashFamilyV1,
    ProofFamilyV1, SuiteIdV1, SuiteSpecV1, WhirConfigV1, WhirRateModeV1, WhirSecurityAssumptionV1,
};
pub use whir::*;
