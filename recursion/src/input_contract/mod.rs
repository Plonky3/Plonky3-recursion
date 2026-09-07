//! Typed native-input descriptors for prepared recursive verifiers.

pub mod fri;

pub use fri::{
    FriCommitStepShape, FriInputBatchShape, FriShape, HidingFriShape, HidingOpeningAdviceShape,
    MerkleCapShape,
};
