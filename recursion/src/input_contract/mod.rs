//! Typed native-input descriptors for prepared recursive verifiers.

pub mod fri;
pub mod stark;
pub mod whir;

pub use fri::{
    FriCommitStepShape, FriInputBatchShape, FriShape, HidingFriShape, HidingOpeningAdviceShape,
    MerkleCapShape,
};
pub use stark::{
    BatchInputContract, CommitmentsShape, GlobalPreprocessedShape, InputContract,
    NonPrimitiveContract, OpenedValuesShape, OpenedValuesWithLookupsShape,
    PreprocessedInstanceShape, UniInputContract,
};
pub use whir::{
    OpeningBatchShape, QueryOpeningsShape, SumcheckShape, WhirPcsRoundShape, WhirShape,
    WhirStepShape, WhirUniShape,
};
