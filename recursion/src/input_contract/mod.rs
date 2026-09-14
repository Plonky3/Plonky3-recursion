//! Typed native-input descriptors for prepared recursive verifiers.

pub mod fri;
pub mod stark;
pub(crate) mod stark_layout;
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
pub use stark_layout::{FriMatrixGeometry, FriOpeningLayout};
pub use whir::{
    CheckedWhirOpening, OpeningBatchShape, QueryOpeningsShape, SumcheckShape, ValidatedWhirContext,
    WhirPcsRoundShape, WhirShape, WhirStepShape, WhirUniShape,
};
