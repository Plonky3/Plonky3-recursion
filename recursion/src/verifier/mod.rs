//! STARK verification within recursive circuits.

mod batch_stark;
mod binary_air;
pub(crate) mod binary_field_policy;
mod binary_bus;
mod binary_poly_bus;
mod binary_fraction;
mod binary_poly_fraction;
pub use binary_poly_fraction::{
    BinaryPolyFractionGkrInputShape, BinaryPolyFractionGkrLayerTargets, BinaryPolyFractionGkrOutput,
    BinaryPolyFractionGkrProofTargets, BinaryPolyFractionGkrVerifier, NativeBinaryPolyFractionGkrInput,
};
mod binary_boolean_multi_stark;
mod binary_grouped_boolean_multi_stark;
mod binary_grouped_multi_stark;
mod binary_indexed;
mod binary_logup;
mod binary_multi_stark;
mod binary_product;
mod binary_poly_product;
pub use binary_poly_product::{
    BinaryPolyProductGkrInputShape, BinaryPolyProductGkrLayerTargets, BinaryPolyProductGkrOutput,
    BinaryPolyProductGkrProofTargets, BinaryPolyProductGkrVerifier, NativeBinaryPolyProductGkrInput,
};
mod binary_whir_multi_stark;
mod binary_poly_whir_multi_stark;
pub use binary_poly_whir_multi_stark::{
    BinaryPolyWhirMultiStarkInputShape, BinaryPolyWhirMultiStarkPreprocessing,
    BinaryPolyWhirMultiStarkProofTargets, BinaryPolyWhirMultiStarkVerifier,
    NativeBinaryPolyWhirMultiStarkInput,
};
mod binary_boolean_whir_multi_stark;
pub use binary_boolean_whir_multi_stark::{
    BinaryBooleanWhirTraceMultiStarkInputShape, BinaryBooleanWhirTraceMultiStarkPreprocessing,
    BinaryBooleanWhirTraceMultiStarkProofTargets, BinaryBooleanWhirTraceMultiStarkVerifier,
    NativeBinaryBooleanWhirTraceMultiStarkInput,
};
mod errors;
mod limits;
mod observable;
mod periodic;
mod quotient;
mod stark;

pub(crate) use batch_stark::plan_batch_native_layout;
pub use batch_stark::{
    CircuitTablesAir, PcsVerifierParams, ReconstructedBatchTables, reconstruct_batch_tables,
    trusted_batch_tables, verify_batch_circuit, verify_p3_batch_proof_circuit,
    verify_trusted_p3_batch_proof_circuit,
};
pub use binary_air::{BinaryAirConstraintPlan, BinaryPolyAirConstraintPlan};
pub use binary_fraction::{
    BinaryFractionGkrInputShape, BinaryFractionGkrLayerTargets, BinaryFractionGkrOutput,
    BinaryFractionGkrProofTargets, BinaryFractionGkrVerifier, NativeBinaryFractionGkrInput,
};
pub use binary_boolean_multi_stark::{
    BinaryBooleanTraceMultiStarkInputShape, BinaryBooleanTraceMultiStarkPreprocessing,
    BinaryBooleanTraceMultiStarkProofTargets, BinaryBooleanTraceMultiStarkVerifier,
    NativeBinaryBooleanTraceMultiStarkInput,
};
pub use binary_grouped_boolean_multi_stark::{
    BinaryGroupedBooleanTraceMultiStarkInputShape, BinaryGroupedBooleanTraceMultiStarkPreprocessing,
    BinaryGroupedBooleanTraceMultiStarkProofTargets, BinaryGroupedBooleanTraceMultiStarkVerifier,
    NativeBinaryGroupedBooleanTraceMultiStarkInput,
};
pub use binary_grouped_multi_stark::{
    BinaryGroupedMultiStarkInputShape, BinaryGroupedMultiStarkPreprocessing,
    BinaryGroupedMultiStarkProofTargets, BinaryGroupedMultiStarkVerifier,
    NativeBinaryGroupedMultiStarkInput,
};
pub use binary_indexed::BinaryIndexedLookupProofTargets;
pub use binary_logup::{
    BinaryLogupStarInputShape, BinaryLogupStarOutput, BinaryLogupStarProofTargets,
    BinaryLogupStarReaderTargets, BinaryLogupStarTableOutput, BinaryLogupStarVerifier,
    NativeBinaryLogupStarInput,
};
pub use binary_multi_stark::{
    BinaryMultiStarkInputShape, BinaryMultiStarkPreprocessing, BinaryMultiStarkProofTargets,
    BinaryMultiStarkVerifier, NativeBinaryMultiStarkInput,
};
pub use binary_product::{
    BinaryProductGkrInputShape, BinaryProductGkrLayerTargets, BinaryProductGkrOutput,
    BinaryProductGkrProofTargets, BinaryProductGkrVerifier, NativeBinaryProductGkrInput,
};
pub use binary_whir_multi_stark::{
    BinaryWhirMultiStarkInputShape, BinaryWhirMultiStarkPreprocessing,
    BinaryWhirMultiStarkProofTargets, BinaryWhirMultiStarkVerifier,
    NativeBinaryWhirMultiStarkInput,
};
pub use errors::VerificationError;
pub use limits::{InputResourceUsage, VerifierLimits};
pub use observable::ObservableCommitment;
pub(crate) use periodic::evaluate_periodic_columns_circuit;
pub use quotient::recompose_quotient_from_chunks_circuit;
pub use stark::verify_p3_uni_proof_circuit;
pub(crate) use stark::{plan_uni_native_layout, plan_uni_native_layout_with_policy};
