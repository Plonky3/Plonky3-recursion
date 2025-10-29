//! STARK verification within recursive circuits.

mod batch_stark;
mod errors;
mod observable;
mod quotient;
mod stark;

pub use batch_stark::{BatchProofTargets, InstanceOpenedValuesTargets, verify_batch_circuit};
pub use errors::VerificationError;
pub use observable::ObservableCommitment;
pub use quotient::{
    compute_quotient_chunk_products_circuit, compute_quotient_evaluation_circuit,
    recompose_quotient_from_chunks_circuit,
};
pub use stark::verify_circuit;
