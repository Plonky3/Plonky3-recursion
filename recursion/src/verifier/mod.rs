//! STARK verification within recursive circuits.

mod batch_stark;
mod errors;
mod observable;
mod periodic;
mod quotient;
mod stark;

pub use batch_stark::{
    CircuitTablesAir, PcsVerifierParams, verify_batch_circuit, verify_p3_batch_proof_circuit,
};
pub use errors::VerificationError;
pub use observable::ObservableCommitment;
pub(crate) use periodic::evaluate_periodic_columns_circuit;
pub use quotient::recompose_quotient_from_chunks_circuit;
pub use stark::verify_p3_uni_proof_circuit;
