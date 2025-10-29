//! STARK verification within recursive circuits.

mod errors;
mod observable;
mod quotient;
mod stark;

pub use errors::VerificationError;
pub use observable::ObservableCommitment;
pub use quotient::recompose_quotient_from_chunks_circuit;
pub use stark::verify_circuit;
