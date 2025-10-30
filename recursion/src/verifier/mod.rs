//! STARK verification within recursive circuits.

mod errors;
mod observable;
mod stark;

pub use errors::VerificationError;
pub use observable::ObservableCommitment;
pub use stark::verify_circuit;
