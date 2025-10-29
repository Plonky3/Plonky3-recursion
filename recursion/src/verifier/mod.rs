//! STARK verification within recursive circuits.

mod batch_stark;
mod errors;
mod observable;
mod stark;

pub use batch_stark::{BatchProofTargets, InstanceOpenedValuesTargets, verify_batch_circuit};
pub use errors::VerificationError;
pub use observable::ObservableCommitment;
pub use stark::verify_circuit;
